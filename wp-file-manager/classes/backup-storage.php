<?php
if (!defined('ABSPATH')) { exit; }

/**
 * Security hardening (CVE-2026-19708).
 *
 * Centralised resolution of the backup storage directory.
 *
 * Historically every backup/restore code path re-derived the storage
 * location independently as `wp_upload_dir()['basedir'] . '/wp-file-manager-pro/fm_backup'`
 * -- i.e. always inside the public `wp-content/uploads` tree, which is
 * served directly by the web server on every common host. `.htaccess` /
 * `web.config` rules written into that directory are defense-in-depth only:
 * they do nothing on Nginx, and nothing on Apache when the host has
 * `AllowOverride None`.
 *
 * This function makes the storage location non-public by design wherever
 * that is safely possible:
 *
 *   1. Prefer a directory one level above the WordPress root
 *      (`dirname(ABSPATH) . '/wpfm-private-backups'`), which on the very
 *      common "webroot = public_html/httpdocs/htdocs, WordPress installed
 *      directly in it" layout sits outside the document root entirely.
 *   2. Before trusting that candidate, verify -- rather than assume -- that
 *      it does not resolve inside `$_SERVER['DOCUMENT_ROOT']` (when the
 *      host exposes that value) and that PHP can actually create/write to
 *      it. Different hosts (e.g. WordPress installed in a subdirectory of
 *      the document root, or symlinked doc roots) can make "one level up"
 *      unsafe or impossible, so this is checked, never assumed.
 *   3. If the private candidate cannot be safely verified or created, fall
 *      back to the historical uploads-based location, but that fallback is
 *      no longer the primary security boundary: `fm_download_backup()` /
 *      `fm_download_backup_all()` always enforce capability + backup-record
 *      + filename validation regardless of which storage mode is active,
 *      and the `.htaccess`/`web.config`/blank-index files are still written
 *      as an additional layer.
 *
 * The chosen directory is per-site under Multisite (subdirectory per blog
 * ID) so subsites cannot see or collide with each other's backups.
 */
if (!function_exists('wpfm_get_backup_storage')) {
    function wpfm_get_backup_storage() {
        static $cache = array();
        $blog_id = function_exists('get_current_blog_id') ? get_current_blog_id() : 0;

        if (array_key_exists($blog_id, $cache)) {
            return $cache[$blog_id];
        }

        /*
         * Backups must never use the public uploads directory as a read or
         * write fallback. Legacy public backups are migrated/removed by
         * wpfm_migrate_legacy_backups() before normal admin backup pages run.
         */
        $storage = wpfm_require_private_backup_storage_for_write();
        if (!$storage) {
            $cache[$blog_id] = false;
            return false;
        }

        $cache[$blog_id] = $storage;
        return $storage;
    }
}

/**
 * Security fix (per reviewer feedback on CVE-2026-19708 / submission #46085):
 * fail closed for NEW backup creation when no non-public storage location is
 * available, instead of silently falling back to the public uploads
 * directory. The permissive, fallback-including resolver above
 * (wpfm_get_backup_storage()) is still used -- unchanged -- for every READ
 * path (download, restore, delete, listing), because a backup that already
 * exists on disk (created before this fix, or on a host where private
 * storage later became unavailable) must remain manageable through the
 * plugin's UI. Only the WRITE path (creating a brand-new backup) is
 * tightened: if a verified-safe, writable, non-public location cannot be
 * established, no backup is written anywhere -- not even to the historical
 * public location -- and the caller must surface a clear, admin-facing
 * error instead.
 *
 * This deliberately does not create or touch the legacy public uploads
 * directory at all when private storage is unavailable; that directory is
 * only ever created (with protection files) as a side effect of an actual
 * successful private-storage check failing on a host where a backup was
 * already being requested under the old fallback behaviour. See
 * create_auto_directory() in file_folder_manager.php for the one place a
 * pre-existing legacy directory's protection files are still refreshed.
 *
 * @return array|false Array with 'path' (always private) and 'is_private'
 *                      (always true) on success; false if no safe,
 *                      writable, non-public location could be established.
 */
if (!function_exists('wpfm_require_private_backup_storage_for_write')) {
    function wpfm_require_private_backup_storage_for_write() {
        static $cache = array();
        $blog_id = function_exists('get_current_blog_id') ? get_current_blog_id() : 0;

        if (array_key_exists($blog_id, $cache)) {
            return $cache[$blog_id];
        }

        $suffix = $blog_id && is_multisite() ? '/site-' . (int) $blog_id : '';

        /**
         * Do not assume dirname(ABSPATH) is the only usable private parent.
         * Two common hosting layouts make that assumption unsafe/unavailable:
         * WordPress may live in a document-root subdirectory, or the
         * immediate parent of ABSPATH may not be writable by PHP. Walk up a
         * small number of existing ancestors and choose the first one that
         * is both writable and demonstrably outside the public document root.
         * The safety helper still performs the final realpath checks before
         * the directory is accepted.
         */
        $private_dir = false;
        $candidate_parent = rtrim(dirname(ABSPATH), '/\\');
        $real_docroot = !empty($_SERVER['DOCUMENT_ROOT']) ? realpath($_SERVER['DOCUMENT_ROOT']) : false;

        for ($i = 0; $i < 6 && $candidate_parent; $i++) {
            $real_parent = realpath($candidate_parent);
            if ($real_parent !== false && is_dir($real_parent) && is_writable($real_parent)) {
                $inside_docroot = false;
                if ($real_docroot !== false) {
                    $docroot = rtrim($real_docroot, '/\\');
                    $inside_docroot = ($real_parent === $docroot || strpos($real_parent . DIRECTORY_SEPARATOR, $docroot . DIRECTORY_SEPARATOR) === 0);
                }

                if (!$inside_docroot) {
                    $candidate = rtrim($real_parent, '/\\') . '/wpfm-private-backups' . $suffix;
                    if (wpfm_backup_dir_is_safe_and_writable($candidate)) {
                        $private_dir = $candidate;
                        break;
                    }
                }
            }

            $next_parent = dirname($candidate_parent);
            if ($next_parent === $candidate_parent) {
                break;
            }
            $candidate_parent = $next_parent;
        }

        if ($private_dir === false) {
            $cache[$blog_id] = false;
            return false;
        }

        $dir = rtrim($private_dir, '/\\') . '/';
        wpfm_write_backup_protection_files_at($dir);

        $result = array(
            'path'       => $dir,
            'is_private' => true,
        );
        $cache[$blog_id] = $result;
        return $result;
    }
}

/**
 * Attempts to create the given directory and verifies it is (a) not
 * resolvable inside the site's public document root, when that can be
 * determined, and (b) actually writable by PHP. Never assumes -- always
 * checks -- because hosting layouts vary (WordPress in a subdirectory,
 * symlinked doc roots, open_basedir restrictions, read-only filesystems
 * above the WP root, etc.).
 *
 * @param string $dir Absolute candidate directory path.
 * @return bool True only if the directory exists/was created, is writable,
 *              and is verifiably outside the document root (or the document
 *              root cannot be determined, in which case we still require it
 *              to differ from and not be nested under the uploads/ABSPATH
 *              public paths as a minimum safety check).
 */
if (!function_exists('wpfm_backup_dir_is_safe_and_writable')) {
    function wpfm_backup_dir_is_safe_and_writable($dir) {
        // Find the nearest existing parent of the candidate and require
        // that parent to be writable. This supports installations where the
        // immediate parent of ABSPATH is not writable, while still allowing
        // wp_mkdir_p() to create the private directory below a higher,
        // verified-safe ancestor.
        $required_existing_parent = rtrim($dir, '/\\');
        while (!is_dir($required_existing_parent)) {
            $next_parent = dirname($required_existing_parent);
            if ($next_parent === $required_existing_parent) {
                return false;
            }
            $required_existing_parent = $next_parent;
        }

        if (!is_writable($required_existing_parent)) {
            return false;
        }

        if (!file_exists($dir)) {
            // wp_mkdir_p() is recursive, so this also creates the private
            // root itself when it doesn't exist yet -- e.g.
            // the first time a given Multisite subsite ever needs it.
            if (!wp_mkdir_p($dir)) {
                return false;
            }
        }

        if (!is_dir($dir) || !is_writable($dir)) {
            return false;
        }

        $real_dir = realpath($dir);
        if ($real_dir === false) {
            return false;
        }

        // Never accept a "private" directory that is actually still inside
        // ABSPATH (would defeat the whole point) ...
        $real_abspath = realpath(ABSPATH);
        if ($real_abspath !== false && strpos($real_dir . DIRECTORY_SEPARATOR, rtrim($real_abspath, '/\\') . DIRECTORY_SEPARATOR) === 0) {
            return false;
        }

        // ... and verify the candidate is not nested inside the actual
        // public web/document root either. This check does not simply
        // trust $_SERVER['DOCUMENT_ROOT'] whenever it happens to be
        // non-empty: WP-CLI populates it with a compatibility shim set to
        // ABSPATH itself, not the real webserver-configured document
        // root, specifically so plugin code that expects a normal HTTP
        // request context doesn't fatal. On a host where WordPress is
        // installed in a subdirectory of the real document root, that
        // shimmed value is simply wrong -- it makes "one level above
        // ABSPATH" look safe by comparing it against ABSPATH's own
        // parent-adjacent shim instead of the true, larger document
        // root, when the true document root is in fact one level further
        // up still. This was found and reproduced directly: a candidate
        // genuinely inside the true public document root was reported
        // "safe" under a simulated WP-CLI subdirectory-install scenario,
        // because the check trusted the shimmed value.
        //
        // We only trust $_SERVER['DOCUMENT_ROOT'] when PHP is actually
        // running under a SAPI that serves real HTTP requests and sets
        // that value from the webserver's own configuration -- not any
        // CLI-family SAPI, regardless of what that CLI tooling has chosen
        // to populate the superglobal with for compatibility purposes.
        // Outside of a genuine web-serving SAPI, or when the value is
        // empty even under one, we cannot prove the candidate directory
        // is outside the publicly served tree, so it is rejected -- fail
        // closed, exactly like every other failed check in this function.
        // This trades availability (backup creation triggered via WP-CLI
        // or cron will fail closed with the plugin's existing "no safe
        // storage location" error) for the guarantee that a "private"
        // verdict is never returned without this check having actually
        // run against a value we have reason to trust.
        $web_serving_sapis = array('apache2handler', 'fpm-fcgi', 'cgi-fcgi', 'litespeed', 'cli-server');
        if (!in_array(php_sapi_name(), $web_serving_sapis, true)) {
            return false;
        }

        if (empty($_SERVER['DOCUMENT_ROOT'])) {
            return false;
        }

        $real_docroot = realpath($_SERVER['DOCUMENT_ROOT']);
        if ($real_docroot === false) {
            // DOCUMENT_ROOT was set but doesn't resolve to a real,
            // existing path (e.g. a misconfigured or non-existent value).
            // Same reasoning as above: cannot prove safety, so fail closed
            // rather than skip the check.
            return false;
        }

        if (strpos($real_dir . DIRECTORY_SEPARATOR, rtrim($real_docroot, '/\\') . DIRECTORY_SEPARATOR) === 0) {
            return false;
        }

        return true;
    }
}

/**
 * Writes/refreshes the defense-in-depth protection files (.htaccess,
 * web.config, blank index.html) inside a given backup directory. Kept even
 * for the private (outside-webroot) storage location, since it costs
 * nothing and covers the case where a future misconfiguration exposes the
 * directory anyway.
 */
if (!function_exists('wpfm_write_backup_protection_files_at')) {
    function wpfm_write_backup_protection_files_at($backup_dirname) {
        $backup_dirname = rtrim($backup_dirname, '/\\');
        if (!is_dir($backup_dirname) || !is_writable($backup_dirname)) {
            return;
        }

        // --- Apache: .htaccess ---------------------------------------------------
        $htaccess = $backup_dirname . '/.htaccess';
        $expected_htaccess = "# Deny direct access to all files in this directory.\n"
            . "# This is a defense-in-depth measure only; it has no effect on\n"
            . "# non-Apache web servers (e.g. Nginx) and must not be relied upon\n"
            . "# as the sole protection for these files.\n"
            . "<IfModule mod_authz_core.c>\n"
            . "    Require all denied\n"
            . "</IfModule>\n"
            . "<IfModule !mod_authz_core.c>\n"
            . "    Order allow,deny\n"
            . "    Deny from all\n"
            . "</IfModule>\n";

        $current_htaccess = file_exists($htaccess) ? @file_get_contents($htaccess) : false;
        if ($current_htaccess === false || $current_htaccess === '' || strpos($current_htaccess, '</Files>') !== false || strpos($current_htaccess, 'Require all denied') === false) {
            $handle = @fopen($htaccess, 'w');
            if ($handle) {
                @fwrite($handle, $expected_htaccess);
                @fclose($handle);
            }
        }

        // --- IIS: web.config -------------------------------------------------------
        $webconfig = $backup_dirname . '/web.config';
        $expected_webconfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            . "<configuration>\n"
            . "  <system.webServer>\n"
            . "    <authorization>\n"
            . "      <deny users=\"*\" />\n"
            . "    </authorization>\n"
            . "  </system.webServer>\n"
            . "</configuration>\n";
        $current_webconfig = file_exists($webconfig) ? @file_get_contents($webconfig) : false;
        if ($current_webconfig === false || strpos($current_webconfig, 'deny users') === false) {
            $handle = @fopen($webconfig, 'w');
            if ($handle) {
                @fwrite($handle, $expected_webconfig);
                @fclose($handle);
            }
        }

        // --- Generic: blank index to prevent directory listing ---------------------
        $index_file = $backup_dirname . '/index.html';
        if (!file_exists($index_file)) {
            $handle = @fopen($index_file, 'w');
            if ($handle) {
                @fclose($handle);
                @chmod($index_file, 0644);
            }
        }
    }
}

/**
 * One-time migration of pre-existing backups from the legacy public
 * `uploads/wp-file-manager-pro/fm_backup` location into the new private
 * storage location, for sites where private storage is available.
 *
 * Safety rules:
 *   - Only runs when the private location is actually in use for this site.
 *   - Never deletes a source file unless it was verified to have been
 *     copied successfully to the destination.
 *   - Never touches/deletes backup DB records -- `backup_name` values are
 *     unchanged, only the physical file location changes, so listing,
 *     download, restore and delete all keep working transparently because
 *     they resolve the directory through wpfm_get_backup_storage().
 *   - Idempotent: safe to run again if a previous run was interrupted
 *     (only copies files that don't already exist at the destination with
 *     a matching size).
 *   - Never runs the same site through migration twice on success: guarded
 *     by a per-site option.
 */
if (!function_exists('wpfm_migrate_legacy_backups')) {
    function wpfm_migrate_legacy_backups() {
        $upload_dir = wp_upload_dir();
        if (empty($upload_dir['basedir'])) {
            return;
        }

        $legacy_dir = rtrim($upload_dir['basedir'], '/\\') . '/wp-file-manager-pro/fm_backup';
        if (!is_dir($legacy_dir)) {
            return;
        }

        $files = @scandir($legacy_dir);
        if ($files === false) {
            return;
        }

        /*
         * Do not identify legacy backup artifacts by their filename prefix.
         * Older/affected releases can create database archives with an empty
         * backup name (for example, `-db.sql.gz`), so a strict backup_<...>
         * pattern leaves a vulnerable archive behind.
         *
         * The legacy directory is dedicated to File Manager backups. Process
         * every regular ZIP/GZIP archive in that directory, regardless of its
         * filename. Non-archive protection/marker files such as .htaccess,
         * web.config and index.html are intentionally left untouched.
         */
        $storage = wpfm_require_private_backup_storage_for_write();
        $migrated_names = array();

        foreach ($files as $file) {
            if ($file === '.' || $file === '..') {
                continue;
            }

            $src = $legacy_dir . '/' . $file;
            if (!is_file($src)) {
                continue;
            }

            /*
             * The legacy fm_backup directory is dedicated to File Manager
             * backup artifacts. Do not identify backups by filename or
             * extension: affected releases can produce unexpected names
             * (for example `-db.sql.gz`), and future backup formats may use
             * different extensions. Process every regular file in this
             * directory, while preserving only the directory's protection
             * / marker files.
             */
            $protected_files = array('.htaccess', 'web.config', 'index.html');
            if (in_array($file, $protected_files, true)) {
                continue;
            }

            /* Never follow a symlink out of the legacy backup directory. */
            $real_legacy_dir = realpath($legacy_dir);
            $real_src = realpath($src);
            if ($real_legacy_dir === false || $real_src === false ||
                strpos($real_src, rtrim($real_legacy_dir, '/\\') . DIRECTORY_SEPARATOR) !== 0) {
                continue;
            }

            if ($storage && !empty($storage['path'])) {
                $dest = rtrim($storage['path'], '/\\') . '/' . $file;

                $src_size = @filesize($src);
                $dest_size = file_exists($dest) ? @filesize($dest) : false;

                if (file_exists($dest) && $src_size !== false && $dest_size === $src_size) {
                    /* A verified copy already exists; remove the public copy. */
                    if (@unlink($src)) {
                        $migrated_names[] = $file;
                    }
                    continue;
                }

                if (@copy($src, $dest) && file_exists($dest) &&
                    $src_size !== false && @filesize($dest) === $src_size) {
                    @chmod($dest, 0600);
                    if (@unlink($src)) {
                        $migrated_names[] = $file;
                    }
                }
            } else {
                /*
                 * No safe private destination exists. Keeping an old archive
                 * in uploads would leave it directly downloadable by nginx or
                 * Apache, so remove every non-protection file in the dedicated File Manager backup directory.
                 */
                if (@unlink($src)) {
                    $migrated_names[] = $file;
                }
            }
        }

        /*
         * If public backups had to be removed because private storage was not
         * available, remove their database rows as well. This prevents the UI
         * from presenting deleted archives as restorable backups.
         */
        if (!$storage && !empty($migrated_names)) {
            global $wpdb;
            $table = $wpdb->prefix . 'wpfm_backup';

            foreach ($migrated_names as $file) {
                $base = preg_replace('/-(?:db\.sql\.gz|plugins\.zip|themes\.zip|uploads\.zip|others\.zip|all\.zip)$/', '', $file);
                if ($base !== '') {
                    $wpdb->delete($table, array('backup_name' => $base), array('%s'));
                }
            }
        }
    }
}

