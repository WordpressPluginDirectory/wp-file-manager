<?php
if (!defined('ABSPATH')) { exit; }

/**
 * Cross-subsite database export scope fix.
 *
 * Root cause: Backup_Database::backupTables() was always invoked with the
 * constant TABLES === '*', which internally runs a bare `SHOW TABLES` against
 * the raw MySQL connection (bypassing $wpdb entirely) and dumps every table
 * it finds. On a single-site install that is correct -- the whole database
 * *is* the site. On a WordPress Multisite install using the (default)
 * shared-database architecture, this is wrong: `SHOW TABLES` returns every
 * subsite's tables (`wp_2_*`, `wp_3_*`, ...) plus the network-global tables
 * (`wp_users`, `wp_usermeta`, `wp_blogs`, `wp_site`, `wp_sitemeta`,
 * `wp_signups`, `wp_registration_log`, `wp_blogmeta`), all in one archive,
 * regardless of which subsite an administrator triggered the export from.
 * A subsite administrator with no visibility into other subsites can
 * therefore obtain a complete dump of the entire network -- including every
 * other subsite's data and the network-wide users/usermeta table (emails +
 * password hashes) -- simply by using this plugin's ordinary "backup
 * database" feature on their own site.
 *
 * Fix: on Multisite, the table list passed to backupTables() is restricted
 * server-side to tables that actually belong to the site the request is
 * currently executing against, using WordPress's own authoritative
 * `$wpdb->tables()` API rather than ad-hoc string matching, plus a
 * conservative prefix-based sweep for custom/plugin tables that follow the
 * site's table prefix but aren't part of WordPress core's known table list.
 * Known network-global tables (`$wpdb->tables('global')` /
 * `$wpdb->tables('ms_global')`) are always excluded from a site-level
 * export. There is currently no supported "network-wide export" feature in
 * this plugin's UI, so no such mode is added here; if one is added later it
 * must be gated server-side on `is_super_admin()` and reachable only from
 * network-admin context, never from a client-supplied parameter.
 *
 * This function deliberately does NOT accept a blog ID (or any other scope
 * indicator) from client input. "Which site is this a backup for" is
 * determined the same way WordPress itself determines it: by the site
 * context the request is already executing in (i.e. $wpdb's current table
 * prefix), which WordPress resolves from the request's host/path before
 * this plugin's code ever runs. Accepting a blog ID as a request parameter
 * here would reintroduce exactly the kind of client-controlled scope this
 * fix is meant to remove.
 */
if (!function_exists('wpfm_get_db_export_tables')) {
    function wpfm_get_db_export_tables() {
        global $wpdb;

        if (!is_multisite()) {
            // Single-site: the whole database is the site. Unchanged from
            // the plugin's original behaviour.
            return '*';
        }

        // --- 1. Known core WordPress tables that belong to the current site ---
        $site_tables = array_values($wpdb->tables('blog'));

        // --- 2. Known network-global tables, which must NEVER be included in
        //        a per-site export, even on the main site (blog ID 1), where
        //        the base prefix and the site's own prefix are identical. ---
        $global_tables = array_merge(
            array_values($wpdb->tables('global')),
            array_values($wpdb->tables('ms_global'))
        );
        $global_tables = array_map('strtolower', $global_tables);

        // --- 3. Sweep for custom/plugin tables that belong to this site but
        //        aren't part of WordPress core's known table list (e.g. a
        //        WooCommerce or third-party plugin table created per-site),
        //        so $wpdb->tables('blog') wouldn't know about them.
        //
        //        This cannot be done with a simple "table name starts with
        //        this site's prefix" check: on the *main* site of the
        //        network, the site's own prefix (e.g. `wp_`) is itself a
        //        literal string-prefix of every subsite's prefix (`wp_2_`,
        //        `wp_3_`, ...), so a naive startsWith() check run from the
        //        main site would incorrectly match -- and export -- every
        //        other subsite's tables too. (This was caught by live
        //        testing against a real two-subsite network before this
        //        fix shipped; exporting from the main site returned every
        //        subsite's tables until the longest-prefix-match logic
        //        below was added.)
        //
        //        Instead, use a longest-prefix match across every blog's
        //        prefix in the network: a table belongs to whichever blog
        //        has the longest matching prefix. This is the same
        //        technique used for CIDR/route matching and is unambiguous
        //        even when one site's prefix is a literal substring of
        //        another's (`wp_` vs `wp_2_` vs `wp_20_`). ---
        $site_prefix = $wpdb->prefix; // Already scoped to the current site.
        $all_tables = $wpdb->get_col('SHOW TABLES');
        $current_blog_id = get_current_blog_id();
        $prefix_map = array(); // prefix => blog_id, longest prefixes first
        $blog_ids = $wpdb->get_col("SELECT blog_id FROM {$wpdb->blogs}");
        if (is_array($blog_ids)) {
            foreach ($blog_ids as $blog_id) {
                $prefix_map[$wpdb->get_blog_prefix((int) $blog_id)] = (int) $blog_id;
            }
        }
        // Always make sure the current blog's own prefix is present, even
        // if (for any reason) it wasn't returned by the query above.
        if (!isset($prefix_map[$site_prefix])) {
            $prefix_map[$site_prefix] = (int) $current_blog_id;
        }
        // Longest prefix first, so the search below finds the most specific
        // (correct) owner rather than stopping at a shorter, coincidental
        // match.
        uksort($prefix_map, function ($a, $b) {
            return strlen($b) - strlen($a);
        });

        $extra_site_tables = array();

        if (is_array($all_tables)) {
            foreach ($all_tables as $table) {
                if (in_array(strtolower($table), $global_tables, true)) {
                    // Known network-global table -- never include in a
                    // per-site export, regardless of prefix.
                    continue;
                }

                $owner_blog_id = null;
                foreach ($prefix_map as $prefix => $blog_id) {
                    if ($prefix !== '' && strpos($table, $prefix) === 0) {
                        $owner_blog_id = $blog_id; // first match = longest match
                        break;
                    }
                }

                if ($owner_blog_id === (int) $current_blog_id) {
                    $extra_site_tables[] = $table;
                }
                // Anything owned by a different blog_id, or unmatched
                // (doesn't start with any known site's prefix -- e.g. a
                // genuinely site-agnostic third-party table with no site
                // prefix at all), is excluded. Excluding the unmatched case
                // is the conservative, safe default: we only ever include a
                // table we can positively attribute to the current site.
            }
        }

        $tables = array_values(array_unique(array_merge($site_tables, $extra_site_tables)));

        /**
         * Known residual limitation (documented, not silently ignored):
         * on the *main* site of a Multisite network, this site's own table
         * prefix is identical to the network base prefix. A third-party
         * plugin table that is genuinely network-global (not core, not
         * caught by $wpdb->tables('global')/'ms_global') but happens to use
         * the base prefix cannot be distinguished from a main-site-only
         * custom table by prefix alone -- WordPress itself does not
         * disambiguate this for third-party tables. Such a table will be
         * included when exporting from the main site. This does not affect
         * subsites (blog ID > 1), whose prefix is unambiguous, and it does
         * not reintroduce the original vulnerability (no *other subsite's*
         * uniquely-prefixed tables, and none of WordPress's own core
         * network tables, are ever included).
         */

        return $tables;
    }
}
