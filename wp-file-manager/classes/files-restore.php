<?php
class wp_file_manager_files_restore {

   /**
    * Security hardening (CVE-2026-19708) - ZIP Slip protection.
    *
    * Previously every non-"wp-file-manager" entry name in the archive was
    * handed straight to ZipArchive::extractTo($destination, $allfiles).
    * While extractTo() does some internal normalisation, it is not a
    * substitute for validating entry names ourselves: a crafted archive
    * whose entries contain absolute paths, `..` traversal segments, or
    * backslash-based traversal (`..\..\wp-config.php`) can, depending on
    * PHP/libzip version, still cause files to be written outside the
    * intended restore directory (e.g. overwriting wp-config.php or placing
    * a PHP file inside a publicly-served directory).
    *
    * This version validates every entry name before extraction, rejects
    * the whole archive (no partial extraction) if any entry is unsafe, and
    * only then extracts. The resolved destination path for every entry is
    * verified to remain inside $destination, and a final on-disk pass
    * confirms nothing extracted outside the destination tree.
    */
   public function extract($source, $destination) {
      if (extension_loaded('zip') !== true) {
          return false;
      }
      if (file_exists($source) !== true) {
          return false;
      }

      $zip = new ZipArchive();
      $res = $zip->open($source);
      if ($res !== TRUE) {
          return false;
      }

      // Resolve/create the destination directory up front so we have a
      // canonical real path to contain every extracted entry within.
      if (!is_dir($destination)) {
          if (!wp_mkdir_p($destination)) {
              $zip->close();
              return false;
          }
      }
      $real_destination = realpath($destination);
      if ($real_destination === false) {
          $zip->close();
          return false;
      }
      $real_destination = rtrim(str_replace('\\', '/', $real_destination), '/') . '/';

      $safe_entries = array();

      for ($i = 0; $i < $zip->numFiles; $i++) {
          $filename = $zip->getNameIndex($i);
          if ($filename === false) {
              continue;
          }
          if (strpos($filename, 'wp-file-manager') !== false) {
              continue;
          }

          if (!$this->is_safe_zip_entry_name($filename)) {
              // Fail closed: abort the entire restore rather than
              // extracting a partial/possibly-malicious archive.
              $zip->close();
              return false;
          }

          $target = $real_destination . ltrim(str_replace('\\', '/', $filename), '/');
          // Belt-and-braces: re-verify the resolved target -- built purely
          // from string concatenation, without touching the filesystem --
          // still resolves (lexically) inside the destination directory.
          if (!$this->path_is_contained($target, $real_destination)) {
              $zip->close();
              return false;
          }

          $safe_entries[] = $filename;
      }

      // Extract only the pre-validated entry list. Every entry has already
      // been proven free of traversal/absolute-path segments above, and
      // extractTo() further normalises within libzip itself, so both
      // layers must agree before anything is written to disk.
      $extracted = $zip->extractTo($destination, $safe_entries);
      $zip->close();

      if (!$extracted) {
          return false;
      }

      // Final on-disk containment check: every file that ended up under
      // $destination must still resolve inside it (defends against any
      // symlink-based trickery introduced by the extraction itself).
      if (!$this->verify_extracted_contents_contained($destination, $real_destination)) {
          return false;
      }

      $isLocal = explode(':\\', $destination);
      $path = count($isLocal) > 1 ? str_replace(DIRECTORY_SEPARATOR, '/', $isLocal[1]) : str_replace(DIRECTORY_SEPARATOR, '/', $isLocal[0]);
      if (is_dir($destination . '/' . $path)) {
          $is_copied = copy_dir($destination . '/' . $path, $destination);
          if ($is_copied) {
              $folderarr = explode('/', $path);
              if (is_dir($destination . '/' . $folderarr[0])) {
                  $this->fm_rmdir($destination . '/' . $folderarr[0]);
              }
              return true;
          }
      }
      return true;
   }

    /**
     * Validates a single ZIP entry name before it is ever used to build a
     * filesystem path. Rejects anything that isn't a plain relative path.
     */
    private function is_safe_zip_entry_name($filename) {
        if ($filename === '' || $filename === null) {
            return false;
        }

        // Reject NUL bytes and other control characters outright.
        if (preg_match('/[\x00-\x1F]/', $filename)) {
            return false;
        }

        // Normalize backslashes to forward slashes for a single set of
        // checks (crafted Windows-style traversal, e.g. "..\..\foo").
        $normalized = str_replace('\\', '/', $filename);

        // Reject absolute paths (Unix "/etc/passwd", Windows "C:\...",
        // UNC "\\server\share").
        if (isset($normalized[0]) && $normalized[0] === '/') {
            return false;
        }
        if (preg_match('#^[A-Za-z]:#', $normalized)) {
            return false;
        }

        // Reject any use of PHP stream wrappers embedded in the entry name.
        if (preg_match('#^[a-zA-Z][a-zA-Z0-9+.\-]*://#', $normalized)) {
            return false;
        }

        // Reject any ".." path segment, wherever it appears.
        $segments = explode('/', $normalized);
        foreach ($segments as $segment) {
            if ($segment === '..') {
                return false;
            }
        }

        return true;
    }

    /**
     * Purely lexical containment check (no filesystem access needed/wanted
     * here since the target does not exist yet): resolves "." and ".."
     * segments against the known-safe $base and confirms the result still
     * starts with $base.
     */
    private function path_is_contained($target, $base) {
        $base = rtrim(str_replace('\\', '/', $base), '/') . '/';
        $target = str_replace('\\', '/', $target);

        $parts = explode('/', $target);
        $resolved = array();
        foreach ($parts as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                array_pop($resolved);
                continue;
            }
            $resolved[] = $part;
        }
        $resolved_path = '/' . implode('/', $resolved);

        return strpos($resolved_path . '/', $base) === 0 || strpos($resolved_path, $base) === 0;
    }

    /**
     * After extraction, walks the destination tree and confirms every
     * regular file/directory realpath()s to somewhere inside the
     * destination directory. Catches any symlink an archive entry might
     * have caused to be created pointing outside the tree.
     */
    private function verify_extracted_contents_contained($destination, $real_destination) {
        if (!is_dir($destination)) {
            return true;
        }
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($destination, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $item) {
            $real_item = realpath($item->getPathname());
            if ($real_item === false) {
                continue;
            }
            $real_item = str_replace('\\', '/', $real_item);
            if (strpos($real_item . '/', $real_destination) !== 0 && $real_item . '/' !== $real_destination) {
                return false;
            }
        }
        return true;
    }

    public function fm_rmdir($src) {
        $dir = opendir($src);
        while(false !== ( $file = readdir($dir)) ) {
            if (( $file != '.' ) && ( $file != '..' )) {
                $full = $src . '/' . $file;
                if ( is_dir($full) ) {
                    $this->fm_rmdir($full);
                }
                else {
                    unlink($full);
                }
            }
        }
        closedir($dir);
        rmdir($src);
    }

}
