<?php

declare(strict_types=1);

/**
 * A bare SPL autoloader, so the package works when copied into a repository.
 *
 * ## Why this exists when composer.json already declares PSR-4
 *
 * Because "drop it into any repository" has to include repositories that do not run Composer,
 * and a host should not have to add a dependency to test it. Thirteen lines is the whole
 * cost, and it is what `tools/prove-standalone.php` loads the package with — so the claim
 * that the package needs no framework is demonstrated rather than asserted.
 *
 * Composer users get the PSR-4 map in composer.json instead, and this file is simply unused.
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'NutriCompare\\Fingerprint\\';
    if (! str_starts_with($class, $prefix)) {
        return;
    }

    $relative = str_replace('\\', DIRECTORY_SEPARATOR, substr($class, strlen($prefix)));

    // `__DIR__` IS the src directory - this file lives inside it - so the path is built from
    // here with no further `src` segment. The first version appended one and resolved
    // `src/src/…`, which never existed. `tools/prove-standalone.php` did not catch it
    // because it uses its own inline autoloader rather than this file: this file had been
    // written and never loaded. `demo/standalone-demo.php` and `tools/golden-check.php` both
    // load the engine through this file, so a broken path fails both.
    $file = __DIR__.DIRECTORY_SEPARATOR.$relative.'.php';

    if (is_file($file)) {
        require $file;
    }
});
