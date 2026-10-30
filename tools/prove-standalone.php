<?php

declare(strict_types=1);

/**
 * Prove the package does not need a framework.
 *
 * ## Why this is a script and not a unit test
 *
 * A unit test can only assert about the classes it happens to load. This asserts about the
 * whole *load graph*: it autoloads every class in `src/`, then checks that not one symbol
 * from Laravel, Symfony, PSR or Composer's runtime is present in `get_declared_classes()`,
 * `get_declared_interfaces()` or `get_declared_traits()`.
 *
 * That is the property a host actually cares about. "It has no `use Illuminate` at the top"
 * is a proxy for "I can drop this in a plain PHP application", and a proxy can be wrong in
 * both directions — a transitive `require`, a class that type-hints a framework type in a
 * signature, a constant reference that only resolves on Laravel.
 *
 * Run: php tools/prove-standalone.php
 *
 * Exits non-zero on the first failure, so it is usable as a CI step.
 */

declare(ticks=1);

$root = dirname(__DIR__);

// A deliberately minimal autoloader. Not Composer's: the point is to demonstrate that the
// package resolves with nothing but PHP's own SPL machinery.
spl_autoload_register(static function (string $class) use ($root): void {
    $prefix = 'NutriCompare\\Fingerprint\\';
    if (! str_starts_with($class, $prefix)) {
        return;
    }

    $relative = str_replace('\\', '/', substr($class, strlen($prefix)));
    $file = $root.'/src/'.$relative.'.php';
    if (is_file($file)) {
        require $file;
    }
});

$failures = [];
$checked = 0;

/** @return list<string> */
function allPhpFiles(string $directory): array
{
    $found = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));
    foreach ($iterator as $file) {
        if ($file instanceof SplFileInfo && $file->isFile() && $file->getExtension() === 'php') {
            $found[] = $file->getPathname();
        }
    }
    sort($found);

    return $found;
}

$classes = [];
foreach (allPhpFiles($root.'/src') as $file) {
    $relative = substr($file, strlen($root.'/src/'));
    if (basename($file) === 'autoload.php') {
        // The SPL autoloader itself. It declares no class, so trying to resolve one from it
        // is a false failure — and the first version of this script reported exactly that.
        continue;
    }

    $fqcn = 'NutriCompare\\Fingerprint\\'.str_replace('/', '\\', substr($relative, 0, -4));

    if (! class_exists($fqcn) && ! interface_exists($fqcn) && ! trait_exists($fqcn) && ! enum_exists($fqcn)) {
        $failures[] = "could not autoload {$fqcn} from {$relative} with a bare SPL autoloader";

        continue;
    }

    $classes[] = $fqcn;
    $checked++;
}

echo "autoloaded {$checked} classes with a bare SPL autoloader\n";

// --- the whole load graph must be framework-free -------------------------------
$loaded = array_merge(get_declared_classes(), get_declared_interfaces(), get_declared_traits());
$forbidden = [
    'Illuminate\\' => 'Laravel',
    'Symfony\\' => 'Symfony',
    'Psr\\' => 'PSR',
    'Laravel\\' => 'Laravel legacy',
    'Monolog\\' => 'Monolog',
    'Composer\\InstalledVersions' => 'Composer runtime',
];

$offenders = [];
foreach ($loaded as $symbol) {
    foreach ($forbidden as $prefix => $label) {
        if (str_starts_with($symbol, $prefix)) {
            $offenders[] = "{$label}: {$symbol}";
        }
    }
}

if ($offenders !== []) {
    foreach (array_slice($offenders, 0, 20) as $offender) {
        $failures[] = "the load graph reached a framework symbol — {$offender}";
    }
    $failures[] = count($offenders).' framework symbol(s) in the load graph';
}

// --- and the source itself must not reference one ------------------------------
//
// Word boundaries, and NOT substrings. The first version of this check used
// `str_contains($contents, 'e(')` and reported every `type(`, `value(` and `case(` in the
// package as a framework call — a false positive on the word "the" plus a paren. A guard
// that cries wolf gets deleted, so the patterns have to mean what they say.
$frameworkPatterns = [
    // NAMESPACE PREFIXES, on the code — not on the load graph.
    //
    // These are here because the load graph CANNOT see them. PHP resolves parameter and
    // return type hints lazily, so a framework class named only in a signature is never
    // autoloaded and never appears in `get_declared_classes()`. `RawHeaderCapture` shipped
    // with `use Illuminate\Http\Request;` in a signature and this script reported STANDALONE
    // PASS — over a file that could not run outside Laravel. A nullable hint never resolves at
    // all, so passing null skips the check entirely.
    //
    // The two halves failed independently: the load-graph half was blind to signatures, and
    // the source half was blind to namespaces because it only looked for helper CALLS. Both
    // are needed and neither is sufficient.
    // NOTE on the escaping below. These are SINGLE-quoted PHP strings, where `\\` collapses
    // to one backslash — so a regex wanting a literal backslash needs FOUR of them in the
    // source. The first version of these patterns used two, which produced a regex ending in
    // a trailing backslash, and PCRE reported "No ending delimiter" once per file. The
    // warnings were noisy rather than dangerous, but a guard that cannot compile is a guard
    // that is not running.
    '#(?<![A-Za-z0-9_\\\\])\bIlluminate\\\\#' => 'Laravel namespace',
    '#(?<![A-Za-z0-9_\\\\])\bSymfony\\\\#' => 'Symfony namespace',
    '#(?<![A-Za-z0-9_\\\\])\bPsr\\\\#' => 'PSR namespace',
    '#(?<![A-Za-z0-9_\\\\])\bMonolog\\\\#' => 'Monolog',
    '#\\\\(?:Illuminate|Symfony|Psr)\\\\#' => 'a fully-qualified framework reference',
    // A host application's own class. The package must drop into a repository that has its
    // own `App\` namespace; depending on one would defeat the whole point of the package.
    '#(?<![A-Za-z0-9_\\\\])\bApp\\\\(?!\\\\)#' => 'a host application class',

    // Helper CALLS.
    '/(?<![A-Za-z0-9_$>])\bconfig\s*\(/' => 'config()',
    '/(?<![A-Za-z0-9_$>])\bLog::/' => 'Log:: facade',
    '/(?<![A-Za-z0-9_$>])\bCache::/' => 'Cache:: facade',
    '/(?<![A-Za-z0-9_$>])\bCookie::/' => 'Cookie:: facade',
    '/(?<![A-Za-z0-9_$>])\bDB::/' => 'DB facade',
    '/(?<![A-Za-z0-9_$>])\bapp\s*\(/' => 'app() helper',
    '/(?<![A-Za-z0-9_$>])\brequest\s*\(/' => 'request() helper',
    '/(?<![A-Za-z0-9_$>])\bredirect\s*\(/' => 'redirect() helper',
    '/(?<![A-Za-z0-9_$>])\bview\s*\(/' => 'view() helper',
    '/(?<![A-Za-z0-9_$>])\bresponse\s*\(/' => 'response() helper',
    '/(?<![A-Za-z0-9_$>])\bevent\s*\(/' => 'event() helper',
    '/(?<![A-Za-z0-9_$>])\bnow\s*\(\s*\)/' => 'now() helper',
    '/(?<![A-Za-z0-9_$>])\bcollect\s*\(/' => 'collect() helper',
    '/(?<![A-Za-z0-9_$>])\bStr::/' => 'Str facade',
    '/(?<![A-Za-z0-9_$>])\bCarbon::/' => 'Carbon',
];

/**
 * Strip comments before scanning.
 *
 * Several of these classes explain in their docblock WHY they do not call `config()` or
 * `Log::`, and a scan that reads prose as code reports the explanation as the violation. The
 * first version of this check reported `Settings.php` for mentioning `config()` in the very
 * sentence that says it does not use it.
 */
$stripComments = static function (string $source): string {
    $source = (string) preg_replace('#/\*.*?\*/#s', '', $source);

    return (string) preg_replace('#^\s*(//|\*).*$#m', '', $source);
};

$sourceHits = [];
foreach (allPhpFiles($root.'/src') as $file) {
    if (basename($file) === 'autoload.php') {
        // Declares `spl_autoload_register`, which the config() and app() patterns do not
        // match anyway, but skipping it keeps the intent obvious.
        continue;
    }

    $code = $stripComments((string) file_get_contents($file));
    foreach ($frameworkPatterns as $pattern => $label) {
        if (preg_match($pattern, $code) === 1) {
            $sourceHits[] = basename($file).' references '.$label;
        }
    }
}
foreach ($sourceHits as $hit) {
    $failures[] = $hit;
}

// ---------------------------------------------------------------------------
// Every REFERENCED package class must resolve to a file in this package.
// ---------------------------------------------------------------------------
//
// ## Why this check exists, and it is not redundant with the count above
//
// The autoloader iterates the files that EXIST. Nothing compared against an expected set and
// nothing resolved a *referenced* name, so deleting a file that is still referenced was
// invisible. Measured, by deleting `Transport/RawHeaderOrder.php` — the return type of
// `RawHeaderCapture::capture()`, referenced from nine places:
//
//     autoloaded 21 classes          (was 22)
//     no framework symbol in the load graph, and no framework reference in src/
//     STANDALONE: PASS                exit 0
//
// while calling that method was:
//     PHP Fatal error: Uncaught Error: Class "…\RawHeaderOrder" not found
//
// ## Counting files would NOT have caught it
//
// The obvious fix — compare the autoloaded class count against the number of class
// declarations in the tree — is a no-op. Deleting the file removes one class from BOTH sides
// of that comparison, so the numbers stay equal and the gate passes on a package that cannot
// load. The only signal that distinguishes the two states is whether a REFERENCED name
// resolves.
//
// This is the same failure class as the `Illuminate\Http\Request` import this script was
// originally blind to: a name that only appears in a signature, which PHP resolves lazily, so
// it never reaches `get_declared_classes()` and the load graph cannot see it.
$declared = [];
foreach (allPhpFiles($root.'/src') as $file) {
    if (basename($file) === 'autoload.php') {
        continue;
    }
    $source = (string) file_get_contents($file);
    // Modifiers in ANY order, any number of them. `final readonly class Ja4` was not matched
    // by a pattern allowing only `final` or `abstract`, so the class was missing from
    // `$declared` and every reference to it was reported as unresolved. A declaration regex
    // that has to be updated each time a modifier is used is a declaration regex that will
    // eventually be wrong; `(?:final\s+|abstract\s+|readonly\s+)*` cannot be.
    if (preg_match('/^(?:(?:final|abstract|readonly)\s+)*(?:class|interface|trait|enum)\s+(\w+)/m', $source, $m) === 1) {
        // PSR-4 takes the namespace from the DIRECTORY and the class from the FILE. The first
        // version of this built it from the whole path including the filename, which produced
        // `…\Support\TransportRequestFacts\TransportRequestFacts` and reported a phantom
        // unresolved reference on a correct tree. A gate that fires on a clean tree is worse
        // than no gate, because the next time it fires you do not know which to believe.
        $dir = dirname(substr($file, strlen($root.'/src/')));
        $namespace = $dir === '.' || $dir === ''
            ? 'NutriCompare\\Fingerprint'
            : 'NutriCompare\\Fingerprint\\'.str_replace('/', '\\', $dir);

        $declared[] = $namespace.'\\'.$m[1];
    }
}

$unresolved = [];
foreach (allPhpFiles($root.'/src') as $file) {
    if (basename($file) === 'autoload.php') {
        continue;
    }

    $source = $stripComments((string) file_get_contents($file));
    $relative = substr($file, strlen($root.'/src/'));
    // Same directory-to-namespace rule as `$declared`, and the empty case handled explicitly:
    // `substr($relative, 0, 0)` is `''`, and concatenating that leaves a trailing separator, so
    // a class at the src root resolved as `NutriCompare\Fingerprint\\RawHeaderOrder`.
    $ownDir = dirname($relative);
    $ownNamespace = $ownDir === '.' || $ownDir === ''
        ? 'NutriCompare\\Fingerprint'
        : 'NutriCompare\\Fingerprint\\'.str_replace('/', '\\', $ownDir);

    // The alias map this file can actually use. A short name means the LAST segment of its
    // import, and that import may be aliased — resolving `Config` against the wrong file's
    // aliases is how a reference-resolution check ends up reporting fifteen phantom failures.
    $aliases = [];
    if (preg_match_all('/^use\s+([A-Za-z0-9_\\\\]+)(?:\s+as\s+(\w+))?;/m', $source, $uses, PREG_SET_ORDER) > 0) {
        foreach ($uses as $use) {
            $short = $use[2] ?? substr($use[1], (int) strrpos($use[1], '\\') + 1);
            $aliases[$short] = $use[1];
        }
    }

    foreach ($aliases as $short => $fqcn) {
        $aliases[$short] = str_starts_with($fqcn, 'NutriCompare\\Fingerprint\\') ? $fqcn : null;
    }

    // Every position a class name can appear: static call, construction, a parameter or return
    // type, a property or constant type, and a catch clause. Type hints are the ones that
    // matter here — they are exactly what the load graph cannot see.
    if (preg_match_all('/(?<![A-Za-z0-9_\\\\$>])([A-Z]\w+)::/', $source, $statics) > 0) {
        foreach ($statics[1] as $name) {
            $candidate = $aliases[$name] ?? ($ownNamespace === '' ? null : $ownNamespace.'\\'.$name);
            if ($candidate !== null && ! in_array($candidate, $declared, true)) {
                $unresolved[$candidate][] = $relative;
            }
        }
    }
    if (preg_match_all('/new\s+([A-Z]\w+)\s*\(/', $source, $news) > 0) {
        foreach ($news[1] as $name) {
            $candidate = $aliases[$name] ?? ($ownNamespace === '' ? null : $ownNamespace.'\\'.$name);
            if ($candidate !== null && ! in_array($candidate, $declared, true)) {
                $unresolved[$candidate][] = $relative;
            }
        }
    }
    if (preg_match_all('/(?<![A-Za-z0-9_\\\\$>])(?:private|public|protected|readonly|\?)?\s*\??([A-Z]\w+)\s+\$/', $source, $params) > 0) {
        foreach ($params[1] as $name) {
            $candidate = $aliases[$name] ?? ($ownNamespace === '' ? null : $ownNamespace.'\\'.$name);
            if ($candidate !== null && ! in_array($candidate, $declared, true)) {
                $unresolved[$candidate][] = $relative;
            }
        }
    }
}

foreach ($unresolved as $fqcn => $where) {
    $failures[] = sprintf(
        'referenced but not loadable in this package: %s (in %s)',
        $fqcn,
        implode(', ', array_unique($where))
    );
}

if ($failures === []) {
    echo "no framework symbol in the load graph, and no framework reference in src/\n";
    echo "\nSTANDALONE: PASS\n";
    exit(0);
}

echo "\n";
foreach ($failures as $failure) {
    echo "  FAIL  {$failure}\n";
}
echo "\nSTANDALONE: FAIL\n";
exit(1);
