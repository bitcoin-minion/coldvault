<?php
// public/env.php
// 2026-09-04: locate and parse the configuration file (public release).
//   No output, no headers, no database — safe to require from any entry point.
//   Deliberately separate from config.php because captcha.php reaches auth.php
//   WITHOUT config.php, and a few settings have to be identical on both paths.

// This file is required from more than one entry point, so it must survive being
// loaded twice. The constant guard below skips the PARSING on a second load, but
// note it cannot guard the function declarations further down: PHP binds top-level
// functions when it COMPILES an included file, before any statement in it runs, so
// an early `return` here would still hit "Cannot redeclare cv_env()". Hence the
// function_exists() wrapper around them, and require_once at every call site.
if (defined('CV_ENV_LOADED')) return;
define('CV_ENV_LOADED', 1);

// ---------------------------------------------------------------------------
// The configuration file holds APP_KEY and the database password, so it lives
// OUTSIDE the document root. Default: one level above public/, i.e. the project
// root. Override with the COLDVAULT_ENV environment variable (Apache SetEnv, or
// an env entry in your PHP-FPM pool) if you keep it somewhere else.
// ---------------------------------------------------------------------------
$cv_env_file = getenv('COLDVAULT_ENV');
if (!is_string($cv_env_file) || $cv_env_file === '') {
    $cv_env_file = dirname(__DIR__) . '/coldvault.env';
}
define('CV_ENV_FILE', $cv_env_file);

// Every NAME=value line. Split on the FIRST '=', so a value may itself contain '='.
// Lines starting with '#' are comments. Matching surrounding quotes are stripped.
$cv_pairs = [];
if (is_readable(CV_ENV_FILE)) {
    foreach (file(CV_ENV_FILE, FILE_IGNORE_NEW_LINES) ?: [] as $cv_l) {
        $cv_l = trim($cv_l);
        if ($cv_l === '' || $cv_l[0] === '#') continue;
        $cv_p = strpos($cv_l, '=');
        if ($cv_p === false) continue;
        $cv_k = strtolower(trim(substr($cv_l, 0, $cv_p)));
        $cv_v = trim(substr($cv_l, $cv_p + 1));
        $cv_n = strlen($cv_v);
        if ($cv_n >= 2 && ($cv_v[0] === '"' || $cv_v[0] === "'") && $cv_v[$cv_n - 1] === $cv_v[0]) {
            $cv_v = substr($cv_v, 1, -1);
        }
        $cv_pairs[$cv_k] = $cv_v;
    }
}
$GLOBALS['CV_ENV'] = $cv_pairs;
unset($cv_pairs, $cv_l, $cv_p, $cv_k, $cv_v, $cv_n, $cv_env_file);

// Conditional on purpose — see the note at the top of this file.
if (!function_exists('cv_env')) {
    function cv_env($name, $default = '') {
        $v = $GLOBALS['CV_ENV'][strtolower($name)] ?? '';
        return ($v === '') ? $default : $v;
    }

    function cv_env_bool($name) {
        return in_array(strtolower((string)cv_env($name, '')), ['1', 'true', 'yes', 'on'], true);
    }
}

// ---------------------------------------------------------------------------
// LOCAL_MODE relaxes the HTTPS requirement so you can open the app over plain
// http://localhost while developing.
//
// NEVER enable it on a reachable host. The keyword IS the encryption key: over
// cleartext HTTP anyone on the path reads it, and with it the recovery phrase.
// ---------------------------------------------------------------------------
if (!defined('LOCAL_MODE')) define('LOCAL_MODE', cv_env_bool('LOCAL_MODE'));

// The label an authenticator app shows for accounts on this instance.
if (!defined('OTP_ISSUER')) define('OTP_ISSUER', cv_env('OTP_ISSUER', 'Coldvault'));
