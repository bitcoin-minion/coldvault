<?php
// public/config.php
// 2026-09-04: Coldvault public release (MIT) — request hardening, tunables, database.
//   Secrets are NOT in this file. They are read from the configuration file located
//   by env.php, which lives outside the document root. See coldvault.env.example.

require_once __DIR__ . '/env.php';

// No secret ever goes to the browser cache or an intermediary.
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// ============================================================================
// Content-Security-Policy lives HERE rather than in the web server config, so
// that script-src can drop 'unsafe-inline'.
//   A nonce has to be fresh per request and has to appear in BOTH the header and
//   every inline <script> tag; a static header cannot generate one, so a policy
//   set in .htaccess could only ever be the weaker version.
//   FAIL-LOUD by design: a <script> block that forgets to echo CSP_NONCE is
//   refused by the browser, so a missed one shows up as a visibly broken page
//   rather than as a quiet return to inline-anything.
//   Do NOT also set a CSP in .htaccess: two CSP headers are BOTH enforced, and
//   the static one would silently re-admit inline script.
//   style-src DELIBERATELY keeps 'unsafe-inline'. Inline style attributes are
//   pervasive in this markup, and injecting style is not executing script.
//   Consequence of setting it here: responses that never load this file — the
//   static assets and captcha.php — carry no CSP. That costs nothing; a CSP on a
//   stylesheet or an image governs nothing. It is the HTML document that matters.
// ============================================================================
define('CSP_NONCE', base64_encode(random_bytes(16)));
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-" . CSP_NONCE . "'; "
     . "style-src 'self' 'unsafe-inline'; "
     . "font-src 'self'; img-src 'self' data:; object-src 'none'; "
     . "base-uri 'self'; frame-ancestors 'none'; form-action 'self'");

// Never render errors to the page — they can leak values. Log nothing sensitive.
ini_set('display_errors', '0');
error_reporting(0);

// ============================================================================
// The keyword is the encryption key, so it must never cross cleartext HTTP.
// LOCAL_MODE (see env.php) is the only way past this, and only for development.
// ============================================================================
// 2026-09-07 (security review): the forwarded-protocol header is honoured ONLY when
// TRUST_FORWARDED_PROTO is enabled (a proxy you control terminates TLS). Otherwise a client
// could send `X-Forwarded-Proto: https` over plain HTTP and turn the HTTPS gate off.
$vault_https = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off')
    || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
    || (TRUST_FORWARDED_PROTO
        && isset($_SERVER['HTTP_X_FORWARDED_PROTO'])
        && strtolower(trim(explode(',', $_SERVER['HTTP_X_FORWARDED_PROTO'])[0])) === 'https');
if (!$vault_https && !LOCAL_MODE) {
    // Do a scheme-upgrading redirect only to a host we can trust. The client Host header (and
    // Apache's SERVER_NAME, which mirrors it under the default UseCanonicalName Off) are attacker-
    // controlled, so reflecting either enables an open redirect / 301 cache poisoning. Redirect
    // only to a configured CANONICAL_HOST; with none set, refuse rather than reflect. In the
    // documented topology the Apache HTTP->HTTPS redirect runs before this anyway.
    $cv_redir_host = (CANONICAL_HOST !== '' && preg_match('/^[A-Za-z0-9.\-]+(:[0-9]{1,5})?$/', CANONICAL_HOST)) ? CANONICAL_HOST : '';
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' || $cv_redir_host === '') { http_response_code(403); exit('HTTPS required.'); }
    header('Location: https://' . $cv_redir_host . ($_SERVER['REQUEST_URI'] ?? '/'));
    exit;
}

// Base URL path, so clean links work whether the app is served at / or in a
// subdirectory. Derived from the executing script, never from user input.
// 2026-09-07 (security review): APP_BASE is echoed into many href/src attributes. It derives from
// SCRIPT_NAME, which is server-set under stock mod_php, but some CGI/FastCGI setups let request
// path segments leak into it. Restrict it to a safe path charset so it can never carry markup.
// 2026-09-08 (second independent review, LOW): the charset guard alone was not enough. "//evil.com"
//   passes it - it starts with "/" and every remaining character is in the allowed set - and
//   "//evil.com/" is a PROTOCOL-RELATIVE URL, so every href/src attribute on the page would have
//   pointed at an attacker's host, including the stylesheet, qrcode.js and the CAPTCHA image. Any
//   repeated slash is now rejected, which also covers "/a//b". Belt and braces with the charset
//   rule: the charset stops markup, this stops host substitution.
$cv_base = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/') . '/';
if (!preg_match('#^/[A-Za-z0-9_./\-]*$#', $cv_base) || strpos($cv_base, '//') !== false) $cv_base = '/';
define('APP_BASE', $cv_base);
unset($cv_base);

// ============================================================================
// KDF cost. Applies to NEW and re-saved vaults; existing vaults keep the
// iteration count stored on their own row, so raising this is always safe.
// 450,000 is roughly 1 second on a modest server. Raise it if yours is faster;
// every guess an attacker makes pays the same price.
// ============================================================================
define('VAULT_ITER', 450000);

// ============================================================================
// Transparent upgrade of format-1 vaults to the envelope scheme (format 2),
// which is what makes shared keywords possible. When true, the next successful
// unlock of a format-1 vault migrates it inside a transaction: the new blob is
// self-checked AND read back through the real format-2 path before commit, so
// any failure rolls back and the vault simply stays format 1, fully usable.
// Reading a vault never requires this flag.
//
// Note the migration is NOT undone by reverting the code — older code cannot
// read a format-2 row. To go back you would need a database backup as well.
// A fresh install creates format-2 vaults from the start, so this only matters
// if you are carrying data forward.
// ============================================================================
define('VAULT_AUTO_UPGRADE', true);

// ============================================================================
// Shared access via one-time invite codes.
//   INVITE_TTL_HOURS  how long an invite code stays valid. It is a full key to
//                     the vault while it lives, so this is deliberately short.
//   INVITE_MAX_FAILS  wrong-code attempts before an invite burns itself out.
//   MIN_KEYSLOT_BITS  entropy floor for any keyword that opens a vault. A shared
//                     vault is only as strong as its WEAKEST keyword, so a guest
//                     cannot undermine the owner with a soft one.
// ============================================================================
define('INVITE_TTL_HOURS', 72);
define('INVITE_MAX_FAILS', 10);
define('MIN_KEYSLOT_BITS', 65);

// 2026-09-07 (security review): each keyword attempt costs one ~1s PBKDF2 derivation. To stop a
// single account from turning that into a CPU-amplification DoS:
//   MAX_VAULTS_PER_ACCOUNT  hard cap on vaults an account may create.
//   COLLISION_CHECK_MAX     above this many vaults, skip the informational "same keyword opens
//                           another vault" check (which derives once per existing vault).
// Unlock additionally refuses to fan out across every vault when no specific vault was chosen
// (see the unlock handler) - it derives exactly once against the chosen vault.
// 2026-09-08 (second independent review, HIGH): COLLISION_CHECK_MAX cut from 25 to 4. At 25 it was
//   BOTH the CPU-amplification lever this block was written to close and a live correctness bug.
//   An `update` that sets a new keyword costs one derivation per vault in the collision loop + 1
//   to open + 2 to wrap and self-check, so at 25 vaults that is 27 derivations. At roughly a
//   second each on a modest server that exceeds PHP's default max_execution_time of 30, and the
//   loop runs AFTER vault_save() has already committed - so the request is killed, the owner's
//   change IS saved, and they get a dead page with no way to tell. `create` at the same vault
//   count has the same shape. At 4 the loop costs at most 3 derivations and the worst request is
//   6, comfortably inside the limit even on slow hardware.
//   The cost of the cut: accounts with 5+ openable vaults no longer get the advisory "that keyword
//   also opens another of your vaults" note. It is ADVISORY only - the vault chooser made a shared
//   keyword non-destructive - so nothing breaks without it. Fixing it properly means storing a
//   keyword fingerprint, which is a schema change and is not done.
define('MAX_VAULTS_PER_ACCOUNT', 50);
define('COLLISION_CHECK_MAX', 4);

// ============================================================================
// How many words a recovery phrase may have.
//   BIP39 mnemonics : 12, 15, 18, 21, 24 words (128 to 256 bits of entropy)
//   SLIP-39 shares  : 20 words (128-bit secret) or 33 (256-bit) — the
//                     Shamir-style backups some hardware wallets produce
// 24 is the default because it is the most common single full backup.
// ============================================================================
define('SEED_LENGTHS', [12, 15, 18, 20, 21, 24, 33]);
define('SEED_LENGTH_MAX', 33);
define('SEED_LENGTH_DEFAULT', 24);

// PHP 8.1+ makes the database driver throw on errors by default; force the
// classic "return false" behaviour so this app's error handling works on 7.4
// and 8.x alike. (mysqli_report is a fixed PHP API name.)
if (function_exists('mysqli_report')) { mysqli_report(MYSQLI_REPORT_OFF); }

// ============================================================================
// Startup failures all give the SAME vague answer: never reveal whether the
// configuration file, the key, the database user or the host is at fault.
// ============================================================================
function cv_unavailable() {
    http_response_code(503);
    header('Retry-After: 60');
    exit('Vault temporarily unavailable.');
}

// 2026-09-07 (security review): the CAPTCHA is the rate limiter on the passwordless sign-in, so it
// must be a real image challenge. GD + FreeType is now a hard requirement - the decodable SVG
// fallback was removed. Refuse to start without it, so this is caught at install, not in production.
if (!function_exists('imagecreatetruecolor') || !function_exists('imagettftext')) { cv_unavailable(); }

// ---------------------------------------------------------------------------
// APP_KEY must decode to exactly 32 bytes, and the app REFUSES TO START
// otherwise — deliberately no default and no fallback.
//
// A wrong or empty key would not fail loudly: it would silently write
// authenticator secrets and backup-code hashes that the real key can never read
// again. Failing closed keeps a mislaid key recoverable.
//
// APP_KEY protects the stored authenticator secrets, the backup codes and the
// invite codes. It does NOT protect the recovery phrase — that is encrypted
// under the vault keyword, which is never stored. So losing APP_KEY locks
// everyone OUT of their accounts while leaving the ciphertext intact and
// unreadable. BACK IT UP, off this machine.
// ---------------------------------------------------------------------------
$cv_ak = base64_decode((string)cv_env('APP_KEY'), true);
if ($cv_ak === false || strlen($cv_ak) !== 32) { cv_unavailable(); }
define('APP_KEY', $cv_ak);

// ---------------------------------------------------------------------------
// Database. Credentials come from the configuration file, never from this file.
// ---------------------------------------------------------------------------
define('CV_DB_NAME', cv_env('DB_NAME', 'coldvault'));

$cv_user = cv_env('DB_USER');
$cv_pass = cv_env('DB_PASS');
$cv_host = cv_env('DB_HOST', 'localhost');
$cv_port = (int)cv_env('DB_PORT', '0');

$con = ($cv_user !== '' && $cv_pass !== '')
    ? ($cv_port > 0
        ? mysqli_connect($cv_host, $cv_user, $cv_pass, CV_DB_NAME, $cv_port)
        : mysqli_connect($cv_host, $cv_user, $cv_pass, CV_DB_NAME))
    : false;

// Drop the secrets from memory so they cannot surface in a later dump or trace.
// (APP_KEY itself must stay reachable, so it lives on only as the constant.)
unset($GLOBALS['CV_ENV'], $cv_ak, $cv_user, $cv_pass, $cv_host, $cv_port);

if (!$con) { cv_unavailable(); }

// Must stay: every secret column is varbinary, but usernames are utf8mb4.
mysqli_set_charset($con, 'utf8mb4');
