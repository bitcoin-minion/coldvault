<?php
/**
 * tools/genkey.php — generate a fresh APP_KEY for a Coldvault instance.
 * 2026-09-04: initial public release (MIT).
 *
 *   php tools/genkey.php
 *
 * Prints one line, ready to paste into coldvault.env. Writes nothing, sends
 * nothing anywhere. CLI only, so the key can never reach an HTTP access log.
 *
 * WHAT THIS KEY DOES
 *   APP_KEY encrypts the stored authenticator secrets and hashes the backup
 *   codes and the invite codes. It does NOT encrypt any recovery phrase — those
 *   are encrypted under each vault's own keyword, which is never stored.
 *
 * SO, THE TWO THINGS TO UNDERSTAND
 *   1. Lose APP_KEY and EVERY account is permanently locked out. No authenticator
 *      code and no backup code can be verified any more. The vault ciphertext
 *      survives untouched — but nothing can sign in to reach it. Back this key up
 *      somewhere off the server, before you create your first account.
 *   2. Changing APP_KEY on a live instance has exactly the same effect as losing
 *      it. Generate it ONCE, at install time.
 *
 * The app refuses to start unless APP_KEY decodes to exactly 32 bytes — no
 * default and no fallback. A wrong key would otherwise fail silently, writing
 * secrets that the real key could never read again.
 */

if (PHP_SAPI !== 'cli') {
    if (!headers_sent()) { header('HTTP/1.1 403 Forbidden'); }
    exit("genkey.php is a command-line tool and refuses to run over the web.\n");
}

if (!function_exists('random_bytes')) {
    fwrite(STDERR, "This PHP build has no random_bytes(). PHP 7.0 or newer is required.\n");
    exit(1);
}

$key = base64_encode(random_bytes(32));

echo "\n";
echo "  Add this line to your coldvault.env (and to nothing else):\n\n";
echo "    APP_KEY=" . $key . "\n\n";
echo "  Then:  chmod 600 coldvault.env\n";
echo "\n";
echo "  Back this key up off the server NOW, before creating an account.\n";
echo "  Losing it locks every account out permanently. Changing it does the same.\n";
echo "\n";
