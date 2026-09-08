<?php
// public/crypto.php
// 2026-09-01: Coldvault crypto helpers (created).
// 2026-09-04: prepared for public release (MIT).
//   New scheme: PBKDF2-HMAC-SHA256 -> AES-256-GCM (authenticated).
// All functions are pure (no I/O). Plaintext is handled here and never sent to the database.
// 2026-09-01: comment wording only — refer to the database generically (no vendor name).

if (!defined('VAULT_AAD')) define('VAULT_AAD', 'coldvault-v1');

// ---- New secure scheme -----------------------------------------------------

// Derive a 32-byte key from a keyword + per-vault salt (slow, GPU-resistant-ish).
// 2026-09-03: returns false on a non-positive iteration count instead of letting
//   hash_pbkdf2() raise a fatal ValueError. A format-2 row carries iterations=0, so a
//   mislabelled or corrupt row must fail closed here rather than 500 the page.
// 2026-09-08 (second independent review, LOW): an UPPER bound as well. The iteration count is read
//   straight out of the row, and the row is exactly what a database-write attacker controls. There
//   was a floor but no ceiling, so setting vault.iterations (or vault_keyslot.iterations) to a
//   billion made every open of that vault run PBKDF2 for hours - one row edit hangs a PHP worker
//   per attempt, and the owner cannot open their own vault to fix it. A derivation at the default
//   450,000 iterations takes roughly a second on a modest server, so this ceiling caps a single
//   derivation at a few seconds while leaving 4.4x headroom above VAULT_ITER for raising the cost
//   later. Legitimate rows carry VAULT_ITER, or 100,000 for the oldest vaults; both are far below.
const VAULT_ITER_MAX = 2000000;

function v_derive($keyword, $salt, $iter) {
    $iter = (int)$iter;
    if ($iter < 1 || $iter > VAULT_ITER_MAX || !is_string($salt) || $salt === '') return false;
    return hash_pbkdf2('sha256', $keyword, $salt, $iter, 32, true);
}

// Encrypt a plaintext string. Returns [iter, salt, nonce, tag, ct] (all raw bytes).
// 2026-09-08 (second independent review, MEDIUM): bound the plaintext HERE, at the only two doors
//   into the ciphertext column, rather than in each handler. AES-GCM adds no padding, so the
//   ciphertext is exactly as long as the payload; the column is varbinary(2048). The create path
//   capped the PIN and passphrase but no path ever capped word LENGTH, so 24 words of 200
//   characters produced ~4.9 KB. On a server without STRICT_TRANS_TABLES that is silently
//   truncated, and because the tag covers the FULL plaintext the vault can never be opened again -
//   indistinguishable from a forgotten keyword, for the one asset this app exists to preserve.
//   Both callers already treat false as "self-check failed; nothing changed", so refusing here
//   fails closed with a message and cannot corrupt anything. Covers every present and future
//   caller, which is why it is not in the handlers.
const VAULT_PT_MAX = 1900;   // varbinary(2048) with room for the GCM tag and future fields

function v_encrypt($plaintext, $keyword, $iter) {
    if (!is_string($plaintext) || strlen($plaintext) > VAULT_PT_MAX) return false;
    $salt  = random_bytes(16);
    $nonce = random_bytes(12);
    $tag   = '';
    $key   = v_derive($keyword, $salt, $iter);
    if ($key === false) return false;
    $ct    = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, VAULT_AAD, 16);
    if ($ct === false) return false;
    return ['iter' => $iter, 'salt' => $salt, 'nonce' => $nonce, 'tag' => $tag, 'ct' => $ct];
}

// Decrypt. Returns plaintext string, or false if the keyword is wrong / data tampered.
function v_decrypt($rec, $keyword) {
    $key = v_derive($keyword, $rec['salt'], (int)$rec['iter']);
    if ($key === false) return false;
    return openssl_decrypt($rec['ct'], 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $rec['nonce'], $rec['tag'], VAULT_AAD);
}

// ---- Envelope scheme (format 2) — shared vaults ----------------------------
// 2026-09-03: multi-keyslot support. The payload is encrypted ONCE under a random
//   32-byte DEK; every authorised person gets that same DEK wrapped under their own
//   PBKDF2(keyword, own salt). So N keywords open one vault without N copies of the
//   ciphertext, and a keyword can be added or changed without re-encrypting the seed.
//   Deliberately distinct AAD per layer, so a wrapped key can never be mistaken for
//   a payload or vice versa, even if a caller mixes up the columns.

if (!defined('VAULT_AAD_V2'))  define('VAULT_AAD_V2',  'coldvault-v2');
if (!defined('VAULT_KEK_AAD')) define('VAULT_KEK_AAD', 'coldvault-kek-v1');

// A fresh data-encryption key. This — not the keyword — encrypts the payload.
function v_new_dek() { return random_bytes(32); }

// Wrap (encrypt) a DEK under one keyword. Returns [iter, salt, nonce, tag, ct].
// Each keyslot gets its own salt, so two slots cannot be correlated.
function v_wrap($dek, $keyword, $iter) {
    if (!is_string($dek) || strlen($dek) !== 32) return false;
    $salt  = random_bytes(16);
    $nonce = random_bytes(12);
    $tag   = '';
    $kek   = v_derive($keyword, $salt, $iter);
    if ($kek === false) return false;
    $ct    = openssl_encrypt($dek, 'aes-256-gcm', $kek, OPENSSL_RAW_DATA, $nonce, $tag, VAULT_KEK_AAD, 16);
    if ($ct === false) return false;
    return ['iter' => $iter, 'salt' => $salt, 'nonce' => $nonce, 'tag' => $tag, 'ct' => $ct];
}

// Unwrap a keyslot. Returns the raw 32-byte DEK, or false on a wrong keyword,
// tampering, or a malformed slot.
function v_unwrap($slot, $keyword) {
    $kek = v_derive($keyword, $slot['salt'], (int)$slot['iter']);
    if ($kek === false) return false;
    $dek = openssl_decrypt($slot['ct'], 'aes-256-gcm', $kek, OPENSSL_RAW_DATA, $slot['nonce'], $slot['tag'], VAULT_KEK_AAD);
    if ($dek === false || strlen($dek) !== 32) return false;
    return $dek;
}

// Encrypt the payload under the DEK. No KDF here — the DEK is already a key.
// Returns [nonce, tag, ct]. A format-2 vault row stores iterations=0 and an unused
// random salt, because those columns are NOT NULL from the format-1 scheme.
function v_encrypt_dek($plaintext, $dek) {
    if (!is_string($dek) || strlen($dek) !== 32) return false;
    if (!is_string($plaintext) || strlen($plaintext) > VAULT_PT_MAX) return false;   // see VAULT_PT_MAX
    $nonce = random_bytes(12);
    $tag   = '';
    $ct    = openssl_encrypt($plaintext, 'aes-256-gcm', $dek, OPENSSL_RAW_DATA, $nonce, $tag, VAULT_AAD_V2, 16);
    if ($ct === false) return false;
    return ['nonce' => $nonce, 'tag' => $tag, 'ct' => $ct];
}

// Decrypt a format-2 payload. Returns plaintext, or false.
function v_decrypt_dek($rec, $dek) {
    if (!is_string($dek) || strlen($dek) !== 32) return false;
    return openssl_decrypt($rec['ct'], 'aes-256-gcm', $dek, OPENSSL_RAW_DATA, $rec['nonce'], $rec['tag'], VAULT_AAD_V2);
}
