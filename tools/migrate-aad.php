<?php
/**
 * tools/migrate-aad.php — re-encrypt APP_KEY-protected blobs under their bound context.
 * 2026-09-08: added with the removal of ak_decrypt()'s legacy AAD fallback (MIT).
 *
 *   php tools/migrate-aad.php            dry run - reports what it WOULD do, writes nothing
 *   php tools/migrate-aad.php --commit   apply, inside one verified transaction
 *
 * RUN THIS ONCE, after deploying a build dated 2026-09-08 or later, IF your instance
 * ever ran a build from before 2026-09-07. If you installed fresh on 2026-09-07 or
 * later there is nothing to migrate and the dry run will say so.
 *
 * WHY IT EXISTS
 *   Blobs encrypted before 2026-09-07 carry a CONSTANT additional-authenticated-data
 *   string. A constant AAD belongs to no particular row and no particular column, so
 *   such a blob decrypts correctly in ANY context — which means someone who can WRITE
 *   to the database can move one blob into a different column and have it accepted.
 *   That is not theoretical: a vault name is a blob whose plaintext the attacker
 *   chooses (they name the vault), so a name could be copied onto a user's stored
 *   authenticator secret, making that vault name the victim's TOTP secret. The
 *   attacker then knows the secret and can sign in as them, having forged nothing.
 *
 *   Newer builds bind each blob to its own row and column, and ak_decrypt() no longer
 *   falls back to the constant AAD. That closes the hole — and it also means any blob
 *   still under the old AAD stops opening. This tool moves them across.
 *
 * WHAT IT TOUCHES
 *   vault_users.secret_blob      bound to the account's username_lc
 *   vault.name_enc              bound to the owning user id
 *   vault_keyslot.label_enc     bound to the vault id
 *   vault_invite.label_enc      bound to the vault id
 *
 * SAFETY
 *   Every row is decrypted, re-encrypted and round-trip verified in memory BEFORE any
 *   write. All writes happen in one transaction, and then every row is read back and
 *   checked to open under its bound context and to NO LONGER open unbound. Any failure
 *   rolls the whole transaction back. Rows already bound are left untouched, so running
 *   it twice is harmless. No plaintext is ever printed or logged — only lengths.
 *
 * IF IT REPORTS "UNDECRYPTABLE"
 *   That row opens under neither AAD, which means APP_KEY is not the key those blobs
 *   were written with. STOP. Do not use --commit. Restore the correct APP_KEY first;
 *   a wrong key here cannot corrupt anything, because nothing is written when any row
 *   fails, but it does tell you the instance is misconfigured.
 */

if (PHP_SAPI !== 'cli') {
    if (!headers_sent()) { header('HTTP/1.1 403 Forbidden'); }
    exit("migrate-aad.php is a command-line tool and refuses to run over the web.\n");
}

$COMMIT = in_array('--commit', array_slice($argv, 1), true);
foreach (array_slice($argv, 1) as $a) {
    if ($a !== '--commit') { fwrite(STDERR, "Unknown option: $a\nUsage: php tools/migrate-aad.php [--commit]\n"); exit(2); }
}

// The app's own bootstrap, so this tool uses exactly the same APP_KEY and connection.
// config.php expects a web-ish environment; give it enough to load without redirecting.
$_SERVER['HTTPS']          = 'on';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI']    = '/';
$_SERVER['SCRIPT_NAME']    = '/index.php';

$root = dirname(__DIR__);

// config.php is written for the WEB: on any startup problem it prints a short, deliberately
// uninformative line and exits. That is exactly right there and exactly wrong here - it would
// leave this tool reporting success (exit 0) after doing nothing. So bootstrapping is guarded:
// if control never reaches $mg_booted, turn the early exit into a real failure with a real
// message. Buffering keeps the web-shaped line off stdout; PHP flushes buffers on exit, so the
// shutdown handler collects it rather than relying on ob_end_clean() ever being reached.
$mg_booted = false;
register_shutdown_function(function () use (&$mg_booted, $root) {
    if ($mg_booted) return;
    $buf = '';
    while (ob_get_level() > 0) { $buf .= (string)ob_get_clean(); }
    $buf = trim(preg_replace('/\s+/', ' ', strip_tags($buf)));
    fwrite(STDERR, "\n  Could not start: the app's own bootstrap refused to load"
        . ($buf !== '' ? " (\"$buf\")" : '') . ".\n"
        . "  This tool reads the same configuration as the web app. Check that\n"
        . "  " . $root . "/coldvault.env exists, is readable, and has a valid APP_KEY\n"
        . "  and database settings. Nothing was written.\n\n");
    exit(1);
});

if (!is_readable($root . '/coldvault.env')) {
    fwrite(STDERR, "\n  No readable coldvault.env at " . $root . "/coldvault.env\n"
        . "  Run this from an installed instance; it needs the same APP_KEY the app uses.\n\n");
    $mg_booted = true;   // this message is complete on its own
    exit(1);
}

ob_start();
require $root . '/public/config.php';
require $root . '/public/auth.php';
while (ob_get_level() > 0) { ob_end_clean(); }
$mg_booted = true;

if (!defined('APP_KEY') || strlen(APP_KEY) !== 32) {
    fwrite(STDERR, "  APP_KEY is missing or not 32 bytes. Fix the environment first. Nothing was written.\n");
    exit(1);
}
if (!isset($con) || !($con instanceof mysqli)) {
    fwrite(STDERR, "  No database connection after bootstrap. Nothing was written.\n");
    exit(1);
}

/** decrypt with ONE explicit AAD and no fallback, so each row can be classified */
function mg_raw($b, $aad) {
    if (!is_string($b) || strlen($b) <= 28) return false;
    return openssl_decrypt(substr($b, 28), 'aes-256-gcm', APP_KEY, OPENSSL_RAW_DATA,
                           substr($b, 0, 12), substr($b, 12, 16), $aad);
}

$JOBS = [
    ['vault_users',   'id', 'secret_blob', "SELECT id, secret_blob AS bb, username_lc AS k FROM vault_users",
        function ($x) { return ak_ctx_secret($x['k']); }],
    ['vault',         'id', 'name_enc',    "SELECT id, name_enc AS bb, user_id AS k FROM vault",
        function ($x) { return ak_ctx_name($x['k']); }],
    ['vault_keyslot', 'id', 'label_enc',   "SELECT id, label_enc AS bb, vault_id AS k FROM vault_keyslot",
        function ($x) { return ak_ctx_label($x['k']); }],
    ['vault_invite',  'id', 'label_enc',   "SELECT id, label_enc AS bb, vault_id AS k FROM vault_invite",
        function ($x) { return ak_ctx_label($x['k']); }],
];

echo $COMMIT ? "\n  AAD migration - COMMIT MODE\n\n" : "\n  AAD migration - DRY RUN (nothing will be written)\n\n";

if ($COMMIT && !mysqli_begin_transaction($con)) {
    fwrite(STDERR, "Could not start a transaction; aborted without writing.\n"); exit(1);
}

$plan = []; $bad = 0; $bound = 0;
foreach ($JOBS as $job) {
    list($tbl, $pk, $col, $sql, $ctxfn) = $job;
    $res = mysqli_query($con, $sql);
    if (!$res) { printf("    %-16s %s\n", $tbl, 'query failed: ' . mysqli_error($con)); $bad++; continue; }
    while ($x = mysqli_fetch_assoc($res)) {
        $b = $x['bb'];
        if ($b === null || $b === '') continue;
        $ctx = $ctxfn($x);
        if (mg_raw($b, ak_aad($ctx)) !== false) { $bound++; continue; }   // already bound
        $pt = mg_raw($b, ak_aad(''));                                    // legacy constant AAD
        if ($pt === false) {
            printf("    %-16s %s=%-6s %-12s UNDECRYPTABLE - wrong APP_KEY? nothing will be written\n", $tbl, $pk, $x['id'], $col);
            $bad++; continue;
        }
        $new = ak_encrypt($pt, $ctx);
        $ok  = ($new !== false && mg_raw($new, ak_aad($ctx)) === $pt);
        printf("    %-16s %s=%-6s %-12s legacy -> bound   plaintext %d B, blob %d -> %d B, round-trip %s\n",
               $tbl, $pk, $x['id'], $col, strlen($pt), strlen($b), $new === false ? 0 : strlen($new), $ok ? 'ok' : 'FAILED');
        if (!$ok) { $bad++; continue; }
        $plan[] = [$tbl, $pk, (int)$x['id'], $col, $new, $ctx, $pt];
    }
}

printf("\n    %d row(s) already bound, %d to migrate, %d problem(s).\n", $bound, count($plan), $bad);

if (!$COMMIT) {
    echo count($plan) === 0 && $bad === 0
        ? "\n    Nothing to do - this instance has no legacy blobs.\n\n"
        : "\n    Dry run only. Re-run with --commit to apply.\n\n";
    exit($bad > 0 ? 1 : 0);
}
if ($bad > 0)          { fwrite(STDERR, "\n    Refusing to commit while any row has a problem.\n\n"); mysqli_rollback($con); exit(1); }
if (count($plan) === 0) { echo "\n    Nothing to do.\n\n"; mysqli_rollback($con); exit(0); }

foreach ($plan as $p) {
    list($tbl, $pk, $id, $col, $new) = $p;
    $s = mysqli_prepare($con, "UPDATE `$tbl` SET `$col`=? WHERE `$pk`=?");
    if (!$s) { fwrite(STDERR, "    prepare failed on $tbl.$col; rolled back.\n"); mysqli_rollback($con); exit(1); }
    mysqli_stmt_bind_param($s, 'si', $new, $id);
    if (!mysqli_stmt_execute($s) || mysqli_stmt_affected_rows($s) !== 1) {
        fwrite(STDERR, "    write failed on $tbl.$col id=$id; rolled back.\n"); mysqli_rollback($con); exit(1);
    }
}

// read every row back, still inside the transaction, before committing anything
$fail = 0;
foreach ($plan as $p) {
    list($tbl, $pk, $id, $col, $new, $ctx, $pt) = $p;
    $s = mysqli_prepare($con, "SELECT `$col` AS bb FROM `$tbl` WHERE `$pk`=?");
    if (!$s) { $fail++; continue; }
    mysqli_stmt_bind_param($s, 'i', $id); mysqli_stmt_execute($s);
    $r = mysqli_stmt_get_result($s); $got = $r ? mysqli_fetch_assoc($r) : null;
    $opensBound   = $got && mg_raw($got['bb'], ak_aad($ctx)) === $pt;
    $opensUnbound = $got && mg_raw($got['bb'], ak_aad('')) !== false;
    printf("    verify %-16s %s=%-6s bound=%-3s still-unbound=%-3s %s\n", $tbl, $pk, $id,
           $opensBound ? 'yes' : 'NO', $opensUnbound ? 'YES' : 'no',
           ($opensBound && !$opensUnbound) ? 'ok' : 'FAILED');
    if (!($opensBound && !$opensUnbound)) $fail++;
}

if ($fail > 0) {
    fwrite(STDERR, "\n    $fail verification failure(s) - ROLLED BACK, nothing changed.\n\n");
    mysqli_rollback($con); exit(1);
}
mysqli_commit($con);
printf("\n    Committed %d row(s). Every blob now opens only under its bound context.\n\n", count($plan));
exit(0);
