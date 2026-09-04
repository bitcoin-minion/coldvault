<?php
// public/index.php
// 2026-09-04: prepared for public release (MIT).
// 2026-09-01: Coldvault page — encrypt/decrypt seed vaults in PHP; the database stores ciphertext only (created).
// 2026-09-01: unified DB wording to "database" (UI copy + comments); help sections start collapsed.
require __DIR__ . '/config.php';   // headers, HTTPS enforcement, $con, VAULT_ITER
require __DIR__ . '/crypto.php';
require __DIR__ . '/auth.php';     // 2026-09-01: TOTP gate (replaces HTTP Basic auth)

$action   = $_POST['action'] ?? '';
$msg = null; $err = null; $notice = null; $revealed = null; $revealedId = null; $activeTab = 'unlock';
$pickedVault = 0;   // 2026-09-03: which vault the two-step chooser is working on

/* ===== 2026-09-03: CSRF gate — ONE check for every POST =====
   Deliberately here and nowhere else. Verifying per handler means the next handler
   someone adds is unprotected until they remember, and $_POST['action'] is read in only
   two places, so clearing it here disarms the request completely.
   On failure the action simply never happens and the page re-renders with a notice -
   no dead-end error screen - because in practice a bad token means a stale page or an
   expired session, not an attack.
   'logout' is EXEMPT on purpose: ending your own session cannot harm you, and refusing a
   legitimate sign-out would leave a session alive, which is strictly worse than letting
   someone force one to end. */
$__csrfbad = false;
if ($action !== '' && $action !== 'logout' && !cv_csrf_ok()) {
    if (($_POST['ajax'] ?? '') === '1') {
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'err' => 'This page has gone stale. Reload it and try again.']);
        exit;
    }
    if ($action === 'ping') { http_response_code(403); exit; }   // the client signs out on a non-204
    $action = ''; unset($_POST['action']);
    $__csrfbad = true;
    $notice = 'That page had gone stale, so nothing was done. Please try again.';
}

function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/* ================= vault access (2026-09-03: two storage formats) =================
   format 1 — the original scheme: the keyword itself derives the payload key.
   format 2 — envelope scheme: a random DEK encrypts the payload once, and each
              authorised person holds that DEK wrapped under their own keyword
              in vault_keyslot. This is what allows shared keywords.
   Both are read by the same code path below, so old and new vaults coexist.      */

// Every vault this user can open: their own format-1 vaults, plus any vault they
// hold a keyslot on. Their own keyslot is joined in, so unlock derives exactly once
// per vault instead of scanning every slot (~0.8s per derivation at 450k).
function vault_rows_for($con, $uid) {
    $st = mysqli_prepare($con,
        "SELECT v.id, v.format, v.user_id AS owner_id, v.name_enc, v.iterations, v.salt, v.nonce, v.tag, v.ciphertext,
                k.iterations AS k_iter, k.salt AS k_salt, k.nonce AS k_nonce,
                k.tag AS k_tag, k.wrapped_dek AS k_ct
         FROM vault v
         LEFT JOIN vault_keyslot k ON k.vault_id = v.id AND k.user_id = ?
         WHERE (v.format = 1 AND v.user_id = ?) OR k.id IS NOT NULL
         ORDER BY v.id");
    if (!$st) return [];
    mysqli_stmt_bind_param($st, 'ii', $uid, $uid);
    mysqli_stmt_execute($st);
    $res = mysqli_stmt_get_result($st);
    $out = [];
    while ($res && ($r = mysqli_fetch_assoc($res))) $out[] = $r;
    return $out;
}

// 2026-09-03: the vaults this user can open, WITHOUT any crypto material - just enough
//   to draw a chooser. Names are optional and APP_KEY-encrypted at rest, because
//   a vault name is sensitive metadata in its own right.
function vault_list_for($con, $uid) {
    $st = mysqli_prepare($con,
        "SELECT v.id, v.name_enc, v.created_at, v.user_id AS owner_id,
                (SELECT COUNT(*) FROM vault_keyslot k2 WHERE k2.vault_id = v.id) AS holders
         FROM vault v
         LEFT JOIN vault_keyslot k ON k.vault_id = v.id AND k.user_id = ?
         WHERE (v.format = 1 AND v.user_id = ?) OR k.id IS NOT NULL
         ORDER BY v.id");
    if (!$st) return [];
    mysqli_stmt_bind_param($st, 'ii', $uid, $uid);
    mysqli_stmt_execute($st);
    $res = mysqli_stmt_get_result($st);
    $out = [];
    while ($res && ($r = mysqli_fetch_assoc($res))) {
        $r['name'] = '';
        if ($r['name_enc'] !== null && $r['name_enc'] !== '') {
            $d = ak_decrypt($r['name_enc']);
            if ($d !== false) $r['name'] = $d;
        }
        unset($r['name_enc']);
        $out[] = $r;
    }
    return $out;
}

// Try one keyword against one vault row.
// Returns [plaintext, dek] on success (dek is null for format 1), or false.
function vault_try_open($row, $kw) {
    if ((int)$row['format'] === 2) {
        if ($row['k_ct'] === null) return false;                 // no keyslot here for this user
        $dek = v_unwrap(['iter'=>$row['k_iter'],'salt'=>$row['k_salt'],'nonce'=>$row['k_nonce'],
                         'tag'=>$row['k_tag'],'ct'=>$row['k_ct']], $kw);
        if ($dek === false) return false;
        $pt = v_decrypt_dek(['nonce'=>$row['nonce'],'tag'=>$row['tag'],'ct'=>$row['ciphertext']], $dek);
        return ($pt === false) ? false : [$pt, $dek];
    }
    $pt = v_decrypt(['iter'=>$row['iterations'],'salt'=>$row['salt'],'nonce'=>$row['nonce'],
                     'tag'=>$row['tag'],'ct'=>$row['ciphertext']], $kw);
    return ($pt === false) ? false : [$pt, null];
}

// 2026-09-03: "12, 15, 18, 20, 21, 24 or 33" - for error messages.
function seed_lengths_text() {
    $l = SEED_LENGTHS; $last = array_pop($l);
    return implode(', ', $l) . ' or ' . $last;
}

// Normalise a submitted phrase: trailing blanks are dropped, so a 12-word phrase can be
// typed into the full grid without the empty slots below it counting as missing words.
function seed_normalise($raw) {
    $w = array_map('trim', array_map('strval', (array)$raw));
    while (count($w) && end($w) === '') array_pop($w);
    return $w;
}

// 2026-09-03: two vaults must never share a keyword. Unlock stops at the FIRST vault
//   the keyword opens, so a second one becomes permanently unreachable through the app -
//   silently, with no error and no hint that it exists. Worse, an "Edit" afterwards
//   would quietly modify the wrong vault. Returns the colliding vault id, or 0.
//   Costs one key derivation per vault the user can open, which is why it is only
//   called when a keyword is being SET, never on a plain unlock.
function vault_keyword_collision($con, $uid, $kw, $exceptVaultId = 0) {
    if ($kw === '') return 0;
    foreach (vault_rows_for($con, $uid) as $row) {
        if ((int)$row['id'] === (int)$exceptVaultId) continue;
        if (vault_try_open($row, $kw) !== false) return (int)$row['id'];
    }
    return 0;
}

// Migrate one format-1 vault to the envelope scheme. Everything is verified BEFORE
// commit — including reading the row back through the real v2 path inside the same
// transaction — so any failure rolls back and leaves the original vault untouched.
// Returns true only when the upgrade is committed.
function vault_upgrade_v2($con, $vid, $uid, $kw, $payload) {
    $dek  = v_new_dek();
    $body = v_encrypt_dek($payload, $dek);
    $slot = v_wrap($dek, $kw, VAULT_ITER);
    if ($body === false || $slot === false)      return false;
    if (v_unwrap($slot, $kw) !== $dek)           return false;   // self-check the wrap
    if (v_decrypt_dek($body, $dek) !== $payload) return false;   // self-check the payload
    $label = ak_encrypt('owner');
    if ($label === false)                        return false;

    $ok = false;
    mysqli_begin_transaction($con);
    do {
        $zero = 0; $unused = random_bytes(16);   // iterations/salt are unused under format 2, but NOT NULL
        $u = mysqli_prepare($con, "UPDATE vault SET format=2, iterations=?, salt=?, nonce=?, tag=?, ciphertext=?
                                   WHERE id=? AND user_id=? AND format=1");
        if (!$u) break;
        mysqli_stmt_bind_param($u, 'issssii', $zero, $unused, $body['nonce'], $body['tag'], $body['ct'], $vid, $uid);
        if (!mysqli_stmt_execute($u) || mysqli_stmt_affected_rows($u) !== 1) break;

        $i = mysqli_prepare($con, "INSERT INTO vault_keyslot (vault_id,user_id,label_enc,iterations,salt,nonce,tag,wrapped_dek)
                                   VALUES (?,?,?,?,?,?,?,?)");
        if (!$i) break;
        mysqli_stmt_bind_param($i, 'iisissss', $vid, $uid, $label, $slot['iter'], $slot['salt'], $slot['nonce'], $slot['tag'], $slot['ct']);
        if (!mysqli_stmt_execute($i)) break;

        // read back through the real unlock path, still inside the transaction
        $back = null;
        foreach (vault_rows_for($con, $uid) as $r) { if ((int)$r['id'] === $vid) { $back = $r; break; } }
        if (!$back || (int)$back['format'] !== 2) break;
        $chk = vault_try_open($back, $kw);
        if ($chk === false || $chk[0] !== $payload) break;

        $ok = true;
    } while (false);
    if ($ok) mysqli_commit($con); else mysqli_rollback($con);
    return $ok;
}

// Who owns this vault? Ownership gates editing, inviting, removing and transferring.
function vault_owner_id($con, $vid) {
    $st = mysqli_prepare($con, "SELECT user_id FROM vault WHERE id=? LIMIT 1");
    if (!$st) return 0;
    mysqli_stmt_bind_param($st, 'i', $vid);
    mysqli_stmt_execute($st);
    $r = mysqli_stmt_get_result($st);
    $row = $r ? mysqli_fetch_assoc($r) : null;
    return $row ? (int)$row['user_id'] : 0;
}
function vault_is_owner($con, $vid, $uid) {
    return (int)$uid > 0 && vault_owner_id($con, $vid) === (int)$uid;
}

// Hand the vault to somebody who ALREADY holds a keyslot - you cannot make a stranger
// the owner. Irreversible from the old owner's side: they keep read access but lose all
// authority, and only the new owner can hand it back. Pending invite codes are
// destroyed, because codes the previous owner gave out must not keep working under new
// management.
function vault_transfer_owner($con, $row, $actorUid, $newOwnerUid) {
    $vid = (int)$row['id'];
    if ((int)($row['owner_id'] ?? 0) !== (int)$actorUid) return 'Only the owner of this vault can transfer it.';
    if ((int)$newOwnerUid <= 0)                          return 'Choose who should become the owner.';
    if ((int)$newOwnerUid === (int)$actorUid)            return 'That is already the owner.';
    $st = mysqli_prepare($con, "SELECT id FROM vault_keyslot WHERE vault_id=? AND user_id=? LIMIT 1");
    if (!$st) return 'Could not transfer ownership.';
    mysqli_stmt_bind_param($st, 'ii', $vid, $newOwnerUid);
    mysqli_stmt_execute($st);
    $r = mysqli_stmt_get_result($st);
    if (!$r || !mysqli_fetch_assoc($r)) return 'That person does not have access to this vault, so they cannot own it. Invite them first.';

    $ok = false;
    mysqli_begin_transaction($con);
    do {
        $u = mysqli_prepare($con, "UPDATE vault SET user_id=? WHERE id=? AND user_id=?");
        if (!$u) break;
        mysqli_stmt_bind_param($u, 'iii', $newOwnerUid, $vid, $actorUid);
        if (!mysqli_stmt_execute($u) || mysqli_stmt_affected_rows($u) !== 1) break;
        $d = mysqli_prepare($con, "DELETE FROM vault_invite WHERE vault_id=? AND used_at IS NULL");
        if (!$d) break;
        mysqli_stmt_bind_param($d, 'i', $vid);
        if (!mysqli_stmt_execute($d)) break;
        if (!vault_is_owner($con, $vid, $newOwnerUid)) break;   // confirm before committing
        $ok = true;
    } while (false);
    if (!$ok) { mysqli_rollback($con); return 'Could not transfer ownership; nothing was changed.'; }
    mysqli_commit($con);
    return null;
}

// Remove one person's access, properly. Deleting their row is NOT revocation: anyone
// holding a copy of that row plus the ciphertext can still recover the key offline and
// read the vault forever. So the data key is REPLACED and the payload re-encrypted
// under it, which makes every previously-issued wrap useless.
//
// The unavoidable consequence: only the person performing the removal has typed a
// keyword, so only THEIR slot can be re-wrapped. Every other slot is dropped and has
// to re-join by invite. Pending invites are dropped too, since they carry the old key.
// Returns null on success, or an error string.
function vault_revoke($con, $row, $actorUid, $kw) {
    $vid = (int)$row['id'];
    if ((int)$row['format'] !== 2) return 'This vault is not on the shared-capable format.';
    // 2026-09-03: SECURITY - the engine enforces ownership itself, not just the handler.
    //   This function deletes every keyslot except the caller's own, so if a guest ever
    //   reached it they would delete the OWNER'S entry and take the vault over. Guarding
    //   only at the handler left that one line away from a takeover. Never again.
    if ((int)($row['owner_id'] ?? 0) !== (int)$actorUid) return 'Only the owner of this vault can remove access.';
    $open = vault_try_open($row, $kw);
    if ($open === false) return 'Wrong keyword - nothing was changed.';
    $payload = $open[0];

    $dek2 = v_new_dek();
    $body = v_encrypt_dek($payload, $dek2);
    $slot = v_wrap($dek2, $kw, VAULT_ITER);
    if ($body === false || $slot === false)          return 'Self-check failed; nothing was changed.';
    if (v_decrypt_dek($body, $dek2) !== $payload)    return 'Self-check failed; nothing was changed.';
    if (v_unwrap($slot, $kw) !== $dek2)              return 'Self-check failed; nothing was changed.';

    $ok = false;
    mysqli_begin_transaction($con);
    do {
        $d = mysqli_prepare($con, "DELETE FROM vault_keyslot WHERE vault_id=? AND user_id<>?");
        if (!$d) break;
        mysqli_stmt_bind_param($d, 'ii', $vid, $actorUid);
        if (!mysqli_stmt_execute($d)) break;

        $u = mysqli_prepare($con, "UPDATE vault_keyslot SET iterations=?,salt=?,nonce=?,tag=?,wrapped_dek=? WHERE vault_id=? AND user_id=?");
        if (!$u) break;
        mysqli_stmt_bind_param($u, 'issssii', $slot['iter'], $slot['salt'], $slot['nonce'], $slot['tag'], $slot['ct'], $vid, $actorUid);
        if (!mysqli_stmt_execute($u) || mysqli_stmt_affected_rows($u) !== 1) break;

        $v = mysqli_prepare($con, "UPDATE vault SET nonce=?,tag=?,ciphertext=? WHERE id=? AND format=2");
        if (!$v) break;
        mysqli_stmt_bind_param($v, 'sssi', $body['nonce'], $body['tag'], $body['ct'], $vid);
        if (!mysqli_stmt_execute($v)) break;

        $ci = mysqli_prepare($con, "DELETE FROM vault_invite WHERE vault_id=? AND used_at IS NULL");
        if (!$ci) break;
        mysqli_stmt_bind_param($ci, 'i', $vid);
        if (!mysqli_stmt_execute($ci)) break;

        // prove the actor can still open it, before committing anything
        $back = null;
        foreach (vault_rows_for($con, $actorUid) as $r) if ((int)$r['id'] === $vid) $back = $r;
        if (!$back) break;
        $chk = vault_try_open($back, $kw);
        if ($chk === false || $chk[0] !== $payload) break;
        $ok = true;
    } while (false);
    if (!$ok) { mysqli_rollback($con); return 'Could not complete the removal; nothing was changed.'; }
    mysqli_commit($con);
    return null;
}

// Write an edited payload back. Returns null on success, or an error string.
// Under format 2 the payload is re-encrypted with the SAME DEK, so everyone else's
// keyslot keeps working, and a new keyword re-wraps only the caller's own keyslot.
function vault_save($con, $row, $uid, $kw, $newkw, $payload, $dek) {
    $vid = (int)$row['id'];
    // 2026-09-03: SECURITY - only the owner may change what a vault CONTAINS. A guest
    //   holding a keyslot can read the seed (that is the point of sharing) but must not
    //   be able to overwrite it: this vault is a backup, so a silent corruption would
    //   only surface on the day it is actually needed. Enforced here, in the function
    //   that does the writing, not merely in the request handler.
    if ((int)($row['owner_id'] ?? 0) !== (int)$uid) return 'Only the owner of this vault can change what it contains.';
    if ((int)$row['format'] === 2) {
        $body = v_encrypt_dek($payload, $dek);
        if ($body === false || v_decrypt_dek($body, $dek) !== $payload) return 'Update self-check failed; nothing changed.';
        $newslot = null;
        if ($newkw !== '') {
            $newslot = v_wrap($dek, $newkw, VAULT_ITER);
            if ($newslot === false || v_unwrap($newslot, $newkw) !== $dek) return 'Update self-check failed; nothing changed.';
        }
        $ok = false;
        mysqli_begin_transaction($con);
        do {
            $u = mysqli_prepare($con, "UPDATE vault SET nonce=?,tag=?,ciphertext=? WHERE id=? AND format=2");
            if (!$u) break;
            mysqli_stmt_bind_param($u, 'sssi', $body['nonce'], $body['tag'], $body['ct'], $vid);
            if (!mysqli_stmt_execute($u)) break;
            if ($newslot !== null) {
                $k = mysqli_prepare($con, "UPDATE vault_keyslot SET iterations=?,salt=?,nonce=?,tag=?,wrapped_dek=?
                                           WHERE vault_id=? AND user_id=?");
                if (!$k) break;
                mysqli_stmt_bind_param($k, 'issssii', $newslot['iter'], $newslot['salt'], $newslot['nonce'], $newslot['tag'], $newslot['ct'], $vid, $uid);
                if (!mysqli_stmt_execute($k) || mysqli_stmt_affected_rows($k) !== 1) break;
            }
            $ok = true;
        } while (false);
        if (!$ok) { mysqli_rollback($con); return 'Could not save changes.'; }
        mysqli_commit($con);
        return null;
    }
    // format 1 — unchanged: the keyword encrypts the payload directly
    $enckw = $newkw !== '' ? $newkw : $kw;
    $rec = v_encrypt($payload, $enckw, VAULT_ITER);
    if ($rec === false || v_decrypt($rec, $enckw) !== $payload) return 'Update self-check failed; nothing changed.';
    $u = mysqli_prepare($con, "UPDATE vault SET iterations=?,salt=?,nonce=?,tag=?,ciphertext=? WHERE id=? AND user_id=?");
    if (!$u) return 'Could not save changes.';
    mysqli_stmt_bind_param($u, 'issssii', $rec['iter'], $rec['salt'], $rec['nonce'], $rec['tag'], $rec['ct'], $vid, $uid);
    return mysqli_stmt_execute($u) ? null : 'Could not save changes.';
}

/* ---- shared access: entropy floor + one-time invite codes (2026-09-03) ---- */

// Server-side mirror of the browser strength meter and kwcheck.php. Keep the three
// in step; the standalone checker exists so a keyword can be audited offline.
//
// 2026-09-03: repetition no longer inflates the score. Two ways of gaming the floor
//   were closed, both found by testing the estimator against deliberately weak input:
//     a) each copy of a repeated word scored a full 11 bits, so
//        "aaa-aaa-aaa-aaa-aaa-aaa" measured 66 and cleared the 65-bit floor. Only
//        DISTINCT words count now, compared without regard to case.
//     b) the character fallback multiplied the FULL length by the alphabet size, so a
//        single letter repeated 24 times measured 113. Length is now capped at twice
//        the number of distinct characters, which leaves ordinary keywords untouched
//        (verified: every generated keyword and every kwcheck.php test vector scores
//        exactly what it scored before) and collapses repetitive ones.
//   This only ever gates a NEW keyword. It is not used to derive any key, so no
//   existing vault is affected - an old keyword that now measures lower still opens
//   its vault, and only triggers the advisory notice on unlock.
function cv_entropy($v) {
    if ($v === '') return 0;
    $t = []; $u = [];
    foreach (preg_split('/[^A-Za-z0-9]+/', $v) as $p)
        if (strlen($p) >= 3 && preg_match('/^[A-Za-z]+$/', $p)) { $t[] = $p; $u[strtolower($p)] = 1; }
    if (count($t) >= 3) {
        $b = count($u) * 11;                              // log2(2048) per DISTINCT word
        if (preg_match('/[A-Z]/', $v))           $b += 2;
        if (preg_match('/[0-9]/', $v))           $b += 3;
        if (preg_match('/[^A-Za-z0-9 \-]/', $v)) $b += 4;
    } else {
        $cs = 0;
        if (preg_match('/[a-z]/', $v))        $cs += 26;
        if (preg_match('/[A-Z]/', $v))        $cs += 26;
        if (preg_match('/[0-9]/', $v))        $cs += 10;
        if (preg_match('/[^A-Za-z0-9]/', $v)) $cs += 33;
        $b = min(strlen($v), 2 * count(count_chars($v, 1))) * log($cs ?: 2, 2);
    }
    return (int)round($b);
}

// 24 symbols from a 32-character alphabet with no I and no O, so nothing is mistaken
// for 1 or 0 when read aloud or copied by hand: 24 * 5 = ~120 bits.
function invite_alphabet() { return 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; }
function invite_new_code() {
    $a = invite_alphabet(); $o = '';
    for ($i = 0; $i < 24; $i++) $o .= $a[random_int(0, 31)];
    return $o;
}
function invite_fmt($c)   { return trim(chunk_split($c, 4, ' ')); }
function invite_norm($s)  { return preg_replace('/[^A-Z0-9]/', '', strtoupper((string)$s)); }
function invite_shape_ok($c) { return strlen($c) === 24 && strspn($c, invite_alphabet()) === 24; }
// Only the HMAC is stored, never the code itself - so a database leak cannot yield a
// working invite, and the code truly cannot be shown twice.
function invite_hash($c)  { return hash_hmac('sha256', $c, APP_KEY, true); }

// Who can open this vault. Labels are APP_KEY-encrypted at rest.
function vault_keyslots($con, $vid) {
    $st = mysqli_prepare($con,
        "SELECT k.id, k.user_id, k.label_enc, k.created_at, k.last_used_at, u.username
         FROM vault_keyslot k LEFT JOIN vault_users u ON u.id = k.user_id
         WHERE k.vault_id = ? ORDER BY k.id");
    if (!$st) return [];
    mysqli_stmt_bind_param($st, 'i', $vid);
    mysqli_stmt_execute($st);
    $res = mysqli_stmt_get_result($st); $out = [];
    while ($res && ($r = mysqli_fetch_assoc($res))) {
        $r['label'] = ak_decrypt($r['label_enc']);
        if ($r['label'] === false) $r['label'] = '(unreadable)';
        unset($r['label_enc']);
        $out[] = $r;
    }
    return $out;
}

// Invites still open: not redeemed, not expired, not burned by failed attempts.
function vault_invites_pending($con, $vid) {
    $st = mysqli_prepare($con,
        "SELECT id, label_enc, created_at, expires_at, fails
         FROM vault_invite
         WHERE vault_id = ? AND used_at IS NULL AND expires_at > NOW() AND fails < ?
         ORDER BY id");
    if (!$st) return [];
    $max = INVITE_MAX_FAILS;
    mysqli_stmt_bind_param($st, 'ii', $vid, $max);
    mysqli_stmt_execute($st);
    $res = mysqli_stmt_get_result($st); $out = [];
    while ($res && ($r = mysqli_fetch_assoc($res))) {
        $r['label'] = ak_decrypt($r['label_enc']);
        if ($r['label'] === false) $r['label'] = '(unreadable)';
        unset($r['label_enc']);
        $out[] = $r;
    }
    return $out;
}

/* ================= TOTP auth gate (2026-09-01) ================= */
function auth_shell($tagline, $inner, $qrScript = null) {
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
       . '<meta name="viewport" content="width=device-width, initial-scale=1">'
       . '<meta name="robots" content="noindex, nofollow">'
       . '<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0">'
       . '<title>Coldvault</title>' . '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHJlY3Qgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiByeD0iNSIgZmlsbD0iIzBhMGMwZCIvPjxnIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzVmZTNjMyIgc3Ryb2tlLXdpZHRoPSIxLjkiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCI+PHJlY3QgeD0iNC41IiB5PSIxMC41IiB3aWR0aD0iMTUiIGhlaWdodD0iOS41IiByeD0iMiIvPjxwYXRoIGQ9Ik04IDEwLjVWN2E0IDQgMCAwIDEgOCAwdjMuNSIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTUuNSIgcj0iMS4zIiBmaWxsPSIjNWZlM2MzIiBzdHJva2U9Im5vbmUiLz48L2c+PC9zdmc+">'
       . '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
       . '<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">'
       . '<link rel="stylesheet" href="'.APP_BASE.'style.css"></head><body><div class="wrap">'
       . '<div class="top"><div class="brand"><div class="mark"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.6" stroke-linecap="round"><rect x="4" y="10.5" width="16" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/><circle cx="12" cy="15.5" r="1.4"/></svg></div>'
       . '<div><h1>Cold<span class="b">vault</span><span class="cursor"></span></h1><div class="tagline">'.h($tagline).'</div></div></div></div>'
       . '<div class="card"><div class="authpane auth-narrow">'.$inner.'</div></div>'
       . '<div class="foot">coldvault &middot; authenticator required &middot; <a href="'.APP_BASE.'help/">help &amp; security</a></div></div>';
    if ($qrScript !== null) echo '<script src="'.APP_BASE.'qrcode.js"></script><script nonce="'.CSP_NONCE.'">'.$qrScript.'</script>';
    echo cv_busy_js();
    echo '<script nonce="'.CSP_NONCE.'">try{if(window.history&&history.replaceState)history.replaceState(null,"",location.pathname);}catch(e){}</script></body></html>';
}
// 2026-09-03: shared submit-feedback script. Swaps a submit button for a spinner +
//   label so a 1-4s PBKDF2 request never looks like a dead click. Skips forms whose
//   submit was already cancelled (failed validation, or an AJAX handler taking over).
function cv_busy_js() {
    // 2026-09-03: the JS body stays in a NOWDOC (no PHP interpolation, so nothing in it
    //   can be mangled), and the tag is concatenated around it to carry the nonce.
    $js = <<<'JS'
(function(){
  function busy(b,label){ if(!b||b.dataset.busy) return; b.dataset.busy='1'; b.dataset.html=b.innerHTML;
    b.classList.add('loading'); b.innerHTML='<span class="spin"></span> '+label;
    setTimeout(function(){ b.disabled=true; },0); }            // disable AFTER the form serialises
  function idle(b){ if(!b||!b.dataset.busy) return; b.disabled=false; b.classList.remove('loading');
    b.innerHTML=b.dataset.html; delete b.dataset.busy; delete b.dataset.html;
    if(b.form&&b.form.dataset.cvbusy) delete b.form.dataset.cvbusy; }
  window.cvBusy=busy; window.cvIdle=idle;

  /* 2026-09-03: every on*="..." attribute in the app now arrives here instead, as
     data-cv="<action>". Attributes cannot be nonced - that is the whole reason
     script-src had to allow 'unsafe-inline' - and one delegated listener replaces all
     23 of them. e.target is usually the <svg> inside a button, hence closest().
     ACT is an explicit allow-list, tested with ===1 so an inherited property name like
     "constructor" cannot slip through: markup injected into the page therefore gets no
     further than toggling a help panel, even though data attributes need no nonce. */
  var ACT={cvKeep:1,cvHelp:1,cvKwHelp:1,cvSeedHelp:1,cvSecHelp:1,toggleMask:1,editMode:1,
           cvGenKeyword:1,clearAll:1,idleStay:1,idleLogoutNow:1,ivCopy:1,rGen:1};
  document.addEventListener('click',function(e){
    var el=(e.target&&e.target.closest)?e.target.closest('[data-cv]'):null;
    if(!el) return;
    var a=el.getAttribute('data-cv');
    if(a==='eye'){ var i=document.getElementById(el.getAttribute('data-cv-for'));
                   if(i) i.type=(i.type==='password'?'text':'password'); return; }
    if(a==='peek'){ if(typeof window.peek==='function') window.peek(el.getAttribute('data-cv-for'),el); return; }
    if(a==='reload'){ location.reload(); return; }
    if(ACT[a]!==1) return;
    var fn=window[a]; if(typeof fn==='function') fn.call(el);
  },false);

  document.addEventListener('change',function(e){
    var el=(e.target&&e.target.closest)?e.target.closest('[data-cv-change]'):null;
    if(!el||el.getAttribute('data-cv-change')!=='cvSetCount') return;
    if(typeof window.cvSetCount==='function') window.cvSetCount(el.value);
  },false);

  /* Registered BEFORE the busy listener below, deliberately: it has to be able to
     preventDefault() first, so the spinner never starts on a form that failed
     validation. The old inline submit attribute gave that ordering for free, because an
     attribute handler runs at the element, before anything bound on document. */
  document.addEventListener('submit',function(e){
    var f=e.target;
    if(!f||!f.getAttribute||f.getAttribute('data-cv-validate')!=='validateCreate') return;
    if(typeof window.validateCreate==='function'&&!window.validateCreate()) e.preventDefault();
  },false);

  document.addEventListener('submit',function(e){
    var f=e.target; if(!f||f.tagName!=='FORM') return;
    if(f.dataset.cvbusy){ e.preventDefault(); return; }   // already submitted: block Enter-key repeats
    if(e.defaultPrevented) return;                        // validation failed, or AJAX took over
    var b=f.querySelector('button[type="submit"]')||f.querySelector('button:not([type])');
    if(b){ f.dataset.cvbusy='1'; busy(b, b.getAttribute('data-busytext')||'Working\u2026'); }
  },false);
})();
JS;
    return '<script nonce="' . CSP_NONCE . '">' . $js . '</script>';
}

// 2026-09-03: send someone back where they were headed after signing in. Only a
//   whitelisted screen NAME is remembered, never a URL, so this cannot be turned
//   into an open redirect. Reading it also clears it.
function auth_after_login_url() {
    $map = ['redeem' => 'redeem/', 'security' => 'security/'];
    $w = $_SESSION['cv_after'] ?? '';
    unset($_SESSION['cv_after']);
    return APP_BASE . ($map[$w] ?? '');
}

function captcha_field() {
    return '<label class="fl" for="cap" style="margin-top:14px">Human check</label>'
        . '<div class="caprow"><img class="capimg" src="'.APP_BASE.'captcha.php?'.bin2hex(random_bytes(4)).'" alt="captcha" width="190" height="62">'
        . '<input id="cap" name="captcha" type="text" autocomplete="off" autocorrect="off" autocapitalize="characters" spellcheck="false" placeholder="type the characters"></div>';
}
function render_login($err, $needCaptcha, $prefill) {
    $e = $err ? '<div class="banner bad"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg><span>'.h($err).'</span></div>' : '';
    $cap = $needCaptcha ? captcha_field() : '';
    $ctx = (($_SESSION['cv_after'] ?? '') === 'redeem')
        ? '<div class="banner ok"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg><span>Sign in first and we will take you straight to your invite. No account yet? Use <b>Create account</b> below &mdash; it only takes a minute.</span></div>'
        : '';
    $inner = '<h2 class="at">Sign in</h2><p class="lead">Enter your username and the current 6-digit code from your authenticator app. A backup code also works.</p>'.$ctx.$e
        . '<details class="hnote"><summary>Which code? Lost your phone?</summary><div>Enter the current 6-digit code from your authenticator app (Google Authenticator, Authy, 1Password, and similar). It rotates every 30 seconds. If you do not have your phone, type one of your one-time backup codes instead.</div></details>'
        . '<form method="POST" action="" autocomplete="off"><input type="hidden" name="action" value="login">'
        . cv_csrf_field()
        . '<label class="fl" for="lu">Username</label><div class="field"><input id="lu" name="username" type="text" value="'.h($prefill).'" autocomplete="username" autocorrect="off" autocapitalize="off" spellcheck="false" autofocus></div>'
        . '<label class="fl" for="lc">Code</label><input id="lc" class="codebig" name="code" type="tel" inputmode="numeric" autocomplete="one-time-code" placeholder="000000">'
        . $cap
        . '<div class="row" style="margin-top:16px"><button class="btn btn-primary" type="submit" data-busytext="Signing in…"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M5 12h14M13 6l6 6-6 6"/></svg> Sign in</button>'
        . '<a class="btn btn-ghost" href="'.APP_BASE.'register/">Create account</a></div></form>';
    auth_shell('sign in', $inner);
}
function render_register_start($err, $prefill) {
    $e = $err ? '<div class="banner bad"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg><span>'.h($err).'</span></div>' : '';
    $inner = '<h2 class="at">Create account</h2><p class="lead">Pick a username and solve the check. Next you will scan a QR into your authenticator app.</p>'.$e
        . '<form method="POST" action="" autocomplete="off"><input type="hidden" name="action" value="register_start">'
        . cv_csrf_field()
        . '<label class="fl" for="ru">Username</label><div class="field"><input id="ru" name="username" type="text" value="'.h($prefill).'" placeholder="3-32 chars: letters, numbers, . _ -" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" autofocus></div>'
        . '<input type="text" name="website" value="" tabindex="-1" autocomplete="off" style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0" aria-hidden="true">'
        . captcha_field()
        . '<div class="row" style="margin-top:16px"><button class="btn btn-primary" type="submit" data-busytext="Checking…"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M5 12h14M13 6l6 6-6 6"/></svg> Continue</button>'
        . '<a class="btn btn-ghost" href="'.APP_BASE.'">Have an account? Sign in</a></div></form>';
    auth_shell('create account', $inner);
}
function render_register_confirm($username, $secretB32, $err) {
    $uri = otpauth_uri($secretB32, $username);
    $e = $err ? '<div class="banner bad"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg><span>'.h($err).'</span></div>' : '';
    $grouped = trim(chunk_split($secretB32, 4, ' '));
    $inner = '<h2 class="at">Set up your authenticator</h2>'
        . '<ol class="steps"><li>Open Google Authenticator, Authy, 1Password, or similar.</li><li>Scan this QR (it saves as <b>'.h(OTP_ISSUER).'</b>).</li><li>Enter the 6-digit code it shows to finish.</li></ol>'
        . '<div class="qrbox" id="qrbox"></div><div class="mkey">'.h($grouped).'</div>'.$e
        . '<form method="POST" action="" autocomplete="off" style="margin-top:16px"><input type="hidden" name="action" value="register_confirm">'
        . cv_csrf_field()
        . '<input class="codebig" name="code" type="tel" inputmode="numeric" autocomplete="one-time-code" placeholder="000000" autofocus>'
        . '<div class="row" style="margin-top:16px"><button class="btn btn-primary" type="submit" data-busytext="Verifying…"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg> Verify &amp; activate</button></div></form>';
    $script = 'var qr=qrcode(0,"M");qr.addData('.json_encode($uri).');qr.make();document.getElementById("qrbox").innerHTML=qr.createSvgTag({cellSize:5,margin:1});';
    auth_shell('for '.h($username), $inner, $script);
}
function render_backup_codes($codes, $username) {
    $cells = '';
    foreach ($codes as $c) $cells .= '<div>'.h(fmt_backup_code($c)).'</div>';
    $inner = '<h2 class="at">Save your backup codes</h2><p class="lead">If you lose your phone, each code below logs <b>'.h($username).'</b> in <b>once</b>. Keep them somewhere safe and offline &mdash; they are shown only now.</p>'
        . '<div class="bcodes">'.$cells.'</div>'
        . '<div class="warn">These are not shown again.</div>'
        . '<div class="row" style="margin-top:18px"><a class="btn btn-primary" href="'.auth_after_login_url().'"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M5 12h14M13 6l6 6-6 6"/></svg> I saved them &mdash; continue</a></div>';
    auth_shell('backup codes', $inner);
}

// 2026-09-01: standalone public Help & security page (no secrets; readable while signed out).
function render_help() {
    $B = APP_BASE;
    $ico = 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHJlY3Qgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiByeD0iNSIgZmlsbD0iIzBhMGMwZCIvPjxnIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzVmZTNjMyIgc3Ryb2tlLXdpZHRoPSIxLjkiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCI+PHJlY3QgeD0iNC41IiB5PSIxMC41IiB3aWR0aD0iMTUiIGhlaWdodD0iOS41IiByeD0iMiIvPjxwYXRoIGQ9Ik04IDEwLjVWN2E0IDQgMCAwIDEgOCAwdjMuNSIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTUuNSIgcj0iMS4zIiBmaWxsPSIjNWZlM2MzIiBzdHJva2U9Im5vbmUiLz48L2c+PC9zdmc+';
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
       . '<meta name="viewport" content="width=device-width, initial-scale=1">'
       . '<meta name="robots" content="noindex, nofollow">'
       . '<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0">'
       . '<title>Coldvault &mdash; Help &amp; security</title>'
       . '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,'.$ico.'">'
       . '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
       . '<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">'
       . '<link rel="stylesheet" href="'.$B.'style.css"></head><body><div class="wrap helpwrap">'
       . '<div class="top"><div class="brand"><div class="mark"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.6" stroke-linecap="round"><rect x="4" y="10.5" width="16" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/><circle cx="12" cy="15.5" r="1.4"/></svg></div>'
       . '<div><h1>Cold<span class="b">vault</span></h1><div class="tagline">help &amp; security</div></div></div>'
       . '<a class="btn btn-ghost" href="'.$B.'"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M19 12H5M11 6l-6 6 6 6"/></svg> Back to vault</a></div>';
    echo <<<'HTML'
<p class="help-intro">Plain-language notes on how Coldvault protects your seed &mdash; and what the words on the screen actually mean. Nothing here is secret; it is the same design whether or not you are signed in. Tap any question to expand it.</p>
<div class="help-toc"><a href="#s1">Seed vs keyword</a><a href="#s2">Is 84 bits enough?</a><a href="#s3">Your seed phrase</a><a href="#s4">AES-256-GCM</a><a href="#s5">PBKDF2 &amp; 450k</a><a href="#s6">Zero-trace</a><a href="#s7">PIN &amp; passphrase</a><a href="#s8">Timers &amp; logout</a><a href="#s9">Lost keyword</a><a href="#s10">Lost your phone</a><a href="#s11">Sharing a vault</a></div>

<details class="qa" id="s1">
  <summary><span class="qn">01</span><span>The two secrets people mix up: your <b>seed</b> vs your <b>keyword</b></span><svg class="chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></summary>
  <div class="qa-body">
    <p>Coldvault involves two different secrets, and almost every security question comes from confusing them.</p>
    <p><b>Your seed</b> &mdash; your recovery words &mdash; is your wallet&rsquo;s real key. Whoever holds it controls the coins. Your wallet created it; Coldvault only stores an encrypted copy. It carries about <span class="m">256 bits</span> of entropy.</p>
    <p><b>Your keyword</b> is the password that encrypts that stored copy. Its only job is to stop someone who steals the encrypted database from reading your seed. It is not part of your wallet and never touches it.</p>
    <p>Why this matters: the &ldquo;you need at least 128 bits&rdquo; rule you may have read is about the <b>seed / key</b>, not the keyword. Two different jobs, two different bars &mdash; see the next section.</p>
  </div>
</details>

<details class="qa" id="s2">
  <summary><span class="qn">02</span><span>Is 84 bits low? For a keyword, no &mdash; it is very strong</span><svg class="chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></summary>
  <div class="qa-body">
    <p>&ldquo;Bits&rdquo; measure how many guesses an attacker needs &mdash; each extra bit <b>doubles</b> it. 84 bits is about 1.9 &times; 10<sup>25</sup> guesses (19 septillion).</p>
    <p>The 128-bit bar you have heard of is for <b>raw cryptographic keys</b>, which an attacker can test at full hardware speed &mdash; billions per second, no slowdown &mdash; plus a safety margin for future and quantum computers. <b>Your keyword is not attacked that way.</b></p>
    <p>Before a single keyword guess can even be checked, Coldvault runs it through <b>PBKDF2 450,000 times</b> (next section). That makes every guess about 450,000&times; slower. At 84 bits, a 100-GPU cracking farm would need <b>hundreds of billions of years</b>. There is no realistic attack.</p>
    <table class="help-tt">
      <tr><th>Generated keyword</th><th>Approx. entropy</th></tr>
      <tr><td>7 words + number + symbol</td><td>~84 bits</td></tr>
      <tr><td>12 words</td><td class="ok">~143 bits</td></tr>
      <tr><td>16 words</td><td class="ok">~187 bits</td></tr>
    </table>
    <div class="help-callout"><b>Bottom line:</b> past ~100 bits with the KDF, extra keyword bits lower an already-zero real-world risk to&hellip; still zero &mdash; it is peace of mind, which is a fine reason to go longer. The secret that genuinely needs 128+ bits is your <b>seed</b>, and a 24-word phrase already has ~256.</div>
  </div>
</details>

<details class="qa" id="s3">
  <summary><span class="qn">03</span><span>Your seed phrase &mdash; the 24 words</span><svg class="chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></summary>
  <div class="qa-body">
    <p>A BIP39 recovery phrase drawn from a fixed 2,048-word list. <b>24 words = 256 bits</b> of entropy; <b>12 words = 128 bits</b>, which is still far beyond brute force. Coldvault accepts every standard length &mdash; 12, 15, 18, 21 or 24 for BIP39, and 20 or 33 for the Shamir-style shares (SLIP-39) that some hardware wallets produce &mdash; so store whatever your wallet actually gave you rather than padding it. This <i>is</i> your wallet &mdash; anyone with the words (plus your passphrase, if you use one) can spend your coins.</p>
    <p><b>Coldvault never generates your seed and never keeps it in the clear.</b> You bring your existing phrase; it is encrypted on the server before it reaches the database, and it is wiped from the screen when you leave.</p>
    <p>The weak-wallet stories you may have read (for example &ldquo;Milk Sad&rdquo;) were about wallets that <i>generated</i> seeds with too little randomness, making them crackable. Coldvault does not generate seeds, so that whole class of bug does not apply here.</p>
  </div>
</details>

<details class="qa" id="s4">
  <summary><span class="qn">04</span><span>What is <span class="m">AES-256-GCM</span>?</span><svg class="chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></summary>
  <div class="qa-body">
    <p><b>AES-256</b> is the cipher that actually encrypts your seed &mdash; the same algorithm used to protect top-secret government data, with a 256-bit key.</p>
    <p><b>GCM</b> adds tamper-detection: it can tell if the stored ciphertext was altered, and a wrong keyword <b>fails cleanly</b> &mdash; you simply get &ldquo;no vault matches,&rdquo; never a partial or garbled leak. That leaves an attacker no &ldquo;oracle&rdquo; to probe.</p>
    <p>Every vault gets its own random <b>salt</b> and <b>nonce</b>, so two vaults encrypted with the same keyword still look completely different on disk.</p>
  </div>
</details>

<details class="qa" id="s5">
  <summary><span class="qn">05</span><span>What is <span class="m">PBKDF2</span>, and why 450,000 rounds?</span><svg class="chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></summary>
  <div class="qa-body">
    <p>A <b>KDF</b> (key-derivation function) turns your human keyword into the 256-bit key that AES needs. <b>PBKDF2</b> does it by hashing the keyword over and over &mdash; here, <b>450,000 times</b>.</p>
    <p>That repetition is the point: it makes <b>every guess an attacker tries about 450,000&times; more expensive</b>, while costing you only a fraction of a second once. This is exactly why an 84-bit keyword is safe &mdash; the KDF multiplies the attacker&rsquo;s cost enormously.</p>
    <p>The round count is stored <b>per vault</b>, so raising it later never breaks vaults you already saved &mdash; each keeps the number it was created with until you re-save it.</p>
  </div>
</details>

<details class="qa" id="s6">
  <summary><span class="qn">06</span><span>What &ldquo;zero-trace&rdquo; means</span><svg class="chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></summary>
  <div class="qa-body">
    <p>Coldvault deliberately keeps as little as possible:</p>
    <p>&bull; Your <b>keyword</b> is used once in memory to derive the key, then discarded &mdash; never stored, never logged.<br>
    &bull; Only <b>ciphertext</b> reaches the database; your seed never appears in a database query or log.<br>
    &bull; Keyword and seed are sent by <b>POST</b>, never in the URL, so they do not land in browser history or server access logs.<br>
    &bull; Pages are served <span class="m">no-store</span>, so the browser will not cache them, and fields are wiped when you leave or switch tabs.</p>
  </div>
</details>

<details class="qa" id="s7">
  <summary><span class="qn">07</span><span>PIN and Passphrase (the BIP39 &ldquo;25th word&rdquo;)</span><svg class="chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></summary>
  <div class="qa-body">
    <p><b>PIN</b> (optional) is just a convenient place to keep a device PIN alongside the phrase. Coldvault stores it as one more secret; it is not part of the encryption.</p>
    <p><b>Passphrase</b> (optional) is the BIP39 &ldquo;25th word.&rdquo; Combined with your recovery words it derives a <b>completely separate, hidden wallet</b>. It is a wallet feature, not a Coldvault feature.</p>
    <p>So: if your wallet uses one, store the <b>exact same</b> passphrase here &mdash; character for character, or it opens a different (empty) wallet. Storing an existing wallet? Type the passphrase it already uses, or leave the field blank. Do not invent a new one here.</p>
  </div>
</details>

<details class="qa" id="s8">
  <summary><span class="qn">08</span><span>The reveal timer and the auto-logout</span><svg class="chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></summary>
  <div class="qa-body">
    <p><b>60-second reveal timer.</b> Once a vault is decrypted on screen it hides itself after 60 seconds. Tap the clock to reset it and keep it open. Switching browser tabs or reloading the page also re-locks it at once &mdash; the decrypted words are never left sitting on a page you could reload into.</p>
    <p><b>13-minute idle logout.</b> If you do not interact for 13 minutes, a &ldquo;Still there?&rdquo; prompt appears with a 60-second countdown; ignore it and you are signed out. Any click or keypress before then quietly keeps your session alive.</p>
  </div>
</details>

<details class="qa" id="s9">
  <summary><span class="qn">09</span><span>What if I lose my keyword?</span><svg class="chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></summary>
  <div class="qa-body">
    <p>Because the keyword is never stored, <b>nobody &mdash; including us &mdash; can recover or reset it.</b> Lose it and that vault&rsquo;s contents are gone for good. That is the trade for zero-trace security: no backdoor, no &ldquo;forgot password&rdquo; email.</p>
    <p>So save your keyword in a password manager the moment you create it. And remember it only protects the <b>copy stored here</b> &mdash; your real backup is still your seed phrase, kept safely offline.</p>
  </div>
</details>

<details class="qa" id="s10">
  <summary><span class="qn">10</span><span>What if I lose the phone with my authenticator app?</span><svg class="chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></summary>
  <div class="qa-body">
    <p><b>If you saved your backup codes</b> &mdash; the eight codes shown once when you signed up &mdash; you are fine. On the sign-in screen, type a <b>backup code</b> into the code box instead of the 6-digit number. Each code works <b>once</b>.</p>
    <p>Once you are in, open <b>Security</b> and use <b>Replace authenticator device</b> to pair a new phone. You scan a fresh QR and confirm a code from it <b>before anything changes</b>, so you cannot lock yourself out. Then use <b>New backup codes</b> to replace the set you have been eating into. Both actions ask for a current code first, so someone who finds your screen unlocked cannot quietly take the account over.</p>
    <p><b>Worth knowing:</b> each 6-digit code can only be used <b>once</b>. So if you sign in with a code and then straight away enter that same code to authorise a Security action, it will be refused. Wait for your authenticator app to roll over to the next code &mdash; up to 30 seconds &mdash; and use that one. The same goes for backup codes: each is good for a single use.</p>
    <p><b>If you have no backup codes left and no authenticator</b>, there is no automatic reset &mdash; by design there is no email or SMS recovery to attack. Your <b>vaults are still safe</b>: they are encrypted with your keyword, which has nothing to do with the authenticator. But the account cannot be opened without help from whoever runs the server.</p>
    <div class="help-callout"><b>Do this now:</b> open <b>Security</b> and check how many unused backup codes you have. If it is a low number, generate a fresh set and store them offline &mdash; not on the same phone as the authenticator.</div>
  </div>
</details>

<details class="qa" id="s11">
  <summary><span class="qn">11</span><span>Sharing a vault with someone else</span><svg class="chev" viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></summary>
  <div class="qa-body">
    <p>A vault can be opened by more than one person, and <b>each of you uses your own keyword</b>. You never learn theirs and they never learn yours &mdash; there is no shared password to pass around, and changing your own keyword does not disturb anybody else's.</p>
    <p><b>Be clear about what you are giving away.</b> Anyone you invite can open the vault <b>immediately</b> and sees the full seed phrase. This is for someone who should have access <i>today</i> &mdash; a spouse or an equal partner in the funds. It is <i>not</i> the way to leave something to an heir who should only get in later; that needs a different arrangement entirely.</p>
    <p><b>They can read it, not rewrite it.</b> Only the vault's owner can change what it contains, or invite and remove people. Everybody else can open it and read the seed, and that is all. A vault is a backup, so an accidental overwrite by somebody else would be the kind of damage you would not notice until the day you actually needed it.</p>
    <p><b>Handing a vault over.</b> If somebody else should be in charge of it &mdash; a partner taking over the finances, say &mdash; you can transfer ownership to anybody who already has access. They then decide who can open it, and they can remove you. You keep being able to read it with your own keyword. You cannot undo it yourself afterwards: only the new owner can hand it back.</p>
    <p><b>You can take access away &mdash; but not what they have seen.</b> <b>Remove</b> beside someone's name stops them opening the vault ever again, and it does so properly: the vault is re-encrypted under a brand new key, so even a saved copy of their old entry is useless. What it cannot do is un-see anything. If they ever opened the vault they already have your seed phrase, and no software can take that back &mdash; if that worries you, move the funds to a new wallet.</p>
    <p><b>One consequence to know before you remove somebody.</b> Replacing the key invalidates <i>everybody's</i> entry, and only yours can be rebuilt, because only you have typed a keyword. So if three of you share a vault and you remove one, the third person needs a fresh invite too. The app tells you exactly who will be affected before you confirm.</p>
    <p><b>The invite code is a key, not a message.</b> It opens the vault on its own for as long as it lives, which is 72 hours. So hand it over <b>in person</b> if you possibly can, and never send it by email or chat. It is shown to you exactly once, because it is not kept anywhere &mdash; if it goes astray, cancel it and make another.</p>
    <p><b>Why a guest's keyword has to be strong.</b> A shared vault is only as strong as its <b>weakest</b> keyword, since any one of them opens it. That is why a new keyword has to clear a minimum strength before it is accepted, however strong yours already is. Use the generator.</p>
  </div>
</details>
HTML;
    // 2026-09-01: open the <details> section the URL hash points to (deep-links from tooltips + TOC chips).
    echo '<div class="foot">coldvault &middot; plain-language security notes</div></div>'
       . '<script nonce="'.CSP_NONCE.'">(function(){function o(){var id=location.hash.slice(1);if(!id)return;var el=document.getElementById(id);if(el&&el.tagName==="DETAILS"){el.open=true;el.scrollIntoView();}}o();addEventListener("hashchange",o);})();</script>'
       . '</body></html>';
}

// 2026-09-01: account security screens — re-pair authenticator device, regenerate backup codes.
//   Both changes are gated by auth_stepup_check() (current code or backup code).
function sec_banner($err, $msg) {
    $o = '';
    if ($msg) $o .= '<div class="banner ok"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg><span>'.h($msg).'</span></div>';
    if ($err) $o .= '<div class="banner bad"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg><span>'.h($err).'</span></div>';
    return $o;
}
function sec_stepup_field($id) {
    return '<label class="fl" for="'.$id.'">Authorize with a current code</label>'
        . '<div class="field"><input id="'.$id.'" name="stepup" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit code or backup code" autocorrect="off" autocapitalize="characters" spellcheck="false"></div>';
}
function render_security($con, $uid, $err = null, $msg = null) {
    $left = bc_unused_count($con, $uid);
    $col  = $left <= 2 ? ' style="color:var(--danger)"' : '';
    $inner = '<h2 class="at">Account security</h2>'
      . '<p class="lead">Signed in as <b>'.h(auth_uname()).'</b>. Unused backup codes: <b'.$col.'>'.$left.'</b>.</p>'
      . sec_banner($err, $msg)
      . '<details class="hnote"><summary>Lost the phone with your authenticator?</summary><div>Sign in with one of your one-time backup codes, then use <b>Replace authenticator device</b> below to pair a new phone. Finish by generating fresh backup codes. If you have no backup codes left and no authenticator, nobody can reset it from here &mdash; your vaults stay encrypted and safe, but the account cannot be opened.'
      . '<a class="help-more" href="'.APP_BASE.'help/#s10" target="_blank" rel="noopener">Full explanation &rarr;</a></div></details>'
      . '<div class="gridhead"><span class="t">Replace authenticator device</span></div>'
      . '<p class="lead" style="margin-bottom:14px">Pairs a new phone. You scan a fresh QR and confirm it <b>before anything changes</b>, so you cannot lock yourself out.</p>'
      . '<form method="POST" action="" autocomplete="off"><input type="hidden" name="action" value="sec_rekey_start">'
      . cv_csrf_field()
      . sec_stepup_field('su1')
      . '<div class="row"><button class="btn btn-primary" type="submit"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M5 12h14M13 6l6 6-6 6"/></svg> Start</button></div></form>'
      . '<div class="gridhead"><span class="t">New backup codes</span></div>'
      . '<p class="lead" style="margin-bottom:14px">Generates 8 fresh single-use codes and <b>invalidates every current one</b>. They are shown once.</p>'
      . '<form method="POST" action="" autocomplete="off"><input type="hidden" name="action" value="sec_backup">'
      . cv_csrf_field()
      . sec_stepup_field('su2')
      . '<div class="row"><button class="btn btn-primary" type="submit"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg> Generate</button></div></form>'
      . '<div class="gridhead"><span class="t">Sign out everywhere else</span></div>'
      . '<p class="lead" style="margin-bottom:14px">Ends every other signed-in session at once, on every other device and browser. This one stays open. Use it if you think someone else may still be signed in as you.</p>'
      . '<form method="POST" action="" autocomplete="off"><input type="hidden" name="action" value="sec_signout_others">'
      . cv_csrf_field()
      . sec_stepup_field('su3')
      . '<div class="row"><button class="btn btn-primary" type="submit"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg> Sign out other sessions</button></div></form>'
      . '<div class="row" style="margin-top:20px"><a class="btn btn-ghost" href="'.APP_BASE.'"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M19 12H5M11 6l-6 6 6 6"/></svg> Back to vault</a></div>';
    auth_shell('account security', $inner);
}
function render_security_rekey($secretB32, $err) {
    $uri = otpauth_uri($secretB32, auth_uname());
    $grouped = trim(chunk_split($secretB32, 4, ' '));
    $inner = '<h2 class="at">Pair a new authenticator</h2>'
      . '<ol class="steps"><li>Open your authenticator app on the new phone.</li><li>Scan this QR (it saves as <b>'.h(OTP_ISSUER).'</b>).</li><li>Enter the 6-digit code it shows to finish.</li></ol>'
      . '<div class="qrbox" id="qrbox"></div><div class="mkey">'.h($grouped).'</div>'
      . sec_banner($err, null)
      . '<div class="warn" style="margin-top:14px">Nothing has changed yet &mdash; your old authenticator keeps working until you confirm below.</div>'
      . '<form method="POST" action="" autocomplete="off" style="margin-top:16px"><input type="hidden" name="action" value="sec_rekey_confirm">'
      . cv_csrf_field()
      . '<input class="codebig" name="code" type="tel" inputmode="numeric" autocomplete="one-time-code" placeholder="000000" autofocus>'
      . '<div class="row" style="margin-top:16px"><button class="btn btn-primary" type="submit"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg> Confirm &amp; switch</button>'
      . '<a class="btn btn-ghost" href="'.APP_BASE.'security/">Cancel</a></div></form>';
    $script = 'var qr=qrcode(0,"M");qr.addData('.json_encode($uri).');qr.make();document.getElementById("qrbox").innerHTML=qr.createSvgTag({cellSize:5,margin:1});';
    auth_shell('new authenticator', $inner, $script);
}
function render_new_backup_codes($codes) {
    $cells = '';
    foreach ($codes as $c) $cells .= '<div>'.h(fmt_backup_code($c)).'</div>';
    $inner = '<h2 class="at">Your new backup codes</h2><p class="lead">Each code signs you in <b>once</b> if you lose your authenticator. Every previous code has been invalidated. Keep these somewhere safe and offline &mdash; they are shown only now.</p>'
      . '<div class="bcodes">'.$cells.'</div>'
      . '<div class="warn">These are not shown again.</div>'
      . '<div class="row" style="margin-top:18px"><a class="btn btn-primary" href="'.APP_BASE.'"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M5 12h14M13 6l6 6-6 6"/></svg> I saved them &mdash; continue</a>'
      . '<a class="btn btn-ghost" href="'.APP_BASE.'security/">Back to security</a></div>';
    auth_shell('backup codes', $inner);
}

$__ga = $_POST['action'] ?? '';
if (($_GET['screen'] ?? '') === 'help') { render_help(); exit; }   // 2026-09-01: public Help & security page
if ($__ga === 'logout') { auth_logout(); header('Location: ' . APP_BASE); exit; }

if (!auth_is_logged_in($con)) {
    if ($__ga === 'register_start') {
        auth_session_start();
        $u = trim($_POST['username'] ?? '');
        if (($_POST['website'] ?? '') !== '') { render_register_start('Registration blocked.', ''); exit; }
        if (!captcha_check($_POST['captcha'] ?? '')) { render_register_start('Wrong CAPTCHA - try again.', $u); exit; }
        if (!username_valid($u)) { render_register_start('Username must be 3-32 chars: letters, numbers, . _ -', $u); exit; }
        if (reg_throttled($con)) { render_register_start('Too many sign-ups in the last hour - please try again later.', ''); exit; }
        if (user_exists($con, $u)) { render_register_start('That username is taken - choose another.', $u); exit; }
        $_SESSION['cv_reg_user'] = $u;
        $_SESSION['cv_reg_secret'] = base32_encode(gen_totp_secret());
        render_register_confirm($u, $_SESSION['cv_reg_secret'], null); exit;
    }
    if ($__ga === 'register_confirm') {
        auth_session_start();
        $u = $_SESSION['cv_reg_user'] ?? ''; $b32 = $_SESSION['cv_reg_secret'] ?? '';
        if ($u === '' || $b32 === '') { render_register_start('Session expired - start again.', ''); exit; }
        if (totp_verify(base32_decode($b32), $_POST['code'] ?? '', time(), 1) !== false) {
            if (user_exists($con, $u)) { unset($_SESSION['cv_reg_user'],$_SESSION['cv_reg_secret']); render_register_start('That username was just taken - choose another.', ''); exit; }
            $codes = gen_backup_codes(8);
            $uid = user_register($con, $u, base32_decode($b32), $codes);
            if ($uid) {
                reg_record($con);
                unset($_SESSION['cv_reg_user'],$_SESSION['cv_reg_secret']);
                auth_login_user($uid, $u, user_secret_version($con, $uid));
                render_backup_codes($codes, $u); exit;
            }
            render_register_confirm($u, $b32, 'Could not create account - try again.'); exit;
        }
        render_register_confirm($u, $b32, 'That code did not match - check the app and try again.'); exit;
    }
    if ($__ga === 'login') {
        $u = trim($_POST['username'] ?? '');
        $row = user_find($con, $u);
        // 2026-09-03: the human check is now gated on server-side state as well as on the
        //   session. The session counter alone could be cleared by simply dropping the
        //   cookie, so a script could keep guessing codes without ever meeting a check;
        //   fail_count lives in the database and cannot be reset from the client. An
        //   unknown username is treated exactly like a gated one, so the requirement
        //   itself never reveals whether an account exists.
        $needCap = (($_SESSION['cv_login_fails'] ?? 0) >= 1)
                || !$row
                || (int)$row['fail_count'] >= AUTH_CAPTCHA_AFTER;
        if ($needCap && !captcha_check($_POST['captcha'] ?? '')) {
            $_SESSION['cv_login_fails'] = ($_SESSION['cv_login_fails'] ?? 0) + 1;
            render_login('Solve the human check below, then try again.', true, $u); exit;
        }
        // 2026-09-03: a lockout is no longer a refusal HERE, because it was a denial of
        //   service: anyone who knew a username could hold that account shut for good with
        //   five wrong codes every five minutes, and the wait message also told an attacker
        //   which usernames existed. A CORRECT code now always signs you in - only the real
        //   owner can produce one - and the human check above is what rate-limits guessing.
        //   lock_until still brakes the step-up path in auth.php, which needs an
        //   authenticated session and so cannot be tripped by an outsider.
        $code = $_POST['code'] ?? ''; $ok = false; $uid = null;
        if ($row) {
            $secret = user_secret($row); $last = ($row['last_step'] !== null) ? (int)$row['last_step'] : -1;
            $step = ($secret !== false) ? totp_verify($secret, $code, time(), 1) : false;
            if ($step !== false && $step > $last) { user_success($con, $row['id'], $step); $ok = true; $uid = $row['id']; }
            elseif (bc_verify_consume($con, $row['id'], $code)) { $ok = true; $uid = $row['id']; }
        }
        // $row is the pre-login snapshot, so read the version back rather than trusting it:
        // a backup code was possibly just consumed, but the version cannot have moved.
        if ($ok) { $_SESSION['cv_login_fails'] = 0; $dest = auth_after_login_url(); auth_login_user($uid, $row['username'], user_secret_version($con, $uid)); header('Location: ' . $dest); exit; }
        if ($row) user_fail($con, $row['id']);
        $_SESSION['cv_login_fails'] = ($_SESSION['cv_login_fails'] ?? 0) + 1;
        render_login('Invalid username or code.', true, $u); exit;
    }
    auth_session_start();
    // 2026-09-03: remember where they were trying to go, so login is not a dead end
    $__want = $_GET['screen'] ?? '';
    if (in_array($__want, ['redeem','security'], true)) $_SESSION['cv_after'] = $__want;
    if ($__want === 'register') { render_register_start(null, ''); exit; }
    render_login($__csrfbad ? 'That page had gone stale, so nothing was done. Please try again.' : null,
                 (($_SESSION['cv_login_fails'] ?? 0) >= 1), ''); exit;
}
/* ================= authenticated below ================= */
$__uid = (int)auth_uid();
// 2026-09-03: one-shot message carried across a redirect (e.g. just after redeeming an
//   invite). Only on a plain page load, so it can never overwrite a handler's own result.
if ($action === '' && !empty($_SESSION['cv_flash'])) { $msg = $_SESSION['cv_flash']; unset($_SESSION['cv_flash']); }
if ($action === 'ping') { http_response_code(204); exit; }
// 2026-09-03: step one of unlocking - the vault is chosen, the keyword comes next.
//   Only a vault id travels here, which is not a secret; the keyword is still typed
//   once and submitted once, on the next step.
if ($action === 'unlock_pick') {
    $activeTab = 'unlock';
    $pickedVault = (int)($_POST['vault_id'] ?? 0);
}   // 2026-09-01: idle keep-alive (auth_is_logged_in already refreshed the session)

/* ===== 2026-09-01: account security — step-up gated re-pairing + backup code regeneration ===== */
if ($action === 'sec_rekey_start') {
    $e = auth_stepup_check($con, $__uid, (string)($_POST['stepup'] ?? ''));
    if ($e !== '') { render_security($con, $__uid, $e); exit; }
    $_SESSION['cv_sec_secret'] = base32_encode(gen_totp_secret());
    render_security_rekey($_SESSION['cv_sec_secret'], null); exit;
}
if ($action === 'sec_rekey_confirm') {
    $b32 = $_SESSION['cv_sec_secret'] ?? '';
    if ($b32 === '') { render_security($con, $__uid, 'That took too long — start again.'); exit; }
    if (totp_verify(base32_decode($b32), $_POST['code'] ?? '', time(), 1) === false) {
        render_security_rekey($b32, 'That code did not match — check the new app and try again.'); exit;
    }
    $__nv = user_set_secret($con, $__uid, base32_decode($b32));
    if (!$__nv) {
        render_security_rekey($b32, 'Could not save the new authenticator — nothing changed. Try again.'); exit;
    }
    // 2026-09-03: keep THIS session alive at the new version. Without this line, pairing a
    //   new authenticator would sign you out of the device you just paired it on.
    $_SESSION['cv_sver'] = (int)$__nv;
    unset($_SESSION['cv_sec_secret']);
    render_security($con, $__uid, null, 'New authenticator paired. Your old device no longer works, and every other signed-in session has been ended — generate fresh backup codes below.'); exit;
}
// 2026-09-03: end every other session without changing the authenticator. Needs a current
//   code, like every other account-security action, so a walk-up at an unlocked screen
//   cannot cut off the real owner's other devices.
if ($action === 'sec_signout_others') {
    $e = auth_stepup_check($con, $__uid, (string)($_POST['stepup'] ?? ''));
    if ($e !== '') { render_security($con, $__uid, $e); exit; }
    $__nv = user_bump_secret_version($con, $__uid);
    if ($__nv === false) { render_security($con, $__uid, 'Could not do that — nothing changed.'); exit; }
    $_SESSION['cv_sver'] = (int)$__nv;
    render_security($con, $__uid, null, 'Every other signed-in session has been ended. This one is still open.'); exit;
}
if ($action === 'sec_backup') {
    $e = auth_stepup_check($con, $__uid, (string)($_POST['stepup'] ?? ''));
    if ($e !== '') { render_security($con, $__uid, $e); exit; }
    $codes = gen_backup_codes(8);
    if (!user_replace_backup_codes($con, $__uid, $codes)) { render_security($con, $__uid, 'Could not generate new codes — try again.'); exit; }
    render_new_backup_codes($codes); exit;
}
if (($_GET['screen'] ?? '') === 'security') { render_security($con, $__uid); exit; }

/* ---- redeem an invite (2026-09-03) --------------------------------------
   The invitee signs in to their OWN account and chooses their OWN keyword. The
   owner never learns it, and the invitee never learns the owner's. The invite code
   is a temporary full key: single use, short-lived, and destroyed on redemption. */
// 2026-09-03: handing the vault over gets its own untimed page. Irreversible from the
//   current owner's side, so the consequences are spelled out before confirming.
function render_transfer_form($con, $vid, $actorUid, $err = null) {
    $cands = [];
    foreach (vault_keyslots($con, $vid) as $k)
        if ((int)$k['user_id'] !== (int)$actorUid) $cands[] = $k;
    if (!$cands) {
        render_generic_notice('Nobody to hand it to', 'Only you can open this vault. Invite somebody first, then you can transfer ownership to them.');
        return;
    }
    $pending = vault_invites_pending($con, $vid);
    $opts = '';
    foreach ($cands as $c)
        $opts .= '<label class="pickone"><input type="radio" name="new_owner" value="'.(int)$c['user_id'].'"><span><b>'.h($c['label']).'</b> &middot; <span class="m">'.h($c['username'] ?? '?').'</span></span></label>';

    $inner = '<h2 class="at">Transfer ownership</h2>'
      . '<p class="lead">Hand this vault to somebody who already has access. They take over deciding who can open it.</p>'
      . sec_banner($err, null)
      . '<div class="factlist" style="margin-top:0"><div class="lh"><svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="1.6"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg> what changes</div><ul>'
      . '<li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M20 6 9 17l-5-5"/></svg><span>They will be able to <b>edit the seed, invite people and remove people</b> &mdash; including removing you.</span></li>'
      . '<li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M20 6 9 17l-5-5"/></svg><span><b>You keep being able to open and read it</b> with your own keyword, but nothing more. Ask them to remove you if you want out entirely.</span></li>'
      . '<li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg><span style="color:var(--amber)"><b>You cannot undo this.</b> Only the new owner can hand it back.</span></li>';
    if ($pending) $inner .= '<li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg><span>'.count($pending).' unused invite '.(count($pending)===1?'code':'codes').' you issued will stop working.</span></li>';
    $inner .= '</ul></div>'
      . '<form method="POST" action="" autocomplete="off" style="margin-top:16px">'
      . '<input type="hidden" name="action" value="transfer_confirm">'
      . cv_csrf_field()
      . '<input type="hidden" name="vault_id" value="'.(int)$vid.'">'
      . '<label class="fl">Hand it to</label>' . $opts
      . '<label class="fl" for="tfk" style="margin-top:16px">Your keyword</label>'
      . '<div class="field"><input id="tfk" name="keyword" type="password" placeholder="your current keyword" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">'
      . '<button type="button" class="eye" data-cv="eye" data-cv-for="tfk" aria-label="show"><svg viewBox="0 0 24 24"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></button></div>'
      . '<label class="fl" for="tfs">Authenticator code</label>'
      . '<div class="field"><input id="tfs" name="stepup" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit code or backup code" autocorrect="off" autocapitalize="characters" spellcheck="false"></div>'
      . '<div class="hint">Nothing on this page is on a timer.</div>'
      . '<div class="row" style="margin-top:18px"><button class="btn btn-primary" type="submit" data-busytext="Transferring&hellip;"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M5 12h14M13 6l6 6-6 6"/></svg> Transfer ownership</button>'
      . '<a class="btn btn-ghost" href="'.APP_BASE.'">Cancel</a></div></form>';
    auth_shell('transfer ownership', $inner);
}

// 2026-09-03: removing access gets its own untimed page. It needs a keyword and an
//   authenticator code, and it has real consequences that must be read before
//   confirming - none of which belongs inside a 60-second self-destruct region.
function render_revoke_form($con, $vid, $targetId, $actorUid, $err = null) {
    $slots = vault_keyslots($con, $vid);
    $target = null; $others = [];
    foreach ($slots as $k) {
        if ((int)$k['id'] === (int)$targetId)      $target = $k;
        elseif ((int)$k['user_id'] !== (int)$actorUid) $others[] = $k;
    }
    if (!$target) { render_generic_notice('Nothing to remove', 'That access has already been removed.'); return; }
    $pending = vault_invites_pending($con, $vid);

    $who = h($target['label']).' ('.h($target['username'] ?? '?').')';
    $inner = '<h2 class="at">Remove access</h2>'
      . '<p class="lead">You are about to stop <b>'.$who.'</b> from being able to open this vault.</p>'
      . sec_banner($err, null)
      . '<div class="factlist" style="margin-top:0"><div class="lh"><svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="1.6"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg> what will happen</div><ul>'
      . '<li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M20 6 9 17l-5-5"/></svg><span><b>'.$who.'</b> will no longer be able to open it.</span></li>'
      . '<li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M20 6 9 17l-5-5"/></svg><span>The vault is <b>re-encrypted under a brand new key</b>. Simply deleting their entry would not be enough &mdash; a saved copy of it would still open the vault later.</span></li>'
      . '<li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M20 6 9 17l-5-5"/></svg><span><b>Your own keyword does not change.</b> Carry on using the one you just typed.</span></li>';
    if ($others) {
        $names = [];
        foreach ($others as $o) $names[] = h($o['label']).' ('.h($o['username'] ?? '?').')';
        $inner .= '<li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg><span style="color:var(--amber)"><b>'.count($others).' other '.(count($others)===1?'person':'people').' will also lose access</b> and need a fresh invite: '.implode(', ', $names).'. There is no way round this: replacing the key invalidates every entry, and only yours can be rebuilt because only you have typed a keyword.</span></li>';
    }
    if ($pending) {
        $inner .= '<li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg><span>'.count($pending).' unused invite '.(count($pending)===1?'code':'codes').' will stop working.</span></li>';
    }
    $inner .= '</ul></div>'
      . '<div class="warn" style="margin-top:14px"><b>This cannot undo what they have already seen.</b> If they ever opened this vault, they have your seed phrase and removing access does not take it back. If that is a concern, move the funds to a new wallet.</div>'
      . '<form method="POST" action="" autocomplete="off" style="margin-top:16px">'
      . '<input type="hidden" name="action" value="revoke_confirm">'
      . cv_csrf_field()
      . '<input type="hidden" name="vault_id" value="'.(int)$vid.'">'
      . '<input type="hidden" name="keyslot_id" value="'.(int)$targetId.'">'
      . '<label class="fl" for="rvk">Your keyword</label>'
      . '<div class="field"><input id="rvk" name="keyword" type="password" placeholder="your current keyword" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" autofocus>'
      . '<button type="button" class="eye" data-cv="eye" data-cv-for="rvk" aria-label="show"><svg viewBox="0 0 24 24"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></button></div>'
      . '<label class="fl" for="rvs">Authenticator code</label>'
      . '<div class="field"><input id="rvs" name="stepup" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit code or backup code" autocorrect="off" autocapitalize="characters" spellcheck="false"></div>'
      . '<div class="hint">Nothing on this page is on a timer. Take as long as you need.</div>'
      . '<div class="row" style="margin-top:18px"><button class="btn btn-primary" type="submit" data-busytext="Removing&hellip;"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M6 6l12 12M18 6L6 18"/></svg> Remove access &amp; re-key</button>'
      . '<a class="btn btn-ghost" href="'.APP_BASE.'">Cancel</a></div></form>';
    auth_shell('remove access', $inner);
}

// A plain one-off notice page, for the cases where there is nothing to act on.
function render_generic_notice($title, $body) {
    auth_shell('notice', '<h2 class="at">'.h($title).'</h2><p class="lead">'.h($body).'</p>'
      . '<div class="row" style="margin-top:18px"><a class="btn btn-primary" href="'.APP_BASE.'">Back to the vault</a></div>');
}

// 2026-09-03: the invite FORM also gets its own page. It lived inside the vault
//   reveal area, which self-destructs after 60s - and filling it in means fetching a
//   code off your phone, which is exactly the kind of pause that ran the timer out
//   and threw the half-filled form away. Nothing on this page is on a timer.
function render_invite_form($vid, $label = '', $err = null) {
    $inner = '<h2 class="at">Invite someone to this vault</h2>'
      . '<p class="lead">They will get their <b>own</b> keyword &mdash; you never learn theirs, they never learn yours. Anyone you invite can open this vault <b>immediately</b> and read the seed phrase.'
      . '<a class="help-more" href="'.APP_BASE.'help/#s11" target="_blank" rel="noopener">Full explanation &rarr;</a></p>'
      . sec_banner($err, null)
      . '<form method="POST" action="" autocomplete="off">'
      . '<input type="hidden" name="action" value="invite_create">'
      . cv_csrf_field()
      . '<input type="hidden" name="vault_id" value="'.(int)$vid.'">'
      . '<label class="fl" for="ivl">Label</label>'
      . '<div class="field"><input id="ivl" name="label" type="text" value="'.h($label).'" placeholder="who is it for, e.g. spouse" maxlength="32" autocomplete="off" spellcheck="false" autofocus></div>'
      . '<label class="fl" for="ivk">Your keyword</label>'
      . '<div class="field"><input id="ivk" name="keyword" type="password" placeholder="your current keyword" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">'
      . '<button type="button" class="eye" data-cv="eye" data-cv-for="ivk" aria-label="show"><svg viewBox="0 0 24 24"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></button></div>'
      . '<label class="fl" for="ivs">Authenticator code</label>'
      . '<div class="field"><input id="ivs" name="stepup" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit code or backup code" autocorrect="off" autocapitalize="characters" spellcheck="false"></div>'
      . '<div class="warn">Take your time &mdash; <b>nothing on this page is on a timer</b>. Go and fetch the code off your phone. If you signed in with a code moments ago, wait for the next one: each code works only once.</div>'
      . '<div class="row" style="margin-top:18px"><button class="btn btn-primary" type="submit" data-busytext="Creating&hellip;"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg> Create invite code</button>'
      . '<a class="btn btn-ghost" href="'.APP_BASE.'">Cancel</a></div></form>';
    auth_shell('invite someone', $inner);
}

// 2026-09-03: the invite code gets its OWN page, deliberately.
//   It was first shown inside the vault reveal area, which the 60s auto-lock wipes -
//   so the code could vanish before it was written down, and it can never be shown
//   again. Same one-shot handling as the backup-codes screen: no timer, no auto-lock,
//   and an explicit acknowledgement before leaving.
function render_invite_code($code, $label) {
    $inner = '<h2 class="at">Invite code for &ldquo;'.h($label).'&rdquo;</h2>'
      . '<p class="lead">Shown <b>once &mdash; right now</b>. Only a fingerprint of it is stored, so this page can never be shown again. Write it down or copy it before you leave; if you lose it, cancel the invite and create another.</p>'
      . '<div class="bcodes" style="grid-template-columns:1fr;margin:16px 0 10px"><div id="ivcode" style="font-size:18px;letter-spacing:3px">'.h(invite_fmt($code)).'</div></div>'
      . '<div class="row"><button class="btn btn-ghost" type="button" id="ivcopy" data-cv="ivCopy" style="padding:10px 16px;font-size:11px">Copy to clipboard</button></div>'
      . '<div class="warn" style="margin-top:16px">For the next '.(int)INVITE_TTL_HOURS.' hours this code is a <b>full key to this vault</b> &mdash; whoever holds it can open it and read the seed. Hand it over <b>in person</b> if you possibly can, and never send it by email or chat. Copying places it on your clipboard, where other apps can read it.</div>'
      . '<div class="row" style="margin-top:20px"><a class="btn btn-primary" href="'.APP_BASE.'"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg> I have saved it &mdash; continue</a></div>'
      . '<script nonce="'.CSP_NONCE.'">function ivCopy(){var t=document.getElementById("ivcode").textContent.trim(),b=document.getElementById("ivcopy");'
      . 'function done(){b.textContent="Copied";setTimeout(function(){b.textContent="Copy to clipboard";},2500);}'
      . 'if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done).catch(function(){b.textContent="Copy failed - select it by hand";});}'
      . 'else{var r=document.createRange();r.selectNodeContents(document.getElementById("ivcode"));var sel=getSelection();sel.removeAllRanges();sel.addRange(r);b.textContent="Selected - press Cmd/Ctrl+C";}}</script>';
    auth_shell('invite code', $inner);
}

function render_redeem($err = null, $msg = null, $code = '') {
    $min = MIN_KEYSLOT_BITS;
    $inner = '<h2 class="at">Redeem an invite</h2>'
      . '<p class="lead">Someone has shared a vault with you. Enter the code they gave you and choose <b>your own</b> keyword &mdash; they never learn yours, and you never learn theirs.</p>'
      . sec_banner($err, $msg)
      . '<form method="POST" action="" autocomplete="off"><input type="hidden" name="action" value="redeem">'
      . cv_csrf_field()
      . '<label class="fl" for="ic">Invite code</label>'
      . '<div class="field"><input id="ic" name="code" type="text" value="'.h($code).'" placeholder="XXXX XXXX XXXX XXXX XXXX XXXX" autocomplete="off" autocorrect="off" autocapitalize="characters" spellcheck="false" autofocus></div>'
      . '<label class="fl" for="rk">Choose your keyword</label>'
      . '<div class="field"><input id="rk" name="keyword" type="password" placeholder="needs ~'.$min.'+ bits" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false">'
      . '<button type="button" class="eye" data-cv="eye" data-cv-for="rk" aria-label="show"><svg viewBox="0 0 24 24"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></button></div>'
      . '<label class="fl" for="rk2">Confirm keyword</label>'
      . '<div class="field"><input id="rk2" name="keyword2" type="password" placeholder="repeat" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false"></div>'
      . '<div class="hint" id="rstrength">strength &mdash; enter a keyword</div>'
      . '<div class="row" style="margin-top:10px;gap:8px"><button type="button" class="btn btn-ghost" data-cv="rGen" style="padding:10px 16px;font-size:11px">Generate strong keyword</button></div>'
      . '<div id="rgennote" class="warn" style="display:none;margin-top:10px">Generated a strong keyword and filled both boxes. <b>Copy it somewhere safe now</b> &mdash; it is never stored and cannot be recovered.</div>'
      . '<div class="warn" style="margin-top:14px">This keyword is yours alone. Lose it and your access to the vault is gone &mdash; the owner cannot recover it for you, though they can send a fresh invite.</div>'
      . '<div class="row" style="margin-top:16px"><button class="btn btn-primary" type="submit" data-busytext="Joining&hellip;"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M5 12h14M13 6l6 6-6 6"/></svg> Join vault</button>'
      . '<a class="btn btn-ghost" href="'.APP_BASE.'">Cancel</a></div></form>'
      . '<script src="'.APP_BASE.'words.js"></script>'
      . '<script nonce="'.CSP_NONCE.'">'
      // 2026-09-03: same repetition fix as cvEntropy() and cv_entropy() - distinct words,
      //   and a repetition cap on the character fallback. Keep all three in step.
      . 'function rEnt(v){if(!v)return 0;var t=v.split(/[^A-Za-z0-9]+/).filter(function(x){return x.length>=3&&/^[A-Za-z]+$/.test(x);});var b;if(t.length>=3){var u=[];t.forEach(function(x){var k=x.toLowerCase();if(u.indexOf(k)<0)u.push(k);});b=u.length*11;if(/[A-Z]/.test(v))b+=2;if(/[0-9]/.test(v))b+=3;if(/[^A-Za-z0-9 \-]/.test(v))b+=4;}else{var c=0;if(/[a-z]/.test(v))c+=26;if(/[A-Z]/.test(v))c+=26;if(/[0-9]/.test(v))c+=10;if(/[^A-Za-z0-9]/.test(v))c+=33;var d=0;for(var i=0;i<v.length;i++)if(v.indexOf(v[i])===i)d++;b=Math.min(v.length,2*d)*Math.log2(c||2);}return Math.round(b);}'
      . 'var MIN='.$min.';'
      . 'function rShow(){var v=document.getElementById("rk").value,s=document.getElementById("rstrength"),b=rEnt(v),ok=b>=MIN;'
      . 's.innerHTML=v.length?("strength &mdash; <span style=\"color:"+(ok?"var(--accent)":"var(--danger)")+"\">~"+b+" bits</span> &middot; "+(ok?"accepted":"too weak, needs ~"+MIN)):"strength &mdash; enter a keyword";}'
      . 'document.getElementById("rk").addEventListener("input",rShow);'
      . 'function rGen(){var W=window.CV_WORDS,kw;if(W&&W.length){var r=new Uint32Array(7),o=[];crypto.getRandomValues(r);for(var i=0;i<7;i++)o.push(W[r[i]%W.length]);kw=o.join("-");}else{var c="abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789",r2=new Uint32Array(24);crypto.getRandomValues(r2);kw=[].map.call(r2,function(x){return c[x%c.length];}).join("");}'
      . 'var sy="!@#$%^&*?_+=",rr=new Uint32Array(2);crypto.getRandomValues(rr);kw=kw+"-"+(10+rr[0]%90)+sy[rr[1]%sy.length];'
      . 'var a=document.getElementById("rk"),b=document.getElementById("rk2");a.type="text";a.value=kw;b.type="text";b.value=kw;document.getElementById("rgennote").style.display="block";rShow();}'
      . '</script>';
    auth_shell('redeem invite', $inner);
}

if ($action === 'redeem') {
    $code = invite_norm($_POST['code'] ?? '');
    $kw   = (string)($_POST['keyword']  ?? '');
    $kw2  = (string)($_POST['keyword2'] ?? '');
    if (!invite_shape_ok($code)) { render_redeem('That code is not the right shape - 24 letters and digits. Check for a typo.'); exit; }
    if ($kw === '' || $kw !== $kw2) { render_redeem('Your two keywords are empty or do not match.', null, invite_fmt($code)); exit; }
    $bits = cv_entropy($kw);
    if ($bits < MIN_KEYSLOT_BITS) {
        render_redeem('That keyword is too weak (~'.$bits.' bits; this vault needs ~'.MIN_KEYSLOT_BITS.'). A shared vault is only as strong as its weakest keyword - use Generate.', null, invite_fmt($code)); exit;
    }
    $hash = invite_hash($code);
    $st = mysqli_prepare($con, "SELECT * FROM vault_invite WHERE code_hash=? LIMIT 1");
    mysqli_stmt_bind_param($st, 's', $hash);
    mysqli_stmt_execute($st); $res = mysqli_stmt_get_result($st);
    $inv = $res ? mysqli_fetch_assoc($res) : null;
    if (!$inv)                                        { render_redeem('No open invite matches that code.'); exit; }
    if ($inv['used_at'] !== null)                     { render_redeem('That invite has already been used. Ask for a new one.'); exit; }
    if (strtotime($inv['expires_at']) <= time())      { render_redeem('That invite has expired. Ask for a new one.'); exit; }
    if ((int)$inv['fails'] >= INVITE_MAX_FAILS)       { render_redeem('That invite was tried too many times and is no longer valid.'); exit; }
    if ($inv['wrapped_dek'] === null)                 { render_redeem('That invite is no longer usable. Ask for a new one.'); exit; }

    $dek = v_unwrap(['iter'=>$inv['iterations'],'salt'=>$inv['salt'],'nonce'=>$inv['nonce'],
                     'tag'=>$inv['tag'],'ct'=>$inv['wrapped_dek']], $code);
    if ($dek === false) {
        $b = mysqli_prepare($con, "UPDATE vault_invite SET fails=fails+1 WHERE id=?");
        mysqli_stmt_bind_param($b, 'i', $inv['id']); mysqli_stmt_execute($b);
        render_redeem('That code did not work.'); exit;
    }
    $vid = (int)$inv['vault_id'];
    $have = mysqli_prepare($con, "SELECT id FROM vault_keyslot WHERE vault_id=? AND user_id=? LIMIT 1");
    mysqli_stmt_bind_param($have, 'ii', $vid, $__uid);
    mysqli_stmt_execute($have); $hr = mysqli_stmt_get_result($have);
    if ($hr && mysqli_fetch_assoc($hr)) { render_redeem('You already have access to that vault with your own keyword.'); exit; }

    $slot = v_wrap($dek, $kw, VAULT_ITER);
    if ($slot === false || v_unwrap($slot, $kw) !== $dek) { render_redeem('Self-check failed; nothing was changed. Try again.'); exit; }

    $ok = false;
    mysqli_begin_transaction($con);
    do {
        $i = mysqli_prepare($con, "INSERT INTO vault_keyslot (vault_id,user_id,label_enc,iterations,salt,nonce,tag,wrapped_dek) VALUES (?,?,?,?,?,?,?,?)");
        if (!$i) break;
        mysqli_stmt_bind_param($i, 'iisissss', $vid, $__uid, $inv['label_enc'], $slot['iter'], $slot['salt'], $slot['nonce'], $slot['tag'], $slot['ct']);
        if (!mysqli_stmt_execute($i)) break;
        // burn the invite: mark used AND destroy the wrapped key, so the code is dead
        $m = mysqli_prepare($con, "UPDATE vault_invite SET used_at=NOW(), wrapped_dek=NULL WHERE id=? AND used_at IS NULL");
        if (!$m) break;
        mysqli_stmt_bind_param($m, 'i', $inv['id']);
        if (!mysqli_stmt_execute($m) || mysqli_stmt_affected_rows($m) !== 1) break;
        // prove the new keyslot works, before committing
        $back = null;
        foreach (vault_rows_for($con, $__uid) as $r) if ((int)$r['id'] === $vid) $back = $r;
        if (!$back || vault_try_open($back, $kw) === false) break;
        $ok = true;
    } while (false);
    if (!$ok) { mysqli_rollback($con); render_redeem('Could not join that vault; nothing was changed. Try again.'); exit; }
    mysqli_commit($con);
    // 2026-09-03: do NOT re-render the form on success - that left the invitee staring
    //   at an empty invite box. Put them on the vault, where the keyword box is, and
    //   carry a one-shot message across the redirect.
    $__clash = vault_keyword_collision($con, $__uid, $kw, $vid);
    $_SESSION['cv_flash'] = 'You are in. Enter the keyword you just chose to open the vault.'
        . ($__clash > 0 ? ' Note: that keyword also opens vault #'.$__clash.' - if it were ever exposed, both would be.' : '');
    header('Location: ' . APP_BASE); exit;
}
if (($_GET['screen'] ?? '') === 'redeem') { render_redeem(); exit; }

// 2026-09-03: invite creation lives on its own pages, so a slow form fill or an
//   error can never be wiped by the vault's 60s auto-lock.
if ($action === 'transfer_form' || $action === 'transfer_confirm') {
    $vid = (int)($_POST['vault_id'] ?? 0);
    $row = null;
    foreach (vault_rows_for($con, $__uid) as $r) if ((int)$r['id'] === $vid) $row = $r;
    if (!$row)                            { render_generic_notice('Vault not found', 'That vault does not exist, or you cannot open it.'); exit; }
    if ((int)$row['owner_id'] !== $__uid) { render_generic_notice('Not allowed', 'Only the owner of this vault can transfer it.'); exit; }
    if ($action === 'transfer_form')      { render_transfer_form($con, $vid, $__uid); exit; }

    $nw = (int)($_POST['new_owner'] ?? 0);
    $kw = (string)($_POST['keyword'] ?? '');
    if ($nw <= 0)  { render_transfer_form($con, $vid, $__uid, 'Choose who should become the owner.'); exit; }
    if ($kw === '') { render_transfer_form($con, $vid, $__uid, 'Enter your keyword to confirm.'); exit; }
    // proving the keyword means a hijacked session alone is not enough to give the vault away
    if (vault_try_open($row, $kw) === false) { render_transfer_form($con, $vid, $__uid, 'Wrong keyword - nothing was changed.'); exit; }
    $e = auth_stepup_check($con, $__uid, (string)($_POST['stepup'] ?? ''));
    if ($e !== '') { render_transfer_form($con, $vid, $__uid, $e); exit; }
    $e2 = vault_transfer_owner($con, $row, $__uid, $nw);
    if ($e2 !== null) { render_transfer_form($con, $vid, $__uid, $e2); exit; }
    $_SESSION['cv_flash'] = 'Ownership transferred. You can still open and read this vault with your keyword, but you can no longer change it, invite, or remove anyone.';
    header('Location: ' . APP_BASE); exit;
}
if ($action === 'revoke_form' || $action === 'revoke_confirm') {
    $vid = (int)($_POST['vault_id'] ?? 0);
    $kid = (int)($_POST['keyslot_id'] ?? 0);
    $row = null;
    foreach (vault_rows_for($con, $__uid) as $r) if ((int)$r['id'] === $vid) $row = $r;
    // Only the vault's owner may remove people, and never their own entry - that would
    // orphan the vault. A guest must not be able to lock the owner out.
    if (!$row)                                  { render_generic_notice('Vault not found', 'That vault does not exist, or you cannot open it.'); exit; }
    if ((int)$row['owner_id'] !== $__uid)       { render_generic_notice('Not allowed', 'Only the owner of this vault can remove access.'); exit; }
    $slots = vault_keyslots($con, $vid);
    $target = null;
    foreach ($slots as $k) if ((int)$k['id'] === $kid) $target = $k;
    if (!$target)                               { render_generic_notice('Nothing to remove', 'That access has already been removed.'); exit; }
    if ((int)$target['user_id'] === $__uid)     { render_generic_notice('Not allowed', 'You cannot remove your own access - that would leave the vault with no way in.'); exit; }

    if ($action === 'revoke_form') { render_revoke_form($con, $vid, $kid, $__uid); exit; }

    $kw = (string)($_POST['keyword'] ?? '');
    if ($kw === '') { render_revoke_form($con, $vid, $kid, $__uid, 'Enter your keyword to confirm.'); exit; }
    $e = auth_stepup_check($con, $__uid, (string)($_POST['stepup'] ?? ''));
    if ($e !== '')  { render_revoke_form($con, $vid, $kid, $__uid, $e); exit; }

    $dropped = 0;
    foreach ($slots as $k) if ((int)$k['user_id'] !== $__uid && (int)$k['id'] !== $kid) $dropped++;
    $err2 = vault_revoke($con, $row, $__uid, $kw);
    if ($err2 !== null) { render_revoke_form($con, $vid, $kid, $__uid, $err2); exit; }
    $_SESSION['cv_flash'] = 'Access removed and the vault re-keyed under a new key. Your keyword is unchanged.'
        . ($dropped > 0 ? ' '.$dropped.' other '.($dropped===1?'person needs':'people need').' a fresh invite.' : '');
    header('Location: ' . APP_BASE); exit;
}
if ($action === 'invite_form') {
    // 2026-09-03: SECURITY - only the owner decides who else gets in. Previously any
    //   keyslot holder could issue invites to a vault that was not theirs.
    $vid = (int)($_POST['vault_id'] ?? 0);
    if (!vault_is_owner($con, $vid, $__uid)) { render_generic_notice('Not allowed', 'Only the owner of this vault can invite people to it.'); exit; }
    render_invite_form($vid); exit;
}
if ($action === 'invite_create') {
    // Granting access to a seed is the highest-privilege action here, so it needs BOTH
    // the vault keyword (technically required, to recover the key) AND a current
    // authenticator code - a walk-up at an unlocked screen must not be enough.
    $vid   = (int)($_POST['vault_id'] ?? 0);
    $kw    = (string)($_POST['keyword'] ?? '');
    $label = trim((string)($_POST['label'] ?? ''));
    if ($label === '')                                      { render_invite_form($vid, $label, 'Give the invite a label, so you remember who it was for.'); exit; }
    if (!preg_match('/^[\pL\pN ._-]{1,32}$/u', $label))      { render_invite_form($vid, '', 'Label: up to 32 letters, numbers, spaces, dots or dashes.'); exit; }
    if ($vid <= 0 || $kw === '')                            { render_invite_form($vid, $label, 'Enter your keyword to create an invite.'); exit; }
    if (!vault_is_owner($con, $vid, $__uid))                { render_generic_notice('Not allowed', 'Only the owner of this vault can invite people to it.'); exit; }
    $e = auth_stepup_check($con, $__uid, (string)($_POST['stepup'] ?? ''));
    if ($e !== '')                                          { render_invite_form($vid, $label, $e); exit; }
    $row = null;
    foreach (vault_rows_for($con, $__uid) as $r) if ((int)$r['id'] === $vid) $row = $r;
    $open = $row ? vault_try_open($row, $kw) : false;
    if (!$row)                        { render_invite_form($vid, $label, 'Vault not found.'); exit; }
    if ($open === false)              { render_invite_form($vid, $label, 'Wrong keyword - no invite was created.'); exit; }
    if ((int)$row['format'] !== 2)    { render_invite_form($vid, $label, 'This vault is not on the shared-capable format yet. Unlock it once to upgrade it, then try again.'); exit; }
    $code = invite_new_code();
    $wrap = v_wrap($open[1], $code, VAULT_ITER);
    $lab  = ak_encrypt($label);
    if ($wrap === false || $lab === false || v_unwrap($wrap, $code) !== $open[1]) { render_invite_form($vid, $label, 'Self-check failed; no invite was created.'); exit; }
    $hash = invite_hash($code); $ttl = (int)INVITE_TTL_HOURS;
    $i = mysqli_prepare($con, "INSERT INTO vault_invite (vault_id,created_by,code_hash,label_enc,iterations,salt,nonce,tag,wrapped_dek,expires_at) VALUES (?,?,?,?,?,?,?,?,?, DATE_ADD(NOW(), INTERVAL ? HOUR))");
    if (!$i) { render_invite_form($vid, $label, 'Could not create the invite.'); exit; }
    mysqli_stmt_bind_param($i, 'iississssi', $vid, $__uid, $hash, $lab, $wrap['iter'], $wrap['salt'], $wrap['nonce'], $wrap['tag'], $wrap['ct'], $ttl);
    if (!mysqli_stmt_execute($i)) { render_invite_form($vid, $label, 'Could not create the invite.'); exit; }
    render_invite_code($code, $label); exit;
}

if ($action === 'create') {
    $activeTab = 'create';
    $kw  = (string)($_POST['keyword']  ?? '');
    $kw2 = (string)($_POST['keyword2'] ?? '');
    $words = seed_normalise($_POST['w'] ?? []);
    $pin = trim((string)($_POST['pin'] ?? ''));
    $pass = trim((string)($_POST['pass'] ?? ''));
    $vname = trim((string)($_POST['vname'] ?? ''));

    if ($kw === '' || $kw !== $kw2)        $err = 'Keywords are empty or do not match.';
    elseif ($vname !== '' && !preg_match('/^[\pL\pN ._\-]{1,40}$/u', $vname))
        $err = 'Vault name: up to 40 letters, numbers, spaces, dots, dashes.';
    // 2026-09-03: the entropy floor applies to the OWNER too. It previously only
    //   applied to people joining by invite, which was backwards - the owner's keyword
    //   protects the same seed, and a vault is only as strong as its weakest keyword.
    elseif (cv_entropy($kw) < MIN_KEYSLOT_BITS)
        $err = 'That keyword is too weak (~'.cv_entropy($kw).' bits; this vault needs ~'.MIN_KEYSLOT_BITS.'). Use Generate, or a longer passphrase.';
    elseif (!in_array(count($words), SEED_LENGTHS, true))
        $err = 'A recovery phrase must be ' . seed_lengths_text() . ' words - you entered ' . count($words) . '.';
    elseif (in_array('', $words, true))
        $err = 'There is a gap in the words. Fill every slot up to the length you are using.';
    // 2026-09-03: this used to be a hard refusal, because unlock stopped at the first
    //   matching vault and the second became unreachable. The chooser fixed that, so it
    //   is now only a warning: sharing a keyword means one compromise exposes both.
    
    else {
        $payload = json_encode(['w' => $words, 'pin' => $pin, 'pass' => $pass], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $rec = v_encrypt($payload, $kw, VAULT_ITER);
        if ($rec === false) $err = 'Encryption failed.';
        else {
            $nenc = ($vname !== '') ? ak_encrypt($vname) : null;
            $stmt = mysqli_prepare($con, "INSERT INTO vault (user_id,iterations,salt,nonce,tag,ciphertext,name_enc) VALUES (?,?,?,?,?,?,?)");
            mysqli_stmt_bind_param($stmt, 'iisssss', $__uid, $rec['iter'], $rec['salt'], $rec['nonce'], $rec['tag'], $rec['ct'], $nenc);
            if (mysqli_stmt_execute($stmt)) {
                $newid = mysqli_insert_id($con);
                $clash = vault_keyword_collision($con, $__uid, $kw, $newid);
                $msg = 'Vault #' . $newid . ($vname !== '' ? ' (' . $vname . ')' : '') . ' encrypted and stored.'
                     . ($clash > 0 ? ' Note: that keyword also opens vault #'.$clash.' - if it were ever exposed, both would be.' : '');
            }
            else $err = 'Could not store vault.';
        }
        $kw = $kw2 = $payload = ''; $words = []; // best-effort wipe
    }
}
elseif ($action === 'unlock') {
    $activeTab = 'unlock';
    $kw = (string)($_POST['keyword'] ?? '');
    if ($kw === '') $err = 'Enter a keyword.';
    else {
        // 2026-09-03: when the chooser tells us WHICH vault, derive the key once against
        //   that vault alone. Two vaults sharing a keyword is then harmless - you picked
        //   one - and an unlock costs one derivation however many vaults you own.
        $__want = (int)($_POST['vault_id'] ?? 0);
        $__rows = vault_rows_for($con, $__uid);
        if ($__want > 0) {
            $__only = [];
            foreach ($__rows as $r) if ((int)$r['id'] === $__want) $__only[] = $r;
            if ($__only) $__rows = $__only;
        }
        foreach ($__rows as $row) {
            $open = vault_try_open($row, $kw);          // 2026-09-03: handles format 1 and 2
            if ($open === false) continue;
            $data = json_decode($open[0], true);
            if (!is_array($data) || !isset($data['w'])) continue;
            $revealed = $data; $revealedId = (int)$row['id'];
            // 2026-09-03: existing keywords predate the floor. Measure in memory and
            //   nudge - never blocking, never stored, never logged.
            $__kwBits = cv_entropy($kw);
            if ($__kwBits < MIN_KEYSLOT_BITS) $notice = 'Your keyword measures about '.$__kwBits.' bits. New keywords now need ~'.MIN_KEYSLOT_BITS.'. Consider changing it: Edit, then New keyword.';
            // 2026-09-03: transparent migration to the shared-capable format, gated by config.
            //   A failure here is harmless: the vault stays format 1 and is already revealed.
            if (VAULT_AUTO_UPGRADE && (int)$row['format'] === 1
                && vault_upgrade_v2($con, $revealedId, $__uid, $kw, $open[0])) {
                $msg = 'Vault #' . $revealedId . ' upgraded to the shared-capable format.';
            }
            break;
        }
        if ($revealed === null)
            $err = ($__want > 0) ? 'That keyword does not open the vault you chose.' : 'No vault matches that keyword.';
        $pickedVault = $__want;   // stay on that vault's keyword step either way
        $kw = '';
    }
    // 2026-09-03: AJAX REVEAL. The phrase is returned as JSON and written into the grid by
    //   script, so it is never part of an HTML document: no copy in the page source, none
    //   in bfcache, nothing for view-source to show. And because the keyword arrives on an
    //   XHR rather than a form navigation, no history entry ever holds it - so there is
    //   nothing a reload, a back/forward, or a crash-restore could resubmit. That removes
    //   the whole class rather than defusing one route through it.
    if (($_POST['ajax'] ?? '') === '1') {
        header('Content-Type: application/json');
        if ($revealed === null) { echo json_encode(['ok'=>false,'err'=>$err]); exit; }
        echo json_encode([
            'ok'       => true,
            'vault_id' => (int)$revealedId,
            'words'    => array_values(array_map('strval', (array)($revealed['w'] ?? []))),
            'pin'      => (string)($revealed['pin']  ?? ''),
            'pass'     => (string)($revealed['pass'] ?? ''),
            'msg'      => $msg,
            'notice'   => $notice,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }
    // Without script there is no reveal at all. The old path embedded the phrase in the
    // response; that is deliberately gone rather than kept as a fallback.
    if ($revealed !== null) {
        $revealed = null;
        $err = 'JavaScript is required to open a vault. The phrase is fetched separately so it never lands in the page source.';
    }
}
elseif ($action === 'update') {
    $activeTab = 'unlock';
    $vid   = (int)($_POST['vault_id'] ?? 0);
    $kw    = (string)($_POST['keyword'] ?? '');
    $newkw = (string)($_POST['new_keyword'] ?? '');
    $words = seed_normalise($_POST['w'] ?? []);
    $pin   = trim((string)($_POST['pin'] ?? ''));
    $pass  = trim((string)($_POST['pass'] ?? ''));
    if ($vid > 0) { $revealed = ['w'=>$words,'pin'=>$pin,'pass'=>$pass]; $revealedId = $vid; }   // 2026-09-01: keep edits visible if update errors
    if ($vid <= 0 || $kw === '')          $err = 'Enter your keyword to save.';
    // 2026-09-03: a keyword CHANGE must clear the same floor as a new one
    elseif ($newkw !== '' && cv_entropy($newkw) < MIN_KEYSLOT_BITS)
        $err = 'That new keyword is too weak (~'.cv_entropy($newkw).' bits; needs ~'.MIN_KEYSLOT_BITS.'). Nothing was changed.';
    
    elseif (!in_array(count($words), SEED_LENGTHS, true))
        $err = 'A recovery phrase must be ' . seed_lengths_text() . ' words - this one has ' . count($words) . '.';
    elseif (in_array('', $words, true))
        $err = 'There is a gap in the words. Fill every slot.';
    else {
        // 2026-09-03: find it among the vaults this user can open (owner OR keyslot holder),
        //   so someone sharing the vault can save edits too. Access is proven by the keyword.
        $row = null;
        foreach (vault_rows_for($con, $__uid) as $r) { if ((int)$r['id'] === $vid) { $row = $r; break; } }
        $open = $row ? vault_try_open($row, $kw) : false;
        if (!$row)               $err = 'Vault not found.';
        elseif ($open === false) $err = 'Wrong keyword — cannot update this vault.';
        elseif ((int)$row['owner_id'] !== $__uid) $err = 'Read-only: only the owner of this vault can change what it contains.';
        else {
            $payload = json_encode(['w'=>$words,'pin'=>$pin,'pass'=>$pass], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $err = vault_save($con, $row, $__uid, $kw, $newkw, $payload, $open[1]);
            if ($err === null) {
                // rename is owner-only, like every other change to a vault
                $vname = trim((string)($_POST['vname'] ?? ''));
                if ($vname === '' || preg_match('/^[\pL\pN ._\-]{1,40}$/u', $vname)) {
                    $nenc = ($vname !== '') ? ak_encrypt($vname) : null;
                    // 2026-09-03: AND user_id=? added. It cannot change the outcome here -
                    //   the owner check above already proved $__uid owns $vid, and owner_id
                    //   IS vault.user_id - but every other write in this file carries its
                    //   owner clause, and without it a refactor upstream would turn this
                    //   line into a rename-any-vault-by-id hole without a word of warning.
                    $un = mysqli_prepare($con, "UPDATE vault SET name_enc=? WHERE id=? AND user_id=?");
                    if ($un) { mysqli_stmt_bind_param($un, 'sii', $nenc, $vid, $__uid); mysqli_stmt_execute($un); }
                }
                $__clash = ($newkw !== '') ? vault_keyword_collision($con, $__uid, $newkw, $vid) : 0;
                $msg = 'Vault #' . $vid . ' updated.'
                     . ($newkw !== '' ? ((int)$row['format'] === 2
                        ? ' Your keyword changed (anyone else with access keeps theirs).'
                        : ' Keyword changed.') : '')
                     . ($__clash > 0 ? ' Note: that keyword also opens vault #'.$__clash.' - if it were ever exposed, both would be.' : '');
                $revealed = ['w'=>$words,'pin'=>$pin,'pass'=>$pass]; $revealedId = $vid;
            }
            $payload = '';
        }
    }
    $kw = $newkw = '';
    if (($_POST['ajax'] ?? '') === '1') { header('Content-Type: application/json'); echo json_encode(['ok'=>($err===null),'msg'=>$msg,'err'=>$err]); exit; }
}
elseif ($action === 'invite_cancel') {
    // Cancelling only ever removes access, so it does not need step-up.
    $activeTab = 'unlock';
    $iid = (int)($_POST['invite_id'] ?? 0);
    $d = mysqli_prepare($con, "DELETE FROM vault_invite WHERE id=? AND created_by=? AND used_at IS NULL");
    if ($iid > 0 && $d) {
        mysqli_stmt_bind_param($d, 'ii', $iid, $__uid);
        $msg = (mysqli_stmt_execute($d) && mysqli_stmt_affected_rows($d) === 1)
             ? 'Invite cancelled - that code no longer works.'
             : 'That invite was already used or cancelled.';
    } else $err = 'Could not cancel that invite.';
}
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0">
<title>Coldvault</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="style.css">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHJlY3Qgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiByeD0iNSIgZmlsbD0iIzBhMGMwZCIvPjxnIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzVmZTNjMyIgc3Ryb2tlLXdpZHRoPSIxLjkiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCI+PHJlY3QgeD0iNC41IiB5PSIxMC41IiB3aWR0aD0iMTUiIGhlaWdodD0iOS41IiByeD0iMiIvPjxwYXRoIGQ9Ik04IDEwLjVWN2E0IDQgMCAwIDEgOCAwdjMuNSIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTUuNSIgcj0iMS4zIiBmaWxsPSIjNWZlM2MzIiBzdHJva2U9Im5vbmUiLz48L2c+PC9zdmc+">
</head>
<body>
<script src="<?php echo APP_BASE;?>words.js"></script>
<div class="wrap">
  <div class="top">
    <div class="brand">
      <div class="mark"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.6" stroke-linecap="round"><rect x="4" y="10.5" width="16" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/><circle cx="12" cy="15.5" r="1.4"/></svg></div>
      <div><h1>Cold<span class="b">vault</span><span class="cursor"></span></h1><div class="tagline">offline-grade seed custody</div></div>
    </div>
    <div class="badges"><span class="badge" style="color:var(--accent)"><span class="dot"></span> <?php echo h(auth_uname());?></span><span class="badge"><span class="dot"></span> zero-trace</span><span class="badge"><span class="dot"></span> aes-256-gcm</span><span class="badge"><span class="dot"></span> pbkdf2 kdf</span><button class="infobtn" type="button" data-cv="cvSecHelp" aria-label="About the security" title="What do these mean?" style="margin:0 2px"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><circle cx="12" cy="7.8" r="1" fill="currentColor" stroke="none"/></svg></button><a class="btn btn-ghost" href="<?php echo APP_BASE;?>security/" style="padding:8px 13px;font-size:10px;letter-spacing:1px;margin:0 0 0 4px">Security</a><a class="btn btn-ghost" href="<?php echo APP_BASE;?>help/" style="padding:8px 13px;font-size:10px;letter-spacing:1px;margin:0 0 0 4px">Help</a><form method="POST" action="" style="margin:0 0 0 4px"><input type="hidden" name="action" value="logout"><?php echo cv_csrf_field();?><button class="btn btn-ghost" type="submit" style="padding:8px 13px;font-size:10px;letter-spacing:1px">Lock</button></form></div>
  </div>

  <div id="sechelp" class="helpnote" style="display:none">
    <svg viewBox="0 0 24 24" stroke-width="1.7"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/></svg>
    <div><b>AES-256-GCM</b> is the encryption that locks your seed — the same cipher used to protect top-secret data. The “GCM” part also detects tampering, so a wrong keyword fails cleanly instead of leaking anything. <b>PBKDF2 KDF</b> turns your keyword into the encryption key by hashing it 450,000 times, which makes every password guess ~450,000&times; slower — so brute-forcing your keyword is enormously expensive. <b>Zero-trace</b>: your keyword and seed are never stored or logged, the page is never cached, and only ciphertext ever reaches the database. <a class="help-more" href="<?php echo APP_BASE;?>help/#s4" target="_blank" rel="noopener">Full explanation &rarr;</a></div>
  </div>
  <div class="card">
    <div class="tabs" role="tablist">
      <button class="tab" role="tab" data-pane="unlock"  aria-selected="<?php echo $activeTab==='unlock'?'true':'false';?>"><span class="n">01</span>Unlock</button>
      <button class="tab" role="tab" data-pane="create"  aria-selected="<?php echo $activeTab==='create'?'true':'false';?>"><span class="n">02</span>New vault</button>
    </div>

    <!-- UNLOCK -->
    <section class="pane <?php echo $activeTab==='unlock'?'on':'';?>" id="unlock">
      <?php if($activeTab==='unlock' && $msg): ?><div class="banner ok"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg><span><?php echo h($msg);?></span></div><?php endif; ?>
      <?php if($activeTab==='unlock' && $err): ?><div class="banner bad"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg><span><?php echo h($err);?></span></div><?php endif; ?>
      <?php if(!empty($notice)): ?><div class="warn" style="margin-bottom:18px"><?php echo h($notice);?></div><?php endif; ?>
      <?php
        $__vl = vault_list_for($con, $__uid);
        // 2026-09-03: two-step unlock. With one vault there is nothing to choose, so it
        //   goes straight to the keyword. With several, you pick first and the keyword
        //   step then targets exactly that vault - one key derivation, whatever you own.
        $__target = null;
        if (count($__vl) === 1)      $__target = $__vl[0];
        elseif ($pickedVault > 0)    { foreach($__vl as $vv) if ((int)$vv['id'] === $pickedVault) $__target = $vv; }
        elseif ($revealedId)         { foreach($__vl as $vv) if ((int)$vv['id'] === (int)$revealedId) $__target = $vv; }
        $__vname = function($v){ return $v['name'] !== '' ? h($v['name']) : 'Vault #'.(int)$v['id']; };
      ?>
      <?php if(count($__vl) === 0): ?>
      <p class="lead">Nothing stored yet.</p>
      <div class="warn">You have no vaults. Open <b>New vault</b> to store your first recovery phrase.</div>

      <?php elseif($__target === null): ?>
      <!-- STEP 1: choose a vault -->
      <p class="lead">You have <b><?php echo count($__vl);?></b> vaults. Choose the one to open, then enter its keyword.</p>
      <?php foreach($__vl as $vv): ?>
      <form method="POST" action="" style="margin:0 0 9px">
        <input type="hidden" name="action" value="unlock_pick">
        <?php echo cv_csrf_field();?>
        <input type="hidden" name="vault_id" value="<?php echo (int)$vv['id'];?>">
        <button type="submit" class="vaultpick" data-busytext="Opening&hellip;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><rect x="4" y="10.5" width="16" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/><circle cx="12" cy="15.5" r="1.3" fill="currentColor" stroke="none"/></svg>
          <span class="vp-main"><?php echo $__vname($vv);?></span>
          <span class="vp-meta">created <?php echo h(substr((string)$vv['created_at'],0,10));?><?php if((int)$vv['holders'] > 1): ?> &middot; <span style="color:var(--amber)">shared with <?php echo (int)$vv['holders']-1;?></span><?php endif; ?><?php if((int)$vv['owner_id'] !== $__uid): ?> &middot; not yours<?php endif; ?></span>
          <svg class="vp-go" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M9 6l6 6-6 6"/></svg>
        </button>
      </form>
      <?php endforeach; ?>

      <?php else: ?>
      <!-- STEP 2: the keyword, for that vault only -->
      <?php if(count($__vl) > 1): ?>
      <form method="POST" action="" style="margin:0 0 16px">
        <input type="hidden" name="action" value="unlock_pick">
        <?php echo cv_csrf_field();?>
        <input type="hidden" name="vault_id" value="0">
        <button type="submit" class="btn btn-ghost" style="padding:8px 13px;font-size:10px;letter-spacing:1px"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M19 12H5M11 6l-6 6 6 6"/></svg> All vaults</button>
      </form>
      <?php endif; ?>
      <div class="gridhead" style="margin-top:0"><span class="t">Opening <?php echo $__vname($__target);?></span></div>
      <p class="lead">The key is derived in memory to decrypt the phrase &mdash; the keyword is never placed in a URL, saved, or logged.</p>
      <div id="unlockmsg"></div>
      <form method="POST" action="" autocomplete="off" id="unlockForm">
        <input type="hidden" name="action" value="unlock">
        <?php echo cv_csrf_field();?>
        <input type="hidden" name="vault_id" value="<?php echo (int)$__target['id'];?>">
        <label class="fl" for="uk">Keyword</label>
        <div class="field">
          <input id="uk" name="keyword" type="password" placeholder="••••••••••••••••" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"<?php echo $revealed===null?' autofocus':'';?>>
          <button type="button" class="eye" data-cv="peek" data-cv-for="uk" aria-label="show"><svg viewBox="0 0 24 24"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></button>
        </div>
        <div class="row"><button class="btn btn-primary" type="submit" data-busytext="Decrypting&hellip;"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M5 12h14M13 6l6 6-6 6"/></svg> Decrypt</button></div>
      </form>
      <?php endif; ?>
      <?php if($__target !== null):
        $revealedId = (int)$__target['id'];          // everything below already keys off this
        $__ownerId  = vault_owner_id($con, $revealedId);
        $__isOwner  = ($__ownerId === $__uid);
      ?>
      <!-- 2026-09-03: rendered EMPTY and hidden. The phrase arrives as JSON from the AJAX
           unlock and is written in by script, so this document never contains it. -->
      <div id="revealbox" style="display:none">
      <form method="POST" action="" autocomplete="off" id="editForm">
        <input type="hidden" name="action" value="update">
        <?php echo cv_csrf_field();?>
        <input type="hidden" name="vault_id" value="<?php echo (int)$revealedId;?>">
        <div class="gridhead"><span class="t" id="seedcount">phrase + PIN + passphrase</span>
          <div style="display:flex;gap:8px">
            <button class="clock" type="button" data-cv="cvKeep" id="cvclock" title="Tap to keep it open"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3 2"/></svg><span class="tt">1:00</span></button><button class="infobtn" type="button" data-cv="cvHelp" id="cvinfo" aria-label="About the timer" title="What is this?"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><circle cx="12" cy="7.8" r="1" fill="currentColor" stroke="none"/></svg></button><button class="btn btn-ghost" type="button" data-cv="toggleMask" id="maskbtn">Show</button>
            <?php if($__isOwner): ?><button class="btn btn-ghost" type="button" data-cv="editMode" id="editbtn">Edit</button><?php endif; ?>
          </div>
        </div>
        <div id="cvhelp" class="helpnote" style="display:none">
          <svg viewBox="0 0 24 24" stroke-width="1.7"><circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3 2"/></svg>
          <div><b>Auto-hide timer.</b> For your security the decrypted vault hides itself after 60 seconds. <b>Tap the clock</b> to reset it and keep the vault open. At 0:00 — or if you switch tabs or reload — it re-locks and you'll need your keyword again to view it. <a class="help-more" href="<?php echo APP_BASE;?>help/#s8" target="_blank" rel="noopener">Full explanation &rarr;</a></div>
        </div>
        <div class="seed reveal-anim masked" id="useed"></div>
        <?php if($__isOwner): ?>
        <div id="editbox" style="display:none">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:16px">
            <div><label class="fl" for="ek">Keyword (required to save)</label><div class="field"><input id="ek" name="keyword" type="password" placeholder="current keyword" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"></div></div>
            <div><label class="fl" for="evn">Vault name (optional)</label><div class="field"><input id="evn" name="vname" type="text" value="<?php echo h($__target['name']);?>" placeholder="blank = no name" maxlength="40" autocomplete="off" spellcheck="false"></div></div>
            <div><label class="fl" for="enk">New keyword (optional)</label><div class="field"><input id="enk" name="new_keyword" type="password" placeholder="blank = keep current; needs ~<?php echo (int)MIN_KEYSLOT_BITS;?>+ bits" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false"></div></div>
          </div>
          <div id="editmsg" class="banner" style="display:none;margin:14px 0 0"></div>
          <div class="row"><button class="btn btn-primary" type="submit" data-busytext="Saving…"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg> Save changes</button><button class="btn btn-ghost" type="button" data-cv="reload">Cancel</button></div>
        </div>
        <?php endif; ?>
      </form>
      <?php
        $__ks  = vault_keyslots($con, (int)$revealedId);
        $__inv = vault_invites_pending($con, (int)$revealedId);
      ?>
      <div id="sharedbox">
        <div class="gridhead"><span class="t">Shared access</span>
          <span class="hint" style="margin:0"><?php echo count($__ks);?> keyword<?php echo count($__ks)===1?'':'s';?> can open this vault</span>
        </div>
        <div class="factlist">
          <div class="lh"><svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="1.6"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/></svg> who can open it</div>
          <ul>
            <?php foreach($__ks as $k): ?>
            <li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M20 6 9 17l-5-5"/></svg><span><b><?php echo h($k['label']);?></b> &middot; <span class="m"><?php echo h($k['username'] ?? '?');?></span> &middot; added <?php echo h(substr((string)$k['created_at'],0,10));?><?php if((int)$k['user_id'] === $__ownerId): ?> &middot; <span class="m" style="color:var(--amber)">owner</span><?php endif; ?><?php echo $k['last_used_at']?' &middot; last used '.h(substr((string)$k['last_used_at'],0,10)):'';?><?php if($__isOwner && (int)$k['user_id'] !== $__uid): ?>
              <form method="POST" action="" style="display:inline;margin-left:8px"><input type="hidden" name="action" value="revoke_form"><?php echo cv_csrf_field();?><input type="hidden" name="vault_id" value="<?php echo (int)$revealedId;?>"><input type="hidden" name="keyslot_id" value="<?php echo (int)$k['id'];?>"><button class="btn btn-ghost" type="submit" data-busytext="Opening&hellip;" style="padding:4px 10px;font-size:9.5px;letter-spacing:1px">Remove</button></form>
            <?php endif; ?></span></li>
            <?php endforeach; ?>
            <?php foreach($__isOwner ? $__inv : [] as $iv): ?>
            <li><svg viewBox="0 0 24 24" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3 2"/></svg><span><b><?php echo h($iv['label']);?></b> &middot; invite pending, expires <?php echo h(substr((string)$iv['expires_at'],0,16));?>
              <form method="POST" action="" style="display:inline;margin-left:8px"><input type="hidden" name="action" value="invite_cancel"><?php echo cv_csrf_field();?><input type="hidden" name="invite_id" value="<?php echo (int)$iv['id'];?>"><button class="btn btn-ghost" type="submit" data-busytext="Cancelling&hellip;" style="padding:4px 10px;font-size:9.5px;letter-spacing:1px">Cancel</button></form>
            </span></li>
            <?php endforeach; ?>
          </ul>
        </div>
        <?php if(!$__isOwner): ?>
        <div class="hint" style="margin-top:12px">You can open and read this vault. Only its owner can change its contents, or invite and remove people.</div>
        <?php else: ?>
        <form method="POST" action="" style="margin-top:14px">
          <input type="hidden" name="action" value="invite_form">
          <?php echo cv_csrf_field();?>
          <input type="hidden" name="vault_id" value="<?php echo (int)$revealedId;?>">
          <button class="btn btn-ghost" type="submit" data-busytext="Opening&hellip;" style="padding:11px 18px;font-size:11px"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg> Invite someone to this vault</button>
        </form>
        <?php if(count($__ks) > 1): ?>
        <form method="POST" action="" style="margin-top:8px">
          <input type="hidden" name="action" value="transfer_form">
          <?php echo cv_csrf_field();?>
          <input type="hidden" name="vault_id" value="<?php echo (int)$revealedId;?>">
          <button class="btn btn-ghost" type="submit" data-busytext="Opening&hellip;" style="padding:11px 18px;font-size:11px"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M5 12h14M13 6l6 6-6 6"/></svg> Transfer ownership</button>
        </form>
        <?php endif; ?>
        <?php endif; ?>
      </div>
      </div><!-- /revealbox -->
      <p class="hint" id="revealhint" style="display:none;margin-top:14px">Fetched just now and held only in this tab — nothing here is cached; leaving or reloading wipes it.<?php echo $__isOwner ? ' Use <b>Edit</b> to fix a word, the PIN, or the passphrase.' : ' This vault is <b>read-only</b> for you: only its owner can change what it contains.';?></p>
      <div class="banner ok" id="relocknote" style="display:none;margin-top:14px"><svg viewBox="0 0 24 24" stroke-width="1.8"><rect x="4" y="10.5" width="16" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/></svg><span>Auto-locked — enter your keyword above to view it again.</span></div>
      <?php endif; ?>
    </section>

    <!-- CREATE -->
    <section class="pane <?php echo $activeTab==='create'?'on':'';?>" id="create">
      <?php if($activeTab==='create' && $msg): ?><div class="banner ok"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg><span><?php echo h($msg);?></span></div><?php endif; ?>
      <?php if($activeTab==='create' && $err): ?><div class="banner bad"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/></svg><span><?php echo h($err);?></span></div><?php endif; ?>
      <p class="lead">Create a new vault. Everything is encrypted <b>server-side</b> before it reaches the database.</p>
      <form method="POST" action="" autocomplete="off" id="createForm" data-cv-validate="validateCreate">
        <input type="hidden" name="action" value="create">
        <?php echo cv_csrf_field();?>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
          <div><label class="fl" for="ck">Keyword</label><div class="field"><input id="ck" name="keyword" type="password" placeholder="needs ~<?php echo (int)MIN_KEYSLOT_BITS;?>+ bits — use Generate" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false"><button type="button" class="eye" data-cv="peek" data-cv-for="ck" aria-label="show"><svg viewBox="0 0 24 24"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></button></div></div>
          <div><label class="fl" for="ck2">Confirm keyword</label><div class="field"><input id="ck2" name="keyword2" type="password" placeholder="repeat" autocomplete="new-password" autocorrect="off" autocapitalize="off" spellcheck="false"></div></div>
        </div>
        <label class="fl" for="vn" style="margin-top:4px">Vault name (optional)</label>
        <div class="field"><input id="vn" name="vname" type="text" placeholder="e.g. main backup - helps you pick it later" maxlength="40" autocomplete="off" spellcheck="false"></div>
        <div class="hint" id="strength">strength — enter a keyword · random &gt; passphrase &gt; words</div>
        <div class="row" style="margin-top:10px;gap:8px">
          <button type="button" class="btn btn-ghost" data-cv="cvGenKeyword" style="padding:10px 16px;font-size:11px"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M4 4v6h6M20 20v-6h-6"/><path d="M20 9a8 8 0 0 0-14-3M4 15a8 8 0 0 0 14 3"/></svg> Generate strong keyword</button>
          <button class="infobtn" type="button" data-cv="cvKwHelp" aria-label="About the keyword" title="What is the keyword?"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><circle cx="12" cy="7.8" r="1" fill="currentColor" stroke="none"/></svg></button>
        </div>
        <div id="kwhelp" class="helpnote" style="display:none"><svg viewBox="0 0 24 24" stroke-width="1.7"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/></svg><div><b>The keyword encrypts this vault</b> — it is Coldvault's master password for your seed (it never touches your wallet). Pick something strong, or hit <b>Generate</b> for a random 7-word passphrase. It is stretched with PBKDF2 and <b>never stored</b>; lose it and the vault cannot be decrypted, so save it somewhere safe. <a class="help-more" href="<?php echo APP_BASE;?>help/#s1" target="_blank" rel="noopener">Full explanation &rarr;</a></div></div>
        <div id="gennote" class="warn" style="display:none;margin-top:10px">Generated a strong random keyword (7 words + a number and symbol) and filled both boxes. <b>Copy it somewhere safe now</b> (a password manager) — it is not stored anywhere and cannot be recovered.</div>
        <div class="gridhead"><span class="t">Seed phrase <button class="infobtn" type="button" data-cv="cvSeedHelp" aria-label="About these fields" title="What are these?" style="margin-left:5px;vertical-align:middle"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><circle cx="12" cy="7.8" r="1" fill="currentColor" stroke="none"/></svg></button></span><span class="hint" style="margin:0;display:flex;align-items:center;gap:8px">
          <label for="wcount" style="margin:0">length</label>
          <select id="wcount" name="wcount" data-cv-change="cvSetCount" style="background:var(--slot);border:1px solid var(--line2);color:var(--text);font-family:var(--mono);font-size:11px;border-radius:7px;padding:5px 7px">
            <?php foreach(SEED_LENGTHS as $L): ?><option value="<?php echo (int)$L;?>"<?php echo $L===SEED_LENGTH_DEFAULT?' selected':'';?>><?php echo (int)$L;?> words</option><?php endforeach; ?>
          </select>
          &middot; or just paste the whole phrase into slot 01</span></div>
        <div id="seedhelp" class="helpnote" style="display:none"><svg viewBox="0 0 24 24" stroke-width="1.7"><rect x="4" y="10.5" width="16" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/></svg><div><b>The words</b> = your wallet recovery phrase, whatever length your wallet gave you (12, 15, 18, 21 or 24 for BIP39; 20 or 33 for SLIP-39 Shamir shares). Pick the length above, or just paste the phrase into slot 01 and it will size itself. <b>PIN</b> (optional) = a device PIN to keep alongside it. <b>Passphrase</b> (optional) = a human-chosen extra password (BIP39 “25th word”) that opens a <b>separate hidden wallet</b>. Only fill it if your wallet uses one — and it must match your wallet <b>exactly</b>. If you're storing an existing wallet, type its existing passphrase (or leave blank). <a class="help-more" href="<?php echo APP_BASE;?>help/#s7" target="_blank" rel="noopener">Full explanation &rarr;</a></div></div>
        <div class="seed" id="cseed">
          <?php for($i=1;$i<=SEED_LENGTH_MAX;$i++): ?>
          <div class="slot" data-i="<?php echo $i;?>"<?php echo $i>SEED_LENGTH_DEFAULT?' style="display:none"':'';?>><span class="idx"><?php echo str_pad((string)$i,2,'0',STR_PAD_LEFT);?></span><input type="password" name="w[]" placeholder="word <?php echo $i;?>" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"></div>
          <?php endfor; ?>
          <div class="slot pin"><span class="idx">PIN</span><input type="password" name="pin" placeholder="PIN (optional)" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"></div>
          <div class="slot pass"><span class="idx">PASS</span><input type="password" name="pass" placeholder="Passphrase / 25th word (optional)" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"></div>
        </div>
        <div class="row" style="margin-top:20px"><button class="btn btn-primary" type="submit" data-busytext="Encrypting…"><svg viewBox="0 0 24 24" stroke-width="1.8"><rect x="4" y="10.5" width="16" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/></svg> Encrypt &amp; store</button><button class="btn btn-ghost" type="button" data-cv="clearAll">Clear all</button></div>
      </form>
      <div class="factlist">
        <div class="lh"><svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="1.6"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/></svg> no-trace guarantees</div>
        <ul>
          <li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M20 6 9 17l-5-5"/></svg><span><b>Keyword is never stored.</b> Used once to derive the key with <span class="m">PBKDF2 · 100k</span>, then discarded.</span></li>
          <li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M20 6 9 17l-5-5"/></svg><span><b>Seed encrypted with <span class="m">AES-256-GCM</span></b>, random salt + nonce per vault. Wrong keyword fails cleanly — no oracle.</span></li>
          <li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M20 6 9 17l-5-5"/></svg><span><b>Database sees ciphertext only.</b> Plaintext never appears in a database query.</span></li>
          <li><svg viewBox="0 0 24 24" stroke-width="1.8"><path d="M20 6 9 17l-5-5"/></svg><span><b>No browser residue.</b> <span class="m">POST</span> only, <span class="m">no-store</span> headers, autofill off, fields wiped on leave.</span></li>
        </ul>
      </div>
    </section>

  </div>
  <div class="foot">coldvault · encrypted at rest · nothing cached</div>
</div>
<?php echo cv_busy_js(); ?>
<div class="toast" id="toast"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg><span id="toastmsg">wiped</span></div>
<div class="modal" id="idleModal">
  <div class="modal-card">
    <div class="mc-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3 2"/></svg></div>
    <h3>Still there?</h3>
    <p>You've been inactive. For your security this vault will lock and sign you out in <b id="idleLeft">1:00</b>.</p>
    <div class="mc-row"><button class="btn btn-primary" type="button" data-cv="idleStay">Stay logged in</button><button class="btn btn-ghost" type="button" data-cv="idleLogoutNow">Log out now</button></div>
  </div>
</div>
<script nonce="<?php echo CSP_NONCE;?>">
  // 2026-09-01: a reload must NOT resubmit the unlock POST (that would re-decrypt after auto-lock).
  //             Convert this history entry to a plain GET so Cmd+R reloads locked, no resubmission prompt.
  try{ if(window.history&&history.replaceState) history.replaceState(null,'',location.pathname); }catch(e){}
  const tabs=[...document.querySelectorAll('.tab')];
  tabs.forEach(t=>t.onclick=()=>{if(t.dataset.pane!=='unlock'&&document.getElementById('editForm'))cvRelock();tabs.forEach(x=>x.setAttribute('aria-selected',x===t));document.querySelectorAll('.pane').forEach(p=>p.classList.remove('on'));document.getElementById(t.dataset.pane).classList.add('on');});
  function peek(id,btn){const el=document.getElementById(id);el.type=el.type==='password'?'text':'password';btn.style.color=el.type==='text'?'var(--accent)':'';}
  let masked=true;
  const CVMASK='••••••••';
  // 2026-09-03: the phrase lives HERE, in memory, and nowhere in the document. It is
  //   written into the inputs only while visible, and wiped on re-lock. Values are set
  //   through .value (never innerHTML), so no word is ever HTML-parsed.
  var CV_SEED = null;
  function cvSeedVals(){ return CV_SEED ? CV_SEED.words.concat([CV_SEED.pin, CV_SEED.pass]) : []; }
  function cvWipeSeed(){ if(CV_SEED){ CV_SEED.words = []; CV_SEED.pin = ''; CV_SEED.pass = ''; } CV_SEED = null; }
  function cvBuildGrid(d){
    var g = document.getElementById('useed'); if(!g) return;
    var h = '', n = d.words.length;
    for (var i = 0; i < n; i++)
      h += '<div class="slot" style="animation-delay:'+(i*24)+'ms"><span class="idx">'
         + ('0'+(i+1)).slice(-2) + '</span><input class="vfld" type="text" name="w[]" readonly spellcheck="false"></div>';
    h += '<div class="slot pin"><span class="idx">PIN</span><input class="vfld" type="text" name="pin" readonly spellcheck="false" placeholder="(none)"></div>';
    h += '<div class="slot pass"><span class="idx">PASS</span><input class="vfld" type="text" name="pass" readonly spellcheck="false" placeholder="(none)"></div>';
    g.innerHTML = h;
    var sc = document.getElementById('seedcount');
    if (sc) sc.textContent = n + ' words + PIN + passphrase';
  }
  function cvFlds(){return document.querySelectorAll('#useed .vfld');}
  function applyMask(on){var v=cvSeedVals();cvFlds().forEach((i,ix)=>{i.value = on ? CVMASK : (v[ix]||'');});const g=document.getElementById('useed');if(g)g.classList.toggle('masked',on);}
  function toggleMask(){masked=!masked;applyMask(masked);const b=document.getElementById('maskbtn');if(b)b.textContent=masked?'Show':'Hide';}
  function editMode(){masked=false;applyMask(false);cvFlds().forEach(i=>i.readOnly=false);const b=document.getElementById('maskbtn');if(b)b.style.display='none';const eb=document.getElementById('editbox');if(eb)eb.style.display='block';const btn=document.getElementById('editbtn');if(btn)btn.style.display='none';const fst=cvFlds()[0];if(fst)fst.focus();}
  function prepEdit(){var v=cvSeedVals();cvFlds().forEach((i,ix)=>{if(i.value===CVMASK)i.value=(v[ix]||'');});return true;}
  // client-side banner, since a successful unlock no longer reloads the page
  function cvBanner(kind,text){
    var c=document.getElementById('unlockmsg'); if(!c||!text) return;
    var ok = (kind==='ok');
    c.innerHTML = '<div class="banner '+(ok?'ok':'bad')+'"><svg viewBox="0 0 24 24" stroke-width="2">'
      + (ok?'<path d="M20 6 9 17l-5-5"/>':'<path d="M12 8v5M12 16.5v.5"/><circle cx="12" cy="12" r="9"/>')
      + '</svg><span></span></div>';
    c.querySelector('span').textContent = text;      // textContent: server text is never parsed as HTML
    if (ok) setTimeout(function(){ var b=c.querySelector('.banner'); if(b){b.classList.add('fading'); setTimeout(function(){c.innerHTML='';},550);} }, 10000);
  }
  function cvNotice(text){
    var c=document.getElementById('unlockmsg'); if(!c||!text) return;
    var d=document.createElement('div'); d.className='warn'; d.style.marginBottom='18px'; d.textContent=text;
    c.appendChild(d);
  }
  // 2026-09-03: :not([type=hidden]) — the wipe used to clear the form's own hidden fields
  //   too, including the action, so a submit after "wipe fields" silently did nothing.
  //   Hidden fields here hold no secret (an action name, a vault id, the request token).
  function clearAll(){
    document.querySelectorAll('#createForm input:not([type=hidden])').forEach(i=>i.value='');
    // 2026-09-03: the strength meter only redraws on an 'input' event, and setting .value
    //   does not fire one - so it went on showing the bit count of the keyword that had
    //   just been wiped. Same dispatch cvGenKeyword() already uses below.
    var k=document.getElementById('ck'); if(k)k.dispatchEvent(new Event('input'));
    // 2026-09-03: and hide the "generated a keyword" note, which otherwise went on
    //   announcing a keyword that had just been wiped.
    var g=document.getElementById('gennote'); if(g)g.style.display='none';
    toast('fields wiped',true);
  }
  function toast(m,ok){const t=document.getElementById('toast');document.getElementById('toastmsg').textContent=m;t.style.borderColor=ok?'var(--accent-dim)':'var(--danger)';t.style.color=ok?'var(--accent)':'var(--danger)';t.classList.add('show');clearTimeout(window._tt);window._tt=setTimeout(()=>t.classList.remove('show'),1900);}
  // 2026-09-03: phrase length is selectable - BIP39 uses 12/15/18/21/24, and SLIP-39
  //   Shamir shares are 20 or 33. Slots beyond the chosen length are hidden AND cleared,
  //   so nothing stray is ever submitted.
  const CV_LENS = <?php echo json_encode(SEED_LENGTHS);?>;
  function cvSetCount(n){
    n = parseInt(n,10) || <?php echo (int)SEED_LENGTH_DEFAULT;?>;
    document.querySelectorAll('#cseed .slot[data-i]').forEach(function(d){
      var i = parseInt(d.getAttribute('data-i'),10), on = (i <= n);
      d.style.display = on ? '' : 'none';
      var inp = d.querySelector('input');
      if (inp && !on) inp.value = '';
    });
  }
  function cvWordCount(){ var s=document.getElementById('wcount'); return s ? parseInt(s.value,10) : <?php echo (int)SEED_LENGTH_DEFAULT;?>; }
  // paste the whole phrase into slot 01 -> detect its length and distribute
  const cseed=document.getElementById('cseed');
  if(cseed){const first=cseed.querySelector('input[name="w[]"]');
    first.addEventListener('paste',e=>{
      const t=(e.clipboardData||window.clipboardData).getData('text').trim().split(/\s+/);
      if(t.length>=12){
        e.preventDefault();
        if(CV_LENS.indexOf(t.length)>=0){ const sel=document.getElementById('wcount'); if(sel){ sel.value=String(t.length); } cvSetCount(t.length); }
        else { toast(t.length+' words is not a valid phrase length',false); }
        const ins=[...cseed.querySelectorAll('input[name="w[]"]')];
        t.slice(0,<?php echo (int)SEED_LENGTH_MAX;?>).forEach((w,i)=>{if(ins[i])ins[i].value=w;});
      }});}
  // client-side gate so a server rejection never wipes the 24 words
  function validateCreate(){const kw=document.getElementById('ck').value,kw2=document.getElementById('ck2').value;
    if(!kw||kw!==kw2){toast('keywords must match',false);return false;}
    // check the floor BEFORE submitting, so a rejection never costs you the 24 words
    var kb=cvEntropy(kw); if(kb<CV_MIN){toast('keyword too weak: ~'+kb+' bits, needs ~'+CV_MIN,false);document.getElementById('ck').focus();return false;}
    const n=cvWordCount();
    if(CV_LENS.indexOf(n)<0){toast('pick a valid phrase length',false);return false;}
    const ws=[...document.querySelectorAll('#cseed input[name="w[]"]')].slice(0,n);
    if(ws.some(i=>!i.value.trim())){toast('fill all '+n+' words',false);return false;}return true;}
  // strength meter
  const CV_MIN = <?php echo (int)MIN_KEYSLOT_BITS;?>;   // 2026-09-03: same floor as the server
  // 2026-09-03: distinct words only, and the character fallback caps length at twice the
  //   number of distinct characters, so repetition cannot inflate the meter. Mirrors
  //   cv_entropy() in PHP exactly - cross-checked over 1193 inputs, zero disagreements.
  function cvEntropy(v){if(!v)return 0;var t=v.split(/[^A-Za-z0-9]+/).filter(function(x){return x.length>=3&&/^[A-Za-z]+$/.test(x);});var b;if(t.length>=3){var u=[];t.forEach(function(x){var k=x.toLowerCase();if(u.indexOf(k)<0)u.push(k);});b=u.length*11;if(/[A-Z]/.test(v))b+=2;if(/[0-9]/.test(v))b+=3;if(/[^A-Za-z0-9 \-]/.test(v))b+=4;}else{var cs=0;if(/[a-z]/.test(v))cs+=26;if(/[A-Z]/.test(v))cs+=26;if(/[0-9]/.test(v))cs+=10;if(/[^A-Za-z0-9]/.test(v))cs+=33;var d=0;for(var i=0;i<v.length;i++)if(v.indexOf(v[i])===i)d++;b=Math.min(v.length,2*d)*Math.log2(cs||2);}return Math.round(b);}
  const ck=document.getElementById('ck');
  if(ck)ck.addEventListener('input',e=>{const v=e.target.value,s=document.getElementById('strength');var b=cvEntropy(v),label,col;if(!v.length){label='enter a keyword';col='var(--faint)';}else if(b<36){label='weak';col='var(--danger)';}else if(b<56){label='fair';col='var(--amber)';}else if(b<75){label='strong';col='var(--accent)';}else{label='very strong';col='var(--accent)';}s.innerHTML='strength — <span style="color:'+col+'">'+label+'</span>'+(v.length?' · ~'+b+' bits · '+v.length+' chars · '+(b>=CV_MIN?'<span style="color:var(--accent)">accepted</span>':'<span style="color:var(--danger)">below the ~'+CV_MIN+'-bit minimum</span>'):'');});
  // 2026-09-03: success banners auto-dismiss after 10s, or on click. Errors
  //   (.banner.bad) deliberately stay put - you may still need to act on them.
  //   #relocknote is EXCLUDED: it is state, not a confirmation, and is revealed by
  //   cvRelock() at 60s - fading it here would leave it invisible when it matters.
  //   #editmsg is excluded too; the AJAX save handler owns it.
  (function(){
    var skip={relocknote:1,editmsg:1};
    var list=[].filter.call(document.querySelectorAll('.banner.ok'),function(b){return !skip[b.id];});
    if(!list.length) return;
    function hide(b){ b.classList.add('fading'); setTimeout(function(){ b.style.display='none'; },550); }
    list.forEach(function(b){
      b.classList.add('dismissable');
      b.title='Click to dismiss';
      b.addEventListener('click',function(){ hide(b); });
      setTimeout(function(){ hide(b); },10000);
    });
  })();

  // wipe inputs when leaving/hiding the page (defeats bfcache retention)
  window.addEventListener('pagehide',()=>document.querySelectorAll('input:not([type=hidden])').forEach(i=>{if(!i.readOnly)i.value='';}));
  // 2026-09-01: auto-hide — a decrypted vault re-locks (wipes) after 60s unless you tap the clock
  const CV_DUR=60; let cvLeft=CV_DUR, cvT=null;
  function cvClockShow(){const c=document.getElementById('cvclock');if(!c)return;const t=c.querySelector('.tt');if(t)t.textContent=Math.floor(cvLeft/60)+':'+String(cvLeft%60).padStart(2,'0');c.classList.toggle('warn',cvLeft<=15&&cvLeft>5);c.classList.toggle('crit',cvLeft<=5);}
  function cvKeep(){cvLeft=CV_DUR;cvClockShow();}
  function cvHelp(){const h=document.getElementById('cvhelp');if(h)h.style.display=(h.style.display==='none'||!h.style.display)?'flex':'none';}
  function cvKwHelp(){const h=document.getElementById('kwhelp');if(h)h.style.display=(h.style.display==='none'||!h.style.display)?'flex':'none';}
  function cvSeedHelp(){const h=document.getElementById('seedhelp');if(h)h.style.display=(h.style.display==='none'||!h.style.display)?'flex':'none';}
  function cvSecHelp(){const h=document.getElementById('sechelp');if(h)h.style.display=(h.style.display==='none'||!h.style.display)?'flex':'none';}
  function cvDice(n){var W=window.CV_WORDS;if(W&&W.length){var r=new Uint32Array(n);crypto.getRandomValues(r);var o=[];for(var i=0;i<n;i++)o.push(W[r[i]%W.length]);return o.join('-');}var c='abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789',r2=new Uint32Array(20);crypto.getRandomValues(r2);return [].map.call(r2,function(x){return c[x%c.length];}).join('');}
  function cvGenKeyword(){var kw=cvDice(7);var sy='!@#$%^&*?_+=',rr=new Uint32Array(2);crypto.getRandomValues(rr);kw=kw+'-'+(10+rr[0]%90)+sy[rr[1]%sy.length];var a=document.getElementById('ck'),b=document.getElementById('ck2');if(a){a.type='text';a.value=kw;}if(b){b.type='text';b.value=kw;}var g=document.getElementById('gennote');if(g)g.style.display='block';if(a)a.dispatchEvent(new Event('input'));}
  function cvStart(){cvLeft=CV_DUR;cvClockShow();if(cvT)clearInterval(cvT);cvT=setInterval(()=>{cvLeft--;cvClockShow();if(cvLeft<=0)cvRelock();},1000);}
  // 2026-09-03: re-lock now WIPES the in-memory phrase and empties the grid, rather than
  //   removing a form whose attributes held the words. There is no copy left behind.
  function cvRelock(){
    if(cvT){clearInterval(cvT);cvT=null;}
    cvWipeSeed();
    var g=document.getElementById('useed'); if(g)g.innerHTML='';
    var rb=document.getElementById('revealbox'); if(rb)rb.style.display='none';
    var rh=document.getElementById('revealhint'); if(rh)rh.style.display='none';
    var n=document.getElementById('relocknote'); if(n)n.style.display='flex';
    masked=true;
  }
  // bind the keep-alive, but do NOT start the timer on load: the box exists (hidden)
  // before anything is revealed, so the clock must start only after a successful fetch.
  (function(){const f=document.getElementById('editForm');if(f)f.addEventListener('input',cvKeep);})();

  // ---- the AJAX unlock itself ----
  (function(){
    var uf=document.getElementById('unlockForm'); if(!uf) return;
    uf.addEventListener('submit',function(e){
      e.preventDefault();
      var btn=uf.querySelector('button[type="submit"]');
      var kwEl=document.getElementById('uk');
      if(!kwEl || !kwEl.value){ cvBanner('bad','Enter a keyword.'); if(kwEl)kwEl.focus(); return; }
      if(window.cvBusy)cvBusy(btn,'Decrypting\u2026');
      var body=new URLSearchParams(new FormData(uf)); body.set('ajax','1');
      fetch('',{method:'POST',body:body,cache:'no-store'})
        .then(function(r){ return r.json(); })
        .then(function(j){
          if(window.cvIdle)cvIdle(btn);
          kwEl.value='';                                   // the keyword leaves the page at once
          var c=document.getElementById('unlockmsg'); if(c)c.innerHTML='';
          if(!j || !j.ok){ cvBanner('bad',(j&&j.err)||'Could not open that vault.'); kwEl.focus(); return; }
          CV_SEED={words:j.words||[],pin:j.pin||'',pass:j.pass||''};
          cvBuildGrid(CV_SEED);
          masked=true; applyMask(true);
          var mb=document.getElementById('maskbtn'); if(mb){mb.style.display='';mb.textContent='Show';}
          var eb=document.getElementById('editbox');  if(eb)eb.style.display='none';
          var ebt=document.getElementById('editbtn'); if(ebt)ebt.style.display='';
          var rb=document.getElementById('revealbox'); if(rb)rb.style.display='';
          var rh=document.getElementById('revealhint'); if(rh)rh.style.display='';
          var rn=document.getElementById('relocknote'); if(rn)rn.style.display='none';
          cvStart();
          if(j.msg)    cvBanner('ok',j.msg);
          if(j.notice) cvNotice(j.notice);
        })
        .catch(function(){ if(window.cvIdle)cvIdle(btn); cvBanner('bad','Network error - nothing was revealed. Try again.'); });
    });
  })();

  // 2026-09-01: save edits via AJAX so validation errors show INLINE (no reload, no lost edits)
  (function(){
    const ef=document.getElementById('editForm'); if(!ef) return;
    function em(msg,ok){ const e=document.getElementById('editmsg'); if(!e)return; e.textContent=msg; e.className='banner '+(ok?'ok':'bad'); e.style.display='flex'; }
    function editDone(){ var w=[],f=cvFlds();
      for(var i=0;i<f.length;i++){ if(i<f.length-2) w.push(f[i].value); f[i].readOnly=true; }
      if(CV_SEED){ CV_SEED.words=w; CV_SEED.pin=f[f.length-2].value; CV_SEED.pass=f[f.length-1].value; } if(typeof applyMask==='function')applyMask(true); masked=true; const eb=document.getElementById('editbox'); if(eb)eb.style.display='none'; const mb=document.getElementById('maskbtn'); if(mb){mb.style.display='';mb.textContent='Show';} const ebt=document.getElementById('editbtn'); if(ebt)ebt.style.display=''; const k=document.getElementById('ek'); if(k)k.value=''; const nk=document.getElementById('enk'); if(nk)nk.value=''; const eg=document.getElementById('editmsg'); if(eg)eg.style.display='none'; }
    ef.addEventListener('submit',function(e){
      e.preventDefault();
      if(typeof prepEdit==='function') prepEdit();
      const k=document.getElementById('ek'); const kw=k?k.value:'';
      if(!kw){ em('Enter your keyword to save.',false); if(k)k.focus(); return; }
      const ws=[...ef.querySelectorAll('input[name="w[]"]')];
      if(ws.some(i=>!i.value.trim())){ em('Every word slot must be filled.',false); return; }
      const nk=document.getElementById('enk'); const nkv=nk?nk.value:'';
      if(nkv){ var nb=cvEntropy(nkv); if(nb<CV_MIN){ em('That new keyword is too weak (~'+nb+' bits; needs ~'+CV_MIN+'). Nothing was changed.',false); nk.focus(); return; } }
      const body=new URLSearchParams(new FormData(ef)); body.set('ajax','1');
      const sbtn=ef.querySelector('button[type="submit"]');
      if(window.cvBusy)cvBusy(sbtn,'Saving\u2026');
      em('Saving…',true);
      fetch('',{method:'POST',body:body}).then(r=>r.json()).then(j=>{ if(window.cvIdle)cvIdle(sbtn); if(j&&j.ok){ if(typeof toast==='function')toast(j.msg||'Saved.',true); if(typeof cvKeep==='function')cvKeep(); editDone(); } else em((j&&j.err)||'Could not save.',false); }).catch(()=>{ if(window.cvIdle)cvIdle(sbtn); em('Network error — try again.',false); });
    });
  })();

  // 2026-09-01: idle auto-logout with an in-page prompt (no alert/confirm)
  (function(){
    const modal=document.getElementById('idleModal'); if(!modal) return;
    const WARN_AFTER=13*60*1000, GRACE=60, PING_EVERY=60*1000;
    // 2026-09-03: these three POST without a form, so they carry the token explicitly.
    const CV_T=<?php echo json_encode(cv_csrf());?>;
    let last=Date.now(), lastPing=Date.now(), warnOpen=false, grace=GRACE;
    const fmt=s=>Math.floor(Math.max(s,0)/60)+':'+String(Math.max(s,0)%60).padStart(2,'0');
    const leftEl=()=>document.getElementById('idleLeft');
    function bgPing(){ try{fetch('',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'action=ping&cvt='+encodeURIComponent(CV_T),keepalive:true});}catch(e){} lastPing=Date.now(); }
    function bump(){ if(warnOpen) return; last=Date.now(); if(Date.now()-lastPing>=PING_EVERY) bgPing(); }
    ['mousemove','keydown','click','scroll','touchstart'].forEach(ev=>document.addEventListener(ev,bump,{passive:true}));
    function openWarn(){ warnOpen=true; grace=GRACE; const e=leftEl(); if(e)e.textContent=fmt(grace); modal.classList.add('show'); }
    function closeWarn(){ warnOpen=false; last=Date.now(); modal.classList.remove('show'); }
    function doLogout(){ const f=document.createElement('form'); f.method='POST'; f.action=''; f.innerHTML='<input type="hidden" name="action" value="logout"><input type="hidden" name="cvt" value="'+CV_T+'">'; document.body.appendChild(f); f.submit(); }
    window.idleStay=function(){ fetch('',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'action=ping&cvt='+encodeURIComponent(CV_T)}).then(r=>{ if(r.status===204){ lastPing=Date.now(); closeWarn(); } else doLogout(); }).catch(()=>doLogout()); };
    window.idleLogoutNow=function(){ doLogout(); };
    setInterval(()=>{ if(warnOpen){ grace--; const e=leftEl(); if(e)e.textContent=fmt(grace); if(grace<=0){ warnOpen=false; doLogout(); } } else if(Date.now()-last>=WARN_AFTER){ openWarn(); } },1000);
  })();
</script>
</body>
</html>
