<?php
// public/auth.php
// 2026-09-01: Multi-user TOTP authentication (created).
// 2026-09-04: prepared for public release (MIT).
//   Per-user secrets (AES-256-GCM at rest via APP_KEY), per-user backup codes +
//   lockout, sessions, self-registration with CAPTCHA + honeypot + a site-wide
//   sign-up throttle. This is a GATE only — vaults stay encrypted by their own
//   per-vault keyword and are owned per user.

// LOCAL_MODE and OTP_ISSUER, needed on EVERY entry point that starts a session.
// captcha.php requires this file but not config.php, and the session cookie's
// Secure flag has to match on both paths or the CAPTCHA answer is stored under a
// cookie the page never sends back.
require_once __DIR__ . '/env.php';

define('AUTH_IDLE',        900);   // session idle timeout (seconds)
define('AUTH_MAX_FAILS',   5);     // wrong codes before per-user lockout
define('AUTH_LOCK_SECS',   300);   // lockout duration (step-up path only - see user_fail)
// 2026-09-03: wrong logins before the sign-in form demands the human check. This is what
//   rate-limits code guessing now that a lockout no longer refuses a login - the lockout
//   was a denial of service, because anyone who knew a username could hold that account
//   shut indefinitely. It counts fail_count, which is server-side state a client cannot
//   clear by dropping its cookie.
define('AUTH_CAPTCHA_AFTER', 3);
// 2026-09-07 (security review): per-account sign-in budget. A sign-in is one 6-digit code with
//   no password, so the CAPTCHA was the ONLY limiter and ~333k guesses (a few hundred dollars of
//   solving) was affordable. This caps code evaluations per username per hour, then throttles to
//   one per LOGIN_THROTTLE_INTERVAL - but never fully locks, so an outsider cannot hold a known
//   username shut (the reason the old five-strike lock was removed). Applied identically to
//   unknown usernames, so it leaks nothing about existence.
define('LOGIN_MAX_PER_HOUR',   30);
define('LOGIN_THROTTLE_INTERVAL', 60);   // seconds between attempts once the hourly budget is spent
// 2026-09-08 (internal audit, L1): a per-account KEYWORD-FAILURE budget. A stolen session used to
//   be a free, silent keyword oracle - unlock / update / invite_create / revoke / transfer each
//   derive once per guess and nothing counted the misses, so only PBKDF2's ~1.4s slowed an attacker
//   down. Only a WRONG keyword is recorded, so a legitimate owner is never throttled however
//   heavily they use their vault, and like the sign-in budget it NEVER fully locks: one attempt per
//   interval always gets through, so this cannot be turned into a denial of service against them.
define('KW_MAX_FAILS_PER_HOUR', 10);
define('KW_THROTTLE_INTERVAL',  60);   // seconds between attempts once the failure budget is spent
// Registrations allowed per hour SITE-WIDE. There is no per-address counter
// because no client IP is ever recorded (see the privacy notes in README).
// Accepted trade-off: a sign-up flood can block new registrations for an hour.
define('REG_MAX_PER_HOUR', 5);
// OTP_ISSUER — the label your authenticator app shows — comes from the
// configuration file. See env.php and coldvault.env.example.

// ---- APP_KEY encryption for the stored TOTP secret and other APP_KEY-protected blobs ----
// 2026-09-07 (security review): the AAD now carries a per-row CONTEXT, so a blob encrypted for
//   one account/column cannot be transplanted onto another and still decrypt. Forging any blob
//   needs APP_KEY (to make the GCM tag), and every new blob is context-bound, so a database-write
//   attacker can no longer copy their own authenticator secret or backup-code rows onto a victim.
//   ak_decrypt falls back to the pre-review constant AAD so blobs written by older code still open;
//   because forging requires APP_KEY and freshly written blobs are always bound, that fallback
//   cannot be abused to re-enable the transplant. New writes should always pass $ctx.
function ak_aad($ctx){ return ($ctx === '') ? 'coldvault-auth' : 'coldvault-auth:'.$ctx; }
function ak_encrypt($p,$ctx=''){ $n=random_bytes(12);$t='';$c=openssl_encrypt($p,'aes-256-gcm',APP_KEY,OPENSSL_RAW_DATA,$n,$t,ak_aad($ctx),16);return $c===false?false:$n.$t.$c; }
function ak_decrypt($b,$ctx=''){
    if(strlen($b)<=28)return false;                                  // 28 = nonce(12)+tag(16); reject empty ciphertext
    $n=substr($b,0,12);$t=substr($b,12,16);$c=substr($b,28);
    $p=openssl_decrypt($c,'aes-256-gcm',APP_KEY,OPENSSL_RAW_DATA,$n,$t,ak_aad($ctx));
    if($p===false && $ctx!=='') $p=openssl_decrypt($c,'aes-256-gcm',APP_KEY,OPENSSL_RAW_DATA,$n,$t,ak_aad(''));  // legacy row written before context binding
    return $p;
}
// Context strings for each APP_KEY-protected column. Kept short and stable.
function ak_ctx_secret($lc){ return 's:u:'.strtolower(trim($lc)); }     // TOTP secret_blob, bound to username_lc
function ak_ctx_name($ownerUid){ return 'n:u:'.(int)$ownerUid; }        // vault.name_enc, bound to the owner
// Keyslot and invite labels share one per-vault context: an invite's label_enc ciphertext is
// copied verbatim into the new keyslot on redemption, so both must decrypt under the same AAD.
function ak_ctx_label($vid){ return 'l:v:'.(int)$vid; }

// ---- base32 (RFC 4648) ----
function base32_encode($d){ $a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';$o='';$b=0;$v=0;for($i=0;$i<strlen($d);$i++){$v=($v<<8)|ord($d[$i]);$b+=8;while($b>=5){$o.=$a[($v>>($b-5))&31];$b-=5;}}if($b>0)$o.=$a[($v<<(5-$b))&31];return $o; }
function base32_decode($s){ $a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';$s=strtoupper($s);$o='';$b=0;$v=0;for($i=0;$i<strlen($s);$i++){$c=strpos($a,$s[$i]);if($c===false)continue;$v=($v<<5)|$c;$b+=5;if($b>=8){$o.=chr(($v>>($b-8))&0xFF);$b-=8;}}return $o; }

// ---- TOTP (RFC 6238: HMAC-SHA1, 6 digits, 30s) ----
function totp_at($secretRaw,$counter){ $bin="\0\0\0\0".pack('N',$counter);$h=hash_hmac('sha1',$bin,$secretRaw,true);$off=ord($h[19])&0x0f;$n=((ord($h[$off])&0x7f)<<24)|((ord($h[$off+1])&0xff)<<16)|((ord($h[$off+2])&0xff)<<8)|(ord($h[$off+3])&0xff);return str_pad((string)($n%1000000),6,'0',STR_PAD_LEFT); }
function totp_verify($secretRaw,$code,$t,$window=1){ $code=preg_replace('/\D/','',$code);if(strlen($code)!==6)return false;$step=intdiv($t,30);for($w=-$window;$w<=$window;$w++){if(hash_equals(totp_at($secretRaw,$step+$w),$code))return $step+$w;}return false; }

// ---- session ----
function auth_session_start(){ if(session_status()===PHP_SESSION_ACTIVE)return;$secure=!(defined('LOCAL_MODE')&&LOCAL_MODE);session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>$secure,'httponly'=>true,'samesite'=>'Strict']);session_name('cvsess');@session_start(); }
// 2026-09-03: a session is now tied to the SECRET VERSION it was issued against, and the
//   account row must still exist. Pairing a new authenticator bumps that version, so every
//   OTHER signed-in session ends on its next request. Before this, re-pairing only stopped
//   an intruder getting back IN - a session they were already holding stayed alive, and the
//   idle timeout never expired it, because the page's own keep-alive kept refreshing it.
//   Fails CLOSED: a session carrying no recorded version - i.e. one created before this
//   change - is signed out. That costs everyone one sign-in, once.
function auth_is_logged_in($con){
    auth_session_start();
    if(empty($_SESSION['cv_uid']))return false;
    if(!empty($_SESSION['cv_last'])&&(time()-$_SESSION['cv_last'])>AUTH_IDLE){auth_logout();return false;}
    $row=user_by_id($con,(int)$_SESSION['cv_uid']);
    if(!$row||!isset($_SESSION['cv_sver'])||(int)$row['secret_version']!==(int)$_SESSION['cv_sver']){auth_logout();return false;}
    $_SESSION['cv_last']=time();
    return true;
}
function auth_login_user($uid,$username,$sver){ auth_session_start();session_regenerate_id(true);$_SESSION['cv_uid']=(int)$uid;$_SESSION['cv_uname']=$username;$_SESSION['cv_sver']=(int)$sver;$_SESSION['cv_last']=time(); }
function auth_logout(){ auth_session_start();$_SESSION=[];@session_destroy(); }
function auth_uid(){ return $_SESSION['cv_uid'] ?? null; }
function auth_uname(){ return $_SESSION['cv_uname'] ?? ''; }

// ---- users ----
function username_valid($u){ return (bool)preg_match('/^[A-Za-z0-9_.-]{3,32}$/',$u); }
function user_find($con,$username){ $lc=strtolower(trim($username));$s=mysqli_prepare($con,"SELECT * FROM vault_users WHERE username_lc=? LIMIT 1");mysqli_stmt_bind_param($s,'s',$lc);mysqli_stmt_execute($s);$r=mysqli_stmt_get_result($s);return $r?mysqli_fetch_assoc($r):null; }
function user_exists($con,$username){ return user_find($con,$username)!==null; }
function user_secret($row){ return ($row&&!empty($row['secret_blob']))?ak_decrypt($row['secret_blob'],ak_ctx_secret($row['username_lc']??'')):false; }
// Decrypt a blob under the BOUND context only (no legacy fallback). Used to detect a legacy
// row so it can be re-encrypted context-bound on next use.
function ak_decrypt_bound($b,$ctx){
    if(strlen($b)<=28)return false;
    return openssl_decrypt(substr($b,28),'aes-256-gcm',APP_KEY,OPENSSL_RAW_DATA,substr($b,0,12),substr($b,12,16),ak_aad($ctx));
}
// True if this account's secret_blob is still under the legacy (unbound) AAD.
function user_secret_is_legacy($row){
    if(!$row||empty($row['secret_blob']))return false;
    return ak_decrypt_bound($row['secret_blob'],ak_ctx_secret($row['username_lc']??''))===false
        && user_secret($row)!==false;
}
// Re-encrypt a legacy secret_blob under the bound context (idempotent; skips already-bound rows).
function user_migrate_secret($con,$row){
    if(!user_secret_is_legacy($row))return;
    $sec=user_secret($row); if($sec===false)return;
    $blob=ak_encrypt($sec,ak_ctx_secret($row['username_lc']??'')); if($blob===false)return;
    $s=mysqli_prepare($con,"UPDATE vault_users SET secret_blob=? WHERE id=?");
    if($s){mysqli_stmt_bind_param($s,'si',$blob,$row['id']);mysqli_stmt_execute($s);}
}
function user_locked($row){ if($row&&!empty($row['lock_until'])&&strtotime($row['lock_until'])>time())return strtotime($row['lock_until'])-time();return 0; }
function user_register($con,$username,$secretRaw,$codes){
    $lc=strtolower(trim($username));
    $blob=ak_encrypt($secretRaw,ak_ctx_secret($lc));if($blob===false)return false;
    // 2026-09-07 (security review): the account row and its backup codes are now written in one
    //   transaction with every statement checked, so a mid-registration failure cannot leave an
    //   account that exists but has fewer codes than the user was shown (a later lockout).
    if(!mysqli_begin_transaction($con))return false;
    $s=mysqli_prepare($con,"INSERT INTO vault_users (username,username_lc,secret_blob,enrolled_at,fail_count) VALUES (?,?,?,NOW(),0)");
    if(!$s){mysqli_rollback($con);return false;}
    mysqli_stmt_bind_param($s,'sss',$username,$lc,$blob);
    if(!@mysqli_stmt_execute($s)){mysqli_rollback($con);return false;}   // UNIQUE race -> false
    $uid=mysqli_insert_id($con);
    $ins=mysqli_prepare($con,"INSERT INTO vault_backup_codes (user_id,code_hash) VALUES (?,?)");
    if(!$ins){mysqli_rollback($con);return false;}
    foreach($codes as $c){$h=bc_hash($c,$uid);mysqli_stmt_bind_param($ins,'is',$uid,$h);if(!mysqli_stmt_execute($ins)){mysqli_rollback($con);return false;}}
    mysqli_commit($con);
    return $uid;
}
// 2026-09-07 (security review): $armLock defaults false so the SIGN-IN path can bump the failure
//   counter (which drives the CAPTCHA requirement) WITHOUT arming lock_until. Only the step-up
//   path passes true. Previously a wrong sign-in armed lock_until too, letting an outsider who
//   knew a username keep the owner's account-security controls (sign-out-others, re-pair, revoke)
//   permanently "Too many attempts" - a denial of exactly the incident-response tools.
function user_fail($con,$uid,$armLock=false){
    mysqli_query($con,"UPDATE vault_users SET fail_count=fail_count+1 WHERE id=".(int)$uid);
    if(!$armLock)return;
    $s=mysqli_prepare($con,"SELECT fail_count FROM vault_users WHERE id=?");mysqli_stmt_bind_param($s,'i',$uid);mysqli_stmt_execute($s);$r=mysqli_stmt_get_result($s);$row=$r?mysqli_fetch_assoc($r):null;
    // fail_count is NOT zeroed when the lock is applied; it is the durable signal behind the
    // CAPTCHA requirement. A successful sign-in or step-up clears it - see user_success().
    if($row&&(int)$row['fail_count']>=AUTH_MAX_FAILS){$u=date('Y-m-d H:i:s',time()+AUTH_LOCK_SECS);$q=mysqli_prepare($con,"UPDATE vault_users SET lock_until=? WHERE id=?");mysqli_stmt_bind_param($q,'si',$u,$uid);mysqli_stmt_execute($q);}
}
// 2026-09-07 (security review): last_step is advanced with a compare-and-set (only moves forward),
//   so two concurrent submissions of the same code cannot both record it as newly accepted.
// Compare-and-set on last_step. Returns TRUE only if THIS call advanced it; a concurrent request
// that already recorded the same step gets FALSE, and callers must treat that as a failed attempt.
// Without the return value the guard only stopped the row being overwritten twice - both racers
// still signed in on one code (2026-09-07, follow-up review).
function user_success($con,$uid,$step){ $s=mysqli_prepare($con,"UPDATE vault_users SET fail_count=0,lock_until=NULL,last_step=? WHERE id=? AND (last_step IS NULL OR last_step < ?)");if(!$s)return false;mysqli_stmt_bind_param($s,'iii',$step,$uid,$step);if(!mysqli_stmt_execute($s))return false;return mysqli_stmt_affected_rows($s)===1; }

// ---- backup codes (per user; hashed with APP_KEY pepper; single-use) ----
// 2026-09-07 (security review): the HMAC input now includes the user id, so a code-hash row copied
//   onto another account by a database-write attacker no longer verifies there. bc_verify_consume
//   also accepts the legacy (unbound) hash so codes issued by older code still work, and consumes
//   atomically (UPDATE ... WHERE used_at IS NULL + affected_rows) so the same code cannot be spent
//   twice by two concurrent requests.
function bc_norm($c){ return strtoupper(preg_replace('/[^A-Za-z0-9]/','',$c)); }
function bc_hash($c,$uid){ return hash_hmac('sha256',(int)$uid.':'.bc_norm($c),APP_KEY); }
function bc_hash_legacy($c){ return hash_hmac('sha256',bc_norm($c),APP_KEY); }
function bc_verify_consume($con,$uid,$code){
    $h=bc_hash($code,$uid);$hl=bc_hash_legacy($code);
    $s=mysqli_prepare($con,"SELECT id FROM vault_backup_codes WHERE user_id=? AND code_hash IN (?,?) AND used_at IS NULL LIMIT 1");
    mysqli_stmt_bind_param($s,'iss',$uid,$h,$hl);mysqli_stmt_execute($s);$r=mysqli_stmt_get_result($s);$row=$r?mysqli_fetch_assoc($r):null;
    if(!$row)return false;
    $u=mysqli_prepare($con,"UPDATE vault_backup_codes SET used_at=NOW() WHERE id=? AND used_at IS NULL");
    mysqli_stmt_bind_param($u,'i',$row['id']);mysqli_stmt_execute($u);
    return mysqli_stmt_affected_rows($u)===1;   // lost a concurrent race -> code already spent
}

// ---- account security: step-up re-auth + re-enrollment (2026-09-01) ----
function user_by_id($con,$uid){ $s=mysqli_prepare($con,"SELECT * FROM vault_users WHERE id=? LIMIT 1");mysqli_stmt_bind_param($s,'i',$uid);mysqli_stmt_execute($s);$r=mysqli_stmt_get_result($s);return $r?mysqli_fetch_assoc($r):null; }
function bc_unused_count($con,$uid){ $s=mysqli_prepare($con,"SELECT COUNT(*) c FROM vault_backup_codes WHERE user_id=? AND used_at IS NULL");mysqli_stmt_bind_param($s,'i',$uid);mysqli_stmt_execute($s);$r=mysqli_stmt_get_result($s);$row=$r?mysqli_fetch_assoc($r):null;return $row?(int)$row['c']:0; }
// Prove control of the CURRENT credential before any account change (blocks takeover from a live session).
// Accepts a current TOTP code or an unused backup code. Returns '' on success, else a message.
// Wrong attempts feed the same lockout as login, so this cannot be brute-forced.
function auth_stepup_check($con,$uid,$code){
    $row=user_by_id($con,$uid); if(!$row) return 'Account not found.';
    $w=user_locked($row); if($w>0) return "Too many attempts - wait {$w}s.";
    $secret=user_secret($row); $last=($row['last_step']!==null)?(int)$row['last_step']:-1;
    $step=($secret!==false)?totp_verify($secret,$code,time(),1):false;
    if($step!==false&&$step>$last&&user_success($con,$uid,$step)) return '';   // CAS lost -> fall through as a failure
    if(bc_verify_consume($con,$uid,$code)) return '';
    user_fail($con,$uid,true);   // step-up path DOES arm lock_until (needs an authenticated session)
    return 'That code did not match. If you just signed in with this code, wait for the next one - each code works only once. Otherwise use a fresh 6-digit code, or an unused backup code.';
}
// Swap in a new TOTP secret. Only called after the NEW app has proved it produces valid codes.
// 2026-09-03: also bumps secret_version, which ends every OTHER session on its next
//   request. Returns the NEW version (never 0, the column starts at 1) or false, so the
//   caller can re-stamp the session it is running in - otherwise pairing a new
//   authenticator would sign you out of the very device you just used to do it.
function user_set_secret($con,$uid,$secretRaw){
    $r=user_by_id($con,$uid); if(!$r) return false;
    $blob=ak_encrypt($secretRaw,ak_ctx_secret($r['username_lc'])); if($blob===false)return false;   // context-bound
    $s=mysqli_prepare($con,"UPDATE vault_users SET secret_blob=?,secret_version=secret_version+1,last_step=NULL,fail_count=0,lock_until=NULL,enrolled_at=NOW() WHERE id=?");
    mysqli_stmt_bind_param($s,'si',$blob,$uid);
    return mysqli_stmt_execute($s) ? user_secret_version($con,$uid) : false;
}
function user_secret_version($con,$uid){
    $s=mysqli_prepare($con,"SELECT secret_version FROM vault_users WHERE id=? LIMIT 1");
    mysqli_stmt_bind_param($s,'i',$uid);mysqli_stmt_execute($s);$r=mysqli_stmt_get_result($s);
    $row=$r?mysqli_fetch_assoc($r):null; return $row?(int)$row['secret_version']:false;
}
// Bump the version WITHOUT touching the authenticator: "sign out every other session".
function user_bump_secret_version($con,$uid){
    return mysqli_query($con,"UPDATE vault_users SET secret_version=secret_version+1 WHERE id=".(int)$uid)
        ? user_secret_version($con,$uid) : false;
}
// Replace ALL backup codes (used and unused) with a fresh single-use set, atomically.
function user_replace_backup_codes($con,$uid,$codes){
    if(!mysqli_begin_transaction($con))return false;
    $d=mysqli_prepare($con,"DELETE FROM vault_backup_codes WHERE user_id=?");
    if(!$d){mysqli_rollback($con);return false;}
    mysqli_stmt_bind_param($d,'i',$uid);
    if(!mysqli_stmt_execute($d)){mysqli_rollback($con);return false;}
    $ins=mysqli_prepare($con,"INSERT INTO vault_backup_codes (user_id,code_hash) VALUES (?,?)");
    if(!$ins){mysqli_rollback($con);return false;}
    foreach($codes as $c){$h=bc_hash($c,$uid);mysqli_stmt_bind_param($ins,'is',$uid,$h);if(!mysqli_stmt_execute($ins)){mysqli_rollback($con);return false;}}
    mysqli_commit($con);
    return true;
}

// ---- enrollment helpers ----
function gen_totp_secret(){ return random_bytes(20); }
function gen_backup_codes($n=8){ $c=[];for($i=0;$i<$n;$i++)$c[]=strtoupper(bin2hex(random_bytes(5)));return $c; }
function fmt_backup_code($c){ return substr($c,0,5).'-'.substr($c,5,5); }
function otpauth_uri($secretB32,$label){ return 'otpauth://totp/'.rawurlencode(OTP_ISSUER.':'.$label).'?secret='.$secretB32.'&issuer='.rawurlencode(OTP_ISSUER).'&algorithm=SHA1&digits=6&period=30'; }

// ---- CAPTCHA ----
function captcha_check($input){ auth_session_start();$ok=isset($_SESSION['cv_captcha'])&&strtolower(trim((string)$input))===$_SESSION['cv_captcha'];unset($_SESSION['cv_captcha']);return $ok; }

// ---- CSRF tokens (2026-09-03) ----
// One token per session, verified for EVERY POST from a single gate at the top of
// index.php rather than inside each handler, so a new action cannot be added and left
// unprotected by accident. htmlspecialchars is used directly rather than h(), because
// auth.php is also loaded by captcha.php, where h() does not exist.
//
// This is the only layer here that does not depend on the BROWSER behaving: SameSite=Strict,
// form-action 'self' and POST-only actions already make cross-site submission very hard,
// but all three are enforced by the client. This one is enforced by the server.
function cv_csrf(){ auth_session_start(); if(empty($_SESSION['cv_csrf'])) $_SESSION['cv_csrf']=bin2hex(random_bytes(32)); return $_SESSION['cv_csrf']; }
function cv_csrf_field(){ return '<input type="hidden" name="cvt" value="'.htmlspecialchars(cv_csrf(),ENT_QUOTES,'UTF-8').'">'; }
function cv_csrf_ok(){ auth_session_start(); $t=(string)($_SESSION['cv_csrf'] ?? ''); return $t!=='' && hash_equals($t,(string)($_POST['cvt'] ?? '')); }

// ---- registration throttle (site-wide, no IP) ----
// 2026-09-03: privacy — the app records NO client IP, anywhere. The sign-up throttle
//   counts registrations site-wide per hour instead of per address, so nothing
//   identifying is ever written to the database. The `ip` column was dropped and
//   client_ip() removed. CAPTCHA + honeypot remain the bot defence.
//   Known trade-off: a flood of sign-ups can block new registrations for an hour.
function reg_throttled($con){ mysqli_query($con,"DELETE FROM vault_reg_throttle WHERE ts < (NOW() - INTERVAL 1 HOUR)");$r=mysqli_query($con,"SELECT COUNT(*) c FROM vault_reg_throttle WHERE ts > (NOW() - INTERVAL 1 HOUR)");$row=$r?mysqli_fetch_assoc($r):null;return $row&&(int)$row['c']>=REG_MAX_PER_HOUR; }
function reg_record($con){ mysqli_query($con,"INSERT INTO vault_reg_throttle (ts) VALUES (NOW())"); }

// 2026-09-08 (internal audit, L3): atomically claim one of this hour's sign-up slots. TRUE if the
//   caller may proceed. reg_throttled() above is only ADVISORY - it reserves nothing, so it stays
//   cheap and an abandoned register_start costs the site nothing. The cap used to be checked at
//   register_start and recorded only at register_confirm, so N sessions could be staged past the
//   check and confirmed afterwards, exceeding it; and the count was read-then-act, so two
//   concurrent confirms could both pass.
//   Insert FIRST, then count the hour INCLUDING that row, and roll back if over. That is what
//   makes it atomic without an id column - vault_reg_throttle has none, so a targeted DELETE is
//   impossible, but a rollback removes exactly our own row.
//   ⚠ Never call this inside another transaction: mysqli cannot nest, and user_register() opens
//   its own. Call it immediately BEFORE creating the account.
function reg_reserve($con){
    mysqli_query($con,"DELETE FROM vault_reg_throttle WHERE ts < (NOW() - INTERVAL 1 HOUR)");
    if(!mysqli_begin_transaction($con)) return !reg_throttled($con);   // degrade to the old check
    $ok=false;
    do {
        if(!mysqli_query($con,"INSERT INTO vault_reg_throttle (ts) VALUES (NOW())")) break;
        $r=mysqli_query($con,"SELECT COUNT(*) c FROM vault_reg_throttle WHERE ts > (NOW() - INTERVAL 1 HOUR)");
        $row=$r?mysqli_fetch_assoc($r):null;
        if(!$row) break;
        if((int)$row['c']>REG_MAX_PER_HOUR) break;   // our own row is counted, hence > and not >=
        $ok=true;
    } while(false);
    if($ok) mysqli_commit($con); else mysqli_rollback($con);
    return $ok;
}

// ---- per-account sign-in throttle (2026-09-07 security review) ----
// Returns seconds the caller must wait before another code evaluation for this username, or 0.
// Under the hourly budget it returns 0 (evaluate freely). Once the budget is spent it returns 0
// only if LOGIN_THROTTLE_INTERVAL has elapsed since the last attempt, so the account is slowed but
// never fully locked. Keyed on username_lc regardless of whether the account exists.
function login_throttle_wait($con,$username){
    $lc=strtolower(trim($username)); if($lc==='')return 0;
    mysqli_query($con,"DELETE FROM vault_login_throttle WHERE ts < (NOW() - INTERVAL 1 HOUR)");
    $s=mysqli_prepare($con,"SELECT COUNT(*) c, TIMESTAMPDIFF(SECOND, MAX(ts), NOW()) since FROM vault_login_throttle WHERE username_lc=? AND ts > (NOW() - INTERVAL 1 HOUR)");
    if(!$s)return 0;
    mysqli_stmt_bind_param($s,'s',$lc);mysqli_stmt_execute($s);$r=mysqli_stmt_get_result($s);$row=$r?mysqli_fetch_assoc($r):null;
    if(!$row||(int)$row['c']<LOGIN_MAX_PER_HOUR)return 0;
    $since=($row['since']===null)?LOGIN_THROTTLE_INTERVAL:(int)$row['since'];
    return ($since>=LOGIN_THROTTLE_INTERVAL)?0:(LOGIN_THROTTLE_INTERVAL-$since);
}
function login_throttle_record($con,$username){
    $lc=strtolower(trim($username)); if($lc==='')return;
    $s=mysqli_prepare($con,"INSERT INTO vault_login_throttle (username_lc,ts) VALUES (?,NOW())");
    if($s){mysqli_stmt_bind_param($s,'s',$lc);mysqli_stmt_execute($s);}
}

// ---- per-account keyword-failure budget (2026-09-08, internal audit L1) ----
// Stored in vault_login_throttle under the key "kw:<uid>". That needs no schema change and cannot
// collide with a real account: username_valid() is /^[A-Za-z0-9_.-]{3,32}$/, so a colon can never
// appear in a username. Rows self-purge after an hour, the same as the sign-in budget.
function kw_throttle_key($uid){ return 'kw:'.(int)$uid; }
function kw_fail_wait($con,$uid){
    if((int)$uid<=0)return 0;
    $k=kw_throttle_key($uid);
    mysqli_query($con,"DELETE FROM vault_login_throttle WHERE ts < (NOW() - INTERVAL 1 HOUR)");
    $s=mysqli_prepare($con,"SELECT COUNT(*) c, TIMESTAMPDIFF(SECOND, MAX(ts), NOW()) since FROM vault_login_throttle WHERE username_lc=? AND ts > (NOW() - INTERVAL 1 HOUR)");
    if(!$s)return 0;
    mysqli_stmt_bind_param($s,'s',$k);mysqli_stmt_execute($s);$r=mysqli_stmt_get_result($s);$row=$r?mysqli_fetch_assoc($r):null;
    if(!$row||(int)$row['c']<KW_MAX_FAILS_PER_HOUR)return 0;
    $since=($row['since']===null)?KW_THROTTLE_INTERVAL:(int)$row['since'];
    return ($since>=KW_THROTTLE_INTERVAL)?0:(KW_THROTTLE_INTERVAL-$since);
}
// Called ONLY when a keyword failed to open something. Never on success.
function kw_fail_record($con,$uid){
    if((int)$uid<=0)return;
    $k=kw_throttle_key($uid);
    $s=mysqli_prepare($con,"INSERT INTO vault_login_throttle (username_lc,ts) VALUES (?,NOW())");
    if($s){mysqli_stmt_bind_param($s,'s',$k);mysqli_stmt_execute($s);}
}
