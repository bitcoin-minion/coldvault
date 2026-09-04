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
// Registrations allowed per hour SITE-WIDE. There is no per-address counter
// because no client IP is ever recorded (see the privacy notes in README).
// Accepted trade-off: a sign-up flood can block new registrations for an hour.
define('REG_MAX_PER_HOUR', 5);
// OTP_ISSUER — the label your authenticator app shows — comes from the
// configuration file. See env.php and coldvault.env.example.

// ---- APP_KEY encryption for the stored TOTP secret ----
function ak_encrypt($p){ $n=random_bytes(12);$t='';$c=openssl_encrypt($p,'aes-256-gcm',APP_KEY,OPENSSL_RAW_DATA,$n,$t,'coldvault-auth',16);return $c===false?false:$n.$t.$c; }
function ak_decrypt($b){ if(strlen($b)<28)return false;return openssl_decrypt(substr($b,28),'aes-256-gcm',APP_KEY,OPENSSL_RAW_DATA,substr($b,0,12),substr($b,12,16),'coldvault-auth'); }

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
function user_secret($row){ return ($row&&!empty($row['secret_blob']))?ak_decrypt($row['secret_blob']):false; }
function user_locked($row){ if($row&&!empty($row['lock_until'])&&strtotime($row['lock_until'])>time())return strtotime($row['lock_until'])-time();return 0; }
function user_register($con,$username,$secretRaw,$codes){
    $blob=ak_encrypt($secretRaw);if($blob===false)return false;$lc=strtolower(trim($username));
    $s=mysqli_prepare($con,"INSERT INTO vault_users (username,username_lc,secret_blob,enrolled_at,fail_count) VALUES (?,?,?,NOW(),0)");
    mysqli_stmt_bind_param($s,'sss',$username,$lc,$blob);
    if(!@mysqli_stmt_execute($s))return false;               // UNIQUE race -> false
    $uid=mysqli_insert_id($con);
    $ins=mysqli_prepare($con,"INSERT INTO vault_backup_codes (user_id,code_hash) VALUES (?,?)");
    foreach($codes as $c){$h=bc_hash($c);mysqli_stmt_bind_param($ins,'is',$uid,$h);mysqli_stmt_execute($ins);}
    return $uid;
}
function user_fail($con,$uid){
    mysqli_query($con,"UPDATE vault_users SET fail_count=fail_count+1 WHERE id=".(int)$uid);
    $s=mysqli_prepare($con,"SELECT fail_count FROM vault_users WHERE id=?");mysqli_stmt_bind_param($s,'i',$uid);mysqli_stmt_execute($s);$r=mysqli_stmt_get_result($s);$row=$r?mysqli_fetch_assoc($r):null;
    // 2026-09-03: fail_count is NO LONGER zeroed when the lock is applied. It is now the
    //   durable signal that makes the sign-in form demand a human check after
    //   AUTH_CAPTCHA_AFTER wrong codes, so clearing it every few failures would have
    //   handed an attacker a fresh free run each time round. A successful sign-in still
    //   clears it - see user_success().
    if($row&&(int)$row['fail_count']>=AUTH_MAX_FAILS){$u=date('Y-m-d H:i:s',time()+AUTH_LOCK_SECS);$q=mysqli_prepare($con,"UPDATE vault_users SET lock_until=? WHERE id=?");mysqli_stmt_bind_param($q,'si',$u,$uid);mysqli_stmt_execute($q);}
}
function user_success($con,$uid,$step){ $s=mysqli_prepare($con,"UPDATE vault_users SET fail_count=0,lock_until=NULL,last_step=? WHERE id=?");mysqli_stmt_bind_param($s,'ii',$step,$uid);mysqli_stmt_execute($s); }

// ---- backup codes (per user; hashed with APP_KEY pepper; single-use) ----
function bc_norm($c){ return strtoupper(preg_replace('/[^A-Za-z0-9]/','',$c)); }
function bc_hash($c){ return hash_hmac('sha256',bc_norm($c),APP_KEY); }
function bc_verify_consume($con,$uid,$code){
    $h=bc_hash($code);$s=mysqli_prepare($con,"SELECT id FROM vault_backup_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL LIMIT 1");mysqli_stmt_bind_param($s,'is',$uid,$h);mysqli_stmt_execute($s);$r=mysqli_stmt_get_result($s);$row=$r?mysqli_fetch_assoc($r):null;
    if(!$row)return false;$u=mysqli_prepare($con,"UPDATE vault_backup_codes SET used_at=NOW() WHERE id=?");mysqli_stmt_bind_param($u,'i',$row['id']);mysqli_stmt_execute($u);return true;
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
    if($step!==false&&$step>$last){ user_success($con,$uid,$step); return ''; }
    if(bc_verify_consume($con,$uid,$code)) return '';
    user_fail($con,$uid);
    return 'That code did not match. If you just signed in with this code, wait for the next one - each code works only once. Otherwise use a fresh 6-digit code, or an unused backup code.';
}
// Swap in a new TOTP secret. Only called after the NEW app has proved it produces valid codes.
// 2026-09-03: also bumps secret_version, which ends every OTHER session on its next
//   request. Returns the NEW version (never 0, the column starts at 1) or false, so the
//   caller can re-stamp the session it is running in - otherwise pairing a new
//   authenticator would sign you out of the very device you just used to do it.
function user_set_secret($con,$uid,$secretRaw){
    $blob=ak_encrypt($secretRaw); if($blob===false)return false;
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
// Replace ALL backup codes (used and unused) with a fresh single-use set.
function user_replace_backup_codes($con,$uid,$codes){
    $d=mysqli_prepare($con,"DELETE FROM vault_backup_codes WHERE user_id=?");mysqli_stmt_bind_param($d,'i',$uid);
    if(!mysqli_stmt_execute($d))return false;
    $ins=mysqli_prepare($con,"INSERT INTO vault_backup_codes (user_id,code_hash) VALUES (?,?)");
    foreach($codes as $c){$h=bc_hash($c);mysqli_stmt_bind_param($ins,'is',$uid,$h);if(!mysqli_stmt_execute($ins))return false;}
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
