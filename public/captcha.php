<?php
// public/captcha.php
// 2026-09-04: prepared for public release (MIT). — self-hosted CAPTCHA, no external calls, no plaintext in the source. 2026-09-01
//   Uses GD (distorted PNG) when available; otherwise an SVG drawn as a PIXEL GRID from a
//   built-in 5x7 font — the answer characters are NOT present as text in the markup, so a bot
//   must actually recognise the image (not just parse it). Answer lives only in the session.
require __DIR__ . '/auth.php';
auth_session_start();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

$alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';   // no O/0/I/1
$code = '';
for ($i = 0; $i < 5; $i++) $code .= $alpha[random_int(0, strlen($alpha) - 1)];
$_SESSION['cv_captcha'] = strtolower($code);

$W = 190; $H = 62;
$font = __DIR__ . '/fonts/DejaVuSans-Bold.ttf';


// 2026-09-07 (security review): GD + FreeType is a HARD REQUIREMENT. The previous SVG pixel-grid
// fallback drew the answer as a grid of <rect>s whose coordinates were the glyph bitmap, so it was
// decodable straight from the markup without any OCR - i.e. no CAPTCHA at all. It has been removed.
// (config.php also refuses to start the app if GD is missing, so this should never be hit.)
if (!function_exists('imagecreatetruecolor') || !function_exists('imagettftext') || !is_readable($font)) {
    http_response_code(500);
    header('Content-Type: text/plain');
    exit('CAPTCHA unavailable: this Coldvault instance requires the PHP GD extension (with FreeType) and public/fonts/DejaVuSans-Bold.ttf.');
}

// ---- raster (GD + FreeType) — the answer exists only as pixels ----
header('Content-Type: image/png');
$img = imagecreatetruecolor($W, $H);
imagefilledrectangle($img, 0, 0, $W, $H, imagecolorallocate($img, 12, 16, 18));
for ($i = 0; $i < 700; $i++)
    imagesetpixel($img, random_int(0, $W), random_int(0, $H), imagecolorallocate($img, random_int(28, 70), random_int(28, 70), random_int(30, 72)));
for ($i = 0; $i < 5; $i++)
    imageline($img, random_int(0, $W), random_int(0, $H), random_int(0, $W), random_int(0, $H), imagecolorallocate($img, random_int(40, 90), random_int(90, 150), random_int(120, 185)));
$x = 20;
for ($i = 0; $i < strlen($code); $i++) {
    $col = imagecolorallocate($img, random_int(150, 220), random_int(220, 255), random_int(190, 232));
    imagettftext($img, random_int(22, 28), random_int(-24, 24), $x, random_int(40, 50), $col, $font, $code[$i]);
    $x += 32;
}
imagepng($img);
imagedestroy($img);
exit;
