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

if (function_exists('imagecreatetruecolor') && is_readable($font)) {
    // ---- strong raster (GD + FreeType) — answer is only pixels ----
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
}

// ---- SVG pixel-grid fallback (no extensions; nothing readable as text) ----
$FONT = [
 'A'=>['.###.','#...#','#...#','#...#','#####','#...#','#...#'],
 'B'=>['####.','#...#','#...#','####.','#...#','#...#','####.'],
 'C'=>['.###.','#...#','#....','#....','#....','#...#','.###.'],
 'D'=>['###..','#..#.','#...#','#...#','#...#','#..#.','###..'],
 'E'=>['#####','#....','#....','####.','#....','#....','#####'],
 'F'=>['#####','#....','#....','####.','#....','#....','#....'],
 'G'=>['.###.','#...#','#....','#.###','#...#','#...#','.###.'],
 'H'=>['#...#','#...#','#...#','#####','#...#','#...#','#...#'],
 'J'=>['..###','...#.','...#.','...#.','#..#.','#..#.','.##..'],
 'K'=>['#...#','#..#.','#.#..','##...','#.#..','#..#.','#...#'],
 'L'=>['#....','#....','#....','#....','#....','#....','#####'],
 'M'=>['#...#','##.##','#.#.#','#.#.#','#...#','#...#','#...#'],
 'N'=>['#...#','#...#','##..#','#.#.#','#..##','#...#','#...#'],
 'P'=>['####.','#...#','#...#','####.','#....','#....','#....'],
 'Q'=>['.###.','#...#','#...#','#...#','#.#.#','#..#.','.##.#'],
 'R'=>['####.','#...#','#...#','####.','#.#..','#..#.','#...#'],
 'S'=>['.####','#....','#....','.###.','....#','....#','####.'],
 'T'=>['#####','..#..','..#..','..#..','..#..','..#..','..#..'],
 'U'=>['#...#','#...#','#...#','#...#','#...#','#...#','.###.'],
 'V'=>['#...#','#...#','#...#','#...#','#...#','.#.#.','..#..'],
 'W'=>['#...#','#...#','#...#','#.#.#','#.#.#','#.#.#','.#.#.'],
 'X'=>['#...#','#...#','.#.#.','..#..','.#.#.','#...#','#...#'],
 'Y'=>['#...#','#...#','.#.#.','..#..','..#..','..#..','..#..'],
 'Z'=>['#####','....#','...#.','..#..','.#...','#....','#####'],
 '2'=>['.###.','#...#','....#','...#.','..#..','.#...','#####'],
 '3'=>['#####','...#.','..#..','...#.','....#','#...#','.###.'],
 '4'=>['...#.','..##.','.#.#.','#..#.','#####','...#.','...#.'],
 '5'=>['#####','#....','####.','....#','....#','#...#','.###.'],
 '6'=>['.###.','#....','#....','####.','#...#','#...#','.###.'],
 '7'=>['#####','....#','...#.','..#..','.#...','.#...','.#...'],
 '8'=>['.###.','#...#','#...#','.###.','#...#','#...#','.###.'],
 '9'=>['.###.','#...#','#...#','.####','....#','....#','.###.'],
];

$svg  = '<svg xmlns="http://www.w3.org/2000/svg" width="' . $W . '" height="' . $H . '" viewBox="0 0 ' . $W . ' ' . $H . '">';
$svg .= '<rect width="100%" height="100%" fill="#0c1012"/>';
// background noise
for ($i = 0; $i < 55; $i++)
    $svg .= '<rect x="' . random_int(0, $W) . '" y="' . random_int(0, $H) . '" width="' . (random_int(6, 16) / 10) . '" height="' . (random_int(6, 16) / 10) . '" fill="rgba(120,140,150,.5)"/>';
for ($i = 0; $i < 5; $i++)
    $svg .= '<line x1="' . random_int(0, $W) . '" y1="' . random_int(0, $H) . '" x2="' . random_int(0, $W) . '" y2="' . random_int(0, $H) . '" stroke="rgba(' . random_int(60, 120) . ',' . random_int(120, 180) . ',' . random_int(140, 190) . ',.4)" stroke-width="' . (random_int(8, 16) / 10) . '"/>';
// glyphs as jittered rectangles inside a rotated group (no <text>, so no readable answer)
$cell = 5; $gx = 16;
for ($i = 0; $i < strlen($code); $i++) {
    $rows = $FONT[$code[$i]];
    $rot = random_int(-16, 16);
    $cx = $gx + 2.5 * $cell; $cy = 13 + 3.5 * $cell;
    $col = 'rgb(' . random_int(150, 220) . ',' . random_int(220, 255) . ',' . random_int(190, 232) . ')';
    $svg .= '<g transform="rotate(' . $rot . ' ' . $cx . ' ' . $cy . ')" fill="' . $col . '">';
    for ($r = 0; $r < 7; $r++) for ($c = 0; $c < 5; $c++) {
        if ($rows[$r][$c] !== '#') continue;
        $rx = $gx + $c * $cell + random_int(-1, 1);
        $ry = 13 + $r * $cell + random_int(-1, 1);
        $svg .= '<rect x="' . $rx . '" y="' . $ry . '" width="' . $cell . '" height="' . $cell . '" rx="1"/>';
    }
    $svg .= '</g>';
    $gx += 5 * $cell + 6;
}
$svg .= '</svg>';
header('Content-Type: image/svg+xml');
echo $svg;
