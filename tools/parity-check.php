<?php
/**
 * tools/parity-check.php — prove every copy of the keyword estimator agrees.
 * 2026-09-08: added after a divergence shipped unnoticed (MIT).
 *
 *   php tools/parity-check.php            full check
 *   php tools/parity-check.php --quick    smaller corpus, skip the generator simulation
 *
 * WHY THIS EXISTS
 *   The keyword entropy floor is enforced by PHP on the server and previewed by a
 *   JavaScript twin in the browser, and `tools/kwcheck.php` is a third copy for auditing
 *   a keyword offline. If they disagree, one of two bad things happens: the meter refuses
 *   what the server would accept (merely annoying), or THE SERVER ACCEPTS WHAT THE METER
 *   REFUSED — a keyword weaker than the floor, which is the one thing the floor exists to
 *   prevent. That is not hypothetical. Two divergences have shipped:
 *
 *     - a separator class where PCRE and JavaScript disagreed on U+FEFF and U+00A0, and
 *     - `strtolower()` versus `toLowerCase()`, which differ on 676 of 1,379 cased
 *       characters, so "ÄÖÜÀÈÌÒÙäöüàèìòù" scored 81 bits on the server and 40 in the
 *       browser and crossed the floor.
 *
 *   Both looked identical when the functions were read side by side. The second was in a
 *   LIBRARY CALL that was spelled the same in both languages and behaved differently. A
 *   text diff cannot catch that; only running both over the same inputs can.
 *
 * WHAT IT CHECKS
 *   1. Every copy returns the same number for every candidate in a generated corpus.
 *   2. No disagreement crosses the acceptance floor (reported separately, because that is
 *      the difference between cosmetic and dangerous).
 *   3. The app's own "Generate strong keyword" output always clears its own floor — the
 *      generator once produced a refused keyword about 1 time in 20,000.
 *
 * PRIVACY
 *   Synthetic candidates only. It never reads, prompts for, or writes a real keyword.
 *   Working files go in a temporary directory and are deleted on exit.
 *
 * REQUIREMENTS
 *   PHP with mbstring (the estimator needs it). `node` is optional: without it the PHP
 *   copies are still compared and the JavaScript twin is reported as UNCHECKED — never
 *   silently skipped, because an unchecked twin is exactly how the last one shipped.
 */

if (PHP_SAPI !== 'cli') {
    if (!headers_sent()) { header('HTTP/1.1 403 Forbidden'); }
    exit("parity-check.php is a command-line tool and refuses to run over the web.\n");
}
if (!function_exists('mb_strtolower')) {
    fwrite(STDERR, "This PHP build has no mbstring extension; the estimator needs it.\n");
    exit(1);
}

$QUICK = in_array('--quick', array_slice($argv, 1), true);
foreach (array_slice($argv, 1) as $a) {
    if ($a !== '--quick') { fwrite(STDERR, "Usage: php tools/parity-check.php [--quick]\n"); exit(2); }
}

$ROOT = dirname(__DIR__);
$APP  = $ROOT . '/public/index.php';
$KW   = $ROOT . '/tools/kwcheck.php';
$WORDS= $ROOT . '/public/words.js';
foreach ([$APP, $KW] as $f) if (!is_readable($f)) { fwrite(STDERR, "Cannot read $f\n"); exit(1); }

/* ---------------------------------------------------------------------------
 * Extraction. By MARKER, never by line number: line numbers go stale the moment
 * anything above them is edited, and a stale range fails as a confusing PHP fatal
 * with no message rather than as "the marker moved". Every miss is fatal here.
 * ------------------------------------------------------------------------- */
function slice_between($src, $startMarker, $endAfter, $what) {
    $i = strpos($src, $startMarker);
    if ($i === false) { fwrite(STDERR, "PARITY HARNESS BROKEN: start marker for $what not found ($startMarker).\nThe estimator moved or was renamed; fix this harness before trusting any result.\n"); exit(3); }
    $j = strpos($src, $endAfter, $i);
    if ($j === false) { fwrite(STDERR, "PARITY HARNESS BROKEN: end marker for $what not found ($endAfter).\n"); exit(3); }
    return substr($src, $i, $j - $i + strlen($endAfter));
}
/** a PHP function body, brace-matched from its signature */
function slice_function($src, $fn, $what) {
    $p = strpos($src, "\nfunction $fn(");
    if ($p === false) { fwrite(STDERR, "PARITY HARNESS BROKEN: function $fn not found in $what.\n"); exit(3); }
    $b = strpos($src, '{', $p); $d = 0; $n = strlen($src);
    for ($k = $b; $k < $n; $k++) {
        if ($src[$k] === '{') $d++;
        elseif ($src[$k] === '}') { $d--; if ($d === 0) return substr($src, $p, $k - $p + 1); }
    }
    fwrite(STDERR, "PARITY HARNESS BROKEN: unbalanced braces reading $fn from $what.\n"); exit(3);
}

$appSrc = file_get_contents($APP);
$kwSrc  = file_get_contents($KW);

/** from a marker up to (not including) a later one, plus a named function appended */
function slice_head_plus_fn($src, $startMarker, $stopBefore, $fn, $what) {
    $i = strpos($src, $startMarker);
    if ($i === false) { fwrite(STDERR, "PARITY HARNESS BROKEN: start marker for $what not found ($startMarker).\nThe estimator moved or was renamed; fix this harness before trusting any result.\n"); exit(3); }
    $j = strpos($src, $stopBefore, $i);
    if ($j === false) { fwrite(STDERR, "PARITY HARNESS BROKEN: $stopBefore not found after the start of $what.\n"); exit(3); }
    return substr($src, $i, $j - $i) . slice_function($src, $fn, $what);
}

// server PHP: the constants through the end of cv_entropy()
$estApp = slice_head_plus_fn($appSrc, 'const CV_KW_BLOCK', "\nfunction cv_entropy(", 'cv_entropy', 'the app estimator');
// the browser twin, out of its nowdoc
$twin   = slice_between($appSrc, "<<<'CVJS'", "\nCVJS;", 'the browser twin');
$twin   = substr($twin, strpos($twin, "\n") + 1);
$twin   = substr($twin, 0, strrpos($twin, "\nCVJS;"));
// kwcheck: its own constants through its cv_entropy()
$estKw  = slice_head_plus_fn($kwSrc, 'const CV_KW_BLOCK', "\nfunction cv_entropy(", 'cv_entropy', 'kwcheck');

/* the acceptance floor, read from where it actually lives rather than hardcoded */
$FLOOR = 65;
if (preg_match("/define\('MIN_KEYSLOT_BITS',\s*(\d+)\)/", @file_get_contents($ROOT.'/public/config.php') ?: '', $m)) $FLOOR = (int)$m[1];
if (preg_match("/define\('CV_MIN_BITS',\s*(\d+)\)/", $kwSrc, $m) && (int)$m[1] !== $FLOOR) {
    printf("  !! FLOOR MISMATCH: config.php says %d, kwcheck says %d. Those must agree.\n", $FLOOR, (int)$m[1]);
    $floorMismatch = true;
}

/* ---------------------------------------------------------------------------
 * The corpus. Deterministic, so two runs on two machines compare like for like.
 * Weighted towards the shapes that have actually broken: Unicode separators,
 * cased non-ASCII, affix families, counters, repeats, and random strings.
 * ------------------------------------------------------------------------- */
function build_corpus($quick) {
    $c = [];
    foreach (['wolf-echo-tango-delta-bravo-lima-kilo-73$','Tr0ub4dor&3','password','abc-def-ghi',
              'Password123!','qwertyuiop123!','bus-hip-guard-net-retire-express',
              'correct-horse-battery-staple','Fluffy2019','xK7$mQ9!zR2#pL4',
              'aaa-aaa-aaa-aaa-aaa-aaa','aaaaaaaaaaaaaaaaaaaaaaaa','ab-ab-ab-ab-ab-ab-ab-ab-ab-ab',
              'MyPassword2026','Summer2026!Winter','seedphrasebackup','aaa-bbb-ccc-ddd-eee-fff',
              'bcd-cde-def-efg-fgh-ghi','aab-aac-aad-aae-aaf-aag','baa-caa-daa-eaa-faa-gaa',
              'zzz zzz1 zzz2 zzz3 zzz4 zzz5','1zzz 2zzz 3zzz 4zzz 5zzz','123456-123456-123456',
              'one-two-three-four-five-six','red-orange-yellow-green-blue-indigo'] as $s) $c[] = $s;
    // separators: the class that diverged once already
    foreach (["\u{00A0}","\u{3000}","\u{FEFF}","\u{2007}","\u{202F}","\u{2009}"," ","\t","\u{2028}"] as $sp) {
        $c[] = "q{$sp}19{$sp}19{$sp}cedar{$sp}zebra{$sp}7";
        $c[] = "alpha{$sp}bravo{$sp}charlie{$sp}delta{$sp}echo";
        $c[] = "a{$sp}b{$sp}c";
    }
    // cased non-ASCII: the class that diverged the second time
    foreach ([[0xC0,0xDE],[0x100,0x17F],[0x386,0x3FF],[0x400,0x44F],[0x1E00,0x1E3F]] as $r) {
        $up=''; $lo='';
        for ($cp=$r[0]; $cp<min($r[0]+8,$r[1]); $cp++) { $ch=mb_chr($cp,'UTF-8'); $up.=$ch; $lo.=mb_strtolower($ch,'UTF-8'); }
        $c[]=$up.$lo; $c[]=$up; $c[]=$lo; $c[]=$up.'-'.$lo.'-77!';
    }
    foreach (['a','z','q','m'] as $ch) for ($n=1;$n<=8;$n++) $c[] = str_repeat($ch,$n);
    foreach (['abc','bcd','xyz','zyx','fed','abcdef','qwerty','asdfgh','123456','098765'] as $r) {
        $c[]=$r; $c[]=strtoupper($r); $c[]="$r-$r-$r";
    }
    foreach (['aa','zz','pre','xy'] as $p) {
        $t=[]; for($i=0;$i<6;$i++) $t[]=$p.chr(98+$i); $c[]=implode('-',$t);
        $t2=[]; for($i=0;$i<6;$i++) $t2[]=$p.$i;      $c[]=implode(' ',$t2);
        $t3=[]; for($i=0;$i<6;$i++) $t3[]=chr(98+$i).$p; $c[]=implode('-',$t3);
    }
    $w=['cedar','zebra','wolf','echo','tango','delta','bravo','lima','kilo','ebb','abbey','otter','ridge','amber','flint','quartz'];
    $hi = $quick ? 5 : 8;
    for ($n=3;$n<=$hi;$n++) for ($k=0;$k<($quick?2:6);$k++) {
        $pick=[]; for($i=0;$i<$n;$i++) $pick[]=$w[($k*3+$i*5)%count($w)];
        $c[]=implode('-',$pick); $c[]=implode(' ',$pick); $c[]=implode('',$pick);
        $c[]=implode('-',$pick).'-'.(70+$k).'$';
    }
    $sets=['abcdefghijklmnopqrstuvwxyz',
           'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
           'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?',
           '0123456789'];
    mt_srand(20260908);                                  // fixed seed: comparable across machines
    foreach ($sets as $s) for ($len=4;$len<=($quick?12:24);$len+=2) for ($k=0;$k<($quick?1:3);$k++) {
        $o=''; for($i=0;$i<$len;$i++) $o.=$s[mt_rand(0,strlen($s)-1)]; $c[]=$o;
    }
    foreach (['Tr0ub4dor','P@ssw0rd','S3cur1ty','B1tc01n','h0rs3'] as $l)
        foreach (['','!','2019','&3','2026!'] as $sx) $c[]=$l.$sx;
    foreach (['','a','ab','é','café-noir-table-chaise','日本語のパスワード','🔐🔑🗝️','a🔐b🔑c','naïve-café-über'] as $m) $c[]=$m;
    return array_values(array_unique($c));
}

/* ---------------------------------------------------------------------------
 * Run each copy in its OWN process. Two PHP copies declare the same function
 * names, so they cannot share one.
 * ------------------------------------------------------------------------- */
$tmp = rtrim(sys_get_temp_dir(), '/') . '/cv-parity-' . bin2hex(random_bytes(6));
if (!@mkdir($tmp, 0700)) { fwrite(STDERR, "Could not create $tmp\n"); exit(1); }
register_shutdown_function(function () use ($tmp) {
    foreach (glob("$tmp/*") ?: [] as $f) @unlink($f);
    @rmdir($tmp);
});

$corpus = build_corpus($QUICK);
file_put_contents("$tmp/corpus.json", json_encode($corpus, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
file_put_contents("$tmp/app.inc", "<?php\n".$estApp);
file_put_contents("$tmp/kw.inc",  "<?php\n".$estKw);
file_put_contents("$tmp/twin.js", $twin);
file_put_contents("$tmp/drv.php",
    "<?php require \$argv[1];\n".
    "\$c=json_decode(file_get_contents(__DIR__.'/corpus.json'),true);\$o=[];\n".
    "foreach(\$c as \$i=>\$s)\$o[\$i]=cv_entropy(\$s);\n".
    "file_put_contents(\$argv[2],json_encode(\$o));\n");
file_put_contents("$tmp/drv.js",
    "const fs=require('fs'),p=require('path');\n".
    "eval(fs.readFileSync(p.join(__dirname,'twin.js'),'utf8'));\n".
    "const c=JSON.parse(fs.readFileSync(p.join(__dirname,'corpus.json'),'utf8'));\n".
    "const o={};c.forEach((s,i)=>{o[i]=cvEntropy(s);});\n".
    "fs.writeFileSync(p.join(__dirname,'js.json'),JSON.stringify(o));\n");

$php = PHP_BINARY;
printf("\n  Coldvault estimator parity check\n  %d candidates, floor %d bits, php %s\n\n", count($corpus), $FLOOR, PHP_VERSION);

$scores = [];
foreach ([['app','app.inc'],['kwcheck','kw.inc']] as $job) {
    $out = "$tmp/{$job[0]}.json";
    exec(escapeshellarg($php).' '.escapeshellarg("$tmp/drv.php").' '.escapeshellarg("$tmp/{$job[1]}").' '.escapeshellarg($out).' 2>&1', $o, $rc);
    if ($rc !== 0 || !is_readable($out)) {
        printf("  %-9s FAILED TO RUN (exit %d): %s\n", $job[0], $rc, trim(implode("\n", $o)) ?: '(no output — the extract is probably empty or truncated)');
        printf("  %-9s extract was %d bytes; first line: %s\n", '', filesize("$tmp/{$job[1]}"), trim(strtok(file_get_contents("$tmp/{$job[1]}"), "\n")));
        exit(4);
    }
    $scores[$job[0]] = json_decode(file_get_contents($out), true);
    printf("  %-9s scored %d\n", $job[0], count($scores[$job[0]]));
}

$node = null;
foreach (['node','nodejs'] as $cand) { exec(escapeshellarg($cand).' --version 2>/dev/null', $o2, $rc2); if ($rc2 === 0) { $node = $cand; break; } }
if ($node !== null) {
    exec(escapeshellarg($node).' '.escapeshellarg("$tmp/drv.js").' 2>&1', $o3, $rc3);
    if ($rc3 === 0 && is_readable("$tmp/js.json")) {
        $raw = json_decode(file_get_contents("$tmp/js.json"), true);
        $scores['browser'] = []; foreach ($raw as $i => $v) $scores['browser'][(int)$i] = $v;
        printf("  %-9s scored %d  (via %s)\n", 'browser', count($scores['browser']), $node);
    } else {
        printf("  %-9s FAILED TO RUN: %s\n", 'browser', implode(' ', $o3)); $jsUnchecked = true;
    }
} else { $jsUnchecked = true; }

if (!empty($jsUnchecked)) {
    print("\n  !! THE BROWSER TWIN WAS NOT CHECKED — node is not available here.\n"
        . "     The PHP copies below are still compared, but the twin is the half that has\n"
        . "     diverged before. Install node and re-run before trusting this result.\n");
}

/* ---- compare every pair ---- */
$names = array_keys($scores); $problems = 0; $dangerous = 0;
echo "\n";
for ($a = 0; $a < count($names); $a++) for ($b = $a+1; $b < count($names); $b++) {
    $A = $names[$a]; $B = $names[$b]; $diff = 0; $cross = 0; $shown = 0;
    foreach ($scores[$A] as $i => $v) {
        $w = $scores[$B][$i] ?? null;
        if ($v === $w) continue;
        $diff++;
        $crosses = (($v >= $FLOOR) !== ($w >= $FLOOR));
        if ($crosses) $cross++;
        if ($shown < 6) { printf("      %-34s %s=%d %s=%d%s\n", var_export($corpus[$i], true), $A, $v, $B, $w, $crosses ? '   <-- CROSSES THE FLOOR' : ''); $shown++; }
    }
    printf("  %-9s vs %-9s %d disagreement(s), %d crossing the floor%s\n", $A, $B, $diff, $cross, $diff ? '' : '   ok');
    $problems += $diff; $dangerous += $cross;
}

/* ---- the generator must clear its own floor ---- */
if (!$QUICK && is_readable($WORDS)) {
    $js = file_get_contents($WORDS);
    if (preg_match('/\[(.*)\]/s', $js, $m)) {
        $W = json_decode('['.$m[1].']', true);
        if (is_array($W) && count($W) > 100) {
            file_put_contents("$tmp/gen.php",
                "<?php require __DIR__.'/app.inc';\n".
                "\$W=json_decode(file_get_contents(__DIR__.'/words.json'),true);\n".
                "\$sy=str_split('!@#\$%^&*?_+=');mt_srand(20260908);\n".
                "\$min=9999;\$below=0;\$worst='';\$N=20000;\n".
                "for(\$i=0;\$i<\$N;\$i++){\$p=[];\$g=0;\n".
                "  while(count(\$p)<7&&\$g<280){\$w=\$W[mt_rand(0,count(\$W)-1)];if(!in_array(\$w,\$p,true))\$p[]=\$w;\$g++;}\n".
                "  \$kw=implode('-',\$p).'-'.(10+mt_rand(0,89)).\$sy[mt_rand(0,count(\$sy)-1)];\n".
                "  \$b=cv_entropy(\$kw);if(\$b<\$min){\$min=\$b;\$worst=\$kw;}if(\$b<".$FLOOR.")\$below++;}\n".
                "echo json_encode(['min'=>\$min,'below'=>\$below,'n'=>\$N,'worst'=>\$worst]);\n");
            file_put_contents("$tmp/words.json", json_encode($W));
            exec(escapeshellarg($php).' '.escapeshellarg("$tmp/gen.php").' 2>&1', $o4, $rc4);
            $g = ($rc4 === 0) ? json_decode(implode('', $o4), true) : null;
            if (is_array($g)) {
                printf("\n  generator: %d outputs, minimum %d bits, %d below the %d-bit floor%s\n",
                       $g['n'], $g['min'], $g['below'], $FLOOR, $g['below'] ? '' : '   ok');
                if ($g['below']) { printf("      worst: %s\n      The Generate button can hand a user a keyword the app then refuses.\n", $g['worst']); $problems++; $dangerous++; }
            } else { printf("\n  generator: could not be simulated (%s)\n", implode(' ', $o4)); }
        }
    }
}

/* ---- verdict ---- */
echo "\n";
if (!empty($floorMismatch)) { print("  FAIL: the acceptance floor differs between copies.\n\n"); exit(1); }
if ($dangerous > 0) { printf("  FAIL: %d floor-crossing disagreement(s), counted across every pair — so one\n        broken copy shows up in each pair it belongs to. The server may accept a\n        keyword the meter refused. Do not ship this.\n\n", $dangerous); exit(1); }
if ($problems > 0)  { printf("  FAIL: %d disagreement(s) across every pair. None crosses the floor, so it is\n        cosmetic today — but the copies have drifted and the next edit may not be\n        so lucky.\n\n", $problems); exit(1); }
if (!empty($jsUnchecked)) { print("  INCOMPLETE: the PHP copies agree, but the browser twin was not checked.\n\n"); exit(1); }
print("  PASS: every copy agrees on every candidate, and the generator clears its own floor.\n\n");
exit(0);
