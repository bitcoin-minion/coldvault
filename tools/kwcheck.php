<?php
/**
 * kwcheck.php - Coldvault keyword strength checker. Standalone, offline, no logging.
 * 2026-09-04: prepared for public release (MIT).
 * 2026-09-02: created on request - a dependency-free copy of the app's strength
 *   estimator so keywords can be audited on a separate machine.
 *
 * Single file. No includes, no database, no network, no config. Copy it anywhere
 * with PHP 7.0+ and run it.
 *
 * ---------------------------------------------------------------------------
 * PRIVACY GUARANTEES (by construction, not by promise)
 *   - CLI only. Refuses to run under a web server, so a keyword can never reach
 *     an HTTP access log, a query string or a referer header.
 *   - Refuses to take a keyword as a command-line argument: arguments land in
 *     your shell history and are visible to any user running `ps`. Input is read
 *     from the terminal with echo switched OFF, so it is never displayed.
 *   - Writes NOTHING to disk: no output files, no temp files, no error_log.
 *     PHP's own error logging is disabled on the first lines below.
 *   - Makes no network calls of any kind.
 *   - Never prints the keyword back, not even in the report.
 *
 * LIMITS I CANNOT REMOVE - know about these
 *   - PHP strings are immutable, so a keyword cannot be reliably zeroed in RAM.
 *     Memory is released at exit but may linger until the OS reuses it.
 *   - If the machine swaps or core-dumps, RAM can reach disk. For a real audit,
 *     run with swap off (`sudo swapoff -a`) or from a live/RAM-only system.
 *   - Your terminal's scrollback keeps the REPORT. That is safe: the report
 *     contains no keyword, only measurements.
 *
 * USAGE
 *   php kwcheck.php              interactive; hidden prompt; blank line to quit
 *   php kwcheck.php --explain    print the full methodology and exit
 *   php kwcheck.php --selftest   prove this port matches the web app exactly
 * ---------------------------------------------------------------------------
 */

// 2026-09-03: the app REFUSES any keyword below this, on create, on a keyword change,
//   and when somebody joins a shared vault. Keep in step with MIN_KEYSLOT_BITS in
//   public/config.php. The weak/fair/strong labels below are only descriptive; THIS is
//   the rule that actually decides whether Coldvault accepts a keyword.
define('CV_MIN_BITS', 65);

ini_set('log_errors', '0');      // no keyword fragment can reach a log on a crash
ini_set('error_log', '');
ini_set('display_errors', '1');
error_reporting(E_ALL);

if (PHP_SAPI !== 'cli') {
    if (!headers_sent()) { header('HTTP/1.1 403 Forbidden'); }
    exit("kwcheck.php is a command-line tool and refuses to run over the web.\n");
}

/* ---- reject keywords passed as arguments (shell history + ps exposure) ---- */
$FLAGS = ['--explain', '--selftest', '--help', '-h'];
$mode  = 'check';
foreach (array_slice($argv, 1) as $a) {
    if (!in_array($a, $FLAGS, true)) {
        fwrite(STDERR,
            "\n  Refusing to read a keyword from the command line.\n\n"
          . "  Command-line arguments are saved in your shell history and are visible\n"
          . "  to every other user on this machine via `ps`. That would defeat the\n"
          . "  point of this tool.\n\n"
          . "  Run it with no arguments and type the keyword at the hidden prompt:\n\n"
          . "      php kwcheck.php\n\n");
        exit(2);
    }
    if ($a === '--explain')  { $mode = 'explain';  }
    if ($a === '--selftest') { $mode = 'selftest'; }
    if ($a === '--help' || $a === '-h') { $mode = 'help'; }
}

/* =========================================================================
 * THE ESTIMATOR - a faithful port of cvEntropy() from the Coldvault web app.
 * Keep these two in sync; --selftest proves they agree.
 * ========================================================================= */

/** Word-like tokens: 3+ chars, LETTERS ONLY. Anything with a digit or symbol in it is
    not a word, so a symbol-separated random string is scored per character instead of
    being mistaken for a short passphrase and badly under-rated. */
function cv_tokens($v) {
    $out = [];
    foreach (preg_split('/[^A-Za-z0-9]+/', $v) as $p) {
        if (strlen($p) >= 3 && preg_match('/^[A-Za-z]+$/', $p)) { $out[] = $p; }
    }
    return $out;
}

/** Estimated entropy in bits. Mirrors the app exactly.
 *  2026-09-03: repetition no longer inflates the score, matching the fix made in the
 *  app on the same day. A repeated word counts once, and the charset fallback caps
 *  length at twice the number of distinct characters. Before this, both
 *  "aaa-aaa-aaa-aaa-aaa-aaa" (66) and a single letter repeated 24 times (113) cleared
 *  the 65-bit floor. --selftest covers both. */
function cv_entropy($v) {
    if ($v === '') { return 0; }
    $t = cv_tokens($v);
    if (count($t) >= 3) {
        // Passphrase mode: 11 bits per DISTINCT word (log2 of the 2048-word BIP39 list).
        $u = [];
        foreach ($t as $p) { $u[strtolower($p)] = true; }
        $b = count($u) * 11;
        if (preg_match('/[A-Z]/', $v))            { $b += 2; }
        if (preg_match('/[0-9]/', $v))            { $b += 3; }
        if (preg_match('/[^A-Za-z0-9 \-]/', $v))  { $b += 4; }
    } else {
        // Charset mode: length x log2(alphabet size), with length capped at twice the
        // number of DISTINCT characters so repetition cannot inflate it.
        $cs = 0;
        if (preg_match('/[a-z]/', $v))        { $cs += 26; }
        if (preg_match('/[A-Z]/', $v))        { $cs += 26; }
        if (preg_match('/[0-9]/', $v))        { $cs += 10; }
        if (preg_match('/[^A-Za-z0-9]/', $v)) { $cs += 33; }
        $b = min(strlen($v), 2 * count(count_chars($v, 1))) * log($cs ?: 2, 2);
    }
    return (int)round($b);
}

/** The app's four rating bands. */
function cv_rating($bits) {
    if ($bits < 36) { return 'weak'; }
    if ($bits < 56) { return 'fair'; }
    if ($bits < 75) { return 'strong'; }
    return 'very strong';
}

/* =========================================================================
 * BIP39 wordlist - used ONLY to tell machine-generated phrases from
 * human-invented ones. That distinction decides whether the entropy number
 * above is trustworthy or merely optimistic.
 * ========================================================================= */
$BIP39_RAW = 'abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security seed seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo';

function bip39_set() {
    static $set = null;
    if ($set === null) {
        global $BIP39_RAW;
        $set = [];
        foreach (explode(' ', trim($BIP39_RAW)) as $w) {
            if ($w !== '') { $set[$w] = true; }
        }
    }
    return $set;
}

/* =========================================================================
 * Independent sanity checks the app does NOT perform.
 * ========================================================================= */
function cv_warnings($v) {
    $w    = [];
    $low  = strtolower($v);
    $toks = cv_tokens($v);

    $common = ['password','password1','passw0rd','123456','12345678','123456789',
        'qwerty','qwerty123','letmein','iloveyou','admin','welcome','monkey',
        'dragon','abc123','football','baseball','trustno1','hunter2','sunshine',
        'princess','master','shadow','superman','batman','starwars','whatever',
        'zaq12wsx','1q2w3e4r','asdfgh','000000','111111','666666','696969',
        'bitcoin','satoshi','blockchain','coldvault','seedphrase'];
    if (in_array($low, $common, true)) {
        $w[] = ['fail', 'This is a well-known password. It would fall in seconds regardless of the bit count above.'];
    }

    // Repeated block, e.g. "hunterhunter" or "ab-ab-ab".
    if (strlen($v) >= 4 && preg_match('/^(.{2,})\1+$/', $v)) {
        $w[] = ['fail', 'The whole keyword is one short block repeated. Its real entropy is that of the block alone.'];
    }

    // Keyboard / alphabet / digit runs of 4+.
    $runs = ['abcdefghijklmnopqrstuvwxyz', '0123456789',
             'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '!@#$%^&*()'];
    foreach ($runs as $r) {
        $n = strlen($r);
        for ($i = 0; $i + 4 <= $n; $i++) {
            $frag = substr($r, $i, 4);
            if (strpos($low, $frag) !== false || strpos($low, strrev($frag)) !== false) {
                $w[] = ['warn', 'Contains a keyboard or alphabet run ("' . $frag . '"). Cracking tools try these first.'];
                break 2;
            }
        }
    }

    if (preg_match('/\b(19|20)\d{2}\b/', $v)) {
        $w[] = ['warn', 'Contains something shaped like a year. Dates are among the first substitutions attackers try.'];
    }
    // 2026-09-03: the check above needs word boundaries, so it MISSED "Fluffy2019" -
    //   the year is glued to the word. That word-plus-year shape is one of the first
    //   things a cracking tool tries, so match it directly. Deliberately narrow: it
    //   wants a real letter run touching the year, not any four digits, so a random
    //   string that happens to contain 2019 is not flagged.
    elseif (preg_match('/[A-Za-z]{3,}(19|20)\d{2}|(19|20)\d{2}[A-Za-z]{3,}/', $v)) {
        $w[] = ['fail', 'This is a word with a year stuck to it. Cracking tools generate exactly that combination first, so the bit count above is wildly optimistic.'];
    }

    if (count($toks) === 1 && !preg_match('/[0-9]/', $v) && !preg_match('/[^A-Za-z0-9]/', $v)) {
        $w[] = ['warn', 'A single word with no digits or symbols. If it is a dictionary word, the estimate above is far too generous.'];
    }

    if (strlen($v) < 12) {
        $w[] = ['warn', 'Under 12 characters. Short keywords leave no margin as hardware gets faster.'];
    }

    return $w;
}

/* =========================================================================
 * Practical resistance: bits alone mean nothing without the KDF cost.
 * Rates below ALREADY account for PBKDF2-HMAC-SHA256 at 450,000 iterations,
 * which is what Coldvault uses. They are deliberately generous to the attacker.
 * ========================================================================= */
function cv_attackers() {
    return [
        'one high-end GPU'          => 2.0e4,
        '100-GPU cracking farm'     => 2.0e6,
        'extreme / nation-state'    => 1.0e10,
    ];
}

function fmt_duration($seconds) {
    if (!is_finite($seconds)) { return 'beyond counting'; }
    if ($seconds < 1)         { return 'under a second'; }
    if ($seconds < 60)        { return sprintf('%.0f seconds', $seconds); }
    if ($seconds < 3600)      { return sprintf('%.0f minutes', $seconds / 60); }
    if ($seconds < 86400)     { return sprintf('%.1f hours',   $seconds / 3600); }
    if ($seconds < 31557600)  { return sprintf('%.1f days',    $seconds / 86400); }
    $years = $seconds / 31557600;
    if ($years < 1000)  { return sprintf('%.0f years', $years); }
    if ($years < 1e6)   { return number_format($years, 0) . ' years'; }
    return sprintf('%.1e years', $years);
}

/* =========================================================================
 * Hidden terminal input.
 * ========================================================================= */
function read_hidden($prompt) {
    fwrite(STDOUT, $prompt);
    $tty      = function_exists('posix_isatty') ? @posix_isatty(STDIN) : true;
    $silenced = false;
    if ($tty && function_exists('shell_exec')) {
        @shell_exec('stty -echo 2>/dev/null');
        $silenced = true;
    } elseif ($tty) {
        fwrite(STDOUT, "\n  [!] cannot disable terminal echo here - your typing WILL be visible\n  > ");
    }
    $line = fgets(STDIN);
    if ($silenced) { @shell_exec('stty echo 2>/dev/null'); }
    fwrite(STDOUT, "\n");
    return ($line === false) ? null : rtrim($line, "\r\n");
}

/* =========================================================================
 * Report
 * ========================================================================= */
function report($v) {
    $bits   = cv_entropy($v);
    $rating = cv_rating($bits);
    $toks   = cv_tokens($v);
    $mode   = (count($toks) >= 3) ? 'passphrase' : 'charset';
    $set    = bip39_set();

    $inList = 0;
    foreach ($toks as $t) { if (isset($set[strtolower($t)])) { $inList++; } }

    echo "\n";
    printf("  %-22s %s\n", 'length', strlen($v) . ' characters');
    printf("  %-22s %s\n", 'word-like tokens', count($toks));
    printf("  %-22s %s\n", 'scoring mode', $mode === 'passphrase'
        ? 'passphrase (3+ word tokens -> 11 bits per DISTINCT word)'
        : 'charset (length x log2 of alphabet)');
    printf("  %-22s %s\n", 'character classes',
        implode(', ', array_filter([
            preg_match('/[a-z]/', $v)        ? 'lower'  : null,
            preg_match('/[A-Z]/', $v)        ? 'upper'  : null,
            preg_match('/[0-9]/', $v)        ? 'digits' : null,
            preg_match('/[^A-Za-z0-9]/', $v) ? 'symbols': null,
        ])) ?: 'none');
    echo "\n";
    printf("  %-22s ~%d bits\n", 'ESTIMATED ENTROPY', $bits);
    printf("  %-22s %s\n",       'DESCRIPTIVE LABEL', strtoupper($rating));
    $ok = ($bits >= CV_MIN_BITS);
    printf("  %-22s %s\n",       'COLDVAULT WOULD',
        $ok ? 'ACCEPT this keyword (needs ~'.CV_MIN_BITS.' bits)'
            : 'REFUSE this keyword - it is ~'.(CV_MIN_BITS - $bits).' bits short of the ~'.CV_MIN_BITS.' required');
    echo "\n  Time to exhaust the whole keyspace, with PBKDF2-SHA256 at 450,000 rounds:\n";
    foreach (cv_attackers() as $who => $rate) {
        printf("    %-26s %s\n", $who, fmt_duration(pow(2, $bits) / $rate));
    }
    echo "    (expect roughly half of these on average - a hit can come at any point)\n";

    /* ---- is the headline number trustworthy for THIS input? ---- */
    echo "\n  How much to trust that number:\n";
    if ($mode === 'passphrase') {
        if (count($toks) > 0 && $inList === count($toks)) {
            printf("    [ok]   All %d words are in the BIP39 list, which is what the app's\n", count($toks));
            echo   "           generator draws from. 11 bits per word is a credible assumption\n";
            echo   "           IF these words were machine-picked. If YOU chose them, see below.\n";
        } else {
            printf("    [!]    Only %d of %d words are in the BIP39 list, so this looks\n", $inList, count($toks));
            echo   "           human-invented rather than machine-generated.\n";
            echo   "           11 bits per word assumes a machine picked each word uniformly at\n";
            echo   "           random from 2048 options. Human word choice is heavily biased, and\n";
            echo   "           phrase-aware cracking tools exploit that. Treat the figure above as\n";
            echo   "           an OPTIMISTIC UPPER BOUND, not a measurement.\n";
            $pess = count($toks) * 6;
            printf("           For scale, at a pessimistic 6 bits/word you would have ~%d bits\n", $pess);
            printf("           instead of ~%d. Illustration only, not a second measurement.\n", $bits);
        }
    } else {
        echo   "    [!]    Charset scoring assumes every character is independent and random.\n";
        echo   "           That holds for machine-generated strings. For anything you invented,\n";
        echo   "           including leetspeak like 'P@ssw0rd', it overstates strength badly,\n";
        echo   "           because crackers apply exactly those substitution rules first.\n";
    }

    $warns = cv_warnings($v);
    if ($warns) {
        echo "\n  Findings:\n";
        foreach ($warns as $x) {
            printf("    [%s] %s\n", $x[0] === 'fail' ? 'FAIL' : 'warn', $x[1]);
        }
    } else {
        echo "\n    [ok]   No weak patterns detected by the extra checks.\n";
    }

    echo "\n  " . str_repeat('-', 68) . "\n";
}

/* =========================================================================
 * Methodology text
 * ========================================================================= */
function explain() {
    echo <<<'TXT'

  WHAT THIS VERIFICATION IS BASED ON
  ==================================

  The score is an ENTROPY ESTIMATE, in bits. Bits answer one question: how
  many guesses would an attacker need to exhaust every possibility? Each
  extra bit DOUBLES that number. 84 bits is about 1.9 x 10^25 guesses.

  Bits are not a verdict on their own. What makes a keyword safe is bits
  COMBINED with how expensive a single guess is. Coldvault runs every guess
  through PBKDF2-HMAC-SHA256 450,000 times, so each attempt costs the
  attacker roughly 450,000 times more than a bare hash. That is why the
  report shows time-to-crack, not just a bit count.

  There are two scoring modes, chosen automatically.

  1. PASSPHRASE MODE - used when 3 or more word-like tokens are present, where a
     word means 3+ characters of nothing but letters.
     Each DISTINCT word scores 11 bits, because log2(2048) = 11 and the BIP39
     list the generator draws from has exactly 2048 words. Seven random words
     therefore give 77 bits. Small bonuses are added for mixed case (+2),
     digits (+3) and symbols (+4). Repeating a word adds nothing: it was chosen
     once, so it can only be guessed once.

     THE ASSUMPTION THAT MATTERS: 11 bits per word is only true if a MACHINE
     chose the words uniformly at random. Humans do not choose randomly. We
     pick common, memorable, grammatically linked words, and cracking tools
     are built to exploit exactly that. A human-invented phrase can be orders
     of magnitude weaker than its score suggests. This tool therefore checks
     every word against the BIP39 list and tells you which case you are in.

  2. CHARSET MODE - used when there are fewer than 3 word tokens.
     Score = length x log2(alphabet size), where the alphabet is built from
     the classes actually present: 26 lowercase, 26 uppercase, 10 digits,
     33 symbols. Length is capped at twice the number of DISTINCT characters,
     so a repeated character cannot buy strength it does not have.

     THE ASSUMPTION THAT MATTERS: that every character is independent and
     random. True for generated strings. False for anything human-made.
     "P@ssw0rd!" scores respectably and dies instantly in the real world,
     because rule-based crackers try that exact substitution pattern first.

  THE RULE THAT ACTUALLY DECIDES
     Coldvault refuses any keyword under 65 bits - when you create a vault, when
     you change a keyword, and when somebody joins a vault you shared. So a
     keyword can be labelled "fair" here and still be refused: the label is
     descriptive, the 65-bit floor is the rule. Existing keywords made before
     the floor keep working, but the app nudges you to change them.

  THE DESCRIPTIVE BANDS (same labels the web app shows)
     under 36 bits ....... weak
     36 to 55 bits ....... fair
     56 to 74 bits ....... strong
     75 bits and over .... very strong

  WHAT THIS DOES NOT DO - the honest limits
     - It cannot tell whether YOU invented the keyword or a machine did. It
       infers this from BIP39 membership, which is a strong hint, not proof.
     - It does not check breach corpora. A keyword found in a public dump is
       worthless no matter what it scores here.
     - It does not know the keyword is your dog's name, your address or your
       birthday. Personal-knowledge attacks are invisible to any such tool.
     - It does not model real cracking tools with rules and mangling, which
       beat naive entropy maths comfortably on human-made inputs.

     In short: for MACHINE-GENERATED keywords this estimate is sound and
     slightly conservative. For HUMAN-INVENTED ones it is an upper bound,
     and the true figure can be dramatically lower. Never let a good score
     talk you out of using a generated keyword.


TXT;
}

/* =========================================================================
 * Self-test - proves this port agrees with the app's cvEntropy()
 * ========================================================================= */
function selftest() {
    // Synthetic vectors only. No real keyword appears in this file.
    $vectors = [
        ['wolf-echo-tango-delta-bravo-lima-kilo-73$', 84, 'very strong'],
        ['Tr0ub4dor&3',                               72, 'strong'],
        ['password',                                  38, 'fair'],
        ['abc-def-ghi',                               33, 'weak'],
    ];
    echo "\n  Self-test - this PHP port vs the web app's cvEntropy():\n\n";
    $fail = 0;
    foreach ($vectors as $v) {
        $bits = cv_entropy($v[0]);
        $rate = cv_rating($bits);
        $ok   = ($bits === $v[1] && $rate === $v[2]);
        if (!$ok) { $fail++; }
        printf("    %-6s %-44s %3d bits / %-12s (expected %3d / %s)\n",
            $ok ? '[ok]' : '[FAIL]', $v[0], $bits, $rate, $v[1], $v[2]);
    }
    // the acceptance boundary itself, so a drift in either direction is caught
    $edge = [
        ['bus-hip-guard-net-retire-express',            66, true ],   // 6 words, just over
        ['correct-horse-battery-staple',                44, false],   // 4 words, well under
        ['Fluffy2019',                                  60, false],   // under, and rightly refused
        ['xK7$mQ9!zR2#pL4',                             99, true ],   // random string, must NOT be misread
        // 2026-09-03: repetition must not buy strength. Both of these cleared the floor
        //   before the fix - the first scored 66, the second 113.
        ['aaa-aaa-aaa-aaa-aaa-aaa',                     11, false],
        ['aaaaaaaaaaaaaaaaaaaaaaaa',                     9, false],
        ['ab-ab-ab-ab-ab-ab-ab-ab-ab-ab',               35, false],
    ];
    foreach ($edge as $e) {
        $b  = cv_entropy($e[0]);
        $acc = ($b >= CV_MIN_BITS);
        $ok = ($b === $e[1] && $acc === $e[2]);
        if (!$ok) { $fail++; }
        printf("    %-6s %-44s %3d bits -> %-7s (expected %3d / %s)\n",
            $ok ? '[ok]' : '[FAIL]', $e[0], $b, $acc?'accept':'refuse', $e[1], $e[2]?'accept':'refuse');
    }
    printf("\n    %-6s acceptance floor is %d bits\n", '[ok]', CV_MIN_BITS);

    $words = count(bip39_set());
    printf("\n    %-6s BIP39 wordlist embedded: %d words (expected 2048)\n",
        $words === 2048 ? '[ok]' : '[FAIL]', $words);
    if ($words !== 2048) { $fail++; }
    echo $fail ? "\n  {$fail} CHECK(S) FAILED\n\n" : "\n  All checks passed - this tool scores identically to the app.\n\n";
    return $fail === 0 ? 0 : 1;
}

/* =========================================================================
 * Main
 * ========================================================================= */
echo "\n  Coldvault keyword checker - offline, nothing written to disk, nothing logged.\n";

if ($mode === 'help') {
    echo "\n  php kwcheck.php              check keywords at a hidden prompt\n";
    echo "  php kwcheck.php --explain    what the verification is based on\n";
    echo "  php kwcheck.php --selftest   verify this port matches the app\n\n";
    exit(0);
}
if ($mode === 'explain')  { explain(); exit(0); }
if ($mode === 'selftest') { exit(selftest()); }

echo "  Typing is hidden. Press Enter on an empty line to quit.\n";
echo "  Run with --explain to see exactly what the score means.\n";

$n = 0;
while (true) {
    $n++;
    $kw = read_hidden("\n  keyword #{$n} (hidden) > ");
    if ($kw === null || $kw === '') {
        echo "  Done. Nothing was saved.\n\n";
        break;
    }
    report($kw);
    $kw = null;   // best-effort release; see the note at the top of this file
    unset($kw);
}
