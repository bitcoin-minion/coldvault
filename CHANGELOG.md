# Changelog

Notable changes to Coldvault, newest first. Dates are ISO 8601 (`YYYY-MM-DD`).

There are no release tags yet, so each entry describes the state of `main` on that date.

---

## 2026-09-08 — a guest can change their own keyword

### Fixed — the one thing a shared-vault guest could not do for themselves

`new_keyword` existed in exactly one place: the owner-only update handler, which rejects a
non-owner before the save function is ever reached. So somebody holding a keyslot on a vault they
did not own could **not change their own keyword** — their only remedy was to ask the owner to
remove them and re-invite them. Needing a second person in order to react to your own possible
compromise is the wrong shape, and it fell hardest on exactly the people most likely to need it.

`vault_rewrap_slot()` re-wraps **one** keyslot: the caller's. It deliberately does not touch the
ciphertext and does not mint a new data key, which is what makes it safe on a shared vault — the
owner and every other holder are unaffected **by construction** rather than by remembering to be
careful. Verified on a three-holder vault: after a guest re-key the ciphertext and the owner's and
the other guest's keyslots are all **byte-identical**, both still open with their own keywords, the
guest's new keyword works and their old one does not, and a forced write failure leaves the guest
still holding the keyword they had.

- **The entropy floor applies to a guest too.** A shared vault is only as strong as its weakest
  keyword, so read access must not come with the ability to soften the lock on somebody else's
  seed.
- **The owner is refused this path and pointed at Edit**, because Edit rotates the data key when
  the vault has a single holder and therefore does strictly more. Offering one person two keyword
  paths of differing strength is a trap; for a shared vault Edit already performs exactly this
  re-wrap, so nothing is lost.
- **No step-up code**, consistent with Edit: the current keyword is the proof, and whoever holds it
  can already read the seed — a worse outcome than changing it.
- Rate limiting needed no new code. The single gate that fires for any request carrying a keyword
  already applies both the wrong-keyword budget and the work budget to this action.
- ⚠️ Do not "improve" this into rotating the data key. A new key invalidates every other keyslot,
  and no other holder's keyword is available to re-wrap with, so a guest rotating would lock the
  owner out of their own vault.

The client-side validator dispatch now handles a second validator by explicit name comparison and
an explicit branch — **not** `window[name]()`, which `SECURITY.md` records as deliberately avoided
so injected markup can never reach an arbitrary global.

---

## 2026-09-08 — patterned keywords, and a generator that refused its own output

Closing the two entropy-floor bypasses the previous entry recorded as known limitations, plus a
generator bug found while measuring the fix.

### Fixed — the entropy gate over-scored mechanically patterned keywords

Every rule in the estimator scored each token **in isolation**, so a family of related tokens was
charged as if its members were independent. Two shapes therefore cleared the 65-bit floor while
being trivially enumerable:

| keyword | before | now |
|---|---|---|
| `aab-aac-aad-aae-aaf-aag` | 66 — accepted | **48 — refused** |
| `zzz zzz1 zzz2 zzz3 zzz4 zzz5` | 84 — accepted | **38 — refused** |
| `baa-caa-daa-eaa-faa-gaa` | 66 — accepted | **48 — refused** |
| `1zzz 2zzz 3zzz 4zzz 5zzz` | 77 — accepted | **37 — refused** |
| `123456-123456-123456` | 76 — accepted | **56 — refused** |

A letter token is now charged `min(its own cost, novel characters x per-character rate)`, where the
novel part is its length minus the longest prefix **or suffix** it shares with any earlier token. So
`aac` after `aab` costs one character rather than a whole word.

`min()` and never `max()` is the load-bearing detail: sharing an affix can only **lower** a charge.
That is what leaves real keywords alone — a six-letter word sharing a three-letter suffix still has
three novel characters, which costs more than a word does, so it stays at the word price. Measured
before shipping: across a 423-candidate corpus every change was downward and **nothing became newly
acceptable**; across 20,000 simulated generator outputs there was **no** additional failure.

**Known and deliberate: this catches MECHANICAL families, not SEMANTIC ones.**
`one-two-three-four-five-six` and `red-orange-yellow-green-blue-indigo` still score 66 and are still
accepted, because they are six genuinely distinct words with no shared affix — and six distinct word
tokens floor the base estimate at 66. Separating a real six-word passphrase from a named category
needs category dictionaries, which is an unbounded data problem rather than arithmetic. Both are
pinned in `tools/kwcheck.php --selftest` as residuals so they cannot drift unnoticed.

### Fixed — Generate could hand you a keyword the app then refused

`cvDice()` drew words **with replacement**, and the estimator counts DISTINCT words. Two repeats in
a seven-word draw left five distinct words and scored 62 bits — under the app's own 65-bit floor. So
roughly **1 in 20,000 clicks of "Generate strong keyword" produced a keyword the form rejected**,
which is a confusing failure at exactly the wrong moment and it undermines the button the app steers
people toward. Found by simulation while measuring the change above, not by report. Draws are now
without replacement; over the same 20,000 outputs the minimum went from 62 bits with one failure to
**84 bits with none**.

### Added — `tools/parity-check.php`

The measurements behind the change above were one-off scripts. They are now a shipped tool, because
the next person to touch the estimator needs them and a text diff will not do: **both** divergences
that have shipped were in library calls spelled identically in the two languages.

```bash
php tools/parity-check.php            # full: ~450 candidates plus the generator simulation
php tools/parity-check.php --quick    # smaller corpus, no simulation
```

It extracts every copy from the source files **by marker rather than by line number** — a stale
line range fails as a silent fatal instead of saying "the marker moved" — runs each in its own
process, and compares every pair. It reports floor-crossing disagreements separately from cosmetic
ones, because that is the difference between a mildly wrong meter and a server accepting a keyword
weaker than its own floor. It also simulates 20,000 **Generate** outputs and fails if any lands
under the floor. Exits non-zero on any problem, so it drops into a hook or CI unchanged.

If `node` is missing it compares the PHP copies and reports the browser twin as **UNCHECKED**,
never silently skipped — an unchecked twin is exactly how the last divergence shipped.

Verified by sabotage, not by assumption: reintroducing the real `strtolower()` bug into one copy
makes it exit 1 and name the offending candidates, `ÀÁÂÃÄÅÆÇàáâãäåæç` among them at 81 bits against
40. It would have caught what shipped.

Also corrects the README's inventory of estimator copies, which listed a fourth, `rEnt()`, on the
redeem screen. That copy was real and did drift, but it was collapsed into `cv_kw_meter_js()` on
2026-09-08 and the table had not caught up — so the document told contributors to keep in step with
something that no longer existed, while under-stating what the browser twin actually is.

### Verification

All four copies of the estimator — server PHP, the browser twin, and `tools/kwcheck.php` — agree on
all 423 corpus candidates with **0 disagreements**, and the pinned self-test vectors were
regenerated as a whole array rather than patched.

---

## 2026-09-08 — second independent security review

A second review, run against the previous day's commit by reviewers with no knowledge of the first
review's findings or conclusions. It confirmed several known-open items and found five new ones at
high severity or above. **No schema change.** One migration step is required if this instance ever
ran a build from before 2026-09-07 — see [UPGRADING.md](UPGRADING.md).

Three of the findings below came from reviewers deliberately trying to *falsify* claims written in
the code comments and in `SECURITY.md`. Every one of those claims was wrong. They are quoted where
they were wrong, rather than quietly deleted, because the reasoning error is the useful part.

### Fixed (high severity)

- **A rate-limit key namespace could be spent by anyone.** `vault_login_throttle` carried both the
  sign-in budget and the keyword-failure budget, the latter under the key `kw:<user id>`. A comment
  argued this could never collide with a real account because usernames may not contain a colon —
  but that rule was only ever enforced on the *registration* path, while the sign-in path wrote the
  raw submitted username into the same column. So an anonymous request with `username=kw:<id>`
  spent that account's keyword budget, locking the owner out of their own vault with no
  self-service remedy. Every key is now explicitly namespaced, and the sign-in path validates the
  username format before recording anything. Found independently by two reviewers.
- **A username-keyed rate limit is a denial of service.** Once the hourly sign-in budget was spent,
  each further attempt required an interval to have elapsed since the newest attempt — a clock
  *shared* by everyone submitting that username. Anyone who knew a username could poll once a
  minute and win every race against a human filling in a form, holding the account shut
  indefinitely. Attempts now fall through to a small per-client reserve that an attacker cannot
  spend, so a correct code is always evaluated. This closes the denial of service; it does not
  tighten the guessing bound.
- **A correct keyword was an unmetered CPU amplifier.** The keyword-failure budget counts only
  *wrong* keywords, by design, which left successful operations entirely unmetered. An update that
  set a new keyword performed up to 27 key derivations — enough to exceed PHP's default
  `max_execution_time`, and enough for one registered account to saturate every PHP worker on the
  host. A per-account *work* budget is now charged for every keyword-bearing request whatever its
  outcome, and the advisory keyword-collision check (which derived once per vault) is capped much
  lower.
- **A keyword-collision check could kill its own request after committing.** The same 27
  derivations ran *after* the vault write had been committed, so an owner with many vaults had the
  request killed mid-loop: the change was saved but the page died with no way to tell.

### Fixed (medium severity)

- **The legacy AAD fallback allowed a cross-column transplant.** Blobs written before context
  binding carry a *constant* AAD, so they decrypt in any context. The previous note here argued the
  fallback was safe "because forging requires `APP_KEY` and freshly written blobs are always
  bound" — which reasoned about forging and missed *moving*. A vault name is a blob whose plaintext
  the attacker chooses, so a name could be copied onto a stored authenticator secret, making that
  name the victim's TOTP secret. The fallback is removed; run `tools/migrate-aad.php` once when
  upgrading. `ak_decrypt_bound()`, `user_secret_is_legacy()` and `user_migrate_secret()` are gone
  with it — removing the fallback made all three permanently inert rather than merely unused.
- **CAPTCHA state enumerated accounts.** The two sign-in messages were made identical in the first
  review, but the *state* deciding whether to demand a CAPTCHA was `vault_users.fail_count`, which
  only exists for accounts that exist. Three wrong codes, then one attempt from a fresh session,
  distinguished a real username from an unused one. The trigger now counts failures in a namespace
  recorded whether or not the account exists.
- **An over-long payload could be silently truncated.** The update path had no length caps (only
  the create path did), so a long passphrase produced a payload larger than the ciphertext column.
  On a server without strict SQL mode that is truncated, and since the authentication tag covers
  the whole plaintext the vault then never opens again — indistinguishable from a forgotten
  keyword. Both encryption entry points now bound the plaintext, and the writes check that a row
  was actually affected.
- **Three ciphertext writes had no scope clause or result check.** Concurrent requests from the
  owner's own two sessions could write a keyword-encrypted payload onto a row another request had
  just upgraded to the envelope format, leaving the vault permanently unopenable. Each write now
  carries its owner and format predicate and verifies one row changed.

### Fixed (low severity)

- **`APP_BASE` accepted a protocol-relative URL.** The path charset guard admitted `//host`, which
  as a URL points at another origin — so every stylesheet, script and image link on the page could
  be redirected. Repeated slashes are now rejected.
- **The key-derivation iteration count had no upper bound.** It is read from the row, which is what
  a database-write attacker controls, so one edit could make every unlock run for hours.
- **Invite creation had no engine-level authorization.** The handler checked ownership, a step-up
  code and the keyword, so it was not exploitable — but it was the only damaging write not
  re-proving ownership *inside* the function that writes, which is the pattern that keeps a
  refactor from silently dropping a check.
- **A failed registration burned a site-wide sign-up slot** for an hour, because the slot is
  reserved before the account is created.
- **The rate limiters failed open.** A missing throttle table made every budget silently vanish;
  they now fail closed.
- **Sign-in no longer feeds the account-security lockout counter.** The default already stopped it
  *arming* the lock, but not *feeding* it, so an outsider could pre-load the counter and the
  owner's next step-up slip would lock their own recovery controls.

### Changed

- The two hand-copied rate-limit implementations were replaced by one primitive. The fail-closed
  fix above had already had to be applied twice; a third copy was about to be added.
- `tools/kwcheck.php` tracks the estimator changes below, and its pinned self-test vectors were
  regenerated. Two patterned shapes that still clear the floor are now pinned explicitly, so the
  gap is recorded rather than forgotten.

### Fixed (medium severity, found while verifying the port)

- **The entropy estimator's PHP and JavaScript halves disagreed on non-ASCII case folding.** Not a
  review finding — this surfaced from a three-way parity check written to prove the port was
  faithful, which is the reason such a check is worth writing. PHP's `strtolower()` is byte-based
  and folds ASCII only; JavaScript's `toLowerCase()` folds all of Unicode. Measured across 1,379
  cased characters, the two disagree on **676** of them, and the disagreement ran in the
  server-permissive direction — the server ENFORCES the floor, the browser only displays a meter:

  | keyword | server, before | browser meter | 65-bit floor |
  |---|---|---|---|
  | `ÄÖÜÀÈÌÒÙäöüàèìòù` | 81 — accepted | 40 — refused | crossed |
  | `ÄÖÜÀÈÌÒÙÇÑäöüàèìòùçñ` | 101 — accepted | 50 — refused | crossed |
  | `ΑΒΓΔΕΖΗΘαβγδεζηθ` (Greek) | 81 — accepted | 40 — refused | crossed |
  | `АБВГДЕЖЗабвгдежз` (Cyrillic) | 81 — accepted | 40 — refused | crossed |

  Unfolded `ÄÖÜ` counted as three further distinct symbols on top of `äöü`, inflating the
  structural cap by roughly 5 bits per character. `cv_leet()` now uses `mb_strtolower()`, which
  agrees with JavaScript on all 1,379 — so **`mbstring` is a hard requirement**, checked at
  startup alongside `gd`. There is deliberately no fallback: a silent one would restore this exact
  bug on any host missing the extension. All three copies of the estimator (server PHP, browser
  twin, `tools/kwcheck.php`) now agree on all 423 candidates of the parity corpus.

### Documentation and packaging (same review)

Several of these are worse than code bugs, because a reader follows them.

- **CRITICAL: two documents combined to publish `APP_KEY` and the database password.** The
  shared-hosting appendix told operators to create an `.htaccess` "containing exactly" a rule
  denying the single filename `coldvault.env` — in the project root, which **already ships an
  `.htaccess` denying the whole directory**, so following the instruction *replaced* a deny-all
  with a deny-one. `UPGRADING.md` then said `cp coldvault.env coldvault.env.backup`, and that
  filename was not the protected one, so it was served on request. The appendix's own test step
  (fetch `coldvault.env`, expect *Forbidden*) passed the whole time, which made it worse than no
  test. Fixed on all three sides: the appendix now says never to replace the shipped file and
  lists four URLs to test, `UPGRADING.md` keeps backups outside the tree, and the deny pattern in
  `public/.htaccess` matches the *shape* of a backup rather than a list of extensions.
- **`schema/coldvault.sql` was described as "additive" and was not.** Every `CREATE TABLE` lacked
  `IF NOT EXISTS`, so re-applying it aborted on the first existing table, part-way through. All
  seven now carry `IF NOT EXISTS`. Re-running it is still not an upgrade mechanism — it skips an
  existing table even when its columns are stale — and that is now stated in the file.
- **The quick start's `chmod 600` broke the install it was describing.** It ends with an Apache
  vhost, where PHP runs as `www-data`, so a root-owned `600` configuration file is unreadable and
  the app reports "Vault temporarily unavailable". Now `chown root:www-data` plus `640`, with the
  cPanel case (`600`, PHP as your own user) called out. `INSTALL.md` always had this right.
- **The install verification told you to expect the wrong status codes**, then contradicted itself
  in the prose below: `404` in the instruction, "an empty 200" in the explanation, and `403` in
  reality, because `public/.htaccess` denies those files by name. A `200` there means
  `AllowOverride All` is not in effect and *no* protection in that file is either — which is now
  what it says. Also adds checks for the backup filenames, both required extensions, and the
  table count.
- **The security-header list did not say the headers are `.htaccess`-dependent.** Without
  `mod_headers` or `AllowOverride All`, Apache drops the whole block silently and the app cannot
  tell. HSTS especially: its absence is invisible in normal use. `SECURITY.md` now says so and
  gives the one-line check. Setting them from PHP instead is recorded as a known gap.
- Corrected the table count (six → **seven**, in two places), the documented strength of
  `Fluffy2019` (60 → **37** bits, in two places — the estimator rewrite changed it and the prose
  did not follow), and the requirement table, which called `gd` "optional with an SVG fallback"
  after that fallback had been deleted as decodable, and listed `mbstring` under "not needed".
- **The `vault_login_throttle` schema comment described one namespace where there are now five**,
  and repeated the falsified claim that the design meant "an outsider cannot hold a known username
  shut". Both the SQL prose and a new table `COMMENT` now list all five namespaces, record why that
  claim was wrong, and state plainly that no client IP is stored and how the per-client bucket is
  derived without one. Applied to a running instance with `ALGORITHM=INPLACE, LOCK=NONE`, so it
  needs no downtime; on a fresh install it comes from the schema. Purely descriptive either way —
  no column, index or row is affected.
- `.gitignore` now covers the suffixes the documentation itself asks operators to create
  (`*.backup`, `*.previous`, `*.save`, `coldvault.env.*`), kept in step with the deny list.

### Added — a real re-key on keyword change

- **Setting a new keyword now rotates the vault's data key, when the vault has exactly one
  keyslot.** Previously a keyword change only re-*wrapped* the existing data key, so the old
  keyword plus a retained copy of the keyslot row and the ciphertext still derived that key — for
  ever, including every later edit. "Change your keyword because it may have leaked" therefore
  changed the label on the lock and not the lock, and a sole owner had no re-key path at all,
  because the only other place a new data key was minted is the remove-access flow, which refuses
  to remove your own keyslot. The honest workaround was to create a second vault, copy the phrase
  across and delete the first.
- **A shared vault deliberately does not rotate on a keyword change.** A new data key invalidates
  every other keyslot, and no other holder's keyword is available to re-wrap with, so rotating
  silently would cut people off as a side effect of an action the owner did not understand. The
  keyword change re-wraps only the caller's slot, and the app now *says* the old keyword still
  opens the vault and what to do about it. Re-keying a shared vault is the remove-access flow,
  which already rotates and already warns.
- The weak-keyword notice follows the same distinction, because advice that is right for one case
  is confidently wrong for the other.
- Cost is unchanged at two key derivations for the wrap and its self-check — minting a key and
  encrypting under it involve no KDF work — plus one more for a read-back.
- ⚠️ **The failure mode here is permanent, so the failure path is tested, not assumed.** Ciphertext
  written under a new data key while the keyslot still wraps the old one is a vault that can never
  be opened again. Every check runs before any write, both writes are verified to touch exactly one
  row, and the vault is then re-opened through the real read path *inside* the transaction. A
  forced mid-rotation failure was verified to roll back and leave the vault openable by the **old**
  keyword — not by neither.

### Known limitations, stated deliberately

- The keyword entropy estimator charges a repeated or sequential letter run as a run rather than a
  word, which closes `aaa-bbb-ccc-…` shapes. **Shared-prefix (`aab-aac-aad-…`) and
  stem-plus-counter (`zzz zzz1 zzz2 …`) shapes still clear the 65-bit floor.** Closing those needs
  dictionary and pattern analysis rather than a structural ceiling.
- A per-account rate limit still cannot bound a large botnet, and no limit keyed on a username can
  be both denial-of-service-proof and guess-bounding without identifying the client.


## 2026-09-08 — security review

A pass of hardening changes from an independent review. **Requires one new database table**
(`vault_login_throttle`) **and one new index** (`vault_invite.k_expires`), plus optionally two new
settings (`TRUST_FORWARDED_PROTO`, `CANONICAL_HOST`) — see [UPGRADING.md](UPGRADING.md).
Existing authenticator secrets, labels and backup codes keep working; do not regenerate `APP_KEY`.

### Fixed (high severity)

- **APP_KEY-encrypted blobs and backup-code hashes are now bound to their row.** The stored
  authenticator secret, the vault/keyslot/invite labels, and the backup-code HMACs previously
  had no per-row context, so anyone with database *write* access could copy their own credentials
  onto another account and sign in as that user. Encryption/HMAC now fold in the account or vault
  context; old rows are read with a fallback and re-encrypted on next use.
- **The passwordless sign-in is now rate-limited per account.** A new per-username evaluation
  budget (`vault_login_throttle`) caps online TOTP guessing, without ever fully locking an account
  out (so it cannot be abused to deny a known user access).

### Fixed (medium severity)

- **`X-Forwarded-Proto` is trusted only behind a configured proxy** (`TRUST_FORWARDED_PROTO`),
  so a client can no longer send that header over plain HTTP to defeat the HTTPS requirement.
- **Unlock no longer fans out across every vault**, and vaults per account are capped, closing a
  CPU-amplification denial of service. PIN/passphrase length is capped so a payload cannot be
  silently truncated by the ciphertext column.
- **Expired invites are purged at rest**, so an unredeemed, uncancelled invite no longer keeps the
  vault's wrapped key in the database past its 72-hour window.
- **The revealed phrase is wiped when the tab is hidden or the page is left** (previously the
  readonly reveal fields and the in-memory copy survived a tab switch).
- **Sign-in no longer reveals whether a username exists**, and no longer arms the account-security
  lock, so an outsider can no longer hold an owner's recovery controls shut.
- **The CAPTCHA now requires the GD image path** (the decodable SVG fallback was removed).

### Fixed (lower severity / hardening)

- The HTTP->HTTPS redirect goes only to a configured `CANONICAL_HOST`, never to the client
  `Host`; with none configured a plain-HTTP request is refused (403) rather than redirected.
  `<Files>` and a root `.htaccess` deny direct access to config/secret files; errors are
  suppressed at the earliest include; backup-code consumption and TOTP replay are race-safe; a
  guest sees only their own row in the sharing panel; `last_used_at` is now recorded; JSON embedded
  in scripts carries the `JSON_HEX_*` flags; the pending re-pair secret is cleared on cancel and
  expires.

### Fixed after a second review of this release

- **Transferring a vault no longer blanks its name.** Vault names are now encrypted bound to the
  owner's account; the transfer path changed the owner but left the name encrypted for the old
  one, so it became unreadable to everybody. The name is re-encrypted for the new owner inside
  the transfer transaction.
- **A sign-in code can no longer produce two sessions.** Two requests carrying the same valid
  6-digit code at the same instant both signed in; the compare-and-set on the last-used step now
  reports whether it won, and the loser is treated as a failed attempt. The same check applies to
  the account-security step-up.
- Indexes added for the two new housekeeping deletes (`vault_invite.expires_at`,
  `vault_login_throttle.ts`) so they do not scan their tables on every request.
- `CANONICAL_HOST` documentation now matches the code (refuse, do not reflect).

### Fixed: the keyword strength gate accepted the weakest common passwords

**This changes which keywords the app accepts.** No database change, no configuration change, and
**existing vaults and keywords are untouched** — the floor has only ever gated a keyword being
*set*, so nothing you already have stops working.

The estimator scored a non-passphrase as `length × log2(alphabet)`. That is true of a *random*
string and badly wrong for a patterned one, so against the 65-bit floor it admitted exactly the
shapes a cracking run tries first:

| keyword | scored | now | realistic |
|---|---:|---:|---:|
| `qwertyuiop123!` | 86 | **18** | ~15 |
| `Password123!` | 79 | **33** | ~15 |
| `MyPassword2026` | 83 | **37** | ~20 |
| `Tr0ub4dor&3` | 72 | **26** | ~28 |
| `Summer2026!` | 72 | **40** | ~20 |

Because the keyword *is* the encryption key, that gate was the only thing standing between a
stolen database dump and the recovery phrase.

The old estimate is now an **upper bound**, taken as a minimum against a structural ceiling built
by tokenising the candidate: leetspeak is folded first, a word-shaped run is charged what a word
costs rather than what its characters would be worth if they were random, and known passwords,
keyboard walks, year suffixes and repeats are charged almost nothing. A genuinely random string
keeps its full value — `xK7$mQ9!zR2#pL4` scores 92, and the app's own **Generate** button (seven
words plus digits and a symbol, ~84 bits) is unaffected.

The **passphrase branch is deliberately unchanged**: four words drawn from a 2048-word list really
is 44 bits, so `correct horse battery staple` was always correctly refused by a 65-bit floor.

Known limitation, and it errs toward refusing: with no dictionary to consult, a long lowercase run
with a plausible vowel ratio is charged as one unknown word whether or not it is one. A random
letters-only keyword may therefore be refused. Prefer **Generate**.

The estimator was replaced in the server, the page script and `tools/kwcheck.php` together, and
cross-checked over **3,414 candidates including multibyte and emoji with zero disagreement**. The
arithmetic is integer hundredths-of-a-bit against a shared table rather than floating-point `log()`,
which is what makes that guarantee hold. `kwcheck.php --selftest` covers the new vectors.

**A sixth copy was missed on the first pass and is now fixed.** `rEnt()` — the strength meter on the
**redeem** page, where a guest chooses their own keyword to join a shared vault — still held the old
formula, so it showed `qwertyuiop123!` as "~86 bits, accepted" while the server refused it at ~18.
It failed safe, because the server always decides, but the meter lied. It was missed because it was
searched for by function name (`cv_entropy`, `cvEntropy`) rather than by formula, and this one was
called something else — the comment above it even read "keep all three in step".

Rather than add a fourth copy, the two browser-side emissions now come from **one** PHP function,
`cv_kw_meter_js()`: the main page used to print the estimator as raw output while `render_redeem()`
built its own inside a string concatenation, which is exactly how they drifted. One source, two
emissions — they cannot diverge again. Verified: the emitted JavaScript agrees with the server over
the same 3,414 candidates, and the redeem page's fully assembled script block parses cleanly.

### Fixed: two rate-limiting gaps (no schema or configuration change)

**A stolen session was an unlimited keyword oracle.** `unlock`, `update`, `invite_create`,
`revoke` and `transfer` each derive one key per guess and nothing counted the misses, so only
PBKDF2's ~1.4 s per attempt slowed an attacker holding a live session — enough to matter against a
weak keyword predating the entropy floor. There is now a **per-account keyword-failure budget**:
10 wrong keywords an hour, then one attempt per minute.

Two properties are deliberate. **Only a wrong keyword is recorded**, so a legitimate owner is never
throttled however heavily they use their vault — verified with three consecutive successful unlocks
recording nothing. And it **never fully locks**: one attempt per interval always gets through, so
it cannot be turned into a denial of service against the owner, the same principle as the sign-in
budget. The check lives at a single gate covering every request that carries a keyword, alongside
the CSRF check and the reference translation, and returns JSON on the AJAX unlock path so the
browser sees a proper error rather than a redirect. State reuses `vault_login_throttle` under the
key `kw:<uid>`, which needs no schema change and cannot collide with an account, because a colon
can never appear in a username.

**The sign-up cap could be exceeded, and was not atomic.** It was checked at `register_start` and
recorded only at `register_confirm`, so N sessions could be staged past the check and completed
afterwards; the count was also read-then-act, so two simultaneous confirmations could both pass. A
slot is now claimed atomically immediately before the account is created — insert the row, count
the hour including it, roll back if over, which is what makes it atomic without an id column that
`vault_reg_throttle` does not have.

The check on the first screen is kept as **advisory only** so an honest user is told before pairing
an authenticator, and it reserves nothing. That is a deliberate departure from the suggestion to
record on the first screen: doing so would let anyone burn the shared hourly budget just by loading
the form, making the very denial of service the cap already risks strictly worse.

Verified over HTTP against a disposable instance: the gate first refuses on the 11th wrong keyword
and not before; a correct keyword is held while the budget is spent and opens the vault again once
the interval elapses; the AJAX path receives `{ok:false, err:…}`; an action carrying no keyword is
never gated; and exactly 5 of 8 sign-up attempts succeed with no row left behind by a refusal.

### Fixed: session lifetime and cookie handling (no schema or configuration change)

**A session that stayed busy never expired.** The 15-minute idle timeout was the only bound, so a
cookie kept warm by use lived indefinitely — and a stolen cookie is, by definition, one being used.
There is now an **absolute lifetime of 12 hours** (`AUTH_MAX_SESSION`) alongside the idle timeout.
A session already in flight when this deploys carries no birth stamp; it is stamped on its next
request rather than signed out mid-visit, so it gets one fresh 12 hours and is bounded from then
on — a deliberate trade against logging every signed-in person out at deployment.

**Signing out left the cookie in the browser.** `auth_logout()` cleared `$_SESSION` and destroyed
the server-side record but never expired the cookie, so a signed-out browser kept presenting a dead
session id on every later request. Logout now also sends an expiring `Set-Cookie`, reusing the live
cookie parameters so the expiry matches the cookie actually set.

**`session.use_strict_mode` is now enabled**, so PHP refuses a session id it did not issue: an
attacker can no longer plant a known id in someone's browser and wait for it to be authenticated.

**The session cookie is scoped to the install** rather than to `/`, so an install served from a
subdirectory no longer hands its session cookie to every other app on the same host. The path is
derived inside `auth.php` instead of read from `APP_BASE`, because `captcha.php` loads `auth.php`
but never `config.php` — if the two entry points disagreed on the path, the CAPTCHA answer would be
stored under a cookie the sign-up page never sends back and registration would fail for everyone.
Both derivations take the same input and produce the same value.

Verified over HTTP against a disposable instance: both entry points issue an identical cookie; a
registration completes, which is the actual proof that the CAPTCHA answer crosses entry points; a
planted session id is neither adopted nor given a session file; logout returns a past expiry and
the browser is signed out; a session backdated past 12 hours is signed out **while not idle**; and
the idle timeout still fires on its own.

## 2026-09-06

### Added

- **Delete a vault.** A vault owner can now remove a vault outright, from its own untimed
  confirmation page.

  - **Owner only**, enforced *inside* `vault_delete()` as well as in the request handler.
    Guarding only the handler is how a takeover bug happened once before in this codebase,
    so authorization lives in the function that does the damage.
  - **Every key to the vault dies with it.** `vault_keyslot.vault_id` and
    `vault_invite.vault_id` are both `ON DELETE CASCADE`, so the owner's keyslot, every
    shared person's keyslot, and every pending invite code are removed along with the row.
    That is enforced by the schema rather than by application code, so it cannot be
    forgotten in a later edit. User accounts themselves are untouched — people only lose
    that vault.
  - **The engine will not commit a half-done delete.** It bails if the statement affected
    anything other than exactly one row (so it never deletes blind), and it re-reads the
    keyslot count before committing, rolling back if anything survived.
  - **Gate: an authenticator code plus typing `DELETE` — deliberately not the vault
    keyword.** Deleting performs no cryptography, so the keyword is not technically needed,
    and demanding it would make a vault whose keyword you had lost *permanently
    undeletable* — which is exactly the vault you are most likely to want gone. The typed
    confirmation is checked before the authenticator code, so a mistyped confirmation does
    not consume one of your backup codes.
  - **The control is on the keyword screen, not behind a successful unlock**, which follows
    from the above: a vault you cannot open must still be removable.
  - The confirmation page names the vault, lists by name everyone who will lose access
    ("with no warning"), counts the invite codes that will stop working, and states plainly
    that the phrase is destroyed rather than archived — and that deleting cannot un-see
    anything: anyone who has already opened the vault still knows the words.

- **A version marker.** `CV_VERSION` is shown on the **Account security** page as
  "App version", so you can tell which release an installation is running before deciding
  whether to update. It is defined in `public/index.php` rather than in `public/config.php`
  deliberately: most updates replace `index.php` and nothing else, so a constant living in
  the config file would keep reporting the old version after an update.
- **[UPGRADING.md](UPGRADING.md)** — how to move an existing installation to a newer version
  without setting it up again.
- **This changelog.**

### Changed

- **No user-visible message names a vault by its numeric id any more.** Vault ids are
  sequential, so a message like "Vault #333 encrypted and stored" told any signed-in user
  roughly how many vaults exist on the installation — and comparing two sightings revealed
  how fast that number was growing. That is metadata about other people's use of your
  installation, and no user needs it. A vault is now identified by its **name**; one with no
  name reads "Unnamed vault", and the duplicate-keyword notice says "another of your vaults"
  instead of naming an id.

- **No row id is sent through a form any more, either.** Removing the id from the *messages*
  was only half the fix — it was still sitting in hidden form fields, so viewing the page
  source revealed it anyway. Vault, keyslot, invite and user references are now opaque:
  `HMAC(kind:id, APP_KEY)` truncated to 16 hex characters. Stable for a given row,
  unguessable without the key, and they say nothing about how many rows exist. `new_owner`
  mattered most here — it carried a raw **user** id, which leaked how many people use the
  installation.

  References are translated back to ids in **one place**, immediately after the
  authentication wall, using the same single-gate reasoning as the CSRF check — so every
  request handler still reads a plain integer and none of them needed changing.

  This hardens authorization as a side effect: a reference is resolved only against rows the
  caller already holds, so a request can no longer even *name* another account's vault, and
  anything unrecognised resolves to 0 and fails closed. Sending a raw integer id is now
  rejected outright, which also ends id enumeration as a probing technique.

- `README.md` documents the new behaviour, and records that rename, invite, remove, transfer
  **and delete** are all owner-only and all enforced in the engine.

---

## 2026-09-04

### Added

- Initial public release under the MIT licence.
- Multi-user encrypted seed-phrase vault: envelope encryption (a random data key encrypts
  the payload once; each authorised person holds that key wrapped under their own keyword),
  AES-256-GCM, PBKDF2-HMAC-SHA256 at 450,000 iterations, and a 65-bit floor on keywords.
- Sharing: one-time invite codes (~120 bits, 72-hour TTL, only the HMAC stored), redemption
  under the invitee's own keyword, access removal by data-key rotation, and ownership
  transfer.
- Recovery phrases of 12/15/18/20/21/24/33 words, covering BIP39 and SLIP-39 shares, plus an
  optional PIN and passphrase.
- Account security: authenticator-app sign-in, eight single-use backup codes, a CAPTCHA gate
  keyed to server-side failure count, session eviction on re-pairing, and CSRF protection at
  a single gate.
- Privacy: no client IP is recorded anywhere in the application, and the app makes **no**
  third-party requests — IBM Plex is bundled, the CAPTCHA is generated locally, the QR code
  is drawn in the browser, and the Content-Security-Policy whitelists no external origin.
- Documentation: [`GETTING-STARTED.md`](GETTING-STARTED.md) (four install paths, including
  shared hosting with no command line), [`INSTALL.md`](INSTALL.md),
  [`GLOSSARY.md`](GLOSSARY.md) and [`SECURITY.md`](SECURITY.md).
- `tools/genkey.php` to generate an `APP_KEY`, and `tools/kwcheck.php` as an offline keyword
  auditor with a self-test.
