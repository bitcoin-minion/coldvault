# Changelog

Notable changes to Coldvault, newest first. Dates are ISO 8601 (`YYYY-MM-DD`).

There are no release tags yet, so each entry describes the state of `main` on that date.

---

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
