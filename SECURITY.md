# Security

What Coldvault protects, what it does not, and every residual risk worth knowing about.

This document is deliberately unflattering. A vault for recovery phrases that oversells
itself is worse than one that says plainly where its limits are.

> **No warranty, and no independent audit.** This software is provided as-is. Nobody
> outside this project has reviewed its cryptography, its authorization model, or its
> implementation. The design notes below describe what was *intended* and what was tested —
> they are not an assurance that the code is free of defects.
>
> Coldvault stores material that grants irreversible control over cryptocurrency holdings.
> Loss or compromise can be permanent and unrecoverable, and no party — including the
> authors — can restore access on your behalf. **Audit the code and the deployment before
> trusting it with anything of value, and use it at your own risk.** See
> [LICENSE](LICENSE) for the full terms.

---

## The one thing to understand

**The server decrypts.**

Your keyword travels to PHP over TLS. PHP derives the key, decrypts the phrase, and sends
it back over an authenticated request. The keyword is never written to the database, never
logged, and is discarded when the request ends — but for the duration of that request it
exists in the server's memory in clear.

So:

| Threat | Protected? |
|---|---|
| Stolen database dump | **Yes.** Ciphertext only. No phrase, no keyword. |
| Stolen filesystem backup | **Yes**, unless it also contains `coldvault.env` — and even then, no phrase. |
| Database credentials leaked (read) | **Yes.** Ciphertext only, same as a dump. |
| Database *write* access | Phrases stay sealed. Account takeover by transplanting credentials is blocked: APP_KEY blobs and backup-code hashes are bound to their row. |
| `APP_KEY` leaked | **Yes, for phrases.** Accounts become impersonable; phrases stay sealed. |
| Someone with your keyword | No. That is the key. |
| An attacker who can edit `index.php` | **No.** Twenty lines capture every keyword typed after that. |
| An attacker with root, or with the PHP process' memory | **No.** |
| A malicious operator of the instance | **No.** |
| Network attacker on the wire | Yes, via TLS. HTTPS is enforced server-side; a forwarded-protocol header is trusted only when `TRUST_FORWARDED_PROTO` is set for a proxy you run. |

**Run your own instance.** Every design decision here assumes the operator and the owner
are the same person. Using someone else's Coldvault means trusting them with your coins as
completely as if you had emailed them the words.

If you need a design where the server genuinely cannot read your phrase, you need
client-side decryption or an air-gapped machine. Coldvault does not claim to be that.

---

## Keys, and what each one protects

There are two independent secrets. Confusing them is the source of almost every question.

### The vault keyword — protects the phrase

- Chosen per vault, by the person who owns or shares it.
- **Never stored.** Not hashed, not encrypted, not held in a session. It exists only in the
  request that uses it.
- `PBKDF2-HMAC-SHA256`, 450,000 iterations, then `AES-256-GCM`.
- Must clear an entropy floor (65 bits by default) on create, on change, and when joining
  a shared vault.
- **Lose it and the vault is unrecoverable by anyone, including you and including whoever
  runs the server.** That is the design, not a limitation.

### `APP_KEY` — protects the account gate

- 32 random bytes, base64, in `coldvault.env`. One per instance, generated at install.
- Encrypts stored authenticator secrets (`AES-256-GCM`), and keys the HMACs for backup
  codes and invite codes.
- **It does not touch any recovery phrase.** `APP_KEY` plus a full database dump still
  yields nothing readable.
- **Lose it and every account is permanently locked out.** No authenticator code and no
  backup code can be verified. The ciphertext survives untouched, but nothing can sign in
  to reach it. Changing it on a live instance does the same thing.
- The app **refuses to start** unless it decodes to exactly 32 bytes — no default, no
  fallback. A wrong key would otherwise fail quietly and write secrets the real key could
  never read again.
- Back it up off the machine, before creating the first account.

---

## Cryptography

| | |
|---|---|
| Payload cipher | AES-256-GCM (authenticated) |
| Key derivation | PBKDF2-HMAC-SHA256, 450,000 iterations, 16-byte salt |
| Data key | 32 bytes from `random_bytes()` |
| Key wrapping | AES-256-GCM, per-keyslot salt and iteration count |
| Invite codes | 24 chars from a 32-symbol alphabet (no `I`, no `O`) ≈ 120 bits; stored as `HMAC-SHA256(code, APP_KEY)` |
| Backup codes | stored as `HMAC-SHA256(code, APP_KEY)` |
| TOTP | RFC 6238, HMAC-SHA1, 6 digits, 30s, ±1 step window |
| Comparisons | `hash_equals()` on every secret comparison |
| Randomness | `random_bytes()` / `random_int()` only — never `rand()` or `mt_rand()` |

Each ciphertext carries authenticated additional data (`coldvault-v1`, `coldvault-v2`,
`coldvault-kek-v1`, `coldvault-auth`), so a blob produced in one context cannot be replayed
into another.

Under the envelope format the vault row's `iterations` column is `0`, a deliberate poison
value: the derivation helper refuses `iterations < 1`, so a mislabelled row fails closed
rather than deriving a key from nothing.

---

## Authorization

Ownership **is** `vault.user_id`. Guests are accounts holding a keyslot.

| | read | edit / rename | invite | remove | transfer |
|---|---|---|---|---|---|
| Owner | yes | yes | yes | yes | yes |
| Guest | **read only** | no | no | no | no |

**Every one of these is enforced inside the function that does the damage**, not only in
the request handler. This is not stylistic. During development a guest calling the
revocation function directly *succeeded*: it deleted the owner's keyslot, rotated the key,
and left the guest as the sole holder — a complete vault takeover, prevented by exactly one
line in one handler. Authorization belongs where the write happens.

**Removal is key rotation, never a row delete.** A retained keyslot row plus the
ciphertext still yields the key offline. So removal mints a new data key, re-encrypts the
payload, and re-wraps only the acting owner's slot. Every other keyslot is invalidated as a
consequence, pending invites are destroyed, and the confirmation page says so before you
confirm.

**Revocation cannot un-see what was already read.** If someone had access to a phrase,
moving the funds is the only real remedy. The UI states this rather than implying otherwise.

---

## Sessions and the account gate

- A session is bound to the account's `secret_version`. Pairing a new authenticator bumps
  it, so **every other live session ends on its next request** — not just future sign-ins.
  There is also an explicit "sign out everywhere else" control.
- `auth_is_logged_in()` re-reads the account row on every request and fails **closed**: a
  missing row or a version mismatch signs you out.
- 15-minute idle timeout, `session_regenerate_id(true)` on login, cookie
  `Secure; HttpOnly; SameSite=Strict`.
- TOTP replay is blocked by recording the last accepted step.
- **No hard lockout on the sign-in path, by design.** Evaluating a code is the only way to
  tell the owner from an attacker, so a hard cap caps the owner too — a 5-strike lockout let
  anyone who knew a username hold that account shut indefinitely. Two limiters do the
  rate-limiting instead, both keyed to server-side state a client cannot clear by dropping
  its cookie, and both applied identically to unknown usernames so the requirement reveals
  nothing: a CAPTCHA gate after a few failures, and a per-account evaluation **budget**
  (`vault_login_throttle`) that, once spent, throttles further guesses to one every so often
  **without ever fully locking the account** — the owner always keeps getting attempts.
  `lock_until` brakes the step-up path (which needs an authenticated session) and is armed
  only by step-up failures, never by sign-in failures, so an outsider cannot trip it.
- **The sign-in response is identical for a known and an unknown username** (same message,
  same CAPTCHA path), so it does not enumerate accounts.
- **A tarpit was considered and rejected.** Sleeping requests do not survive parallel
  connections, and a handful of concurrent sleepers would pin the PHP worker pool — trading
  a per-account denial of service for a site-wide one.

---

## Web hardening

- **CSRF:** one token per session, verified at a single gate near the top of `index.php`.
  On failure the action simply never happens. `logout` is deliberately exempt: refusing a
  legitimate sign-out leaves a session alive, which is worse than someone forcing one to
  end.
- **CSP:** `script-src 'self' 'nonce-<per-request>'`. No `'unsafe-inline'`, no
  `'unsafe-eval'` — the codebase contains no `eval`, no `new Function`, no string
  `setTimeout`, no `javascript:` URL. There are **zero** `on*=` handler attributes; every
  one is a `data-cv` attribute driven by a single delegated listener with an explicit
  allow-list (tested with `!==1`, not `window[name]`, so HTML injection cannot reach an
  arbitrary global). `style-src` keeps `'unsafe-inline'` on purpose: inline style
  attributes are pervasive and injecting style is not executing script.
- **Headers:** HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`, `Cache-Control: no-store`,
  `Permissions-Policy` denying 23 browser APIs the app never uses.
- **Injection:** prepared statements throughout. The only interpolated values are
  `(int)`-cast integers.
- **Output:** every user-controlled value is written with server-side escaping and, in the
  browser, via `.value` / `.textContent`. A vault name containing `<script>` renders as text.
  The few `innerHTML` writes in the page assign only constant or numeric markup (a spinner, a
  QR matrix, a strength meter), never a secret or a user-supplied string.
- **The phrase never exists inside an HTML document.** It is fetched over an authenticated
  request and written into inputs by script. So no history entry, no resubmittable POST,
  and nothing for reload, back-forward or crash-restore to replay. There is deliberately no
  non-JavaScript fallback — adding one would put the words back in the document.

---

## Privacy

The application records **no client IP**. There is no `REMOTE_ADDR` read, no address
column, and no per-visitor counter anywhere in the code. The sign-up throttle stores
timestamps only.

**No third-party requests, either.** Every asset is served from your own origin: the fonts
are bundled as woff2 under `public/fonts/`, the CAPTCHA is generated locally, the QR code
is drawn in the browser, and the favicon is an inline data URI. Nothing is fetched from a
CDN, an analytics service or a font host, so no outside party learns a visitor's address
merely from a page load. The Content-Security-Policy reflects this — `default-src 'self'`
with no external origin whitelisted anywhere in it. Earlier revisions loaded IBM Plex from
Google Fonts; that was removed for exactly this reason.

You can confirm it yourself — this should print nothing:

```bash
grep -roE 'https?://[a-zA-Z0-9./_+-]+' public/*.php public/*.css \
  | grep -vE 'w3\.org/2000/svg|localhost'
```

**What the application cannot fix:** your web server logs every request with the client
address *before PHP runs*. If the privacy stance matters to you, turn that off in the
vhost — [INSTALL.md step 9](INSTALL.md#9-turn-off-ip-logging-optional-but-recommended)
covers it, including the log-rotation archives, panel statistics and CDN logs that
otherwise resurrect the data.

---

## Known residual risks

Ranked by how much they should worry you.

1. **Server-side decryption.** The whole of the section at the top. This is the ceiling on
   everything else, and it is not fixable within a web application that decrypts on the
   server. An offline or air-gapped edition is the genuine answer.

2. **The phrase is in browser memory once revealed.** After you unlock, the words live in
   JavaScript variables and in input values until the 60-second auto-lock wipes them. If
   developer tools were open, the fetch response is visible in the network tab. A malicious
   browser extension with page access can read them. Unlock on a machine you trust.

3. **Losing `APP_KEY` locks everyone out permanently.** Covered above. It is a real
   operational risk, and the most likely way to lose access to a working instance. Back the
   file up off the machine.

4. **Username enumeration through registration.** The sign-up form must tell you a name is
   taken, so a public sign-up page inherently confirms which names exist. Inherent to the
   feature, left in place. The sign-in path leaks nothing — an unknown username is gated
   identically to a known one.

5. **The entropy estimator is still an upper bound, but it is no longer a naive one.** Until
   2026-09-08 it scored a non-passphrase as `length × log2(alphabet)`, which is true only of a
   random string: `Password123!` measured 79 bits, `qwertyuiop123!` 86 and `Tr0ub4dor&3` 72, so
   the 65-bit floor admitted exactly the shapes a cracking run tries first. The score is now
   capped by a structural ceiling — leetspeak is folded first, a word-shaped run is charged what
   a word costs rather than what its characters would be worth if random, and known passwords,
   keyboard walks, years and repeats are charged almost nothing. Those three examples now measure
   33, 18 and 26. A genuinely random string keeps its full value.
   The ceiling cannot see everything: without a dictionary, a long lowercase run with a plausible
   vowel ratio is charged as one unknown word whether or not it is one, so it will be refused even
   if it was random. That direction is deliberate. **Prefer Generate over inventing a keyword**,
   and use `tools/kwcheck.php --explain` for the methodology.

6. **The sign-up throttle is site-wide.** `REG_MAX_PER_HOUR` counts registrations across
   the whole instance, because no per-address counter exists. So a sign-up flood can block
   new registrations for an hour. Accepted trade for storing nothing identifying; close the
   registration page once your accounts exist.

7. **A guest cannot rotate their own keyword.** The keyword-change path runs through the
   owner-only save function. Workaround: the owner removes and re-invites them — which
   rotates the data key and therefore invalidates every other keyslot too.

8. **Clash-checking cost grows with vault count.** When a keyword is *set*, the app derives
   once per existing vault to warn you that the same keyword already opens another one.
   Fine for a handful of vaults; noticeably slow at hundreds. Plain unlocking never pays
   this.

9. **Duplicate keywords are allowed, only flagged.** Two of your vaults may share a
    keyword; you get a note saying so. It was previously a hard refusal, which was worse —
    unlocking stopped at the first match, silently orphaning the second vault.

10. **No third-party audit.** Nobody outside this project has reviewed the cryptography or
    the authorization model. The code is small and deliberately readable. Read it before
    you trust it with anything that matters.

---

## For anyone auditing or extending this

- **The keyword strength estimator exists in four places and must stay in agreement.** Run
  `php tools/kwcheck.php --selftest` after touching any of them — it asserts numeric parity
  against fixed vectors *and* the accept/refuse boundary. A client that accepts what the
  server refuses is a broken vault-creation flow; the reverse is a security hole.
- **Never set a second Content-Security-Policy** in `.htaccess`, the vhost, or a proxy. Two
  CSP headers are both enforced and the intersection kills the app's own scripts. The
  policy belongs in `config.php`, because a nonce must be generated per request.
- **Authorization goes in the function that performs the write**, not only in the handler.
  See the takeover described above.
- **Nothing that takes a user time may live inside the 60-second auto-lock region.** During
  development it wiped a one-shot invite code — leaving a live invite whose code existed
  nowhere — and then a half-filled invite form. Both moved to their own untimed pages.
- **Test the journey, not the pieces.** Three separate dead ends in the invite flow were
  only found by walking it end to end as the invitee.

---

## Reporting a vulnerability

Please open a **private security advisory** on the repository rather than a public issue,
and allow reasonable time for a fix before disclosing.

Useful in a report: the version or commit, what an attacker needs to start (anonymous?
any account? a sharing guest? the owner?), the concrete steps, and what they end up with.

**Please do not** include a real recovery phrase, a real keyword, or a real `APP_KEY` in a
report. Reproduce with throwaway values.
