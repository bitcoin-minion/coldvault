# Changelog

Notable changes to Coldvault, newest first. Dates are ISO 8601 (`YYYY-MM-DD`).

There are no release tags yet, so each entry describes the state of `main` on that date.

---

## 2026-09-07 — security review

A pass of hardening changes from an independent review. **Requires one new database table**
(`vault_login_throttle`) and optionally two new settings — see [UPGRADING.md](UPGRADING.md).
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

- Redirects use a canonical/server name rather than the client `Host`; `<Files>` and a root
  `.htaccess` deny direct access to config/secret files; errors are suppressed at the earliest
  include; backup-code consumption and TOTP replay are race-safe; a guest sees only their own row
  in the sharing panel; `last_used_at` is now recorded; JSON embedded in scripts carries the
  `JSON_HEX_*` flags; the pending re-pair secret is cleared on cancel and expires.

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
