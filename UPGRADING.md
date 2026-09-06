# Updating an existing Coldvault

How to move an installation you are already using onto a newer version **without setting the
app up again**. Your configuration, your database, your accounts and your stored phrases are
not touched by an update.

This applies equally whether you run Coldvault on a hosting account or locally on your own
machine with `LOCAL_MODE=1`.

---

## The short version for the 2026-09-06 release

**Replace one file: `public/index.php`. That is the whole update.**

| | |
|---|---|
Database change needed? | **No.** The delete feature relies on foreign keys that were already in `schema/coldvault.sql` from the first release (`fk_ks_vault` and `fk_inv_vault` are both `ON DELETE CASCADE`). Nothing to migrate. |
New setting in `coldvault.env`? | **No.** The feature reads no new configuration. |
New table or column? | **No.** It only uses `vault` and `vault_keyslot`, which you already have. |
New file or dependency? | **No.** |
Do I have to re-enter my `APP_KEY`? | **No.** Never re-generate it — see the warning below. |

So: update the code, reload the page, done.

---

## Before you start: two backups, both quick

Take these even for a one-file update. They cost a minute and they are what turns a bad
surprise into an inconvenience.

**1. Your configuration file.** This holds your `APP_KEY`, and losing it locks every account
out of the app permanently:

```
cp coldvault.env coldvault.env.backup
```

> ⚠️ **Never generate a new `APP_KEY` as part of an update.** It is not a password you can
> rotate freely: it encrypts your authenticator secrets, your backup codes and your invite
> hashes. A new one means nobody can sign in again. Your stored phrases would survive (they
> are encrypted from your keyword, not from `APP_KEY`), but nothing could reach them.

**2. Your database.** Adjust the name if yours differs:

```
mysqldump -u YOUR_DB_USER -p coldvault > coldvault-backup-$(date +%F).sql
```

If you have no command line, your host's control panel can export the database — in cPanel
that is **phpMyAdmin → your database → Export**.

---

## Updating the code

### If you cloned the repository with git

```
git pull
```

That is it. `coldvault.env` is listed in `.gitignore`, so git will never overwrite your
configuration, and your `public/fonts/` files are unchanged.

### If you downloaded a ZIP

Download the current ZIP, then copy **only** `public/index.php` over your existing one:

```
cp coldvault-main/public/index.php /path/to/your/coldvault/public/index.php
```

> ⚠️ **Do not replace your whole installation folder by extracting the ZIP over it.** The
> download does not contain `coldvault.env` (it is deliberately never published), so a
> wholesale replace can delete your configuration — including your `APP_KEY`. Copy the
> individual files a release changes, or use git.

Keep the file you replaced. If anything looks wrong, putting it back is your rollback:

```
cp public/index.php public/index.php.previous     # before overwriting
```

---

## What an update never touches

- **`coldvault.env`** — your `APP_KEY` and database credentials
- **The database** — every vault, account, keyslot, invite and backup code
- **Your keywords** — they are never stored anywhere, so nothing can disturb them

---

## Check it worked

1. Load the app. You should get the sign-in screen with no error.
2. Sign in with your authenticator as usual.
3. Open a vault and confirm the phrase reads correctly.

If instead you see **"Vault temporarily unavailable"**, the app cannot reach the database or
cannot read its configuration — that is almost always a permissions or path problem with
`coldvault.env`, not the update. Restore `coldvault.env.backup` and check the file mode
(`600` on a typical shared host, `640` with a group change on a VPS where PHP runs as
`www-data`). See [INSTALL.md](INSTALL.md).

If a page is blank or shows a server error, put back the `index.php` you saved and the app
returns to exactly its previous state — nothing else was modified.

---

## For future releases

Every release records what it changed in [CHANGELOG.md](CHANGELOG.md). Read its entry before
updating and look for two things only:

- **A schema change.** If an entry says a table or column changed, it will give you the exact
  statement to run. Nothing else requires touching the database.
- **A new setting.** If an entry adds a key to `coldvault.env.example`, copy that key into
  your own `coldvault.env`.

If an entry mentions neither — as the 2026-09-06 one does not — the update is code only, and
replacing the changed files is the entire procedure.
