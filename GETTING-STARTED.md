# Getting started

This guide assumes you have **never set up a web server**. It explains what each step does
and why, and it does not assume you can use a command line unless your situation requires
one.

If you already run Linux servers, skip this and read [INSTALL.md](INSTALL.md) — it is the
same process written concisely for people who know the stack.

Unfamiliar word? [GLOSSARY.md](GLOSSARY.md) defines every technical term used anywhere in
this project, in plain language.

---

## Part 1 — Read this before you install anything

Coldvault stores your wallet's recovery phrase. Those words *are* your money: whoever has
them can spend your coins, and there is no bank, no password reset and no support desk. So
before anything else, understand the four ways this can go wrong. Every one of them is
permanent.

### 1. You forget your keyword → that vault is gone forever

The **keyword** is the password you choose for a vault. It is what encrypts your recovery
phrase, and it is **never stored anywhere** — not on the server, not in the database, not
in a file. That is deliberate: it is why a stolen database is useless to a thief.

The consequence is absolute. If you forget your keyword, **nobody can recover that vault.**
Not you, not the person running the server, not the author of this software. The encrypted
data will sit there permanently unreadable.

> **Write your keyword on paper before you finish setting up.** Not in a text file on the
> same computer. Paper, or a password manager you already trust and already back up.

### 2. You lose `APP_KEY` → every account is locked out forever

`APP_KEY` is a random value you generate once during setup. It protects the login side:
the authenticator secrets and the backup codes.

If you lose it, **nobody can sign in ever again.** Your encrypted phrases survive intact —
but no six-digit code and no backup code can be checked any more, so nothing can get in to
reach them. **Changing it later does exactly the same damage as losing it.**

> **Copy the finished `coldvault.env` file somewhere off the server, before you create your
> first account.** A password manager entry, an encrypted USB stick, or printed on paper in
> a safe.

### 3. You lose your phone and your backup codes → that account is locked out

Signing in uses an **authenticator app** on your phone (the kind that shows a 6-digit code
that changes every 30 seconds). There is no password and no email recovery.

When you register you are shown **eight backup codes, once**. They are the only way in if
your phone is lost, stolen or wiped.

> **Save the backup codes when they are shown.** They are not shown twice, and only their
> hashes are stored, so they cannot be recovered or re-displayed.

### 4. You treat this as your only copy → one bad day and it is gone

A server can die. A hosting account can be suspended. You can fat-finger a database
command. Coldvault is a **second copy** that survives a house fire — it is not a
replacement for the metal plate or the paper in your safe.

> **Never delete your offline backup because Coldvault has a copy.**

---

## Part 2 — Should you self-host this at all?

An honest answer, because the wrong choice here costs real money.

**Self-hosting means you are the security team.** The server decrypts your phrase in order
to show it to you, so anyone who can get into that server can capture your keyword and
your phrase. Encryption at rest protects you from a **stolen database or stolen backup** —
not from a machine somebody has broken into.

That is fine when the machine is yours and you keep it patched. It is not fine if you were
planning to install this and never think about it again.

**Reasonable reasons to go ahead:**

- You want a second copy that is not in your house, encrypted with a keyword only you know.
- You will keep the server updated, or you are using managed hosting that does it for you.
- You are storing a phrase for a wallet whose loss would hurt but not ruin you.
- You want to share access with a partner or family member in a controlled way.

**Reasons to stop and do something else instead:**

- This would be the *only* copy of your phrase. Make an offline backup first.
- It holds a phrase for funds you cannot afford to lose, and you cannot read the code or
  have someone read it for you. Nobody has audited this software.
- You do not want to think about server updates, ever.

**Want to look before you commit?** Use Path C or Path D below to run it on your own
computer with fake data. Nothing leaves the machine and you can delete it in a minute.

---

## Part 3 — Which situation are you in?

| Your situation | Path | Command line needed? |
|---|---|---|
| I pay for web hosting with a **cPanel** control panel | **[Path A](#path-a--shared-hosting-with-cpanel)** | No |
| I have a **VPS** or dedicated server and root access | **[Path B](#path-b--your-own-linux-server-vps)** | Yes |
| I want to try it on my **Windows or Mac** computer | **[Path C](#path-c--windows-or-macos-just-to-try-it)** | A little |
| I want to try it on my **Linux** computer | **[Path D](#path-d--linux-just-to-try-it)** | Yes |

Not sure whether you have cPanel? Log in to your hosting account. If you see a page full of
icons with names like *File Manager*, *MySQL Databases* and *phpMyAdmin*, that is cPanel —
use Path A.

**Paths C and D are for looking at the software, not for storing a real phrase.** They run
without encryption on the connection, which is safe only because nothing leaves your
machine.

---

## Path A — Shared hosting with cPanel

No command line. About 30 minutes. You will need your cPanel login and a domain or
subdomain you can point at this.

### A1. Check that PHP 8.1+ is available at all

Coldvault needs **PHP 8.1 or newer**. Check before you spend time on the rest.

In cPanel, open **MultiPHP Manager**. Ignore the list of domains for now — just open the
version dropdown and see what is on offer. You want **8.1, 8.2 or 8.3** to appear.

If MultiPHP Manager is missing, or the newest option is below 8.1, contact your host and
ask them to move your account to PHP 8.1+.

> **Why 8.1 and not just "whatever works"?** The code itself is compatible with PHP 7.4 —
> that was tested, it parses and runs — so it will *appear* to work on an old version. The
> reason to insist on 8.1+ is that **PHP 7.4 stopped receiving security patches in November
> 2022.** Running a vault that holds recovery phrases on an unpatched language runtime
> undoes much of the point of the exercise. Insist on it for that reason, not because the
> app will crash.

> **You will come back here in step A3a to set the version for the subdomain itself.**
> Do not bother setting it for your existing domain now — it will not carry over. The
> reason is worth knowing, because it is easy to get wrong: **a new subdomain does not
> inherit its parent domain's PHP version.** It appears as its own row in MultiPHP Manager
> with its own setting. (Tested on cPanel 11.136: a parent domain running PHP 7.4 produced
> new subdomains running 8.1, entirely independently.) So the version has to be set *after*
> the subdomain exists.

### A2. Decide where the files go — this part matters

You are about to make one decision that has real security consequences, so here is what is
going on.

Your hosting account has a folder called `public_html`. **Everything inside it is
downloadable from the internet.** That is its whole job — it is what your website is.

Coldvault has a configuration file, `coldvault.env`, that will contain your `APP_KEY` and
your database password. If that file ends up anywhere inside `public_html`, somebody can
potentially just download it.

So the layout is: **the app folder goes *outside* `public_html`**, and you point your
domain at the `public` folder inside it.

```
/home/YOURACCOUNT/
├── coldvault/                 ← the app goes here, OUTSIDE public_html
│   ├── coldvault.env            your secrets. Not reachable from the web.
│   ├── public/                  ← your domain will point HERE
│   ├── schema/  tools/
│   └── README.md  INSTALL.md ...
└── public_html/               ← your existing website, untouched
```

> **Why not just put it in `public_html/coldvault/`?** Because then
> `coldvault.env` sits at `https://yoursite.com/coldvault/coldvault.env`. Even if you point
> a subdomain at the `public` sub-folder, your **main** domain is still serving the parent
> folder, and it will hand that file to anyone who asks. Keeping the app outside
> `public_html` removes the possibility instead of relying on you getting a rule right.

**To upload it:**

1. Download this project as a ZIP (on GitHub: the green **Code** button → **Download ZIP**).
2. In cPanel, open **File Manager**.
3. Click **Up One Level** until the path bar shows `/home/YOURACCOUNT` — you should see
   `public_html` listed *beside* you, not above you. **Do not enter `public_html`.**
4. Click **Upload**, choose the ZIP, wait for it to finish.
5. Back in File Manager, right-click the ZIP → **Extract**.
6. Rename the extracted folder to `coldvault` (it will have a name like `coldvault-main`).
7. Delete the ZIP.

### A3. Point a subdomain at the `public` folder

Your domain needs to serve the `public` folder specifically — not the folder above it.

In cPanel, open **Domains** (older versions: **Subdomains**) and create one, for example
`vault.yoursite.com`. There will be a **Document Root** field, which cPanel pre-fills with
something like `public_html/vault`.

**Replace that value with:**

```
/home/YOURACCOUNT/coldvault/public
```

Use your real account name. Then create it.

> **Document root** just means "the folder this web address shows." Setting it to `public`
> is what keeps `coldvault.env` — which lives one level above — unreachable.

**This does work.** It was tested on cPanel 11.136: a document root of
`/home/ACCOUNT/coldvault/public` was accepted exactly as typed, not silently rewritten
back inside `public_html`, and a file placed there was served correctly. If your host has
locked this down and cPanel refuses the path or quietly changes it, check what it actually
saved and then see
[A11: if your host will not allow that](#a11-if-your-host-will-not-allow-a-docroot-outside-public_html).

#### cPanel will add some files of its own — leave them alone

The moment you create the subdomain, cPanel writes several things into the document root
that you did not put there:

| File | What it is |
|---|---|
| `.htaccess` | cPanel's PHP handler and error-log settings |
| `php.ini`, `.user.ini` | PHP settings for this folder |
| `cgi-bin/` | An empty folder cPanel always creates |
| `.well-known/` | Appears later, when AutoSSL validates your certificate (step A9) |

This is normal. Two things worth knowing:

- **Your `.htaccess` is not destroyed.** Coldvault ships its own `.htaccess` in `public/`,
  and cPanel **appends** its block to the existing file rather than replacing it (verified
  by test). So if you uploaded in step A2 before creating the subdomain here, both sets of
  rules are present and both work.
- **Do not delete cPanel's block.** The lines between `# BEGIN cPanel-generated` and
  `# END cPanel-generated` are what tell the server which PHP version to use. Removing
  them can break the site.

### A3a. Now set the PHP version for the subdomain

The subdomain has its own PHP setting, separate from your other domains — see the note in
[A1](#a1-check-that-php-81-is-available-at-all).

Go back to **MultiPHP Manager**. Your new subdomain now appears as its own row. Tick it,
choose **8.1** or newer from the dropdown, and click **Apply**.

Confirm the row shows the version you picked before moving on.

Do not skip this on the basis that the site seems to work anyway — it very likely will,
since the code runs on 7.4 too. The problem with an old version here is silent: you get a
working vault on an unpatched runtime, and nothing will ever tell you.

### A4. Create the database

A **database** is where the encrypted data is stored. Coldvault needs its own, plus a user
account that can reach *only* that database — so that if those credentials ever leak, they
open nothing else.

In cPanel, open **MySQL® Databases**:

1. Under *Create New Database*, type `coldvault` and click **Create Database**.
   cPanel will automatically name it something like `youracct_coldvault`. **Write down the
   full name it shows you, including the prefix** — you need it exactly in step A7.
2. Scroll to *MySQL Users → Add New User*. Username `coldvault` (again, cPanel adds a
   prefix). Click **Password Generator**, then **Use Password**, and **copy the password
   somewhere before you close that box.** Click **Create User**.

   > **Keep the username short.** cPanel caps a database username at **32 characters
   > including the prefix**, and the prefix is your whole account name plus an underscore.
   > If your account name is long, `coldvault` may not fit — use `cv` instead. cPanel shows
   > you the remaining allowance as you type. Whatever it ends up as, use the **full
   > prefixed name** in step A7.
3. Scroll to *Add User To Database*. Select the user and the database you just made, click
   **Add**. On the privileges page tick **ALL PRIVILEGES**, then **Make Changes**.

You should now have written down three things: the full database name, the full username,
and the password.

### A5. Import the database structure

The database exists but is empty. It needs its tables — the empty shelves the data goes on.

1. In cPanel, open **phpMyAdmin**.
2. In the left sidebar, click your `youracct_coldvault` database.
3. Click the **Import** tab at the top.
4. **Choose File**, and select `schema/coldvault.sql` from the project folder on your own
   computer (the copy you downloaded and unzipped — the same ZIP contents).
5. Scroll down and click **Import**.

You should see a green success message. Click the database name again; the sidebar should
now list **six** tables: `vault`, `vault_backup_codes`, `vault_invite`, `vault_keyslot`,
`vault_reg_throttle`, `vault_users`.

The file is about 9 KB. phpMyAdmin normally caps uploads at 2 MB (that was the exact
limit on the cPanel this guide was tested against), so it fits with room to spare.

### A6. Make your APP_KEY

`APP_KEY` must be 32 random bytes, written in base64. It has to come from a proper random
generator — **do not invent it, and do not use a website that generates keys for you.**

**Easiest way, if your cPanel has Terminal** (look for a *Terminal* icon):

```bash
php ~/coldvault/tools/genkey.php
```

That prints a line ready to paste.

**If there is no Terminal**, generate it on your own computer instead. The key is just
random bytes; where they are produced does not matter, as long as the generator is a real
one and you do not send the result anywhere.

- **macOS or Linux** — open Terminal:

  ```bash
  openssl rand -base64 32
  ```

- **Windows** — open PowerShell:

  ```powershell
  $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b)
  ```

Either produces a 44-character string ending in `=`. That is your `APP_KEY`.

### A7. Write the configuration file

1. In **File Manager**, go to `/home/YOURACCOUNT/coldvault/`.
2. You will see `coldvault.env.example`. Right-click it → **Copy**, and save the copy in the
   same folder as `coldvault.env` (drop the `.example`).
3. Right-click `coldvault.env` → **Edit**. Click through the encoding warning if it appears.

Fill in the values you collected, using the **full prefixed names** cPanel gave you:

```ini
APP_KEY=paste-the-44-character-key-from-step-A6

DB_HOST=localhost
DB_PORT=
DB_NAME=youracct_coldvault
DB_USER=youracct_coldvault
DB_PASS=the password from step A4

OTP_ISSUER=Coldvault
LOCAL_MODE=
```

Leave `DB_PORT` and `LOCAL_MODE` **empty**. `LOCAL_MODE` is only for testing on your own
computer, and switching it on here would remove the protection on your connection.

Click **Save Changes**.

> **Now do the backup.** Copy the contents of this file into your password manager, or
> print it. Do it before step A10. If you lose `APP_KEY`, every account here is locked out
> permanently and nothing can undo it.

### A8. Lock down the file permissions

**Permissions** decide who can read a file. Right now `coldvault.env` may be readable by
other accounts on the same shared server, which you do not want.

In File Manager, right-click `coldvault.env` → **Change Permissions**. Tick **only**
*Read* and *Write* for **User**. Every Group and World box must be **unticked**. The number
at the bottom should read **0600**.

> **Why 0600 here, when a VPS guide might say 0640?** On cPanel, PHP runs *as your own
> account*, so your account needs to read it and nobody else does. On a VPS, PHP usually
> runs as a separate `www-data` user, which needs group read — so that setup needs `0640`
> and a group change. **Copying the VPS advice onto cPanel makes the file unreadable and
> the site will show "Vault temporarily unavailable."** Different situations, different
> answer; this is why the paths are separate.

### A9. Turn on HTTPS

**HTTPS** is the encrypted `https://` connection — the padlock in the address bar. Coldvault
**refuses to run without it**, and that is not a formality: your keyword travels to the
server, and without HTTPS anyone between you and it can read it.

In cPanel, open **SSL/TLS Status**. Find your new subdomain, tick it, and click **Run
AutoSSL**. Wait a minute or two and refresh; you want a green padlock or "Certificate is
valid" next to it.

Most hosts do this automatically for new subdomains. If AutoSSL is missing or fails, ask
your host to issue a certificate for that subdomain — every mainstream host does this free.

### A10. Check it worked

Visit `https://vault.yoursite.com/` (your subdomain). You should see the Coldvault sign-in
screen.

Then confirm your secrets are not exposed. Visit these two addresses — **both must show an
error page, not text**:

- `https://vault.yoursite.com/coldvault.env`
- `https://yoursite.com/coldvault/coldvault.env`

If either one shows you a page containing `APP_KEY=`, **stop.** Your key is exposed on the
public internet. Go back to A2, move the folder outside `public_html`, then generate a
**new** `APP_KEY` before creating any account.

Seeing **"Vault temporarily unavailable"** instead of the sign-in screen? That single
message covers every startup problem on purpose — it never reveals which one, so an
attacker learns nothing. See [When something goes wrong](#when-something-goes-wrong).

Now skip to [Part 4](#part-4--your-first-account-and-your-first-vault).

### A11. If your host will not allow a docroot outside `public_html`

Some cheap plans lock document roots inside `public_html`. That is workable but weaker,
because you are now relying on a rule being right rather than on the file being out of
reach.

Put the app at `public_html/coldvault/`, set the subdomain's document root to
`public_html/coldvault/public`, and then create a file called `.htaccess` **inside**
`public_html/coldvault/` containing exactly:

```apache
<Files "coldvault.env">
    Require all denied
</Files>
Options -Indexes
```

Then **test it** — visit `https://yoursite.com/coldvault/coldvault.env` and confirm you get
a *Forbidden* error and not your key. If you see the key, do not proceed; ask your host for
a docroot outside `public_html`, or use a different host.

---

## Path B — Your own Linux server (VPS)

You have root access, so you install and configure everything yourself.
**[INSTALL.md](INSTALL.md) has the exact commands** and stays the single source of truth for
them. What follows is what those steps *are for*, so you are not typing commands blind.

| INSTALL.md step | What it does, in plain terms |
|---|---|
| [1. Packages](INSTALL.md#1-install-the-packages) | Installs the four pieces: Apache (serves web pages), PHP (runs this app), MariaDB (stores the data), certbot (gets a free HTTPS certificate). |
| [2. Get the code](INSTALL.md#2-get-the-code) | Downloads the project to `/var/www/coldvault`. The `public` sub-folder is the only part the web ever sees. |
| [3. Database](INSTALL.md#3-create-the-database) | Creates an empty database plus a login that can reach *only* it — so leaked credentials open nothing else. |
| [4. Import](INSTALL.md#4-import-the-structure) | Creates the six tables. The database is empty until you do this. |
| [5. APP_KEY + config](INSTALL.md#5-generate-an-app_key-and-write-the-configuration) | Generates the key that protects logins, and writes it with the database password into `coldvault.env`. **Back this file up here, not later.** |
| [6. Permissions](INSTALL.md#6-file-ownership-and-permissions) | Makes `coldvault.env` readable by PHP and by nothing else. On a VPS this is `640` with a group change — **not** the `600` that cPanel needs. |
| [7. Apache](INSTALL.md#7-configure-apache) | Tells Apache which domain serves this and from which folder. `DocumentRoot` **must** end in `/public`, or you publish your own secrets. |
| [8. Certificate](INSTALL.md#8-get-an-https-certificate) | Gets the free HTTPS certificate. The app will not serve pages without one. |
| [9. IP logging](INSTALL.md#9-turn-off-ip-logging-optional-but-recommended) | Optional. The app records no visitor addresses, but Apache does by default, before the app runs. This turns that off. |
| [10. Verify](INSTALL.md#10-verify-the-install) | Proves it works *and* that `coldvault.env` is not downloadable. Do not skip it. |

Two things people get wrong, both easy to avoid:

- **`DocumentRoot` pointing one folder too high.** If it points at `/var/www/coldvault`
  instead of `/var/www/coldvault/public`, your `APP_KEY` is on the public internet. Step 10
  tests for exactly this.
- **Forgetting `AllowOverride All`.** Without it Apache ignores the app's own rules file and
  the tidy addresses like `/register/` return "Not Found", while the home page works. That
  specific symptom means this specific cause.

Then come back to [Part 4](#part-4--your-first-account-and-your-first-vault).

---

## Path C — Windows or macOS, just to try it

For looking at the software with fake data. **Do not put a real recovery phrase in this
setup** — it runs without an encrypted connection.

### C1. Install a bundle

You need PHP and MySQL together. One installer gives you both:

- **Windows** — [XAMPP](https://www.apachefriends.org/) or
  [Laragon](https://laragon.org/)
- **macOS** — [MAMP](https://www.mamp.info/) or XAMPP

Install with the defaults, open the control panel, and **start MySQL**. You do not need to
start Apache: we will use a simpler web server that PHP includes.

### C2. Put the files somewhere simple

Download this project's ZIP and extract it to a short path:

- Windows: `C:\coldvault`
- macOS: `/Users/yourname/coldvault`

**Do not put it inside XAMPP's `htdocs` or MAMP's `htdocs`.** Those folders are published by
Apache, and `coldvault.env` would be downloadable from them. Keeping it outside avoids that
entirely.

### C3. Create the database

Open `http://localhost/phpmyadmin` (XAMPP) or `http://localhost:8888/phpMyAdmin` (MAMP).

1. Click **New** in the left sidebar.
2. Database name `coldvault`. For collation choose `utf8mb4_general_ci`. Click **Create**.
3. With `coldvault` selected, click **Import**, choose `schema/coldvault.sql` from the
   folder you extracted, and click **Import**.

Six tables should appear in the sidebar.

On a fresh local install the database login is usually `root` with **no password** (XAMPP)
or `root` / `root` (MAMP). That is fine on your own machine and nowhere else.

### C4. Write the configuration

Copy `coldvault.env.example` to `coldvault.env` in the same folder, open it in Notepad or
TextEdit, and set:

```ini
APP_KEY=paste the 44-character key here
DB_HOST=127.0.0.1
DB_PORT=
DB_NAME=coldvault
DB_USER=root
DB_PASS=
OTP_ISSUER=Coldvault Test
LOCAL_MODE=1
```

For `APP_KEY`, use the PowerShell or `openssl` command in [step A6](#a6-make-your-app_key).

`LOCAL_MODE=1` is what lets it run without HTTPS. **It is correct here and nowhere else.**

> MAMP users: if MySQL is on port 8889, set `DB_PORT=8889`.

### C5. Run it

Open a terminal — Command Prompt on Windows, Terminal on macOS — and run:

```bash
cd C:\coldvault\public
```

```bash
php -S localhost:8080
```

If `php` is not recognised on Windows, use the full path, e.g.
`C:\xampp\php\php.exe -S localhost:8080`. On macOS with MAMP it is
`/Applications/MAMP/bin/php/php8.1.*/bin/php`.

Open **`http://localhost:8080/`**. Leave that terminal window open while you use it;
closing it stops the server.

Because this simple server does not read the app's rules file, use these addresses instead
of the tidy ones:

| Instead of | Use |
|---|---|
| `/register/` | `http://localhost:8080/?screen=register` |
| `/help/` | `http://localhost:8080/?screen=help` |

> **This is reachable only from this computer.** Other devices on your network cannot open
> it, which is intentional. If you are tempted to change `localhost` to `0.0.0.0` to reach
> it from your phone — **don't**, not while `LOCAL_MODE=1`. That would broadcast your
> keyword in the clear across your whole network. [INSTALL.md §14](INSTALL.md#14-running-it-locally--with-or-without-https)
> explains how to do it properly with a real certificate.

Then see [Part 4](#part-4--your-first-account-and-your-first-vault). When you are finished
looking, close the terminal, drop the `coldvault` database in phpMyAdmin, and delete the
folder.

---

## Path D — Linux, just to try it

Same purpose as Path C: evaluation with fake data, no real phrase.

```bash
sudo apt install -y php php-mysql mariadb-server
sudo systemctl start mariadb
```

```bash
sudo mysql -e "CREATE DATABASE coldvault CHARACTER SET utf8mb4;
CREATE USER 'cv'@'localhost' IDENTIFIED BY 'testonly';
GRANT ALL ON coldvault.* TO 'cv'@'localhost';"
```

```bash
mysql -u cv -ptestonly coldvault < schema/coldvault.sql
```

```bash
printf 'APP_KEY=%s\nDB_HOST=127.0.0.1\nDB_NAME=coldvault\nDB_USER=cv\nDB_PASS=testonly\nLOCAL_MODE=1\n' \
  "$(php tools/genkey.php | grep -oE 'APP_KEY=.*' | cut -d= -f2-)" > coldvault.env
chmod 600 coldvault.env
```

```bash
cd public && php -S localhost:8080
```

Open `http://localhost:8080/`. The same subdirectory note and the same `0.0.0.0` warning
from Path C apply. To remove it afterwards: `sudo mysql -e "DROP DATABASE coldvault;"` and
delete the folder.

---

## Part 4 — Your first account and your first vault

Same for every path.

### Create your account

1. Open your Coldvault address and click **Create an account** (or go to `/register/`).
2. Choose a username. Letters, numbers, `_`, `.` and `-`, between 3 and 32 characters. It is
   not published anywhere.
3. Type the characters from the distorted image. That is there to stop automated sign-ups.
4. You are shown a **QR code**. Open an authenticator app on your phone and scan it.

   > **Authenticator app** means one that shows a 6-digit code changing every 30 seconds:
   > Google Authenticator, Authy, 1Password, Bitwarden, Aegis. Any of them works. There is
   > **no password** on this account — that code is how you sign in.

5. Type the 6-digit code your app shows, to prove the pairing worked.
6. **You are now shown eight backup codes. Save them now.** They are displayed once and only
   their hashes are stored, so they can never be shown again. They are your only way in if
   you lose your phone. Screenshot them into your password manager, or write them down.

### Create your first vault

1. Sign in and choose **New vault**.
2. Pick how many words your phrase has — 12, 15, 18, 20, 21, 24 or 33. If you are unsure,
   count them. You can also paste the whole phrase into the first box and the form will
   count and resize itself.
3. Type or paste the words. Optionally add the wallet's PIN and its passphrase if it has one.
4. Choose your **keyword**. This is the password that encrypts this vault.

   The form will refuse anything too weak, and tells you as you type. The bar needs to reach
   about **65 bits**. To put that in perspective: `Fluffy2019` scores 60 and is **rejected**.
   A four-word phrase like `correct-horse-battery-staple` scores 44 and is **rejected**.

   > **Press Generate.** It produces a random seven-word phrase which is both far stronger
   > than anything you will invent and easy enough to write down. There is no advantage to
   > choosing your own here.

5. **Write the keyword on paper before you click save.** If you lose it, this vault is
   unrecoverable by anyone.
6. Save. To confirm it really worked, lock the vault and unlock it once with your keyword.

Unlocking takes about a second. That is intentional — the delay is what makes guessing
your keyword impractical.

---

## What to write down, and where to keep it

Three separate things. **Do not keep them all in one place**, and do not keep any of them
only on the machine that runs Coldvault.

| What | Why it matters | Where |
|---|---|---|
| **Your vault keyword(s)** | Lose it and that vault is unrecoverable by anyone | Paper, or a password manager you already back up |
| **`coldvault.env`** (contains `APP_KEY`) | Lose it and every account is locked out permanently | Password manager, encrypted USB, or printed and stored safely |
| **Your eight backup codes** | Your only way in if your phone is lost | With your other account recovery codes |

And keep making database backups. On cPanel: **Backup → Download a MySQL Database Backup**.
On a server: see [INSTALL.md §12](INSTALL.md#12-backups). A backup file on its own reveals
no phrase and no keyword — but restoring it needs the *same* `APP_KEY` the data was written
with, which is one more reason that file matters.

---

## When something goes wrong

### "Vault temporarily unavailable"

Every startup failure gives this same message on purpose, so that an attacker cannot learn
which part is broken. Check these in order:

1. **Is `coldvault.env` in the right place?** It belongs one level *above* the `public`
   folder — beside it, not inside it.
2. **Is `APP_KEY` filled in, and complete?** It must be exactly the 44-character string,
   `=` included. A truncated paste is the most common cause.
3. **Are the database name and username the full prefixed versions?** On cPanel these are
   `youracct_coldvault`, not `coldvault`. This is the second most common cause.
4. **Is the database password right?** Test it by logging in to phpMyAdmin with that
   username and password.
5. **Did the import actually run?** The database must contain six tables. An empty database
   gives this same message.
6. **Are the permissions right?** `0600` on cPanel. `0640` with the right group on a VPS.

Server people: [INSTALL.md §13](INSTALL.md#13-troubleshooting) has commands that check each
of these directly.

### The home page works, but `/register/` says "Not Found"

The web server is ignoring the app's rules file. On a VPS, `AllowOverride All` is missing
from the Apache configuration. On the built-in server used by Paths C and D this is normal
— use `?screen=register` instead.

### It keeps redirecting, or will not load at all

The app is trying to force HTTPS and something is undoing it. Usually the certificate is
not issued yet (Path A step A9), or there is a proxy or CDN in front that is not telling the
app the connection is already encrypted. **Do not work around this by turning on
`LOCAL_MODE`** — that switches off the protection instead of fixing it.

### "HTTPS required." when submitting a form

The page was loaded over `http://` rather than `https://`. Load the `https://` address.

### The distorted image will not load

The server cannot write its temporary session files. On shared hosting, contact your host.

### "JavaScript is required to open a vault."

Working as designed, not a fault. Your phrase is deliberately never placed inside the page's
source, so that it cannot end up in your browser history or be re-sent by a page reload.
Enable JavaScript for the site.

### Buttons do nothing, or the page looks unstyled

Something is adding a second security policy header — often a CDN, or a rule copied into
the web server config. The app sets its own and two conflicting ones cancel each other out.
Remove yours.

---

## Where to go next

- **[GLOSSARY.md](GLOSSARY.md)** — every technical term in this project, explained.
- **[SECURITY.md](SECURITY.md)** — what this protects you from, what it does not, and every
  known weakness. Worth reading even if some of it is unfamiliar; the first section needs no
  technical background.
- **[INSTALL.md](INSTALL.md)** — the concise reference version of setup.
- **[README.md](README.md)** — how the encryption works and how sharing a vault works.
