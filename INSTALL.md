# Installing Coldvault

A complete walkthrough on a fresh Linux server: PHP, Apache, MySQL/MariaDB, HTTPS,
the database structure, and the `APP_KEY`.

Budget about 20 minutes. Nothing here needs Composer, Node, or a build step.

> **This page assumes you are comfortable with a Linux command line, Apache configuration
> and a database client.** If you are not, read
> **[GETTING-STARTED.md](GETTING-STARTED.md)** instead — same process, explained from
> scratch, with a path for cPanel shared hosting that needs no command line at all, and one
> for simply trying it on your own computer. Unfamiliar term? See
> [GLOSSARY.md](GLOSSARY.md).

**Contents**

1. [Install the packages](#1-install-the-packages)
2. [Get the code](#2-get-the-code)
3. [Create the database](#3-create-the-database)
4. [Import the structure](#4-import-the-structure)
5. [Generate an APP_KEY and write the configuration](#5-generate-an-app_key-and-write-the-configuration)
6. [File ownership and permissions](#6-file-ownership-and-permissions)
7. [Configure Apache](#7-configure-apache)
8. [Get an HTTPS certificate](#8-get-an-https-certificate)
9. [Turn off IP logging (optional but recommended)](#9-turn-off-ip-logging-optional-but-recommended)
10. [Verify the install](#10-verify-the-install)
11. [First run: create your account and your first vault](#11-first-run-create-your-account-and-your-first-vault)
12. [Backups](#12-backups)
13. [Troubleshooting](#13-troubleshooting)
14. [Running it locally — with or without HTTPS](#14-running-it-locally--with-or-without-https)

---

## 1. Install the packages

### Debian 12 / Ubuntu 22.04+

```bash
sudo apt update
sudo apt install -y apache2 libapache2-mod-php mariadb-server \
                    php php-mysql php-gd certbot python3-certbot-apache
sudo a2enmod rewrite headers ssl
sudo systemctl enable --now apache2 mariadb
```

### RHEL 9 / AlmaLinux 9 / Rocky 9

```bash
sudo dnf install -y httpd mod_ssl mariadb-server \
                    php php-mysqlnd php-gd certbot python3-certbot-apache
sudo systemctl enable --now httpd mariadb php-fpm
```

`mod_rewrite` and `mod_headers` are built into the base `httpd` package on RHEL-family
systems; no `a2enmod` equivalent is needed.

### What each piece is for

| Package | Why |
|---|---|
| `php` | 8.1 or newer. `openssl` and `json` are compiled in. |
| `php-mysql` / `php-mysqlnd` | The `mysqli` driver. Required. |
| `php-gd` | **Required**, with FreeType. Draws the CAPTCHA, which is the rate limiter on a passwordless sign-in. The old SVG fallback was reconstructible from the page markup and has been removed; the app refuses to start without `gd`. |
| `php-mbstring` | **Required.** Folds letter case in the keyword strength gate. Without it the server scores non-ASCII keywords higher than the meter shown to the user, and would accept keywords its own meter refused. The app refuses to start without it. |
| `mod_rewrite` | Clean URLs (`/register/`, `/help/`, `/redeem/`, `/security/`). |
| `mod_headers` | The static security headers in `public/.htaccess`. |
| `certbot` | A free HTTPS certificate. HTTPS is **not optional** here. |

Confirm the version and the extensions:

```bash
php -v && php -m | grep -E '^(openssl|mysqli|json|gd)$'
```

You need `openssl`, `mysqli` and `json`. `gd` is a bonus.

---

## 2. Get the code

```bash
sudo mkdir -p /var/www
sudo git clone https://github.com/bitcoin-minion/coldvault.git /var/www/coldvault
cd /var/www/coldvault
```

The document root will be `/var/www/coldvault/public`. The configuration file lives one
level up, at `/var/www/coldvault/coldvault.env`, where the web server cannot serve it even
if a rewrite rule is misconfigured. **Keep that arrangement.**

---

## 3. Create the database

Secure the server first if this is a fresh install:

```bash
sudo mysql_secure_installation
```

Then create a database and a user whose rights reach **nothing else**:

```bash
sudo mysql
```

```sql
CREATE DATABASE coldvault CHARACTER SET utf8mb4;
CREATE USER 'coldvault'@'localhost' IDENTIFIED BY 'PUT-A-LONG-RANDOM-PASSWORD-HERE';
GRANT ALL PRIVILEGES ON coldvault.* TO 'coldvault'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Generate that password rather than inventing one:

```bash
openssl rand -base64 30
```

**Why a dedicated user matters.** Coldvault's rows are ciphertext, so these credentials
leaking is survivable. Credentials that *also* open your other databases are not. Grant
this user access to one database and nothing more.

Confirm the confinement actually holds — the second command must fail:

```bash
mysql -u coldvault -p -e "SHOW TABLES;" coldvault
mysql -u coldvault -p -e "SHOW DATABASES;" | grep -v -E 'Database|information_schema|coldvault'
```

---

## 4. Import the structure

```bash
mysql -u coldvault -p coldvault < /var/www/coldvault/schema/coldvault.sql
```

Six tables, structure only — no data, no users, no keys:

```bash
mysql -u coldvault -p coldvault -e "SHOW TABLES;"
```

```
vault
vault_backup_codes
vault_invite
vault_keyslot
vault_reg_throttle
vault_users
```

The file gives no `COLLATE` clause, so each table takes your server's default utf8mb4
collation. That is what keeps it portable between MySQL 8 and MariaDB. Nothing in the app
depends on collation: every secret column is `varbinary`.

---

## 5. Generate an APP_KEY and write the configuration

```bash
cd /var/www/coldvault
sudo cp coldvault.env.example coldvault.env
php tools/genkey.php
```

`genkey.php` prints one line. Paste it into `coldvault.env`, then fill in the database
settings:

```bash
sudo nano coldvault.env
```

```ini
APP_KEY=<the base64 string genkey.php printed>

DB_HOST=localhost
DB_PORT=
DB_NAME=coldvault
DB_USER=coldvault
DB_PASS=<the password from step 3>

OTP_ISSUER=Coldvault
LOCAL_MODE=
```

### Back APP_KEY up now, before you create an account

`APP_KEY` encrypts the stored authenticator secrets and hashes the backup codes and invite
codes.

- **Lose it and every account is locked out permanently.** The vault ciphertext survives
  intact — but no authenticator code and no backup code can be verified, so nothing can
  sign in to reach it.
- **Changing it on a live instance has exactly the same effect.** Generate it once.
- It does **not** encrypt recovery phrases. Those are encrypted under each vault's own
  keyword, which is never stored. So `APP_KEY` plus a full database dump still reveals no
  phrase.

Copy `coldvault.env` somewhere off this machine — a password manager entry, an encrypted
USB stick, paper in a safe. Do it before step 11.

---

## 6. File ownership and permissions

Find out which user PHP runs as:

```bash
ps -o user= -C apache2 | sort -u ; ps -o user= -C httpd | sort -u ; ps -o user= -C php-fpm | sort -u
```

Usually `www-data` (Debian/Ubuntu) or `apache` (RHEL family). Substitute below.

```bash
cd /var/www/coldvault
sudo chown -R root:www-data .
sudo find . -type d -exec chmod 755 {} \;
sudo find . -type f -exec chmod 644 {} \;

# The configuration file: readable by PHP, writable by nobody, invisible to other users.
sudo chown root:www-data coldvault.env
sudo chmod 640 coldvault.env
```

`640` with `root` as owner is better than `600` owned by the web user: PHP can read the
file but cannot rewrite it, and no other local account can read it at all.

Verify:

```bash
sudo -u www-data test -r /var/www/coldvault/coldvault.env && echo "PHP can read it" || echo "PHP CANNOT read it"
```

---

## 7. Configure Apache

### Debian / Ubuntu

```bash
sudo nano /etc/apache2/sites-available/coldvault.conf
```

### RHEL family

```bash
sudo nano /etc/httpd/conf.d/coldvault.conf
```

Either way, the vhost — replace `vault.example.com` throughout:

```apache
<VirtualHost *:80>
    ServerName vault.example.com
    Redirect permanent / https://vault.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName vault.example.com
    DocumentRoot /var/www/coldvault/public

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/vault.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/vault.example.com/privkey.pem

    <Directory /var/www/coldvault/public>
        # REQUIRED — without it .htaccess is ignored and the clean URLs 404.
        AllowOverride All
        Require all granted
        Options -Indexes
    </Directory>

    ErrorLog  /var/log/apache2/coldvault-error.log
    CustomLog /var/log/apache2/coldvault-access.log combined
</VirtualHost>
```

On RHEL family, the log paths are `/var/log/httpd/` instead.

**`DocumentRoot` must point at `public/`, never at the repository root.** Pointing it one
level up would put `coldvault.env` inside the served tree.

Enable and reload:

```bash
sudo a2ensite coldvault && sudo apachectl configtest && sudo systemctl reload apache2
```

```bash
sudo apachectl configtest && sudo systemctl reload httpd
```

---

## 8. Get an HTTPS certificate

The app **refuses to serve over plain HTTP**. The keyword is the encryption key; over
cleartext anyone on the network path reads it, and with it the recovery phrase. This is
enforced in `public/config.php`, not merely suggested.

```bash
sudo certbot --apache -d vault.example.com
```

Certbot installs the certificate and sets up renewal. Check renewal works:

```bash
sudo certbot renew --dry-run
```

**Behind a reverse proxy or load balancer that terminates TLS?** Make sure it forwards
`X-Forwarded-Proto: https`, **and** set `TRUST_FORWARDED_PROTO=1` in `coldvault.env` so
`config.php` will honour that header (it is ignored by default, because otherwise any client
could send it over plain HTTP). Without both you get `403 HTTPS required.`, or a redirect loop
if `CANONICAL_HOST` is set.

---

## 9. Turn off IP logging (optional but recommended)

The application records **no client IP anywhere** — no `REMOTE_ADDR`, no address column,
no per-visitor counter. But your web server logs every request with the client address
*before PHP ever runs*, so the application cannot do anything about it.

If you want the privacy stance to be real, change it in the vhost. Either drop the access
log entirely:

```apache
CustomLog /dev/null combined
```

Or keep the log and omit the address:

```apache
LogFormat "- - - [%t] \"%r\" %>s %b" cv_noip
CustomLog /var/log/apache2/coldvault-access.log cv_noip
```

Then reload Apache. Also check for anything that resurrects the data: log rotation
archives, a hosting panel's traffic statistics, a CDN or proxy in front, and fail2ban.

Note the error log can still contain paths and occasional request detail. Keep it, but
know it exists.

---

## 10. Verify the install

```bash
curl -sI https://vault.example.com/ | head -1
```

Expect `HTTP/1.1 200`. Then walk the checks:

```bash
# Clean URLs work -> AllowOverride All is in effect
curl -sI https://vault.example.com/register/ | head -1
curl -sI https://vault.example.com/help/     | head -1

# Nothing that holds a secret is reachable over the web.
# 2026-09-08: expect 403 or 404 — NOT 200, and never any file content.
# The .backup line is here because UPGRADING.md asks you to keep a copy of the configuration
# before updating, and on a shared host a copy left in the tree used to be served on request.
# Keep the copy outside the project (UPGRADING.md says so now); check anyway.
curl -sI https://vault.example.com/coldvault.env         | head -1
curl -sI https://vault.example.com/coldvault.env.backup  | head -1
curl -sI https://vault.example.com/coldvault.env.bak     | head -1
curl -sI https://vault.example.com/index.php.previous    | head -1
curl -sI https://vault.example.com/env.php               | head -1
curl -sI https://vault.example.com/config.php            | head -1

# Both required extensions are loaded. The app REFUSES TO START without either, so a
# "Vault temporarily unavailable" page with a healthy database is usually one of these.
php -r 'foreach (["gd","mbstring"] as $e) printf("%-9s %s\n", $e, extension_loaded($e) ? "ok" : "MISSING");'
php -r 'printf("freetype  %s\n", function_exists("imagettftext") ? "ok" : "MISSING");'

# The import created all seven tables
mysql -u coldvault -p coldvault -e "SHOW TABLES;" | tail -n +2 | wc -l    # expect 7

# PHP is executing, not being served as text (expect no "<?php" in the output)
curl -s https://vault.example.com/ | grep -c '<?php'

# The security headers are present
curl -sI https://vault.example.com/ | grep -iE 'content-security-policy|strict-transport|x-frame|permissions-policy|referrer'

# Plain HTTP redirects rather than serving
curl -sI http://vault.example.com/ | head -1

# The bundled fonts are being served (expect 200 and font/woff2)
curl -sI https://vault.example.com/fonts/ibm-plex-sans-latin.woff2 | grep -iE '^HTTP|content-type'

# No page requests anything off your own origin (expect no output)
curl -s https://vault.example.com/help/ | grep -oE 'https?://[a-zA-Z0-9./_+-]+' | grep -v 'w3.org/2000/svg'
```

That last check is worth keeping in mind if you modify the templates. The app
deliberately fetches nothing from a CDN or a font host, and the
Content-Security-Policy (`default-src 'self'`, no external origin) enforces it — so
adding an outside asset will fail silently in the browser until you widen the policy.

`env.php` and `config.php` are worth a word, because this section used to describe them
wrongly — it told you to expect `404` and then explained you might get an empty `200`.
Neither is right. Both files *are* inside `public/`, so Apache can see them, but
`public/.htaccess` denies them by name, so the correct answer is **403 Forbidden**. If you
get `200` with any content, or a page of PHP source, then `AllowOverride All` is not in
effect for this directory and **none** of the protections in that file are either — including
the header block below. Fix that before going further.

What matters most is that `coldvault.env` itself, one directory up from `public/`, is not
web-reachable at all. Keep it out of the document root; that is the protection. The deny
rules are the second line, for the case where a host forces you to put the project inside
`public_html` — see
[A11 in GETTING-STARTED.md](GETTING-STARTED.md#a11-if-your-host-will-not-allow-a-docroot-outside-public_html),
which describes that layout and what to test.

---

## 11. First run: create your account and your first vault

1. Open `https://vault.example.com/register/`.
2. Pick a username (3–32 characters: letters, digits, `_`, `.`, `-`) and solve the CAPTCHA.
3. Scan the QR code with any TOTP authenticator, then enter the 6-digit code it shows.
4. **Save the eight backup codes.** They are shown once and stored only as hashes. Without
   them, a lost phone means a lost account.
5. Sign in and choose **New vault**.
6. Select your phrase length, paste or type the words, add the optional PIN and passphrase.
7. Choose a **keyword** that clears the 65-bit floor. Hit **Generate** for a random 7-word
   passphrase, or audit your own idea first, on a different machine:

   ```bash
   php tools/kwcheck.php
   ```

   It reads the keyword from the terminal with echo off, refuses to take it as a command
   line argument, writes nothing to disk and makes no network calls.

8. **Write the keyword down and store it somewhere safe.** It is never stored on the
   server, is not recoverable, and without it the vault cannot be decrypted by anyone —
   including you.

### Close the door behind you

Registration is open by default. Once your accounts exist, either keep the sign-up page
behind something or accept that strangers can create accounts (they can never reach your
vaults — a vault requires a keyslot). To close it entirely, add this to the vhost:

```apache
<Location "/register/">
    Require ip 203.0.113.0/24
</Location>
```

---

## 12. Backups

Two separate things, and they must be stored separately.

**1. `coldvault.env`** — off the server, before you create an account. See step 5. This is
the one that cannot be regenerated.

**2. The database:**

```bash
mysqldump -u coldvault -p --single-transaction coldvault > coldvault-$(date +%F).sql
```

The dump is ciphertext, hashes and encrypted labels. On its own it reveals no phrase and
no keyword — not even with `APP_KEY`, because phrases are encrypted under the vault
keyword, which is stored nowhere. Still encrypt the dump at rest: it tells an observer how
many accounts and vaults exist, and it is the thing an attacker would grind keywords
against offline.

**Restoring** takes both: the dump, and the *same* `APP_KEY` the data was written under.

---

## 13. Troubleshooting

### `Vault temporarily unavailable.` (HTTP 503)

Every startup failure gives this one vague answer on purpose — it never reveals whether
the configuration file, the key, the database user or the host is at fault. Check in this
order:

```bash
# 1. Can PHP read the configuration file?
sudo -u www-data test -r /var/www/coldvault/coldvault.env && echo ok || echo "unreadable"

# 2. Does APP_KEY decode to exactly 32 bytes?
php -r '$l=trim(shell_exec("grep -m1 \"^APP_KEY=\" /var/www/coldvault/coldvault.env"));
        $v=substr($l,8); $d=base64_decode($v,true);
        echo ($d===false ? "not valid base64" : strlen($d)." bytes")."\n";'

# 3. Do the database credentials work?
mysql -u coldvault -p coldvault -e "SELECT COUNT(*) FROM vault_users;"
```

Step 2 must print exactly `32 bytes`. The app refuses to start on anything else,
deliberately: a wrong key would otherwise fail silently and write authenticator secrets
the real key could never read again.

### `/register/` returns 404, but `/` works

`.htaccess` is being ignored. `AllowOverride All` is missing from the `<Directory>` block,
or `mod_rewrite` is not enabled.

```bash
apache2ctl -M | grep -E 'rewrite|headers'
```

### Redirect loop

TLS is terminated upstream and `X-Forwarded-Proto: https` is not reaching PHP, or it is
arriving but `TRUST_FORWARDED_PROTO` is not set so PHP ignores it. Fix it at the proxy and in
`coldvault.env`. Do **not** work around it by enabling `LOCAL_MODE`.

### `HTTPS required.` on every page

PHP believes the request arrived over plain HTTP and no `CANONICAL_HOST` is configured, so it
refuses rather than redirect to an attacker-controllable `Host`. Behind a proxy this is the
same cause as the redirect loop above: forward `X-Forwarded-Proto: https` and set
`TRUST_FORWARDED_PROTO=1`. On a direct Apache install, make sure the vhost actually serves
HTTPS. Optionally set `CANONICAL_HOST=your.host.name` if you want the app to redirect plain
HTTP itself instead of refusing it.

### `HTTPS required.` on form submission only

The POST arrived over plain HTTP. Check the form is being served from the `https://` URL
and that no upstream is downgrading it.

### The page loads but nothing is clickable, buttons do nothing

The Content-Security-Policy nonce is not matching. Almost always one of:

- A second CSP header set in `.htaccess`, the vhost, or a proxy. **Two CSP headers are
  both enforced**, and the intersection blocks the app's own scripts. Remove yours; the
  policy belongs in `config.php`.
- Output buffering or a rewrite that alters the HTML after PHP emits it.

Check you have exactly one:

```bash
curl -sI https://vault.example.com/ | grep -ci content-security-policy
```

That must print `1`.

### The CAPTCHA image is blank or broken

```bash
curl -sI https://vault.example.com/captcha.php | grep -i content-type
```

Expect `image/png` (GD present) or `image/svg+xml` (fallback). If neither, the session
directory is probably not writable by the PHP user.

### Unlocking says "JavaScript is required to open a vault."

Working as designed. The phrase is fetched over an authenticated request and written into
the page by script, so it never exists inside an HTML document — that is what keeps it out
of history entries and resubmittable POSTs. There is deliberately no non-JS fallback.

### A vault takes ~1 second to unlock

Also working as designed. That is 450,000 PBKDF2 iterations. An attacker pays the same
price on every guess. Lower `VAULT_ITER` only if you understand what you are giving up;
raising it is always safe, and existing vaults keep the count stored on their own row.

---

## 14. Running it locally — with or without HTTPS

> **This section is only about your own machine.** A normal hosted install needs nothing
> from it. "HTTPS is mandatory" means the app *requires* SSL — so a server that has a
> certificate is the intended case and works with no extra configuration and `LOCAL_MODE`
> left empty. Deploy the files, point the vhost at `public/`, and you are done; steps 1–11
> above are the whole process.
>
> The app accepts any signal a real host provides: `HTTPS=on`, `HTTPS=1`, `SERVER_PORT`
> 443, or `X-Forwarded-Proto: https` when TLS is terminated by a proxy, load balancer or
> CDN in front of it and `TRUST_FORWARDED_PROTO=1` is set. `LOCAL_MODE` exists only for `localhost`, where obtaining a
> certificate is awkward — **never** as a way to run a public instance without one.

HTTPS is enforced on any reachable host, but you have two ways to run it on your own
machine. **Option B is the better one if you plan to change any code.**

### Option A — no certificate: `LOCAL_MODE`

Set this in `coldvault.env`:

```ini
LOCAL_MODE=1
```

That relaxes the HTTPS requirement and drops the `Secure` flag from the session cookie, so
`http://localhost` works. Nothing else to install:

```bash
cd /var/www/coldvault/public
php -S localhost:8080
```

The clean URLs (`/register/`, `/help/`, `/redeem/`, `/security/`) come from `.htaccess`, so
the built-in server will not route them. Use the query-string forms instead:
`http://localhost:8080/?screen=register`, `?screen=help`, `?screen=redeem`,
`?screen=security`.

**Never set `LOCAL_MODE` on a host anyone else can reach.** Over cleartext HTTP the
keyword — which *is* the encryption key — is readable by anyone on the network path, and
with it the recovery phrase.

#### `localhost` means loopback only — and that is a feature here

`php -S localhost:8080` binds **127.0.0.1 and nothing else**. Only the machine running it
can connect. From another device on your network — `http://10.10.5.23:8080`, say — you get
connection refused. Confirm it yourself:

```bash
ss -ltnp | grep 8080
```

You will see `127.0.0.1:8080`, not `0.0.0.0:8080`.

**Do not "fix" that with `php -S 0.0.0.0:8080` while `LOCAL_MODE` is on.** That combination
serves the vault in cleartext across your whole network: every keyword typed crosses the
LAN readable, the session cookie loses its `Secure` flag, and anyone sharing that network —
or its Wi-Fi — can take both. `LOCAL_MODE` is keyed off the flag, not the hostname; the app
cannot tell `localhost` from a LAN address, so nothing will stop you.

**To reach it from other devices on your network, use Option B instead.** `mkcert` accepts
an IP or a hostname, so you get real TLS over the LAN:

```bash
mkcert 10.10.5.23 coldvault.lan
```

Serve that with Apache or nginx bound to the address, leave `LOCAL_MODE` empty, and install
the mkcert root CA on each device that will connect — `mkcert -CAROOT` shows where it lives.
Those devices then trust the certificate with no warning page.

### Option B — real HTTPS locally, with `LOCAL_MODE` off

You do **not** need a public domain or a Let's Encrypt certificate to run HTTPS on your
own machine. [`mkcert`](https://github.com/FiloSottile/mkcert) creates a private
certificate authority, installs it into your OS and browser trust stores, and issues certs
your browser accepts with **no warning page**:

```bash
# Debian/Ubuntu: apt install mkcert   ·   macOS: brew install mkcert
mkcert -install
mkcert coldvault.localhost
```

That writes `coldvault.localhost.pem` and `coldvault.localhost-key.pem` into the current
directory. Move them somewhere sensible and point a vhost at them:

```apache
<VirtualHost *:443>
    ServerName coldvault.localhost
    DocumentRoot /var/www/coldvault/public

    SSLEngine on
    SSLCertificateFile    /etc/ssl/local/coldvault.localhost.pem
    SSLCertificateKeyFile /etc/ssl/local/coldvault.localhost-key.pem

    <Directory /var/www/coldvault/public>
        AllowOverride All
        Require all granted
        Options -Indexes
    </Directory>
</VirtualHost>
```

Add the hostname to your hosts file, leave `LOCAL_MODE` empty, and reload Apache:

```bash
echo "127.0.0.1 coldvault.localhost" | sudo tee -a /etc/hosts
sudo systemctl reload apache2
```

Then open `https://coldvault.localhost/`. Clean URLs work, the `Secure` cookie flag is
set, and the HTTPS gate is satisfied — the same code path production runs.

### Why Option B is better if you are changing code

**PHP's built-in server cannot do TLS at all.** `php -S` has no HTTPS support, so
Option A is the *only* way to use it — which means `LOCAL_MODE` is the only way to run
without a real web server.

That matters because `LOCAL_MODE` changes real behaviour: it skips the HTTPS gate in
`config.php` and clears the `Secure` flag in `auth_session_start()`. A bug that appears
only with the flag on — or only with it off — is a bug you will never reproduce in the
other environment. If you are touching sessions, cookies, the CSP, or the HTTPS gate
itself, use Option B.

### If `mkcert` is unavailable

A plain self-signed certificate also satisfies the app, because the check is on the
protocol, not on who signed the certificate. Your browser will show an interstitial you
have to click through every session, which is why `mkcert` is preferred:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout coldvault.localhost-key.pem -out coldvault.localhost.pem \
  -subj "/CN=coldvault.localhost" -addext "subjectAltName=DNS:coldvault.localhost"
```

**Behind a TLS-terminating proxy instead?** `config.php` also accepts
`X-Forwarded-Proto: https` once `TRUST_FORWARDED_PROTO=1` is set, so a local Caddy, Traefik or
nginx in front of `php -S` works with `LOCAL_MODE` off — provided the proxy actually sets that
header.
