# Glossary

Every technical term used anywhere in this project, in plain language. Written for someone
with no background in web servers or cryptography.

You do not need to read this front to back. Look up what you hit.

**Jump to:** [Coldvault's own words](#coldvaults-own-words) ·
[Wallets and recovery phrases](#wallets-and-recovery-phrases) ·
[Web servers and hosting](#web-servers-and-hosting) ·
[Databases](#databases) ·
[Security and encryption](#security-and-encryption) ·
[Browser security](#browser-security) ·
[Command line](#command-line)

---

## Coldvault's own words

These mean something specific here, and getting two of them confused is the source of most
confusion.

**Keyword**
The password you choose for one vault. It is what actually encrypts your recovery phrase.
It is **never stored anywhere** — not on the server, not in the database, not in any file.
That is why a stolen database is useless to a thief, and it is also why **forgetting it
means that vault can never be opened again, by anyone.** Each vault has its own.

**`APP_KEY`**
A single random value for the whole installation, generated once during setup and kept in
`coldvault.env`. It protects the **login side**: the authenticator secrets, the backup
codes and the invite codes. It does **not** touch your recovery phrases — those are
encrypted with your keyword. So losing `APP_KEY` locks everybody *out of their accounts*
while leaving the encrypted phrases intact and unreadable. Changing it does the same damage
as losing it.

> **The one distinction worth memorising:** the **keyword** protects your *phrase*.
> **`APP_KEY`** protects your *ability to log in*. They are separate, and neither can
> substitute for the other.

**Vault**
One stored recovery phrase, plus its optional PIN and passphrase. You can have several, each
with its own keyword and its own optional name.

**Keyslot**
The record that says "this person's keyword opens this vault." When you share a vault, the
other person gets their own keyslot with their **own** keyword — you never hand over yours.
Several keyslots can open the same vault.

**Data key**
A random key, generated per vault, that does the actual encrypting of your phrase. Each
authorised person's keyword unlocks a wrapped copy of this same data key. That indirection
is what allows several different keywords to open one encrypted phrase, and what lets a
keyword be changed without re-encrypting anything.

**Invite**
A one-time code the vault's owner creates to give somebody else access. Valid for 72 hours
by default. Only a hash of it is stored, so a database leak yields no usable invite.

**Owner / guest**
The owner is whoever created the vault. Guests are people holding a keyslot: they can
**read** it and nothing else — no renaming, no inviting, no removing, no transferring.

**Revocation (removing someone)**
Taking a person's access away. This does not just delete their record — it generates a
**new** data key and re-encrypts the phrase, because their old record plus the encrypted
data would otherwise still be enough to work out the key offline. The side effect is that
**everyone else's access is invalidated too** and needs re-inviting. The confirmation
screen warns you before you do it.

**Entropy floor**
The minimum keyword strength the app will accept — about **65 bits** by default. A shared
vault is only as strong as its weakest keyword, so this stops one person choosing something
soft. For scale: `Fluffy2019` measures 37 and is rejected; the **Generate** button produces
about 84.

**`LOCAL_MODE`**
A setting that lets the app run without HTTPS, **for testing on your own computer only**.
It also removes a protection from the login cookie. Never enable it on a server anyone else
can reach.

---

## Wallets and recovery phrases

**Recovery phrase** (also *seed phrase*, *mnemonic*, *backup phrase*)
The list of 12–24 words your wallet gave you when you created it. **These words are your
money.** Anyone who has them can spend your coins, from anywhere, without your device.
Coldvault stores an encrypted copy; it never creates one.

**BIP39**
The standard almost all wallets follow for those words. It defines a fixed list of 2,048
English words, and phrases of 12, 15, 18, 21 or 24 words. The fixed list is why your wallet
can tell you that you typed a word wrong.

**SLIP-39**
A different standard that splits a backup into several **shares**, where you need some
number of them to recover. Its shares are 20 or 33 words, which is why Coldvault accepts
those two unusual lengths.

**Passphrase** (the "25th word")
An optional extra word or sentence some wallets support. Combined with your recovery words
it produces a **completely separate, hidden wallet**. It is a wallet feature, not a
Coldvault feature — but if you use one, you must store it, because the words alone will not
reach those funds.

**PIN**
Your hardware wallet's device unlock code. It is not part of any encryption; Coldvault just
gives you somewhere to keep it alongside the phrase.

---

## Web servers and hosting

**Web server**
The program that receives a browser's request and sends back a page. **Apache** is the one
these instructions use; **nginx** is another common one.

**PHP**
The programming language Coldvault is written in. The web server hands it a request, PHP
runs the code and produces the page. You need **version 8.1 or newer**.

**Document root** (also `DocumentRoot`, "web root")
The folder a web address points at. If your document root is `/home/you/coldvault/public`,
then `https://yoursite.com/style.css` serves the file
`/home/you/coldvault/public/style.css`.

**This is the single most important setting to get right.** Everything inside the document
root is downloadable by anyone. Coldvault is arranged so that `coldvault.env` — which holds
your secrets — sits one level *above* it, out of reach. Point the document root one folder
too high and you publish your own key.

**`public_html`**
On shared hosting, the folder that *is* your website. Everything inside it is on the public
internet. Coldvault's app folder belongs **outside** it.

**Virtual host** (`vhost`, `<VirtualHost>`)
A block of Apache configuration saying "for this domain name, serve files from this folder,
using this certificate." One web server can host many sites this way.

**`AllowOverride All`**
An Apache setting that permits a folder to carry its own rules file (see `.htaccess`).
Without it Apache ignores that file, and Coldvault's tidy addresses like `/register/`
return "Not Found" while the home page still works. **That exact symptom means this exact
cause.**

**`.htaccess`**
A per-folder Apache configuration file. Coldvault ships one in `public/` that forces HTTPS,
sets security headers, and makes the tidy addresses work. It only takes effect if
`AllowOverride All` is on — and it is ignored entirely by PHP's built-in server.

**`mod_rewrite` / `mod_headers`**
Two optional Apache components. The first turns `/register/` into the real internal
address; the second sends the security headers. Both must be enabled.

**`php-fpm`**
One common way of running PHP alongside the web server, as a separate background process.
Relevant only because it affects **which user account** PHP runs as, which in turn decides
the right file permissions.

**cPanel**
The web control panel most shared hosting uses — the page of icons with *File Manager*,
*MySQL Databases*, *phpMyAdmin*. It replaces the command line for most tasks.

**AutoSSL**
cPanel's feature that obtains and renews free HTTPS certificates automatically.

**certbot**
The command-line equivalent, used on a VPS. Gets a free certificate from Let's Encrypt and
renews it on a schedule.

**Reverse proxy / load balancer / CDN**
A server that sits **in front of** yours: it receives visitors and passes requests back to
you. Cloudflare is a common example. It matters here because such a setup often handles the
encryption itself and then talks to your server unencrypted — so your server must be told
the visitor's connection *was* secure, via a header (see `X-Forwarded-Proto`).

**`X-Forwarded-Proto`**
The header a proxy adds to say "the visitor came in over `https`." Coldvault checks it, so
it works behind a proxy. If a proxy fails to send it, you get an endless redirect loop —
the fix is at the proxy, never `LOCAL_MODE`.

**`localhost` / `127.0.0.1` / loopback**
Three names for "this same computer." A server bound to loopback can only be reached from
the machine it runs on — not from your phone, not from another PC on your network. This is
a safety property, not a limitation.

**`0.0.0.0`**
Means "every network connection this machine has." Binding here makes a server reachable
from other devices. **Do not combine it with `LOCAL_MODE`** — that publishes your keyword
in the clear across your whole network.

**Port**
A numbered door on a machine. Websites use 443 for `https` and 80 for `http`; the examples
here use 8080 for local testing. `https://example.com:8080` means "port 8080 instead of the
usual one."

**`php -S`**
A tiny web server built into PHP, useful for looking at the app locally. It **cannot do
HTTPS at all**, and it ignores `.htaccess`. Never use it to serve a real site.

**`mkcert`**
A tool that creates a certificate your own computer trusts, so you can use real `https://`
locally with no browser warning. The proper alternative to `LOCAL_MODE`.

**Self-signed certificate**
A certificate you issued yourself. It encrypts the connection perfectly well, but no
browser trusts it, so you get a warning page every time. Fine for testing, wrong for a real
site.

---

## Databases

**Database**
Organised storage the app reads and writes. Coldvault uses **MySQL** or **MariaDB** — the
same thing for our purposes; MariaDB is a compatible fork.

**Table**
One kind of record, like a spreadsheet tab. Coldvault uses six: accounts, vaults, keyslots,
invites, backup codes and a sign-up counter.

**Schema**
The *structure* — which tables exist and what columns they hold — with no data in it. The
file `schema/coldvault.sql` creates that structure in an empty database. It contains no
data, no accounts and no keys.

**phpMyAdmin**
A web page for managing a database by clicking rather than typing. How you import the schema
on shared hosting.

**Database prefix**
cPanel automatically prepends your account name to database and user names, so `coldvault`
becomes `youracct_coldvault`. **You must use the full prefixed name in `coldvault.env`.**
Forgetting the prefix is one of the two most common setup failures.

**Database user / privileges**
A login that reaches the database. Coldvault gets its own, with rights to **only** its own
database, so that leaked credentials open nothing else.

**`InnoDB`**
The storage engine used. It supports transactions and foreign keys — see the next two.

**Transaction**
A group of changes that all succeed or all fail together, never half-applied. Coldvault uses
one when re-encrypting a vault, so an interruption cannot leave your phrase in a broken
state.

**Foreign key**
A rule linking tables and refusing changes that would break the link. Coldvault uses one to
make deleting an account impossible while it still owns a vault — without it, that vault
would become permanently unopenable.

**`varbinary`**
A column type that stores **raw bytes** rather than text. All encrypted values use it, so
nothing can be altered by text-encoding conversions.

**Collation**
The rules a database uses for sorting and comparing text. Mentioned only because MySQL and
MariaDB have different default names for it, which is why the schema file specifies none —
so it imports on both.

**Dump / backup**
A file containing everything in a database, used to restore it. A Coldvault dump reveals no
phrase and no keyword — but restoring it needs the **same `APP_KEY`** the data was written
with.

---

## Security and encryption

**Encryption**
Scrambling data so only someone with the key can read it. **At rest** means the stored data
is scrambled — the protection that makes a stolen database or backup useless.

**Ciphertext**
The scrambled result. What is actually stored in the database. Without the key it is
meaningless bytes.

**AES-256-GCM**
The specific encryption used. AES is the standard cipher; 256 is the key size; **GCM** adds
tamper detection, so altered data is *rejected* rather than silently decrypting to garbage.

**Key derivation / PBKDF2**
Turning a human keyword into a proper encryption key — deliberately **slowly**. Coldvault
repeats the calculation 450,000 times, which is why unlocking takes about a second. You pay
that once; someone guessing pays it on **every single attempt**, which is what makes
guessing impractical.

**Salt**
Random data mixed in before that calculation, different for every keyword. It stops an
attacker pre-computing one giant table of answers and reusing it against everybody.

**Hash**
A one-way fingerprint of some data. You can check whether a guess matches, but you cannot
work backwards to the original. Backup codes and invite codes are stored as hashes, which
is why they can be checked but never displayed again.

**HMAC**
A hash with a secret key mixed in, so only someone holding that key can produce or verify
it. Coldvault uses `APP_KEY` this way for backup and invite codes.

**Entropy / bits**
A measure of how unguessable something is. Each extra bit **doubles** the work of guessing,
so the scale is not linear: 65 bits is not "a bit better" than 60, it is 32 times harder.

**TOTP / authenticator app**
The standard behind the 6-digit code that changes every 30 seconds. Coldvault has **no
passwords** — that code is how you sign in. Google Authenticator, Authy, 1Password,
Bitwarden and Aegis all work.

**Backup codes**
Eight single-use codes shown once at registration. Your only way in if your phone is lost.
Only their hashes are stored, so they cannot be re-displayed.

**HTTPS / TLS / SSL**
The encrypted connection — the padlock in the address bar. **TLS** is the modern protocol;
**SSL** is its obsolete predecessor, and the names are used interchangeably in practice.
Coldvault refuses to run without it because your keyword travels over that connection.

**Certificate**
The file that lets a browser verify a site and set up encryption. Free from Let's Encrypt
via AutoSSL or certbot.

**HSTS**
A header telling browsers "only ever reach this site over HTTPS," so a later plain-HTTP
attempt is refused before it leaves the browser.

**File permissions (`600`, `640`, `chmod`, `chown`)**
Who may read or write a file. `chmod` sets that; `chown` sets who owns it. `600` means only
the owner can read and write. `640` also lets the owner's *group* read.

**Which one you need depends on your setup, and copying the wrong one breaks the site:** on
cPanel, PHP runs as *your own account*, so `600` is correct. On a typical VPS, PHP runs as a
separate `www-data` user that needs group read, so it is `640` plus a group change.

---

## Browser security

You do not need these to install Coldvault. They appear in `SECURITY.md`.

**Content-Security-Policy (CSP)**
A rule sent with each page telling the browser what that page is allowed to load and run.
Coldvault's says, in effect, "only from this site, nowhere else" — so injected code has
nothing to work with.

**Nonce**
A single-use random token. Coldvault's CSP allows only scripts carrying the current page's
nonce, which changes on every request — so script injected by an attacker cannot run.

> **Never add a second Content-Security-Policy** in your web server or CDN. Two policies are
> **both** enforced and their overlap blocks the app's own scripts. The symptom is buttons
> that do nothing.

**CSRF**
An attack where another site tricks your browser into submitting a request to Coldvault
while you are logged in. Prevented with a hidden token every form must carry.

**XSS**
An attack that gets malicious script to run inside a page. Prevented by never inserting
text into a page as markup — so a vault named `<script>...` displays as those literal
characters.

**Permissions-Policy**
A header switching off browser features the app never uses — camera, microphone, location
and twenty more — so injected code cannot reach them either.

**Session / cookie**
A cookie is a small value your browser stores and sends back, identifying your signed-in
session. Coldvault's is marked `Secure` (HTTPS only), `HttpOnly` (unreadable by scripts) and
`SameSite=Strict` (not sent when arriving from another site).

**`woff2` / `unicode-range`**
A compressed web font format, and the CSS feature that lets a browser download only the
character ranges it needs. Coldvault bundles its fonts rather than loading them from Google
so that no outside company sees your visitors' addresses.

---

## Command line

**Terminal / shell / command line**
A window where you type commands. **Command Prompt** or **PowerShell** on Windows,
**Terminal** on macOS and Linux. cPanel sometimes offers one under *Terminal*.

**`sudo`**
"Run this as administrator." Needed on a VPS for system-wide changes. You will be asked for
your password. Not available on shared hosting, which is why Path A avoids it.

**`cd`**
Change folder.

**`apt` / `dnf`**
Software installers on Linux. `apt` on Debian and Ubuntu, `dnf` on RHEL, AlmaLinux and
Rocky.

**`systemctl`**
Starts, stops and restarts background services such as Apache and MySQL.

**`ss -ltnp`**
Lists what is listening for network connections, and on which addresses. Used to confirm a
test server is bound to loopback only.

**`curl`**
Fetches a web address from the command line. Used in the verification steps to check what
your server actually returns.

**`openssl`**
A cryptography toolkit. `openssl rand -base64 32` produces a correct `APP_KEY`.

**SSH**
A secure way to get a terminal on a remote server. How you reach a VPS.

**FTP / SFTP**
Ways to copy files to a server. cPanel's File Manager does the same job in a browser.
Prefer **SFTP** over plain FTP, which sends your password unencrypted.
