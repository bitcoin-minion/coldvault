-- ---------------------------------------------------------------------------
-- Coldvault — database structure
-- 2026-09-04: initial public release (MIT).
--
-- Structure only. No data, no users, no keys.
--
-- Import into an EMPTY database:
--     mysql -u coldvault -p coldvault < schema/coldvault.sql
--
-- Tested on MySQL 8.0 and MariaDB 10.6. No COLLATE clause is given, so each
-- table takes the server's default utf8mb4 collation — which is what keeps this
-- file portable between the two (MySQL 8's utf8mb4_0900_ai_ci does not exist on
-- MariaDB). Nothing in the app depends on collation: every secret column is
-- varbinary, so bytes go in and the same bytes come out. Only `username` is
-- text, and it is compared through the lowercased `username_lc` column.
--
-- WHAT IS STORED HERE, AND WHAT IS NOT
--   Stored:     ciphertext, nonces, tags, salts, iteration counts, wrapped keys,
--               hashed invite codes, hashed backup codes, encrypted labels.
--   NOT stored: any vault keyword, any recovery phrase, any PIN, any passphrase,
--               any client IP address.
--   A full dump of this database, on its own, reveals no phrase and no keyword.
-- ---------------------------------------------------------------------------

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ---------------------------------------------------------------------------
-- vault_users — one row per account. The authenticator secret is encrypted at
-- rest under APP_KEY, so a database dump alone cannot generate valid codes.
--
--   secret_version  bumped whenever a new authenticator is paired. Every OTHER
--                   signed-in session carries the old value and is signed out on
--                   its next request, so re-pairing evicts an intruder who is
--                   already holding a session — not just one trying to get back in.
--   fail_count      wrong sign-in attempts. Drives the CAPTCHA gate. Server-side,
--                   so a client cannot clear it by dropping its cookie.
--   lock_until      brakes the step-up path only. The sign-in path deliberately
--                   ignores it: a correct code always signs you in, because a cap
--                   on evaluations caps the real owner too.
--   last_step       the last TOTP step accepted, so a code cannot be replayed.
-- ---------------------------------------------------------------------------
CREATE TABLE `vault_users` (
  `id`             int unsigned NOT NULL AUTO_INCREMENT,
  `username`       varchar(64)  NOT NULL,
  `username_lc`    varchar(64)  NOT NULL,
  `secret_blob`    varbinary(255) NOT NULL,
  `secret_version` int unsigned NOT NULL DEFAULT 1,
  `enrolled_at`    datetime     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fail_count`     int unsigned NOT NULL DEFAULT 0,
  `lock_until`     datetime     DEFAULT NULL,
  `last_step`      bigint       DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_lc` (`username_lc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- vault — one row per stored recovery phrase. `ciphertext` is AES-256-GCM.
--
--   user_id     the OWNER. There is no separate owner column: ownership IS this
--               column. The foreign key is ON DELETE RESTRICT on purpose —
--               without it, deleting an owner left a vault whose only keyslot had
--               been cascade-deleted, so the ciphertext could never be opened again.
--   format      1 = the keyword derives the payload key directly.
--               2 = envelope: a random per-vault data key encrypts the payload,
--                   and each authorised person holds that key wrapped under their
--                   own keyword in vault_keyslot. This is what lets several
--                   keywords open one ciphertext.
--   iterations  format 1: the PBKDF2 cost for this row.
--               format 2: always 0 — a deliberate poison value. The key-derivation
--                   helper refuses iterations < 1, so a mislabelled row fails
--                   closed instead of deriving a key from nothing.
--   salt        format 2: 16 unused random bytes. The real salt is per keyslot.
--   name_enc    optional vault name, encrypted under APP_KEY. A name like
--               "main backup" is sensitive metadata, so it is not stored in clear.
-- ---------------------------------------------------------------------------
CREATE TABLE `vault` (
  `id`         int unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `iterations` int unsigned NOT NULL,
  `salt`       varbinary(16)   NOT NULL,
  `nonce`      varbinary(12)   NOT NULL,
  `tag`        varbinary(16)   NOT NULL,
  `ciphertext` varbinary(2048) NOT NULL,
  `user_id`    int unsigned NOT NULL,
  `format`     tinyint unsigned NOT NULL DEFAULT 1,
  `name_enc`   varbinary(512) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `k_uid` (`user_id`),
  CONSTRAINT `fk_vault_owner` FOREIGN KEY (`user_id`) REFERENCES `vault_users` (`id`)
    ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- vault_keyslot — "this person's keyword opens this vault."
--
-- Holds the vault's data key wrapped under PBKDF2(their keyword, their own salt,
-- their own iterations). The PBKDF2 cost lives here, not on the vault row, so
-- brute-force cost per keyword is unchanged by sharing.
--
-- Removing someone is NOT a row delete. A retained row plus the ciphertext still
-- yields the key offline, so removal mints a NEW data key, re-encrypts the
-- payload and re-wraps only the acting owner's slot — which invalidates every
-- other slot by design.
-- ---------------------------------------------------------------------------
CREATE TABLE `vault_keyslot` (
  `id`           int unsigned NOT NULL AUTO_INCREMENT,
  `vault_id`     int unsigned NOT NULL,
  `user_id`      int unsigned NOT NULL,
  `label_enc`    varbinary(512) NOT NULL,
  `iterations`   int unsigned NOT NULL,
  `salt`         varbinary(16) NOT NULL,
  `nonce`        varbinary(12) NOT NULL,
  `tag`          varbinary(16) NOT NULL,
  `wrapped_dek`  varbinary(64) NOT NULL,
  `created_at`   datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_used_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_vault_user` (`vault_id`, `user_id`),
  KEY `k_user` (`user_id`),
  CONSTRAINT `fk_ks_vault` FOREIGN KEY (`vault_id`) REFERENCES `vault` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ks_user`  FOREIGN KEY (`user_id`)  REFERENCES `vault_users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- vault_invite — one-time codes that let someone else attach a keyslot.
--
--   code_hash    HMAC-SHA256(code, APP_KEY). The code itself is never stored, so
--                a database leak yields no working invite.
--   wrapped_dek  the data key wrapped under the invite code, NULLed the moment
--                the invite is redeemed.
--   fails        wrong-code attempts; the invite burns out at INVITE_MAX_FAILS.
-- ---------------------------------------------------------------------------
CREATE TABLE `vault_invite` (
  `id`          int unsigned NOT NULL AUTO_INCREMENT,
  `vault_id`    int unsigned NOT NULL,
  `created_by`  int unsigned NOT NULL,
  `code_hash`   varbinary(32)  NOT NULL,
  `label_enc`   varbinary(512) NOT NULL,
  `iterations`  int unsigned NOT NULL,
  `salt`        varbinary(16) NOT NULL,
  `nonce`       varbinary(12) NOT NULL,
  `tag`         varbinary(16) NOT NULL,
  `wrapped_dek` varbinary(64) DEFAULT NULL,
  `created_at`  datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at`  datetime NOT NULL,
  `used_at`     datetime DEFAULT NULL,
  `fails`       int unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_code` (`code_hash`),
  KEY `k_vault` (`vault_id`),
  KEY `fk_inv_user` (`created_by`),
  CONSTRAINT `fk_inv_vault` FOREIGN KEY (`vault_id`)   REFERENCES `vault` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_inv_user`  FOREIGN KEY (`created_by`) REFERENCES `vault_users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- vault_backup_codes — single-use recovery codes, stored as HMAC-SHA256 under
-- APP_KEY (char(64) hex). Used when the authenticator is unavailable.
--
-- No foreign key, matching the schema the application is proven against. Adding
-- `FOREIGN KEY (user_id) REFERENCES vault_users(id) ON DELETE CASCADE` is a
-- reasonable hardening if you want codes to disappear with a deleted account;
-- the app never relies on it either way.
-- ---------------------------------------------------------------------------
CREATE TABLE `vault_backup_codes` (
  `id`        int unsigned NOT NULL AUTO_INCREMENT,
  `code_hash` char(64)     NOT NULL,
  `used_at`   datetime     DEFAULT NULL,
  `user_id`   int unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `k_uid` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- vault_reg_throttle — sign-up rate limiting. Timestamps ONLY.
--
-- There is no address column, and the application records no client IP anywhere.
-- The consequence is that the limit is SITE-WIDE (REG_MAX_PER_HOUR), not per
-- address: a sign-up flood can block new registrations for an hour. That was an
-- accepted trade for storing nothing that identifies a visitor.
-- Rows older than an hour are purged lazily on each registration attempt.
-- ---------------------------------------------------------------------------
CREATE TABLE `vault_reg_throttle` (
  `ts` datetime NOT NULL,
  KEY `k_ts` (`ts`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- vault_login_throttle — per-account sign-in rate limiting (2026-09-07, security review).
--
-- One timestamp per code EVALUATION, keyed by the attempted username_lc (which is
-- server-side state a client cannot clear by dropping its cookie). It bounds an
-- attacker to LOGIN_MAX_PER_HOUR code guesses per account per hour, then a slow
-- trickle - but it NEVER fully locks the account: the owner is always allowed at
-- least one attempt every LOGIN_THROTTLE_INTERVAL seconds, so unlike the old
-- five-strike lock an outsider cannot hold a known username shut. The same rule is
-- applied whether or not the username exists, so it reveals nothing about existence.
-- Rows older than an hour are purged lazily on each attempt. No client IP is stored.
-- ---------------------------------------------------------------------------
CREATE TABLE `vault_login_throttle` (
  `username_lc` varchar(64) NOT NULL,
  `ts` datetime NOT NULL,
  KEY `k_lc_ts` (`username_lc`,`ts`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;
