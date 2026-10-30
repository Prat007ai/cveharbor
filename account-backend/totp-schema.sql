-- Apply to existing cveharbor-accounts D1 only after backup.
-- Additive, opt-in authenticator MFA storage. No existing account is changed.
CREATE TABLE IF NOT EXISTS user_totp (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 encrypted_secret TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 0,
 last_counter INTEGER NOT NULL DEFAULT -1,
 created_at INTEGER NOT NULL,
 enabled_at INTEGER
);
CREATE TABLE IF NOT EXISTS totp_login_challenges (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE,
 expires_at INTEGER NOT NULL,
 consumed_at INTEGER,
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_totp_challenge_expiration ON totp_login_challenges(expires_at);
CREATE TABLE IF NOT EXISTS totp_recovery_codes (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 code_hash TEXT NOT NULL,
 used_at INTEGER,
 PRIMARY KEY(user_id,code_hash)
);
