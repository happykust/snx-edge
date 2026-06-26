// Schema migrations are forward-only and applied in-order at startup.
// To change the schema, add a new entry to `migrations()` with a strictly
// increasing `version` and a SQL body that is idempotent on first run for
// pre-existing installations (use `CREATE TABLE IF NOT EXISTS`,
// `ALTER TABLE ...` is acceptable on later versions). Never edit an existing
// migration: applied versions are recorded in `_schema_migrations` and a
// retroactive change would be silently skipped on already-bootstrapped DBs.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::Serialize;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[allow(unused_imports)]
pub use snx_edge_types::users::{Session, UserResponse};

use crate::error::AppError;

/// bcrypt cost used for new password hashes. Bumped from the historical
/// `bcrypt::DEFAULT_COST` (12) for 2026-era hardening. Existing hashes at the
/// older cost are transparently upgraded on successful login (see `login`
/// handler).
pub const BCRYPT_COST: u32 = 13;

/// A single forward-only schema migration.
pub struct Migration {
    pub version: u32,
    pub sql: &'static str,
}

/// Ordered list of all schema migrations. Append-only; never edit existing
/// entries (see top-of-file comment).
pub fn migrations() -> &'static [Migration] {
    // v1 replicates the original inline schema. `IF NOT EXISTS` keeps it
    // idempotent for installations that pre-date the migration framework —
    // the DDL is a no-op there but still records version=1 in
    // `_schema_migrations`, so subsequent migrations behave the same on
    // legacy and new databases.
    //
    // v2 adds `users.token_generation`. Bumped on password change, user delete,
    // session revocation, and the explicit `/users/{id}/revoke-tokens` endpoint
    // so that already-issued JWT access tokens fail the middleware check.
    const MIGRATIONS: &[Migration] = &[
        Migration {
            version: 1,
            sql: "CREATE TABLE IF NOT EXISTS users (
                id              TEXT PRIMARY KEY,
                username        TEXT UNIQUE NOT NULL,
                password_hash   TEXT NOT NULL,
                role            TEXT NOT NULL DEFAULT 'viewer',
                comment         TEXT NOT NULL DEFAULT '',
                enabled         INTEGER NOT NULL DEFAULT 1,
                failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    TEXT,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id          TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                ip_address  TEXT,
                user_agent  TEXT,
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS profiles (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                config      TEXT NOT NULL,
                enabled     INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);",
        },
        Migration {
            version: 2,
            sql: "ALTER TABLE users ADD COLUMN token_generation INTEGER NOT NULL DEFAULT 0;",
        },
    ];
    MIGRATIONS
}

/// Apply all migrations whose version is greater than the database's current
/// `PRAGMA user_version`. Each migration runs inside its own transaction, the
/// version pragma is bumped, and a row is written to `_schema_migrations`.
fn apply_migrations(conn: &mut rusqlite::Connection, migs: &[Migration]) -> rusqlite::Result<()> {
    // Bookkeeping table for human-readable history. PRAGMA user_version is
    // the source of truth for "what's applied"; this table is just an audit
    // trail.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _schema_migrations (
             version    INTEGER PRIMARY KEY,
             applied_at TEXT NOT NULL DEFAULT (datetime('now'))
         );",
    )?;

    let current: u32 =
        conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))? as u32;

    for m in migs {
        if m.version <= current {
            continue;
        }

        let tx = conn.transaction()?;
        tx.execute_batch(m.sql)?;
        tx.execute(
            "INSERT OR IGNORE INTO _schema_migrations (version) VALUES (?1)",
            params![m.version],
        )?;
        // PRAGMA user_version doesn't support bound params, hence the
        // formatted string. `version: u32` is not user-controlled, so this
        // is safe.
        tx.execute_batch(&format!("PRAGMA user_version = {}", m.version))?;
        tx.commit()?;

        tracing::info!("applied schema migration v{}", m.version);
    }

    Ok(())
}

/// User record from the database.
#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub comment: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub failed_login_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
    /// Monotonic counter used to revoke outstanding JWT access tokens. Bumped
    /// by password change, user delete, session revocation, and the explicit
    /// `/users/{id}/revoke-tokens` endpoint. Embedded into JWT claims so the
    /// `require_auth` middleware can reject stale tokens.
    #[serde(default)]
    pub token_generation: i64,
}

/// Thread-safe database handle wrapping SQLite.
///
/// `profile_key` is the optional 32-byte ChaCha20-Poly1305 key used to encrypt
/// VPN profile secrets at rest. `None` means run in legacy plaintext mode for
/// backwards compatibility — admins who upgrade without setting the env var
/// keep their existing data readable.
#[derive(Clone)]
pub struct UserDb {
    conn: Arc<Mutex<rusqlite::Connection>>,
    profile_key: Option<Arc<[u8; 32]>>,
}

impl UserDb {
    #[allow(dead_code)] // legacy convenience wrapper; tests may still call it once the WIP encryption work lands
    pub async fn new(path: &str) -> anyhow::Result<Self> {
        Self::new_with_key(path, None).await
    }

    pub async fn new_with_key(path: &str, profile_key: Option<[u8; 32]>) -> anyhow::Result<Self> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut conn = rusqlite::Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        apply_migrations(&mut conn, migrations())?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            profile_key: profile_key.map(Arc::new),
        })
    }

    /// Cheap liveness probe for the readiness endpoint. Runs a trivial query
    /// so we exercise the actual SQLite handle. Errors propagate so the
    /// health endpoint can classify them.
    pub async fn health_check(&self) -> Result<(), AppError> {
        let conn = self.conn.lock().await;
        let _: u32 = conn.query_row("SELECT 1", [], |row| row.get(0))?;
        Ok(())
    }

    /// Create admin user from env vars if no users exist yet.
    pub async fn ensure_admin_exists(&self) -> anyhow::Result<()> {
        let count: u32 = {
            let conn = self.conn.lock().await;
            conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?
        };

        if count > 0 {
            return Ok(());
        }

        let admin_user =
            std::env::var("SNX_EDGE_ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
        let admin_password = std::env::var("SNX_EDGE_ADMIN_PASSWORD")
            .map_err(|_| anyhow::anyhow!("SNX_EDGE_ADMIN_PASSWORD env must be set on first run"))?;

        let hash = tokio::task::spawn_blocking(move || bcrypt::hash(&admin_password, BCRYPT_COST))
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))??;
        let now = Utc::now();
        let id = Uuid::new_v4().to_string();

        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, comment, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'admin', 'Initial admin', 1, ?4, ?4)",
            params![id, admin_user, hash, now.to_rfc3339()],
        )?;

        tracing::info!("created initial admin user: {admin_user}");
        Ok(())
    }

    // === User CRUD ===

    pub async fn get_user_by_id(&self, id: &str) -> Result<User, AppError> {
        let conn = self.conn.lock().await;
        let id = id.to_string();
        conn.query_row(
            "SELECT id, username, password_hash, role, comment, enabled,
                    failed_login_attempts, locked_until, created_at, updated_at, token_generation
             FROM users WHERE id = ?1",
            params![id],
            row_to_user,
        )
        .map_err(|_| AppError::NotFound("user not found".to_string()))
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User, AppError> {
        let conn = self.conn.lock().await;
        let username = username.to_string();
        conn.query_row(
            "SELECT id, username, password_hash, role, comment, enabled,
                    failed_login_attempts, locked_until, created_at, updated_at, token_generation
             FROM users WHERE username = ?1",
            params![username],
            row_to_user,
        )
        .map_err(|_| AppError::NotFound("user not found".to_string()))
    }

    pub async fn list_users(&self) -> Result<Vec<User>, AppError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, username, password_hash, role, comment, enabled,
                    failed_login_attempts, locked_until, created_at, updated_at, token_generation
             FROM users ORDER BY created_at",
        )?;
        let users = stmt
            .query_map([], row_to_user)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(users)
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: &str,
        comment: &str,
    ) -> Result<User, AppError> {
        if password.len() < 8 {
            return Err(AppError::BadRequest(
                "password must be at least 8 characters".to_string(),
            ));
        }

        let password_owned = password.to_string();
        let hash = tokio::task::spawn_blocking(move || bcrypt::hash(&password_owned, BCRYPT_COST))
            .await
            .map_err(|e| AppError::Internal(format!("join error: {e}")))?
            .map_err(|e| AppError::Internal(format!("bcrypt error: {e}")))?;

        let now = Utc::now();
        let id = Uuid::new_v4().to_string();

        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, comment, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
            params![id, username, hash, role, comment, now.to_rfc3339()],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e
                && err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
            {
                return AppError::Conflict(format!("username '{username}' already exists"));
            }
            AppError::from(e)
        })?;

        drop(conn);
        self.get_user_by_id(&id).await
    }

    pub async fn update_user(
        &self,
        id: &str,
        role: Option<&str>,
        comment: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<User, AppError> {
        let now = Utc::now();
        let conn = self.conn.lock().await;

        // Read current state UNDER lock to avoid TOCTOU
        let user: User = conn
            .query_row(
                "SELECT id, username, password_hash, role, comment, enabled,
                        failed_login_attempts, locked_until, created_at, updated_at, token_generation
                 FROM users WHERE id = ?1",
                params![id],
                row_to_user,
            )
            .map_err(|_| AppError::NotFound("user not found".to_string()))?;

        let new_role = role.unwrap_or(&user.role);
        let new_comment = comment.unwrap_or(&user.comment);
        let new_enabled = enabled.unwrap_or(user.enabled);

        // Protect last admin -- check under the same lock
        let demoting = user.role == "admin" && new_role != "admin";
        let disabling = user.role == "admin" && !new_enabled;
        if demoting || disabling {
            let admin_count: u32 = conn.query_row(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND enabled = 1 AND id != ?1",
                params![id],
                |row| row.get(0),
            )?;
            if admin_count == 0 {
                return Err(AppError::Conflict(
                    "cannot remove or demote the last admin user".to_string(),
                ));
            }
        }

        conn.execute(
            "UPDATE users SET role = ?1, comment = ?2, enabled = ?3, updated_at = ?4 WHERE id = ?5",
            params![new_role, new_comment, new_enabled, now.to_rfc3339(), id],
        )?;

        drop(conn);
        self.get_user_by_id(id).await
    }

    pub async fn delete_user(&self, id: &str) -> Result<(), AppError> {
        let conn = self.conn.lock().await;

        // Check last admin and delete under the same lock to avoid TOCTOU
        let admin_count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND enabled = 1 AND id != ?1",
            params![id],
            |row| row.get(0),
        )?;
        if admin_count == 0 {
            // Verify the target user is actually an admin before rejecting
            let target_role: String = conn
                .query_row("SELECT role FROM users WHERE id = ?1", params![id], |row| {
                    row.get(0)
                })
                .map_err(|_| AppError::NotFound("user not found".to_string()))?;
            if target_role == "admin" {
                return Err(AppError::Conflict(
                    "cannot remove or demote the last admin user".to_string(),
                ));
            }
        }

        let affected = conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;
        if affected == 0 {
            return Err(AppError::NotFound("user not found".to_string()));
        }
        Ok(())
    }

    /// Increment a user's `token_generation`. Returns the new value. Returns
    /// `Ok(None)` if the user no longer exists (e.g. deleted concurrently) —
    /// callers should treat that as a no-op rather than a hard error.
    ///
    /// The middleware caches the generation per user-id; if you have a handle
    /// to the cache, invalidate it (or write the new value) after this call so
    /// the next request sees the bump immediately rather than waiting out the
    /// 30s TTL.
    #[allow(dead_code)] // wired in by the WIP token-generation feature; kept for that branch
    pub async fn bump_token_generation(&self, id: &str) -> Result<Option<i64>, AppError> {
        let conn = self.conn.lock().await;
        let affected = conn.execute(
            "UPDATE users SET token_generation = token_generation + 1 WHERE id = ?1",
            params![id],
        )?;
        if affected == 0 {
            return Ok(None);
        }
        let gen_: i64 = conn.query_row(
            "SELECT token_generation FROM users WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )?;
        Ok(Some(gen_))
    }

    pub async fn get_token_generation(&self, id: &str) -> Result<i64, AppError> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT token_generation FROM users WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .map_err(|_| AppError::NotFound("user not found".to_string()))
    }

    /// Replace `password_hash` for a user without touching `token_generation`
    /// or `updated_at`. Used by the transparent bcrypt rehash on login: the
    /// password didn't change, only its on-disk encoding did, so existing
    /// access tokens must remain valid.
    #[allow(dead_code)] // used by the WIP transparent-rehash path
    pub async fn set_password_hash_silent(&self, id: &str, hash: &str) -> Result<(), AppError> {
        let conn = self.conn.lock().await;
        let affected = conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            params![hash, id],
        )?;
        if affected == 0 {
            return Err(AppError::NotFound("user not found".to_string()));
        }
        Ok(())
    }

    pub async fn change_password(&self, id: &str, new_password: &str) -> Result<(), AppError> {
        if new_password.len() < 8 {
            return Err(AppError::BadRequest(
                "password must be at least 8 characters".to_string(),
            ));
        }

        let password_owned = new_password.to_string();
        let hash = tokio::task::spawn_blocking(move || bcrypt::hash(&password_owned, BCRYPT_COST))
            .await
            .map_err(|e| AppError::Internal(format!("join error: {e}")))?
            .map_err(|e| AppError::Internal(format!("bcrypt error: {e}")))?;
        let now = Utc::now();

        // Bumping `token_generation` here invalidates every outstanding access
        // token — without this, the old JWT still passes the middleware until
        // its natural expiry (~15 min) even though the password is gone.
        let conn = self.conn.lock().await;
        let affected = conn.execute(
            "UPDATE users SET password_hash = ?1,
                              token_generation = token_generation + 1,
                              updated_at = ?2
             WHERE id = ?3",
            params![hash, now.to_rfc3339(), id],
        )?;
        if affected == 0 {
            return Err(AppError::NotFound("user not found".to_string()));
        }
        Ok(())
    }

    // === Login tracking ===

    pub async fn record_failed_login(
        &self,
        user_id: &str,
        max_attempts: u32,
        lockout_minutes: u32,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock().await;

        // Increment attempts
        conn.execute(
            "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?1",
            params![user_id],
        )?;

        // Check if should lock
        let attempts: u32 = conn.query_row(
            "SELECT failed_login_attempts FROM users WHERE id = ?1",
            params![user_id],
            |row| row.get(0),
        )?;

        if attempts >= max_attempts {
            let locked_until = Utc::now() + chrono::Duration::minutes(lockout_minutes as i64);
            conn.execute(
                "UPDATE users SET locked_until = ?1 WHERE id = ?2",
                params![locked_until.to_rfc3339(), user_id],
            )?;
        }

        Ok(())
    }

    pub async fn reset_failed_logins(&self, user_id: &str) -> Result<(), AppError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?1",
            params![user_id],
        )?;
        Ok(())
    }

    // === Sessions ===

    pub async fn create_session(
        &self,
        jti: &str,
        user_id: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO sessions (id, user_id, ip_address, user_agent, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                jti,
                user_id,
                ip,
                user_agent,
                Utc::now().to_rfc3339(),
                expires_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub async fn delete_session(&self, id: &str) -> Result<(), AppError> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Look up the user_id that owns a session. Returns `Ok(None)` if the
    /// session doesn't exist. The revoke-session handler uses this to know
    /// whose `token_generation` to bump after deletion.
    pub async fn session_owner(&self, session_id: &str) -> Result<Option<String>, AppError> {
        let conn = self.conn.lock().await;
        match conn.query_row(
            "SELECT user_id FROM sessions WHERE id = ?1",
            params![session_id],
            |row| row.get::<_, String>(0),
        ) {
            Ok(uid) => Ok(Some(uid)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            // Other rusqlite errors are real failures (I/O, schema). Map
            // through the generic From impl so callers see AppError::Internal.
            #[allow(clippy::wildcard_enum_match_arm)]
            Err(other) => Err(AppError::from(other)),
        }
    }

    pub async fn delete_user_sessions(&self, user_id: &str) -> Result<u64, AppError> {
        let conn = self.conn.lock().await;
        let count = conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
        Ok(count as u64)
    }

    pub async fn list_sessions(&self) -> Result<Vec<Session>, AppError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, user_id, ip_address, user_agent, created_at, expires_at
             FROM sessions ORDER BY created_at DESC",
        )?;
        let sessions = stmt
            .query_map([], |row| {
                Ok(Session {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    ip_address: row.get(2)?,
                    user_agent: row.get(3)?,
                    created_at: parse_dt(row.get::<_, String>(4)?)?,
                    expires_at: parse_dt(row.get::<_, String>(5)?)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(sessions)
    }

    pub async fn count_user_sessions(&self, user_id: &str) -> Result<usize, AppError> {
        let conn = self.conn.lock().await;
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE user_id = ?1 AND expires_at > ?2",
            params![user_id, Utc::now().to_rfc3339()],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    pub async fn session_exists(&self, jti: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock().await;
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE id = ?1 AND expires_at > ?2",
            params![jti, Utc::now().to_rfc3339()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<u64, AppError> {
        let conn = self.conn.lock().await;
        let count = conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?1",
            params![Utc::now().to_rfc3339()],
        )?;
        Ok(count as u64)
    }

    // === Cleanup ===

    /// Spawns a background task that cleans up expired sessions every hour.
    ///
    /// Takes ownership of `self` (cheap — `UserDb` is just an `Arc<Mutex<…>>` +
    /// clone) and exits cleanly when `cancel` is cancelled by the shutdown
    /// handler.
    pub fn start_cleanup_task(self, cancel: CancellationToken) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            // Skip the immediate first tick so we don't run cleanup at startup.
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match self.cleanup_expired_sessions().await {
                            Ok(count) => {
                                if count > 0 {
                                    tracing::info!("cleaned up {count} expired sessions");
                                }
                            }
                            Err(e) => {
                                tracing::warn!("session cleanup failed: {e}");
                            }
                        }
                    }
                    _ = cancel.cancelled() => {
                        tracing::info!("db cleanup task: shutdown signal received");
                        break;
                    }
                }
            }
        });
    }

    /// Get list of permissions for a role.
    pub fn permissions_for_role(role: &str) -> &'static [&'static str] {
        match role {
            "admin" => &[
                "tunnel.*",
                "config.*",
                "profiles.*",
                "routing.*",
                "routing.setup",
                "routing.teardown",
                "users.*",
                "logs.*",
            ],
            "operator" => &[
                "tunnel.connect",
                "tunnel.disconnect",
                "tunnel.status",
                "config.read",
                "profiles.read",
                "routing.clients.*",
                "routing.bypass.*",
                "routing.corp.*",
                "routing.diagnostics",
                "logs.*",
            ],
            "viewer" => &[
                "tunnel.status",
                "config.read",
                "profiles.read",
                "routing.read",
                "logs.read",
            ],
            _ => &[],
        }
    }
}

// === VPN Profiles ===

pub use snx_edge_types::profiles::Profile;

impl UserDb {
    /// Decrypt a config blob in-place using the configured key, if any. When
    /// the blob carries the `__enc_v` marker but no key is configured we log a
    /// loud warning and return the JSON untouched — the read path keeps
    /// working in degraded mode (downstream callers will see the encrypted
    /// shape) which is preferable to bricking the API after a misconfigured
    /// restart.
    fn decrypt_in_place(&self, value: &mut serde_json::Value) -> Result<(), AppError> {
        if !crate::db_secrets::is_encrypted(value) {
            return Ok(());
        }
        match self.profile_key.as_deref() {
            Some(key) => crate::db_secrets::decrypt_profile_secrets(value, key),
            None => {
                tracing::warn!(
                    "profile blob is encrypted but no profile key configured; \
                     returning ciphertext"
                );
                Ok(())
            }
        }
    }

    /// Inverse of `decrypt_in_place` for write paths. When no key is
    /// configured we leave plaintext as-is for backwards compatibility.
    fn encrypt_in_place(&self, value: &mut serde_json::Value) -> Result<(), AppError> {
        match self.profile_key.as_deref() {
            Some(key) => crate::db_secrets::encrypt_profile_secrets(value, key),
            None => Ok(()),
        }
    }

    pub async fn list_profiles(&self) -> Result<Vec<Profile>, AppError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, name, config, enabled, created_at, updated_at
             FROM profiles ORDER BY name",
        )?;
        let mut profiles = stmt
            .query_map([], |row| {
                let config_str: String = row.get(2)?;
                Ok(Profile {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    config: parse_json_config(&config_str)?,
                    enabled: row.get(3)?,
                    created_at: parse_dt(row.get::<_, String>(4)?)?,
                    updated_at: parse_dt(row.get::<_, String>(5)?)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        drop(conn);
        for p in &mut profiles {
            self.decrypt_in_place(&mut p.config)?;
        }
        Ok(profiles)
    }

    pub async fn get_profile(&self, id: &str) -> Result<Profile, AppError> {
        let conn = self.conn.lock().await;
        let mut profile = conn
            .query_row(
                "SELECT id, name, config, enabled, created_at, updated_at
                 FROM profiles WHERE id = ?1",
                params![id],
                |row| {
                    let config_str: String = row.get(2)?;
                    Ok(Profile {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        config: parse_json_config(&config_str)?,
                        enabled: row.get(3)?,
                        created_at: parse_dt(row.get::<_, String>(4)?)?,
                        updated_at: parse_dt(row.get::<_, String>(5)?)?,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    AppError::NotFound("profile not found".to_string())
                }
                // The remaining rusqlite::Error variants are all "real" database
                // failures (I/O, schema, type-conversion). They map uniformly to
                // AppError::Internal via `From`, so a wildcard is appropriate here.
                #[allow(clippy::wildcard_enum_match_arm)]
                other => AppError::from(other),
            })?;
        drop(conn);
        self.decrypt_in_place(&mut profile.config)?;
        Ok(profile)
    }

    /// Get the raw VPN config JSON for a profile (including secrets, for
    /// internal use). Decrypts before returning so callers (e.g. the tunnel
    /// connect handler) see plaintext.
    pub async fn get_profile_config(&self, id: &str) -> Result<String, AppError> {
        let conn = self.conn.lock().await;
        let raw: String = conn
            .query_row(
                "SELECT config FROM profiles WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .map_err(|_| AppError::NotFound("profile not found".to_string()))?;
        drop(conn);

        // Parse → decrypt → reserialize, so callers always see plaintext JSON.
        let mut value: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| AppError::Internal(format!("invalid stored profile JSON: {e}")))?;
        self.decrypt_in_place(&mut value)?;
        serde_json::to_string(&value)
            .map_err(|e| AppError::Internal(format!("re-serialize profile: {e}")))
    }

    pub async fn create_profile(
        &self,
        name: &str,
        config: &serde_json::Value,
    ) -> Result<Profile, AppError> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // Encrypt secrets before serialization. Clone first because the
        // caller still owns `config` and may reuse it (e.g. masking for the
        // HTTP response).
        let mut to_store = config.clone();
        self.encrypt_in_place(&mut to_store)?;

        let config_str = serde_json::to_string(&to_store)
            .map_err(|e| AppError::BadRequest(format!("invalid config JSON: {e}")))?;

        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO profiles (id, name, config, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, ?4, ?4)",
            params![id, name, config_str, now.to_rfc3339()],
        )?;
        drop(conn);

        self.get_profile(&id).await
    }

    pub async fn update_profile(
        &self,
        id: &str,
        name: Option<&str>,
        config: Option<&serde_json::Value>,
        enabled: Option<bool>,
    ) -> Result<Profile, AppError> {
        let now = Utc::now();

        // Read existing profile and apply update under a single lock
        // acquisition to avoid TOCTOU races, matching the pattern used
        // by update_user.
        let conn = self.conn.lock().await;

        let mut existing = conn
            .query_row(
                "SELECT id, name, config, enabled, created_at, updated_at
                 FROM profiles WHERE id = ?1",
                params![id],
                |row| {
                    let config_str: String = row.get(2)?;
                    Ok(Profile {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        config: parse_json_config(&config_str)?,
                        enabled: row.get(3)?,
                        created_at: parse_dt(row.get::<_, String>(4)?)?,
                        updated_at: parse_dt(row.get::<_, String>(5)?)?,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    AppError::NotFound("profile not found".to_string())
                }
                // See comment above on get_profile: other variants are all
                // genuine DB failures and collapse to AppError::Internal.
                #[allow(clippy::wildcard_enum_match_arm)]
                other => AppError::from(other),
            })?;

        // Decrypt the existing blob so the "keep current secret" logic in
        // the API layer sees plaintext.
        self.decrypt_in_place(&mut existing.config)?;

        let new_name = name.unwrap_or(&existing.name);
        let new_enabled = enabled.unwrap_or(existing.enabled);

        let mut new_value = if let Some(cfg) = config {
            cfg.clone()
        } else {
            existing.config.clone()
        };
        // Re-encrypt before persisting.
        self.encrypt_in_place(&mut new_value)?;
        let new_config_str = serde_json::to_string(&new_value)
            .map_err(|e| AppError::BadRequest(format!("invalid config JSON: {e}")))?;

        conn.execute(
            "UPDATE profiles SET name = ?1, config = ?2, enabled = ?3, updated_at = ?4 WHERE id = ?5",
            params![new_name, new_config_str, new_enabled, now.to_rfc3339(), id],
        )?;
        drop(conn);

        self.get_profile(id).await
    }

    pub async fn delete_profile(&self, id: &str) -> Result<(), AppError> {
        let conn = self.conn.lock().await;
        let affected = conn.execute("DELETE FROM profiles WHERE id = ?1", params![id])?;
        if affected == 0 {
            return Err(AppError::NotFound("profile not found".to_string()));
        }
        Ok(())
    }

    /// Test-only / diagnostic accessor: returns the raw on-disk config string
    /// without decrypting. Used by tests to verify that ciphertext (not
    /// plaintext) is what actually lives in SQLite.
    #[cfg(test)]
    #[allow(dead_code)] // exercised only when the WIP encryption tests land
    pub async fn get_profile_config_raw(&self, id: &str) -> Result<String, AppError> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT config FROM profiles WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .map_err(|_| AppError::NotFound("profile not found".to_string()))
    }
}

fn row_to_user(row: &rusqlite::Row) -> rusqlite::Result<User> {
    let locked_until = row.get::<_, Option<String>>(7)?.map(parse_dt).transpose()?;
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        role: row.get(3)?,
        comment: row.get(4)?,
        enabled: row.get(5)?,
        failed_login_attempts: row.get(6)?,
        locked_until,
        created_at: parse_dt(row.get::<_, String>(8)?)?,
        updated_at: parse_dt(row.get::<_, String>(9)?)?,
        token_generation: row.get(10)?,
    })
}

fn parse_dt(s: String) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&s)
        .map(|d| d.to_utc())
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })
}

fn parse_json_config(s: &str) -> rusqlite::Result<serde_json::Value> {
    serde_json::from_str(s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dt_returns_error_on_invalid_input() {
        assert!(parse_dt("not-a-date".to_string()).is_err());
    }

    #[test]
    fn parse_dt_succeeds_on_valid_rfc3339() {
        assert!(parse_dt("2024-01-01T00:00:00Z".to_string()).is_ok());
    }

    /// Latest version derived from the static `migrations()` table — the
    /// expected `PRAGMA user_version` after a successful bootstrap.
    fn latest_version() -> u32 {
        migrations()
            .iter()
            .map(|m| m.version)
            .max()
            .expect("at least one migration must exist")
    }

    #[test]
    fn migrations_apply_to_empty_db_idempotently() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        apply_migrations(&mut conn, migrations()).expect("first apply");

        let v1: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .map(|v| v as u32)
            .unwrap();
        assert_eq!(v1, latest_version());

        // Second apply is a no-op — version unchanged, no errors.
        apply_migrations(&mut conn, migrations()).expect("second apply");
        let v2: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .map(|v| v as u32)
            .unwrap();
        assert_eq!(v2, latest_version());

        // _schema_migrations should have exactly one row per migration.
        let count: u32 = conn
            .query_row("SELECT COUNT(*) FROM _schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, migrations().len() as u32);
    }

    #[tokio::test]
    async fn migrations_preserve_existing_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let path_str = path.to_string_lossy().to_string();

        // First open: bootstraps the schema.
        let db = UserDb::new(&path_str).await.unwrap();
        let now = Utc::now().to_rfc3339();
        {
            let conn = db.conn.lock().await;
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, comment,
                                    enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'admin', '', 1, ?4, ?4)",
                params!["uid-1", "alice", "hash", now],
            )
            .unwrap();
        }
        drop(db);

        // Second open: must not error and must preserve the inserted row.
        let db = UserDb::new(&path_str).await.unwrap();
        let user = db.get_user_by_username("alice").await.unwrap();
        assert_eq!(user.id, "uid-1");
    }
}
