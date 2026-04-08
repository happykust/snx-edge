use std::sync::Arc;

use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::Serialize;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::AppError;

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
}

/// Session record from the database.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// User data for API responses (without internal fields).
#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub role: String,
    pub comment: String,
    pub enabled: bool,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub active_sessions: usize,
}

/// Thread-safe database handle wrapping SQLite.
#[derive(Clone)]
pub struct UserDb {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl UserDb {
    pub async fn new(path: &str) -> anyhow::Result<Self> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
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
        )?;
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

        let hash = tokio::task::spawn_blocking(move || {
            bcrypt::hash(&admin_password, bcrypt::DEFAULT_COST)
        })
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
                    failed_login_attempts, locked_until, created_at, updated_at
             FROM users WHERE id = ?1",
            params![id],
            |row| row_to_user(row),
        )
        .map_err(|_| AppError::NotFound("user not found".to_string()))
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User, AppError> {
        let conn = self.conn.lock().await;
        let username = username.to_string();
        conn.query_row(
            "SELECT id, username, password_hash, role, comment, enabled,
                    failed_login_attempts, locked_until, created_at, updated_at
             FROM users WHERE username = ?1",
            params![username],
            |row| row_to_user(row),
        )
        .map_err(|_| AppError::NotFound("user not found".to_string()))
    }

    pub async fn list_users(&self) -> Result<Vec<User>, AppError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, username, password_hash, role, comment, enabled,
                    failed_login_attempts, locked_until, created_at, updated_at
             FROM users ORDER BY created_at",
        )?;
        let users = stmt
            .query_map([], |row| row_to_user(row))?
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
        let hash = tokio::task::spawn_blocking(move || {
            bcrypt::hash(&password_owned, bcrypt::DEFAULT_COST)
        })
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
            if let rusqlite::Error::SqliteFailure(ref err, _) = e {
                if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE {
                    return AppError::Conflict(format!("username '{username}' already exists"));
                }
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
                        failed_login_attempts, locked_until, created_at, updated_at
                 FROM users WHERE id = ?1",
                params![id],
                |row| row_to_user(row),
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

    pub async fn change_password(&self, id: &str, new_password: &str) -> Result<(), AppError> {
        if new_password.len() < 8 {
            return Err(AppError::BadRequest(
                "password must be at least 8 characters".to_string(),
            ));
        }

        let password_owned = new_password.to_string();
        let hash = tokio::task::spawn_blocking(move || {
            bcrypt::hash(&password_owned, bcrypt::DEFAULT_COST)
        })
        .await
        .map_err(|e| AppError::Internal(format!("join error: {e}")))?
        .map_err(|e| AppError::Internal(format!("bcrypt error: {e}")))?;
        let now = Utc::now();

        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
            params![hash, now.to_rfc3339(), id],
        )?;
        Ok(())
    }

    // === Login tracking ===

    pub async fn record_failed_login(&self, user_id: &str, max_attempts: u32, lockout_minutes: u32) -> Result<(), AppError> {
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

    pub async fn delete_user_sessions(&self, user_id: &str) -> Result<u64, AppError> {
        let conn = self.conn.lock().await;
        let count = conn.execute(
            "DELETE FROM sessions WHERE user_id = ?1",
            params![user_id],
        )?;
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
                    created_at: parse_dt(row.get::<_, String>(4)?),
                    expires_at: parse_dt(row.get::<_, String>(5)?),
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
    pub fn start_cleanup_task(&self) {
        let db = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                match db.cleanup_expired_sessions().await {
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
        });
    }

    /// Get list of permissions for a role.
    pub fn permissions_for_role(role: &str) -> Vec<String> {
        match role {
            "admin" => vec![
                "tunnel.*",
                "config.*",
                "profiles.*",
                "routing.*",
                "routing.setup",
                "routing.teardown",
                "users.*",
                "logs.*",
            ],
            "operator" => vec![
                "tunnel.connect",
                "tunnel.disconnect",
                "tunnel.status",
                "config.read",
                "profiles.read",
                "routing.clients.*",
                "routing.bypass.*",
                "routing.diagnostics",
                "logs.*",
            ],
            "viewer" => vec![
                "tunnel.status",
                "config.read",
                "profiles.read",
                "routing.read",
                "logs.read",
            ],
            _ => vec![],
        }
        .into_iter()
        .map(String::from)
        .collect()
    }
}

// === VPN Profiles ===

/// VPN connection profile stored in the database.
#[derive(Debug, Clone, Serialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    /// Full VPN config as JSON (deserialized by caller into VpnConfig).
    pub config: serde_json::Value,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UserDb {
    pub async fn list_profiles(&self) -> Result<Vec<Profile>, AppError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, name, config, enabled, created_at, updated_at
             FROM profiles ORDER BY name",
        )?;
        let profiles = stmt
            .query_map([], |row| {
                let config_str: String = row.get(2)?;
                Ok(Profile {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    config: serde_json::from_str(&config_str).unwrap_or_default(),
                    enabled: row.get(3)?,
                    created_at: parse_dt(row.get::<_, String>(4)?),
                    updated_at: parse_dt(row.get::<_, String>(5)?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(profiles)
    }

    pub async fn get_profile(&self, id: &str) -> Result<Profile, AppError> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT id, name, config, enabled, created_at, updated_at
             FROM profiles WHERE id = ?1",
            params![id],
            |row| {
                let config_str: String = row.get(2)?;
                Ok(Profile {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    config: serde_json::from_str(&config_str).unwrap_or_default(),
                    enabled: row.get(3)?,
                    created_at: parse_dt(row.get::<_, String>(4)?),
                    updated_at: parse_dt(row.get::<_, String>(5)?),
                })
            },
        )
        .map_err(|_| AppError::NotFound("profile not found".to_string()))
    }

    /// Get the raw VPN config JSON for a profile (including secrets, for internal use).
    pub async fn get_profile_config(&self, id: &str) -> Result<String, AppError> {
        let conn = self.conn.lock().await;
        conn.query_row(
            "SELECT config FROM profiles WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .map_err(|_| AppError::NotFound("profile not found".to_string()))
    }

    pub async fn create_profile(
        &self,
        name: &str,
        config: &serde_json::Value,
    ) -> Result<Profile, AppError> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let config_str = serde_json::to_string(config)
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

        let existing = conn
            .query_row(
                "SELECT id, name, config, enabled, created_at, updated_at
                 FROM profiles WHERE id = ?1",
                params![id],
                |row| {
                    let config_str: String = row.get(2)?;
                    Ok(Profile {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        config: serde_json::from_str(&config_str).unwrap_or_default(),
                        enabled: row.get(3)?,
                        created_at: parse_dt(row.get::<_, String>(4)?),
                        updated_at: parse_dt(row.get::<_, String>(5)?),
                    })
                },
            )
            .map_err(|_| AppError::NotFound("profile not found".to_string()))?;

        let new_name = name.unwrap_or(&existing.name);
        let new_enabled = enabled.unwrap_or(existing.enabled);
        let new_config_str = if let Some(cfg) = config {
            serde_json::to_string(cfg)
                .map_err(|e| AppError::BadRequest(format!("invalid config JSON: {e}")))?
        } else {
            serde_json::to_string(&existing.config).unwrap_or_default()
        };

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
}

fn row_to_user(row: &rusqlite::Row) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        role: row.get(3)?,
        comment: row.get(4)?,
        enabled: row.get(5)?,
        failed_login_attempts: row.get(6)?,
        locked_until: row.get::<_, Option<String>>(7)?.map(parse_dt),
        created_at: parse_dt(row.get::<_, String>(8)?),
        updated_at: parse_dt(row.get::<_, String>(9)?),
    })
}

fn parse_dt(s: String) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&s)
        .map(|d| d.to_utc())
        .unwrap_or_default()
}
