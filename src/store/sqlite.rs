use std::str::FromStr;

use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    AuditEvent, NewAuditEvent, OneTimeToken, PasskeyRecord, Role, Session, Stage, Store,
    StoreError, TokenKind, TotpRecord, User,
};

const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("migrations/0001_initial.sql"))];

/// SQLite storage. Tables are prefixed `latchkey_` and migrations are tracked in
/// `latchkey_migrations`, so the app's own migrations can share the database.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Opens (creating if missing) and migrates the database at `url`, e.g. `sqlite://auth.db`.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::from_str(url)
            .map_err(db)?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(db)?;
        Self::from_pool(pool).await
    }

    /// A private in-memory database on one long-lived connection.
    pub async fn in_memory() -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(db)?
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await
            .map_err(db)?;
        Self::from_pool(pool).await
    }

    /// Uses an existing pool (with foreign keys on) and applies pending migrations.
    pub async fn from_pool(pool: SqlitePool) -> Result<Self, StoreError> {
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS latchkey_migrations (
                version INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(db)?;
        for (version, sql) in MIGRATIONS {
            let mut tx = self.pool.begin().await.map_err(db)?;
            let applied: Option<i64> =
                sqlx::query_scalar("SELECT version FROM latchkey_migrations WHERE version = ?")
                    .bind(version)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db)?;
            if applied.is_some() {
                continue;
            }
            sqlx::raw_sql(*sql).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("INSERT INTO latchkey_migrations (version, applied_at) VALUES (?, ?)")
                .bind(version)
                .bind(OffsetDateTime::now_utc().unix_timestamp())
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            tx.commit().await.map_err(db)?;
        }
        Ok(())
    }
}

fn db(err: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(inner) = &err
        && inner.is_unique_violation()
    {
        return StoreError::Conflict;
    }
    StoreError::Database(err.to_string())
}

fn ts(at: OffsetDateTime) -> i64 {
    at.unix_timestamp()
}

fn from_ts(raw: i64) -> Result<OffsetDateTime, StoreError> {
    OffsetDateTime::from_unix_timestamp(raw).map_err(|e| StoreError::Corrupt(e.to_string()))
}

fn from_opt_ts(raw: Option<i64>) -> Result<Option<OffsetDateTime>, StoreError> {
    raw.map(from_ts).transpose()
}

fn uuid(raw: &str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(raw).map_err(|e| StoreError::Corrupt(e.to_string()))
}

fn get<'r, T>(row: &'r SqliteRow, column: &str) -> Result<T, StoreError>
where
    T: sqlx::Decode<'r, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
{
    row.try_get(column).map_err(db)
}

fn user_from(row: &SqliteRow) -> Result<User, StoreError> {
    let role: String = get(row, "role")?;
    let failed: i64 = get(row, "failed_attempts")?;
    Ok(User {
        id: uuid(&get::<String>(row, "id")?)?,
        email: get(row, "email")?,
        display_name: get(row, "display_name")?,
        role: Role::parse(&role).ok_or_else(|| StoreError::Corrupt(format!("role {role}")))?,
        password_hash: get(row, "password_hash")?,
        active: get::<i64>(row, "active")? != 0,
        failed_attempts: u32::try_from(failed).unwrap_or(u32::MAX),
        locked_until: from_opt_ts(get(row, "locked_until")?)?,
        created_at: from_ts(get(row, "created_at")?)?,
    })
}

fn session_from(row: &SqliteRow) -> Result<Session, StoreError> {
    let stage: String = get(row, "stage")?;
    Ok(Session {
        id: uuid(&get::<String>(row, "id")?)?,
        token_hash: get(row, "token_hash")?,
        user_id: uuid(&get::<String>(row, "user_id")?)?,
        stage: Stage::parse(&stage).ok_or_else(|| StoreError::Corrupt(format!("stage {stage}")))?,
        csrf_token: get(row, "csrf_token")?,
        method: get(row, "method")?,
        created_at: from_ts(get(row, "created_at")?)?,
        expires_at: from_ts(get(row, "expires_at")?)?,
        authenticated_at: from_opt_ts(get(row, "authenticated_at")?)?,
        ip: get(row, "ip")?,
        user_agent: get(row, "user_agent")?,
    })
}

fn passkey_from(row: &SqliteRow) -> Result<PasskeyRecord, StoreError> {
    Ok(PasskeyRecord {
        id: uuid(&get::<String>(row, "id")?)?,
        user_id: uuid(&get::<String>(row, "user_id")?)?,
        credential_id: get(row, "credential_id")?,
        name: get(row, "name")?,
        data: get(row, "data")?,
        created_at: from_ts(get(row, "created_at")?)?,
        last_used_at: from_opt_ts(get(row, "last_used_at")?)?,
    })
}

macro_rules! select_users {
    ($filter:literal) => {
        concat!(
            "SELECT id, email, display_name, role, password_hash, active, failed_attempts, ",
            "locked_until, created_at FROM latchkey_users ",
            $filter
        )
    };
}

macro_rules! select_sessions {
    ($filter:literal) => {
        concat!(
            "SELECT id, token_hash, user_id, stage, csrf_token, method, created_at, expires_at, ",
            "authenticated_at, ip, user_agent FROM latchkey_sessions ",
            $filter
        )
    };
}

async fn insert_session_on(
    conn: &mut sqlx::SqliteConnection,
    session: &Session,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO latchkey_sessions (id, token_hash, user_id, stage, csrf_token, method, \
         created_at, expires_at, authenticated_at, ip, user_agent) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(session.id.to_string())
    .bind(&session.token_hash)
    .bind(session.user_id.to_string())
    .bind(session.stage.as_str())
    .bind(&session.csrf_token)
    .bind(&session.method)
    .bind(ts(session.created_at))
    .bind(ts(session.expires_at))
    .bind(session.authenticated_at.map(ts))
    .bind(&session.ip)
    .bind(&session.user_agent)
    .execute(conn)
    .await
    .map_err(db)?;
    Ok(())
}

#[async_trait]
impl Store for SqliteStore {
    async fn create_user(&self, user: &User) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO latchkey_users (id, email, display_name, role, password_hash, active, \
             failed_attempts, locked_until, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(user.id.to_string())
        .bind(&user.email)
        .bind(&user.display_name)
        .bind(user.role.as_str())
        .bind(&user.password_hash)
        .bind(i64::from(user.active))
        .bind(i64::from(user.failed_attempts))
        .bind(user.locked_until.map(ts))
        .bind(ts(user.created_at))
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn user_by_id(&self, id: Uuid) -> Result<Option<User>, StoreError> {
        sqlx::query(select_users!("WHERE id = ?"))
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .as_ref()
            .map(user_from)
            .transpose()
    }

    async fn user_by_email(&self, email: &str) -> Result<Option<User>, StoreError> {
        sqlx::query(select_users!("WHERE email = ?"))
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .as_ref()
            .map(user_from)
            .transpose()
    }

    async fn owner(&self) -> Result<Option<User>, StoreError> {
        sqlx::query(select_users!("WHERE role = 'owner'"))
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .as_ref()
            .map(user_from)
            .transpose()
    }

    async fn set_password(&self, user: Uuid, hash: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE latchkey_users SET password_hash = ? WHERE id = ?")
            .bind(hash)
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    async fn set_active(&self, user: Uuid, active: bool) -> Result<(), StoreError> {
        sqlx::query("UPDATE latchkey_users SET active = ? WHERE id = ?")
            .bind(i64::from(active))
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    async fn add_failure(&self, user: Uuid) -> Result<u32, StoreError> {
        let count: Option<i64> = sqlx::query_scalar(
            "UPDATE latchkey_users SET failed_attempts = failed_attempts + 1 WHERE id = ? \
             RETURNING failed_attempts",
        )
        .bind(user.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        Ok(count.and_then(|c| u32::try_from(c).ok()).unwrap_or(0))
    }

    async fn set_locked_until(
        &self,
        user: Uuid,
        until: Option<OffsetDateTime>,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE latchkey_users SET locked_until = ? WHERE id = ?")
            .bind(until.map(ts))
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    async fn clear_failures(&self, user: Uuid) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE latchkey_users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
        )
        .bind(user.to_string())
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn reset_user(&self, user: Uuid) -> Result<(), StoreError> {
        let id = user.to_string();
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query(
            "UPDATE latchkey_users SET password_hash = NULL, active = 0, failed_attempts = 0, \
             locked_until = NULL WHERE id = ?",
        )
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        for sql in [
            "DELETE FROM latchkey_totp WHERE user_id = ?",
            "DELETE FROM latchkey_passkeys WHERE user_id = ?",
            "DELETE FROM latchkey_recovery_codes WHERE user_id = ?",
            "DELETE FROM latchkey_sessions WHERE user_id = ?",
            "DELETE FROM latchkey_tokens WHERE user_id = ?",
        ] {
            sqlx::query(sql)
                .bind(&id)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        tx.commit().await.map_err(db)
    }

    async fn insert_token(&self, token: &OneTimeToken) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("DELETE FROM latchkey_tokens WHERE user_id = ? AND kind = ?")
            .bind(token.user_id.to_string())
            .bind(token.kind.as_str())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query(
            "INSERT INTO latchkey_tokens (hash, kind, user_id, created_at, expires_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&token.hash)
        .bind(token.kind.as_str())
        .bind(token.user_id.to_string())
        .bind(ts(token.created_at))
        .bind(ts(token.expires_at))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)
    }

    async fn consume_token(
        &self,
        hash: &[u8],
        kind: TokenKind,
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, StoreError> {
        let row = sqlx::query(
            "DELETE FROM latchkey_tokens WHERE hash = ? AND kind = ? \
             RETURNING user_id, expires_at",
        )
        .bind(hash)
        .bind(kind.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        if from_ts(get(&row, "expires_at")?)? <= now {
            return Ok(None);
        }
        Ok(Some(uuid(&get::<String>(&row, "user_id")?)?))
    }

    async fn latest_token_at(
        &self,
        user: Uuid,
        kind: TokenKind,
    ) -> Result<Option<OffsetDateTime>, StoreError> {
        let latest: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(created_at) FROM latchkey_tokens WHERE user_id = ? AND kind = ?",
        )
        .bind(user.to_string())
        .bind(kind.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        from_opt_ts(latest)
    }

    async fn insert_session(&self, session: &Session) -> Result<(), StoreError> {
        let mut conn = self.pool.acquire().await.map_err(db)?;
        insert_session_on(&mut conn, session).await
    }

    async fn replace_session(&self, old_hash: &[u8], session: &Session) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("DELETE FROM latchkey_sessions WHERE token_hash = ?")
            .bind(old_hash)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        insert_session_on(&mut tx, session).await?;
        tx.commit().await.map_err(db)
    }

    async fn session_by_hash(&self, hash: &[u8]) -> Result<Option<Session>, StoreError> {
        sqlx::query(select_sessions!("WHERE token_hash = ?"))
            .bind(hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .as_ref()
            .map(session_from)
            .transpose()
    }

    async fn set_session_authenticated(
        &self,
        hash: &[u8],
        at: OffsetDateTime,
        method: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE latchkey_sessions SET authenticated_at = ?, method = ? WHERE token_hash = ?",
        )
        .bind(ts(at))
        .bind(method)
        .bind(hash)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn delete_session(&self, hash: &[u8]) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM latchkey_sessions WHERE token_hash = ?")
            .bind(hash)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    async fn delete_session_by_id(&self, user: Uuid, id: Uuid) -> Result<bool, StoreError> {
        let done = sqlx::query("DELETE FROM latchkey_sessions WHERE id = ? AND user_id = ?")
            .bind(id.to_string())
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    async fn delete_user_sessions(&self, user: Uuid) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM latchkey_sessions WHERE user_id = ?")
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    async fn sessions_for(
        &self,
        user: Uuid,
        now: OffsetDateTime,
    ) -> Result<Vec<Session>, StoreError> {
        sqlx::query(select_sessions!(
            "WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC"
        ))
        .bind(user.to_string())
        .bind(ts(now))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?
        .iter()
        .map(session_from)
        .collect()
    }

    async fn totp(&self, user: Uuid) -> Result<Option<TotpRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT secret, pending_secret, last_step FROM latchkey_totp WHERE user_id = ?",
        )
        .bind(user.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        row.map(|row| {
            Ok(TotpRecord {
                secret: get(&row, "secret")?,
                pending_secret: get(&row, "pending_secret")?,
                last_step: get(&row, "last_step")?,
            })
        })
        .transpose()
    }

    async fn set_pending_totp(&self, user: Uuid, secret: &[u8]) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO latchkey_totp (user_id, pending_secret) VALUES (?, ?) \
             ON CONFLICT (user_id) DO UPDATE SET pending_secret = excluded.pending_secret",
        )
        .bind(user.to_string())
        .bind(secret)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn confirm_totp(&self, user: Uuid, step: i64) -> Result<bool, StoreError> {
        let done = sqlx::query(
            "UPDATE latchkey_totp SET secret = pending_secret, pending_secret = NULL, \
             last_step = ? WHERE user_id = ? AND pending_secret IS NOT NULL",
        )
        .bind(step)
        .bind(user.to_string())
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    async fn use_totp_step(&self, user: Uuid, step: i64) -> Result<bool, StoreError> {
        let done = sqlx::query(
            "UPDATE latchkey_totp SET last_step = ? WHERE user_id = ? AND secret IS NOT NULL \
             AND (last_step IS NULL OR last_step < ?)",
        )
        .bind(step)
        .bind(user.to_string())
        .bind(step)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    async fn delete_totp(&self, user: Uuid) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM latchkey_totp WHERE user_id = ?")
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    async fn all_totp(&self) -> Result<Vec<(Uuid, TotpRecord)>, StoreError> {
        sqlx::query("SELECT user_id, secret, pending_secret, last_step FROM latchkey_totp")
            .fetch_all(&self.pool)
            .await
            .map_err(db)?
            .iter()
            .map(|row| {
                Ok((
                    uuid(&get::<String>(row, "user_id")?)?,
                    TotpRecord {
                        secret: get(row, "secret")?,
                        pending_secret: get(row, "pending_secret")?,
                        last_step: get(row, "last_step")?,
                    },
                ))
            })
            .collect()
    }

    async fn set_totp_secrets(
        &self,
        user: Uuid,
        secret: Option<&[u8]>,
        pending_secret: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE latchkey_totp SET secret = ?, pending_secret = ? WHERE user_id = ?")
            .bind(secret)
            .bind(pending_secret)
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    async fn add_passkey(&self, passkey: &PasskeyRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO latchkey_passkeys (id, user_id, credential_id, name, data, created_at, \
             last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(passkey.id.to_string())
        .bind(passkey.user_id.to_string())
        .bind(&passkey.credential_id)
        .bind(&passkey.name)
        .bind(&passkey.data)
        .bind(ts(passkey.created_at))
        .bind(passkey.last_used_at.map(ts))
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn passkeys_for(&self, user: Uuid) -> Result<Vec<PasskeyRecord>, StoreError> {
        sqlx::query(
            "SELECT id, user_id, credential_id, name, data, created_at, last_used_at \
             FROM latchkey_passkeys WHERE user_id = ? ORDER BY created_at",
        )
        .bind(user.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db)?
        .iter()
        .map(passkey_from)
        .collect()
    }

    async fn update_passkey(
        &self,
        id: Uuid,
        data: &str,
        used_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE latchkey_passkeys SET data = ?, last_used_at = ? WHERE id = ?")
            .bind(data)
            .bind(ts(used_at))
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    async fn delete_passkey(&self, user: Uuid, id: Uuid) -> Result<bool, StoreError> {
        let done = sqlx::query("DELETE FROM latchkey_passkeys WHERE id = ? AND user_id = ?")
            .bind(id.to_string())
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    async fn all_passkeys(&self) -> Result<Vec<PasskeyRecord>, StoreError> {
        sqlx::query(
            "SELECT id, user_id, credential_id, name, data, created_at, last_used_at \
             FROM latchkey_passkeys",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?
        .iter()
        .map(passkey_from)
        .collect()
    }

    async fn set_passkey_data(&self, id: Uuid, data: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE latchkey_passkeys SET data = ? WHERE id = ?")
            .bind(data)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    async fn replace_recovery_codes(
        &self,
        user: Uuid,
        hashes: &[Vec<u8>],
    ) -> Result<(), StoreError> {
        let id = user.to_string();
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("DELETE FROM latchkey_recovery_codes WHERE user_id = ?")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        for hash in hashes {
            sqlx::query("INSERT INTO latchkey_recovery_codes (user_id, hash) VALUES (?, ?)")
                .bind(&id)
                .bind(hash)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        tx.commit().await.map_err(db)
    }

    async fn use_recovery_code(
        &self,
        user: Uuid,
        hash: &[u8],
        now: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query(
            "UPDATE latchkey_recovery_codes SET used_at = ? \
             WHERE user_id = ? AND hash = ? AND used_at IS NULL",
        )
        .bind(ts(now))
        .bind(user.to_string())
        .bind(hash)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    async fn unused_recovery_codes(&self, user: Uuid) -> Result<u32, StoreError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM latchkey_recovery_codes WHERE user_id = ? AND used_at IS NULL",
        )
        .bind(user.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        Ok(u32::try_from(count).unwrap_or(0))
    }

    async fn append_audit(&self, event: &NewAuditEvent) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO latchkey_audit (at, user_id, kind, detail, ip) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(ts(event.at))
        .bind(event.user_id.map(|id| id.to_string()))
        .bind(&event.kind)
        .bind(&event.detail)
        .bind(&event.ip)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn audit(&self, user: Option<Uuid>, limit: u32) -> Result<Vec<AuditEvent>, StoreError> {
        let rows = match user {
            Some(user) => {
                sqlx::query(
                    "SELECT id, at, user_id, kind, detail, ip FROM latchkey_audit \
                     WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                )
                .bind(user.to_string())
                .bind(i64::from(limit))
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query(
                    "SELECT id, at, user_id, kind, detail, ip FROM latchkey_audit \
                     ORDER BY id DESC LIMIT ?",
                )
                .bind(i64::from(limit))
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(db)?;
        rows.iter()
            .map(|row| {
                Ok(AuditEvent {
                    id: get(row, "id")?,
                    at: from_ts(get(row, "at")?)?,
                    user_id: get::<Option<String>>(row, "user_id")?
                        .map(|id| uuid(&id))
                        .transpose()?,
                    kind: get(row, "kind")?,
                    detail: get(row, "detail")?,
                    ip: get(row, "ip")?,
                })
            })
            .collect()
    }

    async fn purge_expired(&self, now: OffsetDateTime) -> Result<(), StoreError> {
        for sql in [
            "DELETE FROM latchkey_tokens WHERE expires_at <= ?",
            "DELETE FROM latchkey_sessions WHERE expires_at <= ?",
        ] {
            sqlx::query(sql)
                .bind(ts(now))
                .execute(&self.pool)
                .await
                .map_err(db)?;
        }
        Ok(())
    }
}
