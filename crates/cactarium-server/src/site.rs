//! Site-wide settings that only the superadmin changes.

use crate::auth::User;
use crate::error::AppResult;
use crate::state::AppState;

/// Who may mark users trusted (their submissions skip review): `superadmin` or `admins`.
pub const TRUST_GRANTED_BY: &str = "trust-granted-by";

pub async fn get(state: &AppState, key: &str) -> AppResult<Option<String>> {
    Ok(sqlx::query_scalar("SELECT value FROM site_settings WHERE key = $1")
        .bind(key)
        .fetch_optional(&state.db)
        .await?)
}

pub async fn set(state: &AppState, key: &str, value: &str) -> AppResult<()> {
    sqlx::query("INSERT INTO site_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
        .bind(key)
        .bind(value)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// Whether `user` may mark users trusted: always the superadmin; other admins only when the
/// superadmin allows it.
pub async fn may_grant_trust(state: &AppState, user: &User) -> AppResult<bool> {
    if user.is_superadmin() {
        return Ok(true);
    }
    Ok(user.is_admin() && get(state, TRUST_GRANTED_BY).await?.as_deref() == Some("admins"))
}
