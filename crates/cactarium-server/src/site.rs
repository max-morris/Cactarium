//! Site-wide settings that only the superadmin changes.

use crate::auth::User;
use crate::error::AppResult;
use crate::state::AppState;

/// Who may mark users, organizations and entries trusted: `superadmin` or `admins`.
pub const TRUST_GRANTED_BY: &str = "trust-granted-by";
/// Whether `@head`/`@master` of an untrusted stack are served: `refuse` or `allow`.
pub const UNTRUSTED_TIPS: &str = "untrusted-tips";
/// The response header that marks a stack's unpinned form as coming from an untrusted stack;
/// cactup warns loudly and asks before installing it.
pub const UNTRUSTED_HEADER: &str = "x-cactarium-untrusted";

/// Whether untrusted stacks' branch tips are served (`allow`); anything else means refuse.
pub async fn untrusted_tips_allowed(state: &AppState) -> AppResult<bool> {
    Ok(get(state, UNTRUSTED_TIPS).await?.as_deref() == Some("allow"))
}

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
