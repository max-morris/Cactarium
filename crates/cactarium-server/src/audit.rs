//! The audit log: every admin action, sign-in, publication and token use.

use crate::error::AppResult;
use crate::state::AppState;

pub async fn audit(
    state: &AppState,
    actor: Option<i64>,
    action: &str,
    target: Option<&str>,
    details: serde_json::Value,
    ip: Option<std::net::IpAddr>,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO audit_log (actor, action, target, details, ip) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(details)
    .bind(ip.map(|i| i.to_string()))
    .execute(&state.db)
    .await?;
    Ok(())
}
