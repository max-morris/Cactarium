//! Creating entries and recording submissions: who goes through review and who does not.
//!
//! A new entry from an ordinary user is `pending` (visible to its owner and admins) with an open
//! submission in the review queue. Trusted users and admins publish straight to `public`; their
//! submission is recorded as auto-approved so the audit trail stays complete. Once an entry is
//! public, its new versions publish without review.

use serde_json::json;

use crate::audit::audit;
use crate::auth::User;
use crate::error::{AppError, AppResult};
use crate::model::{ENTRY_COLS, Entry};
use crate::state::AppState;
use cactup_ecosystem_common::name::{Name, Owner};

pub struct NewEntry<'a> {
    pub kind: &'a str,
    pub owner: &'a str,
    pub name: &'a str,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub curated: bool,
}

/// Who may publish under `owner`: the user of that name, members of the organization of that
/// name, and admins under a namespace that is no user's (such as an org they don't belong to).
pub async fn check_namespace(state: &AppState, user: &User, owner: &str) -> AppResult<()> {
    if owner == user.username || user.orgs.iter().any(|o| o == owner) {
        return Ok(());
    }
    if user.is_admin() {
        let is_user: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)")
                .bind(owner)
                .fetch_one(&state.db)
                .await?;
        if !is_user {
            return Ok(());
        }
        return Err(AppError::Denied(format!(
            "'{owner}' is a user's name; only they can publish under it"
        )));
    }
    Err(AppError::Denied(format!(
        "you can publish only under your own name or an organization you belong to, not '{owner}'"
    )))
}

/// The namespaces `user` may publish under without being an admin: their name and their orgs.
pub fn namespaces(user: &User) -> Vec<String> {
    std::iter::once(user.username.clone())
        .chain(user.orgs.iter().cloned())
        .collect()
}

fn skips_review(user: &User) -> bool {
    user.trusted || user.is_admin()
}

pub async fn create_entry(state: &AppState, user: &User, n: NewEntry<'_>) -> AppResult<Entry> {
    n.owner.parse::<Owner>().map_err(AppError::bad)?;
    n.name.parse::<Name>().map_err(AppError::bad)?;
    if n.curated && !user.is_admin() {
        return Err(AppError::Forbidden);
    }
    if !n.curated {
        check_namespace(state, user, n.owner).await?;
    }
    if find_conflict(state, n.owner, n.name).await? {
        return Err(AppError::Conflict(format!("{}/{} already exists", n.owner, n.name)));
    }
    let visibility = if skips_review(user) { "public" } else { "pending" };
    let entry = sqlx::query_as::<_, Entry>(&format!(
        "INSERT INTO entries (kind, owner, name, summary, description, visibility, curated, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {ENTRY_COLS}"
    ))
    .bind(n.kind)
    .bind(n.owner)
    .bind(n.name)
    .bind(&n.summary)
    .bind(&n.description)
    .bind(visibility)
    .bind(n.curated)
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;
    let status = if skips_review(user) { "auto-approved" } else { "open" };
    sqlx::query("INSERT INTO submissions (entry_id, submitter, status, decided_at) VALUES ($1, $2, $3, CASE WHEN $3 = 'open' THEN NULL ELSE now() END)")
        .bind(entry.id)
        .bind(user.id)
        .bind(status)
        .execute(&state.db)
        .await?;
    audit(
        state,
        Some(user.id),
        "entry.create",
        Some(&entry.slug()),
        json!({ "kind": n.kind, "visibility": visibility }),
        None,
    )
    .await?;
    Ok(entry)
}

/// Whether owner/name is taken, ignoring case.
async fn find_conflict(state: &AppState, owner: &str, name: &str) -> AppResult<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM entries WHERE lower(owner) = lower($1) AND lower(name) = lower($2))")
        .bind(owner)
        .bind(name)
        .fetch_one(&state.db)
        .await?)
}

/// After the owner answers a "changes requested" review, the submission goes back in the queue.
pub async fn resubmit(state: &AppState, entry: &Entry, user: &User) -> AppResult<()> {
    let n = sqlx::query("UPDATE submissions SET status = 'open', created_at = now() WHERE entry_id = $1 AND status = 'changes-requested'")
        .bind(entry.id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n > 0 {
        audit(state, Some(user.id), "entry.resubmit", Some(&entry.slug()), json!({}), None).await?;
    }
    Ok(())
}

pub async fn touch(state: &AppState, entry_id: i64) -> AppResult<()> {
    sqlx::query("UPDATE entries SET updated_at = now() WHERE id = $1")
        .bind(entry_id)
        .execute(&state.db)
        .await?;
    Ok(())
}
