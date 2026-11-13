//! Creating entries and recording submissions: who goes through review and who does not.
//!
//! Users, organizations and entries can be trusted. A new entry is `pending` (visible to its
//! owner and admins) with an open submission in the review queue, unless the user creating it is
//! trusted or an admin, or it goes under a trusted organization: then it goes straight to `public`
//! and its submission is recorded as auto-approved, so the audit trail stays complete.
//!
//! Once an entry is public, each new release (a pushed tag, a snapshot stack release, a new sim
//! version) is reviewed the same way: it publishes at once when the entry itself, its owner (the
//! user or organization), or the user publishing it is trusted. Otherwise it is stored as
//! `pending`, hidden from everyone but the entry's managers and admins, with its own submission in
//! the queue. While the entry itself is still pending, its releases ride on the entry's review.

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

pub fn skips_review(user: &User) -> bool {
    user.trusted || user.is_admin()
}

/// Whether the namespace `owner` is trusted: a trusted (or admin) user who isn't banned, or a
/// trusted organization.
pub async fn owner_trusted(state: &AppState, owner: &str) -> AppResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users WHERE username = $1 AND NOT banned AND (trusted OR role <> 'user'))
             OR EXISTS (SELECT 1 FROM orgs WHERE name = $1 AND trusted)",
    )
    .bind(owner)
    .fetch_one(&state.db)
    .await?)
}

/// Whether `entry` itself or its owner is trusted (who publishes a given release aside).
pub async fn entry_trusted(state: &AppState, entry: &Entry) -> AppResult<bool> {
    let trusted: bool = sqlx::query_scalar("SELECT trusted FROM entries WHERE id = $1")
        .bind(entry.id)
        .fetch_one(&state.db)
        .await?;
    Ok(trusted || owner_trusted(state, &entry.owner).await?)
}

/// The review state a new release of `entry` starts in: `approved` or `pending`. `actor` is the
/// user publishing it, if any (a tag found by polling or a webhook has none: the owner pushed it).
pub async fn release_review(
    state: &AppState,
    entry: &Entry,
    actor: Option<&User>,
) -> AppResult<&'static str> {
    // Re-read: the caller's copy may predate an approval or a change of trust.
    let (visibility, trusted): (String, bool) =
        sqlx::query_as("SELECT visibility, trusted FROM entries WHERE id = $1")
            .bind(entry.id)
            .fetch_one(&state.db)
            .await?;
    let approved = visibility == "pending"
        || trusted
        || actor.is_some_and(skips_review)
        || owner_trusted(state, &entry.owner).await?;
    Ok(if approved { "approved" } else { "pending" })
}

/// Queues a new release stored as `pending` for review; does nothing for an approved one.
pub async fn submit_release(
    db: &mut sqlx::PgConnection,
    entry: &Entry,
    version_id: i64,
    review: &str,
    actor: Option<&User>,
) -> AppResult<()> {
    if review != "pending" {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO submissions (entry_id, version_id, submitter, status) VALUES ($1, $2, $3, 'open')",
    )
    .bind(entry.id)
    .bind(version_id)
    .bind(actor.map(|u| u.id))
    .execute(&mut *db)
    .await?;
    crate::audit::audit_with(
        db,
        actor.map(|u| u.id),
        "release.submit",
        Some(&entry.slug()),
        json!({ "version_id": version_id }),
        None,
    )
    .await
}

pub async fn create_entry(state: &AppState, user: &User, n: NewEntry<'_>) -> AppResult<Entry> {
    let mut tx = state.db.begin().await?;
    let entry = create_entry_in(&mut tx, state, user, n).await?;
    tx.commit().await?;
    Ok(entry)
}

/// [`create_entry`], writing the entry, its submission and the audit record through `db` (a
/// transaction the caller commits with whatever else it creates).
pub async fn create_entry_in(db: &mut sqlx::PgConnection, state: &AppState, user: &User, n: NewEntry<'_>) -> AppResult<Entry> {
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
    let skip = skips_review(user) || owner_trusted(state, n.owner).await?;
    let visibility = if skip { "public" } else { "pending" };
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
    .fetch_one(&mut *db)
    .await?;
    let status = if skip { "auto-approved" } else { "open" };
    sqlx::query("INSERT INTO submissions (entry_id, submitter, status, decided_at) VALUES ($1, $2, $3, CASE WHEN $3 = 'open' THEN NULL ELSE now() END)")
        .bind(entry.id)
        .bind(user.id)
        .bind(status)
        .execute(&mut *db)
        .await?;
    crate::audit::audit_with(
        db,
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

/// Yanks a version (or unyanks it, with `yank` false): it stays downloadable by exact version but
/// no range chooses it. Whoever manages the entry may do this; the reason is shown with it.
pub async fn set_yanked(
    state: &AppState,
    user: &User,
    entry: &Entry,
    version_id: i64,
    yank: bool,
    reason: Option<&str>,
    via: &str,
) -> AppResult<()> {
    if !entry.manageable_by(Some(user)) {
        return Err(AppError::Forbidden);
    }
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    let n =
        sqlx::query("UPDATE versions SET yanked = $3, yank_reason = $4 WHERE id = $1 AND entry_id = $2")
            .bind(version_id)
            .bind(entry.id)
            .bind(yank)
            .bind(if yank { reason } else { None })
            .execute(&state.db)
            .await?
            .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    audit(
        state,
        Some(user.id),
        if yank { "version.yank" } else { "version.unyank" },
        Some(&entry.slug()),
        json!({ "version_id": version_id, "reason": reason, "via": via }),
        None,
    )
    .await
}
