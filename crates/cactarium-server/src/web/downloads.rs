//! Reviewed downloads: a `.sim` input's file or a tarball component, pinned by its sha256,
//! submitted for review so pins to it can be trusted. The server fetches the URL once (under the
//! outbound-fetch policy, with a size and time limit), checks the sha256, and keeps only the row:
//! no copy of the file. Admins approve or reject it on the admin pages; trusted users' and admins'
//! submissions are approved at once (recorded so), as their entries are.

use std::collections::HashMap;
use std::time::Duration;

use axum::Form;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use cactup_ecosystem_common::api::{
    DownloadConflict, DownloadQuery, DownloadReview, DownloadSubmission, ErrorDetail, MAX_LOOKUP_URL_BYTES,
};
use serde_json::json;

use crate::audit::{audit, audit_with};
use crate::auth::Admin;
use crate::error::{ApiResult, AppError, AppResult};
use crate::git::{self, GitPolicy};
use crate::model::fmt_time;
use crate::security::ClientIp;
use crate::state::AppState;
use crate::templates::{AdminDownloadsPage, DownloadRow, PageCtx, page};
use crate::web::api::TokenUser;

/// The most a submitted download's fetch reads.
pub const MAX_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// How long that fetch may take.
const FETCH_TIME: Duration = Duration::from_secs(15 * 60);
/// The longest note a submitter may leave for the reviewer.
const MAX_NOTE_CHARS: usize = 4000;

/// The command that submits a download for review, for messages that refuse a pin to one.
pub fn submit_command(url: &str) -> String {
    format!("cactup download submit {url}")
}

/// The review of each (url, sha256), in order: `pending`, `approved`, `rejected`, or `None` when it
/// was never submitted. The URL is compared as written.
pub async fn reviews_of(state: &AppState, asked: &[DownloadQuery]) -> AppResult<Vec<Option<String>>> {
    if asked.is_empty() {
        return Ok(vec![]);
    }
    let urls: Vec<&str> = asked.iter().map(|d| d.url.trim()).collect();
    let shas: Vec<&str> = asked.iter().map(|d| d.sha256.as_str()).collect();
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT d.url, d.sha256, d.review FROM downloads d
         JOIN UNNEST($1::text[], $2::text[]) AS a(url, sha256) ON a.url = d.url AND a.sha256 = d.sha256",
    )
    .bind(&urls)
    .bind(&shas)
    .fetch_all(&state.db)
    .await?;
    let known: HashMap<(String, String), String> = rows.into_iter().map(|(u, s, r)| ((u, s), r)).collect();
    Ok(asked
        .iter()
        .map(|d| known.get(&(d.url.trim().to_owned(), d.sha256.clone())).cloned())
        .collect())
}

/// The review of one download, if it was submitted.
pub async fn review_of(state: &AppState, url: &str, sha256: &str) -> AppResult<Option<String>> {
    let asked = [DownloadQuery { url: url.to_owned(), sha256: sha256.to_owned() }];
    Ok(reviews_of(state, &asked).await?.pop().flatten())
}

/// Checks a submission's fields before anything is fetched.
fn validate(s: &DownloadSubmission) -> AppResult<()> {
    let url = s.url.trim();
    if url.is_empty() {
        return Err(AppError::bad("give the download's url"));
    }
    if url.len() > MAX_LOOKUP_URL_BYTES {
        return Err(AppError::bad(format!("the url is {} bytes long; at most {MAX_LOOKUP_URL_BYTES}", url.len())));
    }
    if s.sha256.len() != 64 || !s.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(AppError::bad(format!("'{}' is not a sha256 (64 lowercase hex digits)", s.sha256)));
    }
    if s.note.as_deref().is_some_and(|n| n.chars().count() > MAX_NOTE_CHARS) {
        return Err(AppError::bad(format!("the note is longer than {MAX_NOTE_CHARS} characters")));
    }
    Ok(())
}

/// `POST /downloads`: fetches the URL once, checks its sha256, and queues it for review (approved
/// at once for a trusted user or an admin). One submitted before is answered 409 with its review.
pub async fn submit(
    State(state): State<AppState>,
    TokenUser(user): TokenUser,
    ip: ClientIp,
    Json(s): Json<DownloadSubmission>,
) -> ApiResult<Response> {
    validate(&s)?;
    let url = s.url.trim().to_owned();
    if let Some(known) = known(&state, &url, &s.sha256).await? {
        return Ok(conflict(known));
    }
    // Each submission downloads the whole file: a few per user an hour.
    state.limiter.check_user("download-submit", user.id, 10, Duration::from_secs(3600))?;
    state.limiter.check("download-submit", ip.0, 10)?;
    let policy = GitPolicy { allow_local: state.cfg.allow_local_repos };
    let got = git::fetch_and_hash(policy, &url, MAX_DOWNLOAD_BYTES, FETCH_TIME)
        .await
        .map_err(|e| AppError::bad(format!("cannot fetch {url}: {e:#}")))?;
    if got.sha256 != s.sha256 {
        return Err(AppError::bad(format!(
            "{url} has sha256 {}, not {} (the file changed, or the sha256 is wrong); nothing was submitted",
            got.sha256, s.sha256
        ))
        .into());
    }
    let skips = crate::publish::skips_review(&user);
    let review = if skips { "approved" } else { "pending" };
    let note = s.note.as_deref().map(str::trim).filter(|n| !n.is_empty());
    let mut tx = state.db.begin().await.map_err(AppError::from)?;
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO downloads (url, sha256, size, note, review, submitter, reviewer, decided_at)
         VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $5 = 'approved' THEN $6 END, CASE WHEN $5 = 'approved' THEN now() END)
         ON CONFLICT (url, sha256) DO NOTHING RETURNING id",
    )
    .bind(&url)
    .bind(&s.sha256)
    .bind(i64::try_from(got.size).unwrap_or(i64::MAX))
    .bind(note)
    .bind(review)
    .bind(user.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::from)?;
    let Some(id) = id else {
        // Submitted by another request while this one fetched.
        drop(tx);
        let known = known(&state, &url, &s.sha256).await?.ok_or(AppError::NotFound)?;
        return Ok(conflict(known));
    };
    audit_with(
        &mut tx,
        Some(user.id),
        "download.submit",
        Some(&url),
        json!({ "id": id, "sha256": s.sha256, "size": got.size, "review": review }),
        ip.0,
    )
    .await?;
    tx.commit().await.map_err(AppError::from)?;
    Ok(Json(DownloadReview { id, review: review.to_owned() }).into_response())
}

/// A download already submitted, by URL and content.
async fn known(state: &AppState, url: &str, sha256: &str) -> AppResult<Option<DownloadReview>> {
    let row: Option<(i64, String)> = sqlx::query_as("SELECT id, review FROM downloads WHERE url = $1 AND sha256 = $2")
        .bind(url)
        .bind(sha256)
        .fetch_optional(&state.db)
        .await?;
    Ok(row.map(|(id, review)| DownloadReview { id, review }))
}

/// The 409 answer to a download submitted before: an error that also carries its review.
fn conflict(known: DownloadReview) -> Response {
    let body = DownloadConflict {
        error: ErrorDetail { code: "conflict".into(), message: format!("already submitted (#{}, {})", known.id, known.review) },
        known,
    };
    (StatusCode::CONFLICT, Json(body)).into_response()
}

/// `/admin/downloads`: the downloads awaiting review, then the latest decided.
pub async fn admin_page(State(state): State<AppState>, Admin(a): Admin) -> AppResult<Response> {
    let rows: Vec<(i64, String, String, i64, Option<String>, String, Option<String>, Option<String>, Option<String>, time::OffsetDateTime)> =
        sqlx::query_as(
            "SELECT d.id, d.url, d.sha256, d.size, d.note, d.review, d.review_note, s.username, r.username, d.created_at
             FROM downloads d LEFT JOIN users s ON s.id = d.submitter LEFT JOIN users r ON r.id = d.reviewer
             ORDER BY d.review = 'pending' DESC, COALESCE(d.decided_at, d.created_at) DESC LIMIT 200",
        )
        .fetch_all(&state.db)
        .await?;
    let downloads = rows
        .into_iter()
        .map(|(id, url, sha256, size, note, review, review_note, submitter, reviewer, at)| DownloadRow {
            id,
            url,
            sha256,
            size: human_size(size),
            note: note.unwrap_or_default(),
            review,
            review_note: review_note.unwrap_or_default(),
            submitter: submitter.unwrap_or_default(),
            reviewer: reviewer.unwrap_or_default(),
            when: fmt_time(at),
        })
        .collect();
    Ok(page(&AdminDownloadsPage { ctx: PageCtx::new(&state, Some(&a.session)), nav: "downloads".into(), downloads })?.into_response())
}

/// Approves or rejects a download awaiting review (a decided one stays decided).
pub async fn admin_decide(
    State(state): State<AppState>,
    Admin(a): Admin,
    Path(id): Path<i64>,
    Form(f): Form<HashMap<String, String>>,
) -> AppResult<Response> {
    a.session.check_csrf(f.get("_csrf").map(String::as_str).unwrap_or(""))?;
    let review = match f.get("decision").map(String::as_str) {
        Some("approve") => "approved",
        Some("reject") => "rejected",
        _ => return Err(AppError::bad("choose approve or reject")),
    };
    let note = f.get("note").map(|n| n.trim().to_owned()).filter(|n| !n.is_empty());
    let url: Option<String> = sqlx::query_scalar(
        "UPDATE downloads SET review = $2, review_note = $3, reviewer = $4, decided_at = now()
         WHERE id = $1 AND review = 'pending' RETURNING url",
    )
    .bind(id)
    .bind(review)
    .bind(&note)
    .bind(a.user.id)
    .fetch_optional(&state.db)
    .await?;
    let Some(url) = url else {
        return Err(AppError::Conflict("this download was already decided (or doesn't exist); reload the page".into()));
    };
    audit(&state, Some(a.user.id), &format!("download.{}", &review[..review.len() - 1]), Some(&url), json!({ "id": id, "note": note }), None)
        .await?;
    Ok(Redirect::to("/admin/downloads").into_response())
}

/// `1.5 MB`, for a reviewer.
fn human_size(n: i64) -> String {
    let n = n as f64;
    match n {
        n if n >= 1e9 => format!("{:.1} GB", n / 1e9),
        n if n >= 1e6 => format!("{:.1} MB", n / 1e6),
        n if n >= 1e3 => format!("{:.1} kB", n / 1e3),
        n => format!("{n} bytes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(url: &str, sha: &str) -> DownloadSubmission {
        DownloadSubmission { url: url.into(), sha256: sha.into(), note: None }
    }

    #[test]
    fn submissions_are_checked_before_fetching() {
        let sha = "ab".repeat(32);
        assert!(validate(&sub("https://x.org/id.tar.gz", &sha)).is_ok());
        assert!(validate(&sub(" ", &sha)).is_err());
        assert!(validate(&sub("https://x.org/a", &sha.to_uppercase())).is_err(), "lowercase hex");
        assert!(validate(&sub("https://x.org/a", "abc")).is_err());
        let long = format!("https://x.org/{}", "a".repeat(MAX_LOOKUP_URL_BYTES));
        assert!(validate(&sub(&long, &sha)).is_err());
        let chatty = DownloadSubmission { note: Some("x".repeat(MAX_NOTE_CHARS + 1)), ..sub("https://x.org/a", &sha) };
        assert!(validate(&chatty).is_err());
    }

    #[test]
    fn the_conflict_reads_as_an_error_and_a_review() {
        let r = conflict(DownloadReview { id: 7, review: "approved".into() });
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(submit_command("https://x.org/a"), "cactup download submit https://x.org/a");
        assert_eq!(human_size(1_500_000), "1.5 MB");
        assert_eq!(human_size(12), "12 bytes");
    }
}
