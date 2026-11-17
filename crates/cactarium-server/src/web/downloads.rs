//! Reviewed downloads: a `.sim` input's file or a tarball component, pinned by its sha256,
//! submitted for review so pins to it can be trusted. A submission is stored at once; a background
//! job fetches the URL once (under the outbound-fetch policy, with a size and time limit), checks
//! the sha256, and keeps only the row: no copy of the file. Admins approve or reject a verified
//! download on the admin pages, and can reopen a rejected one; trusted users' and admins'
//! submissions are approved once verified, as their entries are.

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

use crate::audit::audit_with;
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
    // What the fetch could never read is refused now; the rest of the policy (public hosts, https
    // outside development) is the fetch's to apply.
    match url::Url::parse(url) {
        Ok(u) if matches!(u.scheme(), "https" | "http") && u.host_str().is_some() => {}
        _ => return Err(AppError::bad(format!("'{url}' is no https:// URL"))),
    }
    if s.sha256.len() != 64 || !s.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(AppError::bad(format!("'{}' is not a sha256 (64 lowercase hex digits)", s.sha256)));
    }
    if s.note.as_deref().is_some_and(|n| n.chars().count() > MAX_NOTE_CHARS) {
        return Err(AppError::bad(format!("the note is longer than {MAX_NOTE_CHARS} characters")));
    }
    Ok(())
}

/// How many submitted downloads one user may have being fetched at once.
const MAX_FETCHING_PER_USER: i64 = 3;

/// Downloads fetched at once, on slots of their own (never the mirrors' or the syncs').
static FETCHES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// `POST /downloads`: stores the submission and answers at once, `pending`; a background job
/// fetches the URL and checks its sha256 ([`verify`]), and only then can it be decided (a trusted
/// user's or an admin's is approved then). One submitted before is answered 409 with its review,
/// unless its fetch failed: then this submission tries it again.
pub async fn submit(
    State(state): State<AppState>,
    TokenUser(user): TokenUser,
    ip: ClientIp,
    Json(s): Json<DownloadSubmission>,
) -> ApiResult<Response> {
    validate(&s)?;
    let url = s.url.trim().to_owned();
    let known: Option<(i64, String, String)> =
        sqlx::query_as("SELECT id, review, fetch_state FROM downloads WHERE url = $1 AND sha256 = $2")
            .bind(&url)
            .bind(&s.sha256)
            .fetch_optional(&state.db)
            .await
            .map_err(AppError::from)?;
    if let Some((id, review, fetch)) = &known
        && fetch != "failed"
    {
        return Ok(conflict(DownloadReview { id: *id, review: review.clone() }));
    }
    // Each fetch downloads the whole file: a few per user an hour, and a few at once.
    state.limiter.check_user("download-submit", user.id, 10, Duration::from_secs(3600))?;
    state.limiter.check("download-submit", ip.0, 10)?;
    let fetching: i64 = sqlx::query_scalar("SELECT count(*) FROM downloads WHERE submitter = $1 AND fetch_state = 'fetching'")
        .bind(user.id)
        .fetch_one(&state.db)
        .await
        .map_err(AppError::from)?;
    if fetching >= MAX_FETCHING_PER_USER {
        return Err(AppError::bad(format!("you have {fetching} downloads being fetched; submit more once they are checked")).into());
    }
    let auto = crate::publish::skips_review(&user);
    let note = s.note.as_deref().map(str::trim).filter(|n| !n.is_empty());
    let mut tx = state.db.begin().await.map_err(AppError::from)?;
    let id: Option<i64> = match known {
        // A failed fetch is tried again, as this user's submission.
        Some((id, _, _)) => sqlx::query_scalar(
            "UPDATE downloads SET fetch_state = 'fetching', fetch_error = NULL, submitter = $2, auto_approve = $3,
                    note = COALESCE($4, note), created_at = now()
             WHERE id = $1 AND fetch_state = 'failed' RETURNING id",
        )
        .bind(id)
        .bind(user.id)
        .bind(auto)
        .bind(note)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::from)?,
        None => sqlx::query_scalar(
            "INSERT INTO downloads (url, sha256, note, submitter, auto_approve) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (url, sha256) DO NOTHING RETURNING id",
        )
        .bind(&url)
        .bind(&s.sha256)
        .bind(note)
        .bind(user.id)
        .bind(auto)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::from)?,
    };
    let retry = known.is_some();
    let Some(id) = id else {
        // Submitted (or retried) by another request meanwhile.
        drop(tx);
        let row: (i64, String) = sqlx::query_as("SELECT id, review FROM downloads WHERE url = $1 AND sha256 = $2")
            .bind(&url)
            .bind(&s.sha256)
            .fetch_one(&state.db)
            .await
            .map_err(AppError::from)?;
        return Ok(conflict(DownloadReview { id: row.0, review: row.1 }));
    };
    audit_with(&mut tx, Some(user.id), "download.submit", Some(&url), json!({ "id": id, "sha256": s.sha256, "retry": retry }), ip.0).await?;
    tx.commit().await.map_err(AppError::from)?;
    spawn_verify(state.clone(), id);
    Ok(Json(DownloadReview { id, review: "pending".to_owned() }).into_response())
}

/// Verifies a submitted download in the background ([`verify`]).
pub fn spawn_verify(state: AppState, id: i64) {
    tokio::spawn(async move {
        if let Err(e) = verify(&state, id).await {
            tracing::warn!("verifying download #{id}: {e}");
        }
    });
}

/// Fetches a submitted download once, on one of [`FETCHES`], under the outbound-fetch policy and
/// the size and time limits, and records the outcome: `ok` (and approved, for a trusted
/// submitter), or `failed` with why. A row no longer being fetched is left alone.
pub async fn verify(state: &AppState, id: i64) -> AppResult<()> {
    let _slot = FETCHES.acquire().await.map_err(anyhow::Error::from)?;
    let row: Option<(String, String)> = sqlx::query_as("SELECT url, sha256 FROM downloads WHERE id = $1 AND fetch_state = 'fetching'")
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    let Some((url, want)) = row else { return Ok(()) };
    let policy = GitPolicy { allow_local: state.cfg.allow_local_repos };
    let outcome = match git::fetch_and_hash(policy, &url, MAX_DOWNLOAD_BYTES, FETCH_TIME).await {
        Ok(got) if got.sha256 == want => Ok(got.size),
        Ok(got) => Err(format!("{url} has sha256 {}, not {want} (the file changed, or the sha256 is wrong)", got.sha256)),
        Err(e) => Err(format!("cannot fetch {url}: {e:#}")),
    };
    let mut tx = state.db.begin().await?;
    let (action, details) = match &outcome {
        Ok(size) => {
            sqlx::query(
                "UPDATE downloads SET fetch_state = 'ok', fetch_error = NULL, size = $2, fetched_at = now(),
                        review = CASE WHEN auto_approve THEN 'approved' ELSE review END,
                        reviewer = CASE WHEN auto_approve THEN submitter ELSE reviewer END,
                        decided_at = CASE WHEN auto_approve THEN now() ELSE decided_at END
                 WHERE id = $1 AND fetch_state = 'fetching'",
            )
            .bind(id)
            .bind(i64::try_from(*size).unwrap_or(i64::MAX))
            .execute(&mut *tx)
            .await?;
            ("download.verified", json!({ "id": id, "size": size }))
        }
        Err(why) => {
            sqlx::query("UPDATE downloads SET fetch_state = 'failed', fetch_error = $2 WHERE id = $1 AND fetch_state = 'fetching'")
                .bind(id)
                .bind(why)
                .execute(&mut *tx)
                .await?;
            ("download.fetch-failed", json!({ "id": id, "error": why }))
        }
    };
    audit_with(&mut tx, None, action, Some(&url), details, None).await?;
    tx.commit().await?;
    Ok(())
}

/// Starts verifying again every download a stopped server left being fetched.
pub async fn requeue(state: &AppState) -> AppResult<usize> {
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM downloads WHERE fetch_state = 'fetching' ORDER BY created_at")
        .fetch_all(&state.db)
        .await?;
    for id in &ids {
        spawn_verify(state.clone(), *id);
    }
    Ok(ids.len())
}

/// The 409 answer to a download submitted before: an error that also carries its review.
fn conflict(known: DownloadReview) -> Response {
    let body = DownloadConflict {
        error: ErrorDetail { code: "conflict".into(), message: format!("already submitted (#{}, {})", known.id, known.review) },
        known,
    };
    (StatusCode::CONFLICT, Json(body)).into_response()
}

/// A row of the admin page's query.
type Row = (
    i64,
    String,
    String,
    Option<i64>,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    time::OffsetDateTime,
);

const ADMIN_COLS: &str =
    "d.id, d.url, d.sha256, d.size, d.fetch_state, d.fetch_error, d.note, d.review, d.review_note, s.username, r.username, d.created_at";

/// `/admin/downloads`: every download awaiting review, oldest first (those still being fetched,
/// or whose fetch failed, with why), then the latest decided ones.
pub async fn admin_page(State(state): State<AppState>, Admin(a): Admin) -> AppResult<Response> {
    let from = "FROM downloads d LEFT JOIN users s ON s.id = d.submitter LEFT JOIN users r ON r.id = d.reviewer";
    let mut rows: Vec<Row> =
        sqlx::query_as(&format!("SELECT {ADMIN_COLS} {from} WHERE d.review = 'pending' ORDER BY d.created_at, d.id"))
            .fetch_all(&state.db)
            .await?;
    let decided: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {ADMIN_COLS} {from} WHERE d.review <> 'pending' ORDER BY d.decided_at DESC NULLS LAST, d.id DESC LIMIT 100"
    ))
    .fetch_all(&state.db)
    .await?;
    rows.extend(decided);
    let downloads = rows
        .into_iter()
        .map(|(id, url, sha256, size, fetch_state, fetch_error, note, review, review_note, submitter, reviewer, at)| DownloadRow {
            id,
            url,
            sha256,
            size: size.map(human_size).unwrap_or_default(),
            fetch: fetch_state,
            fetch_error: fetch_error.unwrap_or_default(),
            note: note.unwrap_or_default(),
            review,
            review_note: review_note.unwrap_or_default(),
            submitter: submitter.unwrap_or_default(),
            reviewer: reviewer.unwrap_or_default(),
            when: fmt_time(at),
        })
        .collect();
    Ok(page(&AdminDownloadsPage { ctx: PageCtx::new(&state, Some(&a.session)), nav: "downloads".into(), downloads })?
        .into_response())
}

/// What an admin's decision does to a download in `review`: the new review, or why it can't be
/// made. A verified download awaiting review is approved or rejected; a rejected one is reopened
/// (back to pending) or approved at once. A download not verified yet can't be decided.
fn decision(review: &str, fetch: &str, decision: &str) -> Result<&'static str, String> {
    if fetch != "ok" {
        return Err("this download isn't verified yet (its fetch is still running, or failed): it can be decided once it is".into());
    }
    match (review, decision) {
        ("pending" | "rejected", "approve") => Ok("approved"),
        ("pending", "reject") => Ok("rejected"),
        ("rejected", "reopen") => Ok("pending"),
        (r, d) => Err(format!(
            "a download that is {r} can't be {}",
            match d {
                "approve" => "approved",
                "reject" => "rejected",
                "reopen" => "reopened",
                _ => "decided so",
            }
        )),
    }
}

/// Approves or rejects a verified download awaiting review, or reopens a rejected one (back to
/// pending, or approved at once). Recorded in the audit log.
pub async fn admin_decide(
    State(state): State<AppState>,
    Admin(a): Admin,
    Path(id): Path<i64>,
    Form(f): Form<HashMap<String, String>>,
) -> AppResult<Response> {
    a.session.check_csrf(f.get("_csrf").map(String::as_str).unwrap_or(""))?;
    let asked = f.get("decision").map(String::as_str).unwrap_or("");
    if !matches!(asked, "approve" | "reject" | "reopen") {
        return Err(AppError::bad("choose approve, reject or reopen"));
    }
    let note = f.get("note").map(|n| n.trim().to_owned()).filter(|n| !n.is_empty());
    let mut tx = state.db.begin().await?;
    let (url, review, fetch): (String, String, String) =
        sqlx::query_as("SELECT url, review, fetch_state FROM downloads WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::NotFound)?;
    let now = decision(&review, &fetch, asked).map_err(AppError::Conflict)?;
    sqlx::query(
        "UPDATE downloads SET review = $2, review_note = COALESCE($3, review_note), reviewer = $4,
                decided_at = CASE WHEN $2 = 'pending' THEN NULL ELSE now() END
         WHERE id = $1",
    )
    .bind(id)
    .bind(now)
    .bind(&note)
    .bind(a.user.id)
    .execute(&mut *tx)
    .await?;
    audit_with(
        &mut tx,
        Some(a.user.id),
        &format!("download.{asked}"),
        Some(&url),
        json!({ "id": id, "was": review, "now": now, "note": note }),
        None,
    )
    .await?;
    tx.commit().await?;
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
        assert!(validate(&sub("file:///etc/hostname", &sha)).is_err(), "no fetchable URL");
        assert!(validate(&sub("not a url", &sha)).is_err());
        assert!(validate(&sub("https://x.org/a", &sha.to_uppercase())).is_err(), "lowercase hex");
        assert!(validate(&sub("https://x.org/a", "abc")).is_err());
        let long = format!("https://x.org/{}", "a".repeat(MAX_LOOKUP_URL_BYTES));
        assert!(validate(&sub(&long, &sha)).is_err());
        let chatty = DownloadSubmission { note: Some("x".repeat(MAX_NOTE_CHARS + 1)), ..sub("https://x.org/a", &sha) };
        assert!(validate(&chatty).is_err());
    }

    /// Only a verified download is decided: one awaiting review is approved or rejected, a
    /// rejected one reopened or approved; nothing else.
    #[test]
    fn decisions_follow_the_review() {
        assert_eq!(decision("pending", "ok", "approve"), Ok("approved"));
        assert_eq!(decision("pending", "ok", "reject"), Ok("rejected"));
        assert_eq!(decision("rejected", "ok", "reopen"), Ok("pending"));
        assert_eq!(decision("rejected", "ok", "approve"), Ok("approved"));
        for (review, asked) in [("approved", "reject"), ("approved", "reopen"), ("approved", "approve"), ("pending", "reopen"), ("rejected", "reject")] {
            assert!(decision(review, "ok", asked).is_err(), "{review} {asked}");
        }
        for fetch in ["fetching", "failed"] {
            let e = decision("pending", fetch, "approve").unwrap_err();
            assert!(e.contains("isn't verified yet"), "{e}");
        }
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
