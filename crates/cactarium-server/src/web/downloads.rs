//! Reviewed downloads: a `.sim` input's file or a tarball component, pinned by its sha256,
//! submitted for review so pins to it can be trusted. A submission is stored at once; a background
//! job fetches the URL once (under the outbound-fetch policy, with a size and time limit), checks
//! the sha256, and keeps only the row: no copy of the file. Admins approve or reject a verified
//! download on the admin pages, and can reopen a rejected one; trusted users' and admins'
//! submissions are approved once verified, as their entries are. An admin can also approve a
//! download without the server fetching it (vouched: too big, or on a host the server can't reach).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
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
use crate::auth::{Admin, User};
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
/// A download still being fetched this long after its fetch started was dropped (its outcome
/// couldn't be stored, say): the sweep starts it again ([`requeue_stale`]).
pub const STALE_FETCH: Duration = Duration::from_secs(FETCH_TIME.as_secs() + 15 * 60);
/// The longest note a submitter may leave for the reviewer.
const MAX_NOTE_CHARS: usize = 4000;
/// How many submitted downloads one user may have being fetched at once.
const MAX_FETCHING_PER_USER: i64 = 3;

/// Downloads fetched at once, on slots of their own (never the mirrors' or the syncs').
static FETCHES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// The downloads this process is fetching (or has queued): each is fetched once at a time,
/// however many submissions, requeues and sweeps ask.
static IN_FLIGHT: std::sync::LazyLock<Mutex<HashSet<i64>>> = std::sync::LazyLock::new(Default::default);

/// The command that submits a download for review, for messages that refuse a pin to one.
pub fn submit_command(url: &str) -> String {
    format!("cactup download submit {url}")
}

/// What the Cactarium knows of a submitted download.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// `pending`, `approved` or `rejected`.
    pub review: String,
    /// `fetching`, `ok` (verified), `failed` or `vouched` (approved by an admin, not fetched).
    pub fetch_state: String,
    /// Why the fetch failed, when it did.
    pub fetch_error: Option<String>,
}

impl Status {
    /// Where its verification stands, for a message: "being verified", "verified", "approved
    /// without being fetched" or "the server couldn't verify it: <why>".
    pub fn verification(&self) -> String {
        match (self.fetch_state.as_str(), &self.fetch_error) {
            ("fetching", _) => "being verified".to_owned(),
            ("failed", Some(e)) => format!("the server couldn't verify it: {e}"),
            ("failed", None) => "the server couldn't verify it".to_owned(),
            ("vouched", _) => "approved by an admin without being fetched".to_owned(),
            _ => "verified".to_owned(),
        }
    }
}

/// What the Cactarium knows of each (url, sha256), in order; `None` when it was never submitted.
/// The URL is compared as written.
pub async fn statuses_of(state: &AppState, asked: &[DownloadQuery]) -> AppResult<Vec<Option<Status>>> {
    if asked.is_empty() {
        return Ok(vec![]);
    }
    let urls: Vec<&str> = asked.iter().map(|d| d.url.trim()).collect();
    let shas: Vec<&str> = asked.iter().map(|d| d.sha256.as_str()).collect();
    let rows: Vec<(String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT d.url, d.sha256, d.review, d.fetch_state, d.fetch_error FROM downloads d
         JOIN UNNEST($1::text[], $2::text[]) AS a(url, sha256) ON a.url = d.url AND a.sha256 = d.sha256",
    )
    .bind(&urls)
    .bind(&shas)
    .fetch_all(&state.db)
    .await?;
    let known: HashMap<(String, String), Status> = rows
        .into_iter()
        .map(|(u, s, review, fetch_state, fetch_error)| ((u, s), Status { review, fetch_state, fetch_error }))
        .collect();
    Ok(asked.iter().map(|d| known.get(&(d.url.trim().to_owned(), d.sha256.clone())).cloned()).collect())
}

/// What the Cactarium knows of one download, if it was submitted.
pub async fn status_of(state: &AppState, url: &str, sha256: &str) -> AppResult<Option<Status>> {
    let asked = [DownloadQuery { url: url.to_owned(), sha256: sha256.to_owned() }];
    Ok(statuses_of(state, &asked).await?.pop().flatten())
}

/// Checks a download's fields (a submission's, or one an admin approves) before anything else.
fn validate(url: &str, sha256: &str, note: Option<&str>) -> AppResult<()> {
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
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(AppError::bad(format!("'{sha256}' is not a sha256 (64 lowercase hex digits)")));
    }
    if note.is_some_and(|n| n.chars().count() > MAX_NOTE_CHARS) {
        return Err(AppError::bad(format!("the note is longer than {MAX_NOTE_CHARS} characters")));
    }
    Ok(())
}

/// `POST /downloads`: stores the submission and answers at once, `pending`; a background job
/// fetches the URL and checks its sha256 ([`verify`]), and only then can it be decided (a trusted
/// user's or an admin's is approved then). One submitted before is answered 409 with its review
/// and where its verification stands. One whose fetch failed is tried again, and the 409 says why
/// the last try failed.
pub async fn submit(
    State(state): State<AppState>,
    TokenUser(user): TokenUser,
    ip: ClientIp,
    Json(s): Json<DownloadSubmission>,
) -> ApiResult<Response> {
    let url = s.url.trim().to_owned();
    let note = s.note.as_deref().map(str::trim).filter(|n| !n.is_empty());
    validate(&url, &s.sha256, note)?;
    let known: Option<(i64, Status)> = sqlx::query_as::<_, (i64, String, String, Option<String>)>(
        "SELECT id, review, fetch_state, fetch_error FROM downloads WHERE url = $1 AND sha256 = $2",
    )
    .bind(&url)
    .bind(&s.sha256)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .map(|(id, review, fetch_state, fetch_error)| (id, Status { review, fetch_state, fetch_error }));
    if let Some((id, st)) = &known
        && st.fetch_state != "failed"
    {
        return Ok(conflict(*id, st, None));
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
    let mut tx = state.db.begin().await.map_err(AppError::from)?;
    let id: Option<i64> = match &known {
        // A failed fetch is tried again. The row keeps its submitter and note; a trusted or admin
        // retrier makes it approved once verified, as their own submission would be.
        Some((id, _)) => sqlx::query_scalar(
            "UPDATE downloads SET fetch_state = 'fetching', fetch_error = NULL, fetch_started_at = now(),
                    auto_approve = auto_approve OR $2
             WHERE id = $1 AND fetch_state = 'failed' RETURNING id",
        )
        .bind(id)
        .bind(auto)
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
    let Some(id) = id else {
        // Submitted (or retried) by another request meanwhile.
        drop(tx);
        let id = row_id(&state, &url, &s.sha256).await?;
        let st = status_of(&state, &url, &s.sha256).await?.ok_or(AppError::NotFound)?;
        return Ok(conflict(id, &st, None));
    };
    let action = if known.is_some() { "download.retry" } else { "download.submit" };
    audit_with(&mut tx, Some(user.id), action, Some(&url), json!({ "id": id, "sha256": s.sha256 }), ip.0).await?;
    tx.commit().await.map_err(AppError::from)?;
    spawn_verify(state.clone(), id);
    match known {
        // Known, and being verified again now: the 409 says why the last try failed.
        Some((_, st)) => {
            let now = Status { review: st.review.clone(), fetch_state: "fetching".into(), fetch_error: None };
            Ok(conflict(id, &now, st.fetch_error.as_deref()))
        }
        None => Ok(Json(DownloadReview { id, review: "pending".to_owned() }).into_response()),
    }
}

async fn row_id(state: &AppState, url: &str, sha256: &str) -> AppResult<i64> {
    Ok(sqlx::query_scalar("SELECT id FROM downloads WHERE url = $1 AND sha256 = $2")
        .bind(url)
        .bind(sha256)
        .fetch_one(&state.db)
        .await?)
}

/// The words of the 409 answer to a download submitted before: its review and where its
/// verification stands, and, for one tried again now, why the last try failed.
fn conflict_message(id: i64, st: &Status, last_failure: Option<&str>) -> String {
    match last_failure {
        Some(why) => format!("already submitted (#{id}, {}); the server couldn't verify it ({why}), so it is being verified again now", st.review),
        None => format!("already submitted (#{id}, {}; {})", st.review, st.verification()),
    }
}

/// The 409 answer to a download submitted before: an error that also carries its review.
fn conflict(id: i64, st: &Status, last_failure: Option<&str>) -> Response {
    let body = DownloadConflict {
        error: ErrorDetail { code: "conflict".into(), message: conflict_message(id, st, last_failure) },
        known: DownloadReview { id, review: st.review.clone() },
    };
    (StatusCode::CONFLICT, Json(body)).into_response()
}

/// Verifies a submitted download in the background ([`verify`]), unless this process already is.
pub fn spawn_verify(state: AppState, id: i64) {
    if !IN_FLIGHT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(id) {
        return;
    }
    tokio::spawn(async move {
        if let Err(e) = verify(&state, id).await {
            tracing::warn!("verifying download #{id}: {e}");
        }
        IN_FLIGHT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&id);
    });
}

/// Why a fetched file isn't the download submitted: its content has another sha256 (the commonest
/// failure). The actual sha256 is told: the file is public.
fn wrong_sha(actual: &str, submitted: &str) -> String {
    format!("the file's sha256 is {actual}, not {submitted} (the file changed, or the sha256 submitted is wrong)")
}

/// Fetches a submitted download once, on one of [`FETCHES`], under the outbound-fetch policy and
/// the size and time limits, and records the outcome: `ok` (and approved, for a trusted
/// submitter), or `failed` with why. A row no longer being fetched is left alone.
pub async fn verify(state: &AppState, id: i64) -> AppResult<()> {
    let _slot = FETCHES.acquire().await.map_err(anyhow::Error::from)?;
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT url, sha256 FROM downloads WHERE id = $1 AND fetch_state = 'fetching'")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let Some((url, want)) = row else { return Ok(()) };
    let policy = GitPolicy { allow_local: state.cfg.allow_local_repos };
    let outcome = match git::fetch_and_hash(policy, &url, MAX_DOWNLOAD_BYTES, FETCH_TIME).await {
        Ok(got) if got.sha256 == want => Ok(got.size),
        Ok(got) => Err(wrong_sha(&got.sha256, &want)),
        Err(e) => Err(format!("cannot fetch it: {e:#}")),
    };
    let mut tx = state.db.begin().await?;
    let (action, applied) = match &outcome {
        Ok(size) => {
            let r = sqlx::query(
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
            ("download.verified", r.rows_affected() > 0)
        }
        Err(why) => {
            let r = sqlx::query("UPDATE downloads SET fetch_state = 'failed', fetch_error = $2 WHERE id = $1 AND fetch_state = 'fetching'")
                .bind(id)
                .bind(why)
                .execute(&mut *tx)
                .await?;
            ("download.fetch-failed", r.rows_affected() > 0)
        }
    };
    // `applied` is false when an admin vouched for the row while it was being fetched: the outcome
    // changed nothing, but is still recorded (a mismatch is worth an admin's look).
    let details = match &outcome {
        Ok(size) => json!({ "id": id, "size": size, "applied": applied }),
        Err(why) => json!({ "id": id, "error": why, "applied": applied }),
    };
    audit_with(&mut tx, None, action, Some(&url), details, None).await?;
    tx.commit().await?;
    Ok(())
}

/// Starts verifying again every download a stopped server left being fetched (at startup).
pub async fn requeue(state: &AppState) -> AppResult<usize> {
    requeue_where(state, "fetch_state = 'fetching'").await
}

/// Starts verifying again the downloads still being fetched [`STALE_FETCH`] after their fetch
/// started: their outcome was never stored (the sweep runs this hourly). One this process is
/// still fetching is left to it.
pub async fn requeue_stale(state: &AppState) -> AppResult<usize> {
    requeue_where(state, &format!("fetch_state = 'fetching' AND fetch_started_at < now() - interval '{} seconds'", STALE_FETCH.as_secs()))
        .await
}

async fn requeue_where(state: &AppState, cond: &str) -> AppResult<usize> {
    let ids: Vec<i64> = sqlx::query_scalar(&format!("SELECT id FROM downloads WHERE {cond} ORDER BY fetch_started_at"))
        .fetch_all(&state.db)
        .await?;
    for id in &ids {
        spawn_verify(state.clone(), *id);
    }
    Ok(ids.len())
}

/// Approves a download without the server fetching it, as `admin` vouching for it (one too big
/// for the fetch, or on a host the server can't reach): a new row, or one awaiting review, whose
/// fetch failed or that was rejected, becomes approved with `fetch_state = 'vouched'` and no size
/// (one the server already verified keeps `ok` and its size, and is simply approved).
/// The audit log says it wasn't verified. Returns the row's id.
pub async fn vouch(state: &AppState, admin: &User, url: &str, sha256: &str, note: Option<&str>) -> AppResult<i64> {
    if !admin.is_admin() {
        return Err(AppError::Forbidden);
    }
    let url = url.trim();
    let note = note.map(str::trim).filter(|n| !n.is_empty());
    validate(url, sha256, note)?;
    let mut tx = state.db.begin().await?;
    let row: Option<(i64, bool)> = sqlx::query_as(
        "INSERT INTO downloads (url, sha256, note, fetch_state, review, submitter, reviewer, review_note, decided_at)
         VALUES ($1, $2, $3, 'vouched', 'approved', $4, $4, $3, now())
         ON CONFLICT (url, sha256) DO UPDATE SET
             -- A row the server verified stays verified: vouching only approves it.
             fetch_state = CASE WHEN downloads.fetch_state = 'ok' THEN 'ok' ELSE 'vouched' END,
             fetch_error = NULL, review = 'approved',
             reviewer = $4, review_note = COALESCE($3, downloads.review_note), decided_at = now()
         WHERE downloads.review <> 'approved'
         RETURNING id, fetch_state = 'ok'",
    )
    .bind(url)
    .bind(sha256)
    .bind(note)
    .bind(admin.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, verified)) = row else {
        return Err(AppError::Conflict(format!("{url} with that sha256 is approved already")));
    };
    audit_with(&mut tx, Some(admin.id), "download.vouch", Some(url), json!({ "id": id, "sha256": sha256, "verified": verified, "note": note }), None)
        .await?;
    tx.commit().await?;
    Ok(id)
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
/// or whose fetch failed, with why), then the latest decided ones; and the form that approves one
/// without fetching it.
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
            size: size.map(human_size).unwrap_or_else(|| "size unknown".to_owned()),
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

/// `POST /admin/downloads/vouch`: approves a download without fetching it ([`vouch`]).
pub async fn admin_vouch(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<HashMap<String, String>>,
) -> AppResult<Response> {
    a.session.check_csrf(f.get("_csrf").map(String::as_str).unwrap_or(""))?;
    let get = |k: &str| f.get(k).map(|v| v.trim().to_owned()).unwrap_or_default();
    let note = get("note");
    vouch(&state, &a.user, &get("url"), &get("sha256"), Some(note.as_str())).await?;
    Ok(Redirect::to("/admin/downloads").into_response())
}

/// What an admin's decision does to a download in `review`: the new review, or why it can't be
/// made. A verified download awaiting review is approved or rejected; a rejected one is reopened
/// (back to pending) or approved at once. A download not verified yet can't be decided (an admin
/// approves one without fetching it with [`vouch`]).
fn decision(review: &str, fetch: &str, decision: &str) -> Result<&'static str, String> {
    if fetch != "ok" {
        return Err("this download isn't verified (its fetch is still running, or failed): it can be decided once it is, or approved without fetching it".into());
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

    #[test]
    fn submissions_are_checked_before_fetching() {
        let sha = "ab".repeat(32);
        assert!(validate("https://x.org/id.tar.gz", &sha, None).is_ok());
        assert!(validate("", &sha, None).is_err());
        assert!(validate("file:///etc/hostname", &sha, None).is_err(), "no fetchable URL");
        assert!(validate("not a url", &sha, None).is_err());
        assert!(validate("https://x.org/a", &sha.to_uppercase(), None).is_err(), "lowercase hex");
        assert!(validate("https://x.org/a", "abc", None).is_err());
        let long = format!("https://x.org/{}", "a".repeat(MAX_LOOKUP_URL_BYTES));
        assert!(validate(&long, &sha, None).is_err());
        assert!(validate("https://x.org/a", &sha, Some(&"x".repeat(MAX_NOTE_CHARS + 1))).is_err());
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
        for fetch in ["fetching", "failed", "vouched"] {
            let e = decision("pending", fetch, "approve").unwrap_err();
            assert!(e.contains("isn't verified"), "{e}");
        }
    }

    /// A submitter learns where verification stands, and why a fetch failed.
    #[test]
    fn the_conflict_says_where_verification_stands() {
        let st = |fetch: &str, error: Option<&str>| Status { review: "pending".into(), fetch_state: fetch.into(), fetch_error: error.map(Into::into) };
        assert_eq!(conflict_message(7, &st("fetching", None), None), "already submitted (#7, pending; being verified)");
        assert_eq!(conflict_message(7, &st("ok", None), None), "already submitted (#7, pending; verified)");
        let why = wrong_sha(&"ab".repeat(32), &"cd".repeat(32));
        assert!(why.starts_with(&format!("the file's sha256 is {}, not {}", "ab".repeat(32), "cd".repeat(32))), "{why}");
        assert_eq!(st("failed", Some(&why)).verification(), format!("the server couldn't verify it: {why}"));
        let retried = conflict_message(7, &st("fetching", None), Some(&why));
        assert!(retried.contains(&why) && retried.contains("being verified again now"), "{retried}");
        assert!(st("vouched", None).verification().contains("without being fetched"));
        let r = conflict(7, &st("ok", None), None);
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(submit_command("https://x.org/a"), "cactup download submit https://x.org/a");
        assert_eq!(human_size(1_500_000), "1.5 MB");
        assert_eq!(human_size(12), "12 bytes");
        assert_eq!(STALE_FETCH, Duration::from_secs(30 * 60));
    }
}
