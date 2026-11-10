//! The admin panel: the review queue, entries, curated packages, tag alerts, users, the audit log.

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;

use crate::audit::audit;
use crate::auth::Admin;
use crate::error::{AppError, AppResult};
use crate::model::{self, ENTRY_COLS, Entry, fmt_time};
use crate::site;
use crate::state::AppState;
use crate::templates::*;
use crate::tracker;
use crate::web::account::tag_alerts;
use crate::web::public::{sim_file, thorn_rows, version_row};
use cactup_ecosystem_common::name::Owner;

fn checklist(kind: &str) -> Vec<(&'static str, &'static str)> {
    match kind {
        "package" => vec![
            ("license", "Has a license"),
            ("readme", "README names a maintainer and says what the thorns do"),
            ("docs", "Thorns carry documentation"),
            ("tests", "Thorns have tests"),
            ("names", "Thorn names do not clash with well-known thorns"),
        ],
        "stack" => vec![
            ("purpose", "Description says what the stack is for"),
            ("sources", "Sources are public and reachable"),
            ("collisions", "Overrides and disabled thorns look deliberate"),
            ("claims", "Claims are plausible"),
        ],
        _ => vec![
            ("purpose", "Description says what the simulation is"),
            ("paths", "No private paths; external data comes through inputs"),
            ("inputs", "Inputs are documented"),
            ("license", "Has a license, or the owner was asked"),
        ],
    }
}

#[derive(Deserialize, Default)]
pub struct QueueQ {
    s: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct SubFull {
    id: i64,
    entry_id: i64,
    /// Set for a new release of a public entry; NULL for a new entry.
    version_id: Option<i64>,
    status: String,
    note: Option<String>,
    checklist: serde_json::Value,
    created_at: time::OffsetDateTime,
    submitter: Option<String>,
    trusted: Option<bool>,
}

pub async fn queue(
    State(state): State<AppState>,
    Admin(a): Admin,
    Query(q): Query<QueueQ>,
) -> AppResult<Response> {
    let subs: Vec<SubFull> = sqlx::query_as(
        "SELECT s.id, s.entry_id, s.version_id, s.status, s.note, s.checklist, s.created_at, u.username AS submitter, u.trusted
         FROM submissions s LEFT JOIN users u ON u.id = s.submitter
         WHERE s.status IN ('open', 'changes-requested') ORDER BY (s.status = 'open') DESC, s.created_at",
    )
    .fetch_all(&state.db)
    .await?;
    let selected = q.s.or(subs.first().map(|s| s.id));
    let mut open = Vec::new();
    let mut review = None;
    for s in &subs {
        let e = model::entry_by_id(&state, s.entry_id).await?;
        let release = release_label(&state, s.version_id).await?;
        open.push(SubRow {
            id: s.id,
            entry: match &release {
                Some(l) => format!("{}@{l}", e.slug()),
                None => e.slug(),
            },
            release: release.is_some(),
            kind: e.kind.clone(),
            status: s.status.clone(),
            submitter: s.submitter.clone().unwrap_or_else(|| format!("{} (pushed a tag)", e.owner)),
            when: fmt_time(s.created_at),
            selected: Some(s.id) == selected,
        });
        if Some(s.id) == selected {
            review = Some(review_view(&state, s, &e).await?);
        }
    }
    Ok(page(&AdminQueuePage {
        ctx: PageCtx::new(&state, Some(&a.session)),
        nav: "review".into(),
        open,
        review,
        can_trust: site::may_grant_trust(&state, &a.user).await?,
    })?
    .into_response())
}

/// The label of a release under review, if the submission is for one.
async fn release_label(state: &AppState, version_id: Option<i64>) -> AppResult<Option<String>> {
    let Some(vid) = version_id else { return Ok(None) };
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT track, version FROM versions WHERE id = $1")
            .bind(vid)
            .fetch_optional(&state.db)
            .await?;
    Ok(row.map(|(t, v)| if t.is_empty() { v } else { format!("{t}:{v}") }))
}

async fn review_view(state: &AppState, s: &SubFull, e: &Entry) -> AppResult<ReviewView> {
    let versions = model::all_versions(state, e.id).await?;
    // A release under review shows that release; a new entry shows its newest usable version.
    let latest = match s.version_id {
        Some(vid) => versions.iter().find(|v| v.id == vid),
        None => versions.iter().find(|v| v.usable()).or(versions.first()),
    };
    let mut warnings: Vec<String> = versions
        .iter()
        .filter(|v| v.state == "invalid")
        .map(|v| format!("{}: {}", v.label(), v.invalid_reason.as_deref().unwrap_or("invalid")))
        .collect();
    let (mut thorns, mut readme_html, mut detail) = (vec![], String::new(), String::new());
    if let Some(v) = latest {
        match e.kind.as_str() {
            "package" => {
                thorns = thorn_rows(state, v.id, &[]).await?;
                readme_html = v.readme_html.clone().unwrap_or_default();
            }
            "stack" => {
                if let Ok(f) = crate::stacks::frozen_of(state, v).await {
                    detail = f.thornlist.text;
                }
                if s.version_id.is_some() {
                    let diff: Option<serde_json::Value> =
                        sqlx::query_scalar("SELECT diff FROM stack_releases WHERE version_id = $1")
                            .bind(v.id)
                            .fetch_optional(&state.db)
                            .await?;
                    for d in diff.and_then(|d| d.as_array().cloned()).unwrap_or_default() {
                        warnings.push(format!(
                            "changed since the last published release: {} {} -> {}",
                            d["repo"].as_str().unwrap_or("?"),
                            d["from"].as_str().unwrap_or("(new)"),
                            d["to"].as_str().unwrap_or("(removed)"),
                        ));
                    }
                }
            }
            _ => {
                let (content, index) = sim_file(state, v.id).await?;
                warnings.extend(index.warnings);
                detail = content;
            }
        }
    }
    let claims: Vec<(String, String, String, Option<String>, Option<String>)> =
        match latest {
            Some(v) => sqlx::query_as(
                "SELECT kind, target_owner, target_name, range, note FROM claims WHERE version_id = $1",
            )
            .bind(v.id)
            .fetch_all(&state.db)
            .await?,
            None => vec![],
        };
    let checked: HashMap<String, bool> = serde_json::from_value(s.checklist.clone()).unwrap_or_default();
    let release = latest.filter(|_| s.version_id.is_some()).map(|v| v.label());
    Ok(ReviewView {
        id: s.id,
        release: release.unwrap_or_default(),
        entry_trusted: e.trusted,
        entry: e.slug(),
        entry_url: e.url(),
        kind: e.kind.clone(),
        status: s.status.clone(),
        submitter: s.submitter.clone().unwrap_or_default(),
        submitter_trusted: s.trusted.unwrap_or(false),
        owner: e.owner.clone(),
        summary: e.summary.clone().unwrap_or_default(),
        versions: versions.iter().map(|v| version_row(e, v, None)).collect(),
        thorns,
        claims: claims
            .into_iter()
            .map(|(k, o, n, r, note)| ClaimRow {
                kind: k.replace('-', " "),
                target: format!("{o}/{n}"),
                target_url: format!("/{o}/{n}"),
                range: r.unwrap_or_default(),
                note: note.unwrap_or_default(),
            })
            .collect(),
        warnings,
        readme_html,
        detail,
        note: s.note.clone().unwrap_or_default(),
        checklist: checklist(&e.kind)
            .into_iter()
            .map(|(k, l)| (k.to_owned(), l.to_owned(), checked.get(k).copied().unwrap_or(false)))
            .collect(),
    })
}

pub async fn decide(
    State(state): State<AppState>,
    Admin(a): Admin,
    Path(id): Path<i64>,
    Form(f): Form<HashMap<String, String>>,
) -> AppResult<Response> {
    a.session.check_csrf(f.get("_csrf").map(String::as_str).unwrap_or(""))?;
    let (entry_id, version_id, submitter): (i64, Option<i64>, Option<i64>) =
        sqlx::query_as("SELECT entry_id, version_id, submitter FROM submissions WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?
            .ok_or(AppError::NotFound)?;
    let e = model::entry_by_id(&state, entry_id).await?;
    let checks: HashMap<String, bool> = f
        .keys()
        .filter_map(|k| k.strip_prefix("check_"))
        .map(|k| (k.to_owned(), true))
        .collect();
    let note = f.get("note").map(|n| n.trim().to_owned()).filter(|n| !n.is_empty());
    let status = match f.get("decision").map(String::as_str) {
        Some("approve") => "approved",
        Some("changes") => "changes-requested",
        Some("reject") => "rejected",
        _ => return Err(AppError::bad("choose approve, request changes or reject")),
    };
    if status == "changes-requested" && note.is_none() {
        return Err(AppError::bad("say what needs to change in the note"));
    }
    if status == "changes-requested" && version_id.is_some() {
        return Err(AppError::bad(
            "a release never changes: reject it with a note, and the owner tags a new one",
        ));
    }
    sqlx::query("UPDATE submissions SET status = $2, note = $3, checklist = $4, reviewer = $5, decided_at = now() WHERE id = $1")
        .bind(id)
        .bind(status)
        .bind(&note)
        .bind(serde_json::to_value(&checks).map_err(anyhow::Error::from)?)
        .bind(a.user.id)
        .execute(&state.db)
        .await?;
    match version_id {
        Some(vid) if status != "changes-requested" => {
            sqlx::query("UPDATE versions SET review = $2 WHERE id = $1")
                .bind(vid)
                .bind(status)
                .execute(&state.db)
                .await?;
            if status == "approved" {
                crate::publish::touch(&state, entry_id).await?;
            }
        }
        None if status == "approved" => {
            sqlx::query("UPDATE entries SET visibility = 'public', updated_at = now() WHERE id = $1 AND visibility = 'pending'")
                .bind(entry_id)
                .execute(&state.db)
                .await?;
        }
        _ => {}
    }
    if f.contains_key("trust_entry") && site::may_grant_trust(&state, &a.user).await? {
        sqlx::query("UPDATE entries SET trusted = TRUE WHERE id = $1")
            .bind(entry_id)
            .execute(&state.db)
            .await?;
        audit(&state, Some(a.user.id), "entry.trust", Some(&e.slug()), json!({}), None).await?;
    }
    if f.contains_key("trust_submitter")
        && let Some(uid) = submitter
        && site::may_grant_trust(&state, &a.user).await?
    {
        sqlx::query("UPDATE users SET trusted = TRUE WHERE id = $1")
            .bind(uid)
            .execute(&state.db)
            .await?;
        audit(&state, Some(a.user.id), "user.trust", None, json!({ "user_id": uid }), None).await?;
    }
    audit(
        &state,
        Some(a.user.id),
        &format!("review.{status}"),
        Some(&e.slug()),
        json!({ "submission": id, "version_id": version_id, "note": note }),
        None,
    )
    .await?;
    Ok(Redirect::to("/admin").into_response())
}

// ---------- entries ----------

#[derive(Deserialize, Default)]
pub struct FilterQ {
    #[serde(default)]
    q: String,
}

async fn admin_rows(state: &AppState, entries: Vec<Entry>) -> AppResult<Vec<AdminEntryRow>> {
    let mut out = Vec::new();
    for e in entries {
        let versions = model::all_versions(state, e.id).await?;
        out.push(AdminEntryRow {
            id: e.id,
            slug: e.slug(),
            url: e.url(),
            kind: e.kind.clone(),
            visibility: e.visibility.clone(),
            verified: e.verified,
            trusted: e.trusted,
            curated: e.curated,
            versions: versions.iter().take(12).map(|v| version_row(&e, v, None)).collect(),
        });
    }
    Ok(out)
}

pub async fn entries(
    State(state): State<AppState>,
    Admin(a): Admin,
    Query(q): Query<FilterQ>,
) -> AppResult<Response> {
    let list = sqlx::query_as::<_, Entry>(&format!(
        "SELECT {ENTRY_COLS} FROM entries WHERE $1 = '' OR owner || '/' || name ILIKE '%' || $1 || '%' ORDER BY updated_at DESC LIMIT 200"
    ))
    .bind(q.q.trim())
    .fetch_all(&state.db)
    .await?;
    let entries = admin_rows(&state, list).await?;
    Ok(page(&AdminEntriesPage {
        ctx: PageCtx::new(&state, Some(&a.session)),
        nav: "entries".into(),
        q: q.q,
        entries,
        can_trust: site::may_grant_trust(&state, &a.user).await?,
    })?
    .into_response())
}

#[derive(Deserialize)]
pub struct EntryAction {
    action: String,
    new_owner: Option<String>,
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn entry_action(
    State(state): State<AppState>,
    Admin(a): Admin,
    Path(id): Path<i64>,
    Form(f): Form<EntryAction>,
) -> AppResult<Response> {
    a.session.check_csrf(&f.csrf)?;
    let e = model::entry_by_id(&state, id).await?;
    let sql = match f.action.as_str() {
        "hide" => "UPDATE entries SET visibility = 'hidden' WHERE id = $1",
        "unhide" => "UPDATE entries SET visibility = 'public' WHERE id = $1",
        "verify" => "UPDATE entries SET verified = TRUE WHERE id = $1",
        "unverify" => "UPDATE entries SET verified = FALSE WHERE id = $1",
        "trust" | "untrust" if !site::may_grant_trust(&state, &a.user).await? => {
            return Err(AppError::Denied(
                "only the superadmin can change what is trusted (see Admin, Site)".into(),
            ));
        }
        "trust" => "UPDATE entries SET trusted = TRUE WHERE id = $1",
        "untrust" => "UPDATE entries SET trusted = FALSE WHERE id = $1",
        "transfer" => {
            let to = f.new_owner.as_deref().map(str::trim).unwrap_or("");
            to.parse::<Owner>().map_err(AppError::bad)?;
            if model::find_entry(&state, to, &e.name).await?.is_some() {
                return Err(AppError::Conflict(format!("{to}/{} already exists", e.name)));
            }
            sqlx::query("UPDATE entries SET owner = $2 WHERE id = $1")
                .bind(id)
                .bind(to)
                .execute(&state.db)
                .await?;
            audit(&state, Some(a.user.id), "entry.transfer", Some(&e.slug()), json!({ "to": to }), None)
                .await?;
            return Ok(Redirect::to("/admin/entries").into_response());
        }
        _ => return Err(AppError::bad("unknown action")),
    };
    sqlx::query(sql).bind(id).execute(&state.db).await?;
    audit(&state, Some(a.user.id), &format!("entry.{}", f.action), Some(&e.slug()), json!({}), None)
        .await?;
    Ok(Redirect::to("/admin/entries").into_response())
}

// ---------- curated packages ----------

async fn curated_page(state: &AppState, a: &Admin, error: Option<String>) -> AppResult<Response> {
    let list = sqlx::query_as::<_, Entry>(&format!(
        "SELECT {ENTRY_COLS} FROM entries WHERE curated ORDER BY owner, name"
    ))
    .fetch_all(&state.db)
    .await?;
    let curated = admin_rows(state, list).await?;
    Ok(page(&AdminCuratedPage {
        ctx: PageCtx::new(state, Some(&a.0.session)),
        nav: "curated".into(),
        curated,
        error,
    })?
    .into_response())
}

pub async fn curated(State(state): State<AppState>, a: Admin) -> AppResult<Response> {
    curated_page(&state, &a, None).await
}

#[derive(Deserialize)]
pub struct CuratedForm {
    owner: String,
    url: String,
    manifest: String,
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn create_curated(
    State(state): State<AppState>,
    a: Admin,
    Form(f): Form<CuratedForm>,
) -> AppResult<Response> {
    a.0.session.check_csrf(&f.csrf)?;
    match tracker::register_curated(&state, &a.0.user, f.owner.trim(), &f.url, &f.manifest).await {
        Ok(_) => Ok(Redirect::to("/admin/curated").into_response()),
        Err(AppError::BadRequest(m) | AppError::Conflict(m) | AppError::Denied(m)) => {
            curated_page(&state, &a, Some(m)).await
        }
        Err(e) => Err(e),
    }
}

#[derive(Deserialize)]
pub struct VirtualForm {
    version: String,
    commit: String,
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn add_virtual(
    State(state): State<AppState>,
    a: Admin,
    Path(id): Path<i64>,
    Form(f): Form<VirtualForm>,
) -> AppResult<Response> {
    a.0.session.check_csrf(&f.csrf)?;
    let e = model::entry_by_id(&state, id).await?;
    if !e.curated {
        return Err(AppError::bad("only curated packages take admin-named versions"));
    }
    match tracker::add_virtual_version(&state, &a.0.user, &e, &f.version, &f.commit).await {
        Ok(()) => Ok(Redirect::to("/admin/curated").into_response()),
        Err(AppError::BadRequest(m) | AppError::Conflict(m) | AppError::Denied(m)) => {
            curated_page(&state, &a, Some(m)).await
        }
        Err(e) => Err(e),
    }
}

// ---------- tag alerts ----------

pub async fn tags(State(state): State<AppState>, Admin(a): Admin) -> AppResult<Response> {
    let alerts = tag_alerts(&state, None).await?;
    Ok(page(&AdminTagsPage { ctx: PageCtx::new(&state, Some(&a.session)), nav: "tags".into(), alerts })?
        .into_response())
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn ack_tag(
    State(state): State<AppState>,
    Admin(a): Admin,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> AppResult<Response> {
    a.session.check_csrf(&f.csrf)?;
    sqlx::query("UPDATE tag_events SET acknowledged_by = $2, acknowledged_at = now() WHERE id = $1")
        .bind(id)
        .bind(a.user.id)
        .execute(&state.db)
        .await?;
    audit(&state, Some(a.user.id), "tag.acknowledge", None, json!({ "event": id }), None).await?;
    Ok(Redirect::to("/admin/tags").into_response())
}

// ---------- users ----------

pub async fn users(
    State(state): State<AppState>,
    Admin(a): Admin,
    Query(q): Query<FilterQ>,
) -> AppResult<Response> {
    let rows: Vec<(
        i64,
        String,
        Option<String>,
        String,
        bool,
        bool,
        time::OffsetDateTime,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT u.id, u.username, u.display_name, u.role, u.trusted, u.banned, u.created_at,
                string_agg(i.provider || ':' || COALESCE(i.login, i.subject), ' ' ORDER BY i.provider)
         FROM users u LEFT JOIN identities i ON i.user_id = u.id
         WHERE $1 = '' OR u.username ILIKE '%' || $1 || '%' OR u.display_name ILIKE '%' || $1 || '%'
         GROUP BY u.id ORDER BY u.created_at DESC LIMIT 300",
    )
    .bind(q.q.trim())
    .fetch_all(&state.db)
    .await?;
    let users = rows
        .into_iter()
        .map(|(id, username, display, role, trusted, banned, created, ids)| AdminUserRow {
            id,
            display: display.unwrap_or_else(|| username.clone()),
            username,
            role,
            trusted,
            banned,
            identities: ids.unwrap_or_default(),
            created: fmt_time(created),
        })
        .collect();
    Ok(page(&AdminUsersPage {
        ctx: PageCtx::new(&state, Some(&a.session)),
        nav: "users".into(),
        q: q.q,
        users,
        can_trust: site::may_grant_trust(&state, &a.user).await?,
    })?
    .into_response())
}

#[derive(Deserialize)]
pub struct UserAction {
    action: String,
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn user_action(
    State(state): State<AppState>,
    Admin(a): Admin,
    Path(id): Path<i64>,
    Form(f): Form<UserAction>,
) -> AppResult<Response> {
    a.session.check_csrf(&f.csrf)?;
    let target = crate::auth::load_user(&state, id).await?.ok_or(AppError::NotFound)?;
    if target.is_superadmin() && f.action != "trust" && f.action != "untrust" {
        return Err(AppError::bad(
            "the superadmin's role and access are set in the server's configuration",
        ));
    }
    let admin_only = matches!(f.action.as_str(), "grant-admin" | "revoke-admin");
    if admin_only && !a.user.is_superadmin() {
        return Err(AppError::Forbidden);
    }
    if target.is_admin() && matches!(f.action.as_str(), "ban") && !a.user.is_superadmin() {
        return Err(AppError::Forbidden);
    }
    if matches!(f.action.as_str(), "trust" | "untrust")
        && !site::may_grant_trust(&state, &a.user).await?
    {
        return Err(AppError::bad("only the superadmin can change who is trusted (see Admin, Site)"));
    }
    let sql = match f.action.as_str() {
        "trust" => "UPDATE users SET trusted = TRUE WHERE id = $1",
        "untrust" => "UPDATE users SET trusted = FALSE WHERE id = $1",
        "ban" => "UPDATE users SET banned = TRUE WHERE id = $1",
        "unban" => "UPDATE users SET banned = FALSE WHERE id = $1",
        "grant-admin" => "UPDATE users SET role = 'admin' WHERE id = $1 AND role = 'user'",
        "revoke-admin" => "UPDATE users SET role = 'user' WHERE id = $1 AND role = 'admin'",
        _ => return Err(AppError::bad("unknown action")),
    };
    sqlx::query(sql).bind(id).execute(&state.db).await?;
    if f.action == "ban" {
        // Signed out everywhere, and their tokens stop working.
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(&state.db)
            .await?;
        sqlx::query("UPDATE api_tokens SET revoked = TRUE WHERE user_id = $1")
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    audit(
        &state,
        Some(a.user.id),
        &format!("user.{}", f.action),
        Some(&target.username),
        json!({}),
        None,
    )
    .await?;
    Ok(Redirect::to("/admin/users").into_response())
}

// ---------- audit ----------

pub async fn audit_log(State(state): State<AppState>, Admin(a): Admin) -> AppResult<Response> {
    let rows: Vec<(time::OffsetDateTime, Option<String>, String, Option<String>, serde_json::Value)> = sqlx::query_as(
        "SELECT l.at, u.username, l.action, l.target, l.details FROM audit_log l LEFT JOIN users u ON u.id = l.actor ORDER BY l.at DESC LIMIT 500",
    )
    .fetch_all(&state.db)
    .await?;
    let rows = rows
        .into_iter()
        .map(|(at, who, action, target, details)| AuditRow {
            when: fmt_time(at),
            actor: who.unwrap_or_else(|| "system".into()),
            action,
            target: target.unwrap_or_default(),
            details: if details == json!({}) { String::new() } else { details.to_string() },
        })
        .collect();
    Ok(page(&AdminAuditPage { ctx: PageCtx::new(&state, Some(&a.session)), nav: "audit".into(), rows })?
        .into_response())
}

// ---------- site (superadmin) ----------

pub async fn site_page(State(state): State<AppState>, Admin(a): Admin) -> AppResult<Response> {
    if !a.user.is_superadmin() {
        return Err(AppError::Forbidden);
    }
    let orgs: Vec<(String, Option<String>, i64, bool)> = sqlx::query_as(
        "SELECT o.name, o.display_name, (SELECT count(*) FROM org_members m WHERE m.org_id = o.id), o.trusted FROM orgs o ORDER BY o.name",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(page(&AdminSitePage {
        ctx: PageCtx::new(&state, Some(&a.session)),
        nav: "site".into(),
        trust_granted_by: site::get(&state, site::TRUST_GRANTED_BY)
            .await?
            .unwrap_or_else(|| "superadmin".into()),
        untrusted_tips: site::get(&state, site::UNTRUSTED_TIPS)
            .await?
            .unwrap_or_else(|| "refuse".into()),
        orgs: orgs.into_iter().map(|(n, d, c, t)| (n, d.unwrap_or_default(), c, t)).collect(),
    })?
    .into_response())
}

#[derive(Deserialize)]
pub struct SiteForm {
    /// Each panel posts one of these.
    trust_granted_by: Option<String>,
    untrusted_tips: Option<String>,
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn site_save(
    State(state): State<AppState>,
    Admin(a): Admin,
    Form(f): Form<SiteForm>,
) -> AppResult<Response> {
    a.session.check_csrf(&f.csrf)?;
    if !a.user.is_superadmin() {
        return Err(AppError::Forbidden);
    }
    let (key, value) = match (f.trust_granted_by.as_deref(), f.untrusted_tips.as_deref()) {
        (Some(v @ ("superadmin" | "admins")), None) => (site::TRUST_GRANTED_BY, v),
        (None, Some(v @ ("refuse" | "allow"))) => (site::UNTRUSTED_TIPS, v),
        _ => {
            return Err(AppError::bad(
                "give trust_granted_by (superadmin or admins) or untrusted_tips (refuse or allow)",
            ));
        }
    };
    site::set(&state, key, value).await?;
    audit(&state, Some(a.user.id), "site.set", Some(key), json!({ "value": value }), None).await?;
    Ok(Redirect::to("/admin/site").into_response())
}
