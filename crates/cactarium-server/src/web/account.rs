//! Pages and actions for signed-in users: the dashboard, publishing, entry management, tokens.

use axum::Form;
use axum::extract::{Multipart, Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use cactup_ecosystem_common::manifest::Manifest;
use cactup_ecosystem_common::version::TrackedVersion;
use serde::Deserialize;
use serde_json::json;

use crate::audit::audit;
use crate::auth::{SignedIn, User, random_token, sha256};
use crate::error::{AppError, AppResult};
use crate::model::{self, ENTRY_COLS, Entry, fmt_date, fmt_time, semver_sort_key};
use crate::publish::{self, NewEntry};
use crate::security::ClientIp;
use crate::sims;
use crate::stacks;
use crate::state::AppState;
use crate::templates::*;
use crate::tracker;
use crate::web::public::entry_rows;

pub async fn tag_alerts(state: &AppState, owners: Option<&[String]>) -> AppResult<Vec<AlertRow>> {
    let rows: Vec<(i64, String, String, String, String, Option<String>, time::OffsetDateTime)> = sqlx::query_as(
        "SELECT t.id, e.owner, e.name, t.tag, t.frozen_commit, t.new_commit, t.seen_at FROM tag_events t JOIN entries e ON e.id = t.entry_id
         WHERE t.acknowledged_at IS NULL AND ($1::text[] IS NULL OR e.owner = ANY($1)) ORDER BY t.seen_at DESC LIMIT 100",
    )
    .bind(owners)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, o, n, tag, frozen, now, at)| AlertRow {
            id,
            entry: format!("{o}/{n}"),
            entry_url: format!("/{o}/{n}"),
            tag,
            frozen: frozen.chars().take(10).collect(),
            now: now.map(|c| c.chars().take(10).collect()).unwrap_or_default(),
            when: fmt_time(at),
        })
        .collect())
}

pub async fn dashboard(State(state): State<AppState>, s: SignedIn) -> AppResult<Response> {
    let mine = publish::namespaces(&s.user);
    let entries = sqlx::query_as::<_, Entry>(&format!(
        "SELECT {ENTRY_COLS} FROM entries WHERE owner = ANY($1) ORDER BY updated_at DESC"
    ))
    .bind(&mine)
    .fetch_all(&state.db)
    .await?;
    // New entries and new releases; a release shows as owner/name@version.
    let reviews: Vec<(String, String, String, Option<String>, time::OffsetDateTime)> = sqlx::query_as(
        "SELECT e.owner, e.name || COALESCE('@' || NULLIF(v.track, '') || ':' || v.version, '@' || v.version, ''),
                s.status, s.note, COALESCE(s.decided_at, s.created_at)
         FROM submissions s JOIN entries e ON e.id = s.entry_id LEFT JOIN versions v ON v.id = s.version_id
         WHERE e.owner = ANY($1) AND s.status <> 'auto-approved' ORDER BY s.created_at DESC LIMIT 20",
    )
    .bind(&mine)
    .fetch_all(&state.db)
    .await?;
    let saved = sqlx::query_as::<_, Entry>(&format!(
        "SELECT {ENTRY_COLS} FROM entries e WHERE visibility = 'public' AND id IN (SELECT entry_id FROM hearts WHERE user_id = $1)
         ORDER BY (SELECT created_at FROM hearts h WHERE h.user_id = $1 AND h.entry_id = e.id) DESC"
    ))
    .bind(s.user.id)
    .fetch_all(&state.db)
    .await?;
    let orgs: Vec<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT o.name, o.display_name, m.role FROM org_members m JOIN orgs o ON o.id = m.org_id WHERE m.user_id = $1 ORDER BY o.name",
    )
    .bind(s.user.id)
    .fetch_all(&state.db)
    .await?;
    let p = DashboardPage {
        ctx: PageCtx::new(&state, Some(&s.session)),
        orgs: orgs.into_iter().map(|(n, d, r)| (n, d.unwrap_or_default(), r)).collect(),
        entries: entry_rows(&state, entries).await?,
        saved: entry_rows(&state, saved).await?,
        reviews: reviews
            .into_iter()
            .map(|(o, n, st, note, at)| (format!("{o}/{n}"), st, note.unwrap_or_default(), fmt_date(at)))
            .collect(),
        alerts: tag_alerts(&state, Some(&mine)).await?,
    };
    Ok(page(&p)?.into_response())
}

// ---------- registering a repo ----------

pub async fn new_repo_page(State(state): State<AppState>, s: SignedIn) -> AppResult<Response> {
    Ok(page(&NewRepoPage {
        ctx: PageCtx::new(&state, Some(&s.session)),
        url: String::new(),
        error: None,
    })?
    .into_response())
}

#[derive(Deserialize)]
pub struct RepoForm {
    url: String,
    /// Admins only: the namespace to publish under, if not their own.
    #[serde(default)]
    owner: Option<String>,
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn new_repo(
    State(state): State<AppState>,
    s: SignedIn,
    ip: ClientIp,
    Form(f): Form<RepoForm>,
) -> AppResult<Response> {
    s.session.check_csrf(&f.csrf)?;
    state.limiter.check("register", ip.0, 10)?;
    match tracker::register(&state, &s.user, &f.url, f.owner.as_deref()).await {
        Ok(entries) => {
            Ok(Redirect::to(&entries.first().map(|e| e.url()).unwrap_or_else(|| "/dashboard".into()))
                .into_response())
        }
        Err(AppError::BadRequest(m) | AppError::Conflict(m) | AppError::Denied(m)) => {
            Ok(page(&NewRepoPage {
                ctx: PageCtx::new(&state, Some(&s.session)),
                url: f.url,
                error: Some(m),
            })?
            .into_response())
        }
        Err(e) => Err(e),
    }
}

// ---------- sims ----------

pub async fn new_sim_page(State(state): State<AppState>, s: SignedIn) -> AppResult<Response> {
    Ok(page(&NewSimPage { ctx: PageCtx::new(&state, Some(&s.session)), error: None })?.into_response())
}

pub async fn new_sim(
    State(state): State<AppState>,
    s: SignedIn,
    ip: ClientIp,
    mut form: Multipart,
) -> AppResult<Response> {
    state.limiter.check("upload", ip.0, 20)?;
    let (mut csrf, mut owner_field, mut name, mut file) =
        (String::new(), String::new(), String::new(), None);
    while let Some(field) = form
        .next_field()
        .await
        .map_err(|e| AppError::bad(format!("upload failed: {e}")))?
    {
        match field.name() {
            Some("_csrf") => csrf = field.text().await.unwrap_or_default(),
            Some("name") => name = field.text().await.unwrap_or_default(),
            Some("owner") => owner_field = field.text().await.unwrap_or_default(),
            Some("file") => {
                file =
                    Some(field.bytes().await.map_err(|e| AppError::bad(format!("upload failed: {e}")))?)
            }
            _ => {}
        }
    }
    s.session.check_csrf(&csrf)?;
    let bytes = file
        .filter(|b| !b.is_empty())
        .ok_or_else(|| AppError::bad("choose a .sim file"))?;
    // The "Publish under" choice, or "owner/name" typed as the name.
    let (owner, name) = match name.trim().split_once('/') {
        Some((o, n)) => (Some(o.to_owned()), n.to_owned()),
        None => (Some(owner_field.trim().to_owned()).filter(|o| !o.is_empty()), name.trim().to_owned()),
    };
    let result = async {
        let checked = sims::check(&bytes)?;
        sims::publish(&state, &s.user, owner.as_deref(), Some(&name), checked).await
    }
    .await;
    match result {
        Ok((entry, n, _)) => Ok(Redirect::to(&format!("{}/{n}", entry.url())).into_response()),
        Err(AppError::BadRequest(m) | AppError::Conflict(m) | AppError::Denied(m)) => {
            Ok(page(&NewSimPage { ctx: PageCtx::new(&state, Some(&s.session)), error: Some(m) })?
                .into_response())
        }
        Err(e) => Err(e),
    }
}

// ---------- stacks cut on the site ----------

#[derive(Deserialize, Default)]
pub struct NewStackQ {
    name: Option<String>,
}

pub async fn new_stack_page(
    State(state): State<AppState>,
    s: SignedIn,
    Query(q): Query<NewStackQ>,
) -> AppResult<Response> {
    // Pre-fill from the stack's latest release when cutting the next one.
    let (mut definition, mut thornlist) = (String::new(), String::new());
    if let Some(slug) = q.name.as_deref()
        && let Some((owner, name)) = slug.split_once('/')
        && let Some(e) = model::find_entry(&state, owner, name).await?
        && e.manageable_by(Some(&s.user))
    {
        let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT s.recipe, s.own_thornlist FROM stack_releases s JOIN versions v ON v.id = s.version_id WHERE v.entry_id = $1 ORDER BY v.created_at DESC LIMIT 1",
        )
        .bind(e.id)
        .fetch_optional(&state.db)
        .await?;
        if let Some((r, t)) = row {
            definition = r.unwrap_or_default();
            thornlist = t.unwrap_or_default();
        }
    }
    Ok(page(&NewStackPage {
        ctx: PageCtx::new(&state, Some(&s.session)),
        error: None,
        definition,
        thornlist,
        version: String::new(),
    })?
    .into_response())
}

#[derive(Deserialize)]
pub struct StackForm {
    /// The user or one of their organizations (empty: the user).
    #[serde(default)]
    owner: String,
    definition: String,
    #[serde(default)]
    thornlist: String,
    version: String,
    #[serde(rename = "_csrf")]
    csrf: String,
}

/// Cuts a snapshot release of a stack defined on the site (not in a repo), under `owner` (the user
/// or one of their organizations; default: the user).
pub async fn cut_release(
    state: &AppState,
    user: &User,
    owner: Option<&str>,
    definition: &str,
    thornlist: Option<&str>,
    version: &str,
) -> AppResult<(Entry, &'static str)> {
    let owner = owner
        .map(str::trim)
        .filter(|o| !o.is_empty())
        .unwrap_or(&user.username)
        .to_owned();
    publish::check_namespace(state, user, &owner).await?;
    let m = Manifest::from_toml(definition).map_err(AppError::bad)?;
    let stack = m
        .stack
        .as_ref()
        .ok_or_else(|| AppError::bad("the definition needs a [stack] section"))?;
    let tv: TrackedVersion = version.trim().parse().map_err(AppError::bad)?;
    let name = stack.name.to_string();
    let label = tv.to_string();
    let existing = model::find_entry(state, &owner, &name).await?;
    if let Some(e) = &existing {
        if e.kind != "stack" {
            return Err(AppError::Conflict(format!("{} is a {}, not a stack", e.slug(), e.kind)));
        }
        if tracker::repo_of(state, e.id).await?.is_some() {
            return Err(AppError::bad(format!(
                "{} is released from its repo; push a version tag instead",
                e.slug()
            )));
        }
        if model::any_version_by_label(state, e.id, &label).await?.is_some() {
            return Err(AppError::Conflict(format!(
                "{}@{label} already exists; releases never change",
                e.slug()
            )));
        }
    }
    // Resolve before anything is created, so a definition that fails leaves no trace.
    let own = thornlist.map(str::trim).filter(|t| !t.is_empty()).map(|t| format!("{t}\n"));
    let resolution = stacks::resolve(state, &owner, stack, own.as_deref(), None).await?;
    let slug = format!("{owner}/{name}@{label}").parse().map_err(AppError::bad)?;
    let frozen = stacks::freeze(slug, &format!("{name}.th"), resolution, Some(definition.to_owned()))?;
    let entry = match existing {
        Some(e) => e,
        None => {
            publish::create_entry(
                state,
                user,
                NewEntry {
                    kind: "stack",
                    owner: &owner,
                    name: &name,
                    summary: stack
                        .description
                        .as_deref()
                        .map(|d| d.lines().next().unwrap_or("").to_owned()),
                    description: None,
                    curated: false,
                },
            )
            .await?
        }
    };
    let toml = toml::to_string(&frozen).map_err(anyhow::Error::from)?;
    let track = tv.track.as_ref().map(|t| t.to_string()).unwrap_or_default();
    let manifest_json = serde_json::to_value(&m).map_err(anyhow::Error::from)?;
    let review = publish::release_review(state, &entry, Some(user)).await?;
    let vid: i64 = sqlx::query_scalar(
        "INSERT INTO versions (entry_id, track, version, sort_key, manifest, published_by, review) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(entry.id)
    .bind(&track)
    .bind(tv.version.to_string())
    .bind(semver_sort_key(&tv.version))
    .bind(&manifest_json)
    .bind(user.id)
    .bind(review)
    .fetch_one(&state.db)
    .await?;
    tracker::store_release(
        state,
        &entry,
        vid,
        &track,
        &frozen,
        &toml,
        "snapshot",
        Some(definition.to_owned()),
        own,
    )
    .await?;
    for (kind, list) in [
        ("depends-on", &m.depends_on),
        ("works-with", &m.works_with),
        ("incompatible-with", &m.incompatible_with),
    ] {
        for c in list {
            sqlx::query("INSERT INTO claims (version_id, kind, target_owner, target_name, range, note) VALUES ($1, $2, $3, $4, $5, $6)")
                .bind(vid)
                .bind(kind)
                .bind(c.target.owner.as_str())
                .bind(c.target.name.as_str())
                .bind(c.range.as_ref().map(|r| r.to_string()))
                .bind(&c.note)
                .execute(&state.db)
                .await?;
        }
    }
    publish::touch(state, entry.id).await?;
    publish::submit_release(state, &entry, vid, review, Some(user)).await?;
    audit(
        state,
        Some(user.id),
        "stack.release",
        Some(&entry.slug()),
        json!({ "version": label, "review": review }),
        None,
    )
    .await?;
    Ok((entry, review))
}

pub async fn new_stack(
    State(state): State<AppState>,
    s: SignedIn,
    ip: ClientIp,
    Form(f): Form<StackForm>,
) -> AppResult<Response> {
    s.session.check_csrf(&f.csrf)?;
    state.limiter.check("release", ip.0, 10)?;
    match cut_release(&state, &s.user, Some(&f.owner), &f.definition, Some(&f.thornlist), &f.version)
        .await
    {
        Ok((e, _)) => Ok(Redirect::to(&e.url()).into_response()),
        Err(AppError::BadRequest(m) | AppError::Conflict(m) | AppError::Denied(m)) => {
            Ok(page(&NewStackPage {
                ctx: PageCtx::new(&state, Some(&s.session)),
                error: Some(m),
                definition: f.definition,
                thornlist: f.thornlist,
                version: f.version,
            })?
            .into_response())
        }
        Err(e) => Err(e),
    }
}

// ---------- managing an entry ----------

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(rename = "_csrf")]
    csrf: String,
}

async fn managed(state: &AppState, s: &SignedIn, owner: &str, name: &str) -> AppResult<Entry> {
    let e = model::find_entry(state, owner, name).await?.ok_or(AppError::NotFound)?;
    if !e.manageable_by(Some(&s.user)) {
        return Err(AppError::Forbidden);
    }
    Ok(e)
}

pub async fn refresh(
    State(state): State<AppState>,
    s: SignedIn,
    ip: ClientIp,
    Path((owner, name)): Path<(String, String)>,
    Form(f): Form<CsrfForm>,
) -> AppResult<Response> {
    s.session.check_csrf(&f.csrf)?;
    state.limiter.check("refresh", ip.0, 10)?;
    let e = managed(&state, &s, &owner, &name).await?;
    let _ = tracker::sync(&state, &e).await;
    Ok(Redirect::to(&e.url()).into_response())
}

#[derive(Deserialize)]
pub struct YankForm {
    version_id: i64,
    yank: String,
    reason: Option<String>,
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn yank(
    State(state): State<AppState>,
    s: SignedIn,
    Path((owner, name)): Path<(String, String)>,
    Form(f): Form<YankForm>,
) -> AppResult<Response> {
    s.session.check_csrf(&f.csrf)?;
    let e = managed(&state, &s, &owner, &name).await?;
    publish::set_yanked(&state, &s.user, &e, f.version_id, f.yank == "1", f.reason.as_deref(), "site")
        .await?;
    Ok(Redirect::to(&format!("{}?tab=versions", e.url())).into_response())
}

/// Saves an entry for later, or un-saves it. The count of saves is public.
pub async fn heart(
    State(state): State<AppState>,
    s: SignedIn,
    Path((owner, name)): Path<(String, String)>,
    Form(f): Form<CsrfForm>,
) -> AppResult<Response> {
    s.session.check_csrf(&f.csrf)?;
    let e = model::visible_entry(&state, &owner, &name, Some(&s.user)).await?;
    let removed = sqlx::query("DELETE FROM hearts WHERE user_id = $1 AND entry_id = $2")
        .bind(s.user.id)
        .bind(e.id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if removed == 0 {
        sqlx::query("INSERT INTO hearts (user_id, entry_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(s.user.id)
            .bind(e.id)
            .execute(&state.db)
            .await?;
    }
    Ok(Redirect::to(&e.url()).into_response())
}

pub async fn resubmit(
    State(state): State<AppState>,
    s: SignedIn,
    Path((owner, name)): Path<(String, String)>,
    Form(f): Form<CsrfForm>,
) -> AppResult<Response> {
    s.session.check_csrf(&f.csrf)?;
    let e = managed(&state, &s, &owner, &name).await?;
    publish::resubmit(&state, &e, &s.user).await?;
    Ok(Redirect::to(&e.url()).into_response())
}

// ---------- settings and API tokens ----------

async fn settings_page(
    state: &AppState,
    s: &SignedIn,
    new_token: Option<String>,
) -> AppResult<Response> {
    let identities: Vec<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT provider, login, subject FROM identities WHERE user_id = $1 ORDER BY provider",
    )
    .bind(s.user.id)
    .fetch_all(&state.db)
    .await?;
    let tokens: Vec<(i64, String, String, Vec<String>, time::OffsetDateTime, time::OffsetDateTime, Option<time::OffsetDateTime>)> = sqlx::query_as(
        "SELECT id, name, prefix, scopes, created_at, expires_at, last_used_at FROM api_tokens WHERE user_id = $1 AND NOT revoked AND expires_at > now() ORDER BY created_at DESC",
    )
    .bind(s.user.id)
    .fetch_all(&state.db)
    .await?;
    let has = |p: &str| identities.iter().any(|i| i.0 == p);
    let p = SettingsPage {
        ctx: PageCtx::new(state, Some(&s.session)),
        can_link_github: state.cfg.github.is_some() && !has("github"),
        can_link_orcid: state.cfg.orcid.is_some() && !has("orcid"),
        identities: identities.into_iter().map(|(p, l, sub)| (p, l.unwrap_or(sub))).collect(),
        tokens: tokens
            .into_iter()
            .map(|(id, name, prefix, scopes, c, x, l)| TokenRow {
                id,
                name,
                prefix,
                scopes: scopes.join(" "),
                created: fmt_date(c),
                expires: fmt_date(x),
                last_used: l.map(fmt_date).unwrap_or_else(|| "never".into()),
            })
            .collect(),
        new_token,
    };
    Ok(page(&p)?.into_response())
}

pub async fn settings(State(state): State<AppState>, s: SignedIn) -> AppResult<Response> {
    settings_page(&state, &s, None).await
}

#[derive(Deserialize)]
pub struct TokenForm {
    name: String,
    days: i64,
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub const TOKEN_PREFIX: &str = "cactarium_";

pub async fn create_token(
    State(state): State<AppState>,
    s: SignedIn,
    Form(f): Form<TokenForm>,
) -> AppResult<Response> {
    s.session.check_csrf(&f.csrf)?;
    let token = mint_token(&state, &s.user, &f.name, f.days.clamp(1, 366) as i32).await?;
    settings_page(&state, &s, Some(token)).await
}

/// Creates a "publish" token for `user`, returning it (it is stored only as a hash).
pub async fn mint_token(state: &AppState, user: &User, name: &str, days: i32) -> AppResult<String> {
    let days = days.clamp(1, 366);
    let name = name.trim().chars().take(80).collect::<String>();
    if name.is_empty() {
        return Err(AppError::bad("give the token a name"));
    }
    let token = format!("{TOKEN_PREFIX}{}", random_token());
    sqlx::query(
        "INSERT INTO api_tokens (user_id, name, token_hash, prefix, scopes, expires_at) VALUES ($1, $2, $3, $4, $5, now() + make_interval(days => $6))",
    )
    .bind(user.id)
    .bind(&name)
    .bind(sha256(&token))
    .bind(token.chars().take(TOKEN_PREFIX.len() + 6).collect::<String>())
    .bind(vec!["publish".to_owned()])
    .bind(days)
    .execute(&state.db)
    .await?;
    audit(state, Some(user.id), "token.create", Some(&name), json!({ "days": days }), None).await?;
    Ok(token)
}

pub async fn revoke_token(
    State(state): State<AppState>,
    s: SignedIn,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> AppResult<Response> {
    s.session.check_csrf(&f.csrf)?;
    sqlx::query("UPDATE api_tokens SET revoked = TRUE WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(s.user.id)
        .execute(&state.db)
        .await?;
    audit(&state, Some(s.user.id), "token.revoke", None, json!({ "id": id }), None).await?;
    Ok(Redirect::to("/settings").into_response())
}
