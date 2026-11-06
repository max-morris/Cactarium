//! Pages anyone can see.

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use cactup_ecosystem_common::manifest::Manifest;
use cactup_ecosystem_common::sim::{ParfileKind, SimFile};
use serde::Deserialize;

use crate::auth::{User, Visitor};
use crate::error::{AppError, AppResult};
use crate::git::normalize_url;
use crate::markdown;
use crate::model::{self, ENTRY_COLS, Entry, Version, fmt_date};
use crate::stacks;
use crate::state::AppState;
use crate::templates::*;
use crate::tracker;

pub fn version_row(e: &Entry, v: &Version, current: Option<i64>) -> VersionRow {
    let mut status = Vec::new();
    if v.yanked {
        status.push(format!("yanked{}", v.yank_reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default()));
    }
    match v.state.as_str() {
        "invalid" => status.push(format!("invalid: {}", v.invalid_reason.as_deref().unwrap_or("?"))),
        "tag-moved" => status.push("tag moved upstream; the frozen commit is still served".into()),
        "upstream-missing" => status.push("tag deleted upstream".into()),
        _ => {}
    }
    if v.is_virtual {
        status.push("curated".into());
    }
    VersionRow {
        label: v.label(),
        url: format!("{}/{}", e.url(), v.label()),
        tag: v.tag.clone().unwrap_or_default(),
        commit: v.short_commit(),
        status: status.join(" · "),
        current: Some(v.id) == current,
        date: fmt_date(v.created_at),
        id: v.id,
        yanked: v.yanked,
    }
}

/// The newest version's label, for listings.
async fn latest_labels(state: &AppState, ids: &[i64]) -> AppResult<BTreeMap<i64, String>> {
    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT DISTINCT ON (entry_id) entry_id, track, version FROM versions
         WHERE entry_id = ANY($1) AND NOT yanked AND state <> 'invalid'
         ORDER BY entry_id, (track = '') DESC, sort_key DESC",
    )
    .bind(ids)
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|(id, t, v)| (id, if t.is_empty() { v } else { format!("{t}:{v}") })).collect())
}

pub async fn entry_rows(state: &AppState, entries: Vec<Entry>) -> AppResult<Vec<EntryRow>> {
    let ids: Vec<i64> = entries.iter().map(|e| e.id).collect();
    let latest = latest_labels(state, &ids).await?;
    Ok(entries
        .into_iter()
        .map(|e| EntryRow {
            slug: e.slug(),
            url: e.url(),
            latest: latest.get(&e.id).cloned().unwrap_or_else(|| "–".into()),
            summary: e.summary.clone().unwrap_or_default(),
            kind: e.kind.clone(),
            visibility: e.visibility.clone(),
            verified: e.verified,
            curated: e.curated,
        })
        .collect())
}

pub async fn home(State(state): State<AppState>, v: Visitor) -> AppResult<Response> {
    let recent = sqlx::query_as::<_, Entry>(&format!(
        "SELECT {ENTRY_COLS} FROM entries WHERE visibility = 'public' ORDER BY updated_at DESC LIMIT 12"
    ))
    .fetch_all(&state.db)
    .await?;
    let counts: Vec<(String, i64)> =
        sqlx::query_as("SELECT kind, count(*) FROM entries WHERE visibility = 'public' GROUP BY kind").fetch_all(&state.db).await?;
    let count = |k: &str| counts.iter().find(|c| c.0 == k).map(|c| c.1).unwrap_or(0);
    let p = HomePage {
        ctx: PageCtx::new(&state, v.0.as_ref()),
        recent: entry_rows(&state, recent).await?,
        packages: count("package"),
        stacks: count("stack"),
        sims: count("sim"),
    };
    Ok(page(&p)?.into_response())
}

#[derive(Deserialize, Default)]
pub struct SearchQ {
    #[serde(default)]
    q: String,
    #[serde(default)]
    kind: String,
}

fn like(q: &str) -> String {
    format!("%{}%", q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"))
}

async fn thorn_hits(state: &AppState, filter: &str, arg: &str) -> AppResult<Vec<ThornHit>> {
    let rows: Vec<(String, String, Option<String>, String, String, String, String)> = sqlx::query_as(&format!(
        "SELECT DISTINCT ON (e.id, t.arrangement, t.name) t.arrangement, t.name, t.implements, e.owner, e.name, v.track, v.version
         FROM thorns t JOIN versions v ON v.id = t.version_id JOIN entries e ON e.id = v.entry_id
         WHERE e.visibility = 'public' AND NOT v.yanked AND {filter}
         ORDER BY e.id, t.arrangement, t.name, (v.track = '') DESC, v.sort_key DESC LIMIT 200"
    ))
    .bind(arg)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(a, n, imp, o, en, t, ver)| ThornHit {
            thorn: format!("{a}/{n}"),
            implements: imp.unwrap_or_default(),
            package: format!("{o}/{en}"),
            package_url: format!("/{o}/{en}"),
            version: if t.is_empty() { ver } else { format!("{t}:{ver}") },
        })
        .collect())
}

pub async fn search(State(state): State<AppState>, v: Visitor, Query(q): Query<SearchQ>) -> AppResult<Response> {
    let term = q.q.trim().to_owned();
    let kind = if ["package", "stack", "sim", "thorn"].contains(&q.kind.as_str()) { q.kind.clone() } else { String::new() };
    let results = if kind == "thorn" {
        vec![]
    } else {
        let entries = sqlx::query_as::<_, Entry>(&format!(
            "SELECT {ENTRY_COLS} FROM entries WHERE visibility = 'public'
             AND ($1 = '' OR kind = $1)
             AND ($2 = '%%' OR owner || '/' || name ILIKE $2 OR summary ILIKE $2
                  OR id IN (SELECT v.entry_id FROM thorns t JOIN versions v ON v.id = t.version_id WHERE t.name ILIKE $2 OR t.implements ILIKE $2))
             ORDER BY (name ILIKE $3) DESC, updated_at DESC LIMIT 100"
        ))
        .bind(&kind)
        .bind(like(&term))
        .bind(term.clone())
        .fetch_all(&state.db)
        .await?;
        entry_rows(&state, entries).await?
    };
    let thorns = if (kind.is_empty() && !term.is_empty()) || kind == "thorn" {
        thorn_hits(&state, "(t.name ILIKE $1 OR t.implements ILIKE $1 OR t.arrangement ILIKE $1)", &like(&term)).await?
    } else {
        vec![]
    };
    let title = match kind.as_str() {
        "package" => "Packages",
        "stack" => "Stacks",
        "sim" => "Sims",
        "thorn" => "Thorns",
        _ if term.is_empty() => "Everything",
        _ => "Search",
    }
    .to_owned();
    Ok(page(&SearchPage { ctx: PageCtx::new(&state, v.0.as_ref()), q: term, kind, results, thorns, title })?.into_response())
}

pub async fn thorn(State(state): State<AppState>, v: Visitor, Path((arr, name)): Path<(String, String)>) -> AppResult<Response> {
    let thorns = thorn_hits(&state, "lower(t.arrangement || '/' || t.name) = lower($1)", &format!("{arr}/{name}")).await?;
    Ok(page(&SearchPage {
        ctx: PageCtx::new(&state, v.0.as_ref()),
        q: format!("{arr}/{name}"),
        kind: "thorn".into(),
        results: vec![],
        thorns,
        title: format!("Thorn {arr}/{name}"),
    })?
    .into_response())
}

pub async fn thorn_by_name(State(state): State<AppState>, v: Visitor, Path(name): Path<String>) -> AppResult<Response> {
    let thorns = thorn_hits(&state, "lower(t.name) = lower($1)", &name).await?;
    Ok(page(&SearchPage { ctx: PageCtx::new(&state, v.0.as_ref()), q: name.clone(), kind: "thorn".into(), results: vec![], thorns, title: format!("Thorn {name}") })?.into_response())
}

pub async fn implementation(State(state): State<AppState>, v: Visitor, Path(name): Path<String>) -> AppResult<Response> {
    let thorns = thorn_hits(&state, "lower(t.implements) = lower($1)", &name).await?;
    Ok(page(&SearchPage {
        ctx: PageCtx::new(&state, v.0.as_ref()),
        q: name.clone(),
        kind: "thorn".into(),
        results: vec![],
        thorns,
        title: format!("Thorns implementing {name}"),
    })?
    .into_response())
}

#[derive(Deserialize)]
pub struct SourcesQ {
    url: String,
}

/// Everything that pins a repo, registered on the Cactarium or not.
pub async fn sources(State(state): State<AppState>, v: Visitor, Query(q): Query<SourcesQ>) -> AppResult<Response> {
    let entries = sqlx::query_as::<_, Entry>(&format!(
        "SELECT {ENTRY_COLS} FROM entries WHERE visibility = 'public' AND id IN
         (SELECT v.entry_id FROM source_pins p JOIN versions v ON v.id = p.version_id WHERE p.url_norm = $1)
         ORDER BY updated_at DESC"
    ))
    .bind(normalize_url(&q.url))
    .fetch_all(&state.db)
    .await?;
    Ok(page(&SearchPage {
        ctx: PageCtx::new(&state, v.0.as_ref()),
        q: q.url.clone(),
        kind: String::new(),
        results: entry_rows(&state, entries).await?,
        thorns: vec![],
        title: format!("Everything that pins {}", q.url),
    })?
    .into_response())
}

pub async fn owner(State(state): State<AppState>, v: Visitor, Path(owner): Path<String>) -> AppResult<Response> {
    let display: Option<Option<String>> = sqlx::query_scalar("SELECT display_name FROM users WHERE username = $1")
        .bind(&owner)
        .fetch_optional(&state.db)
        .await?;
    let user = v.user();
    let entries: Vec<Entry> = sqlx::query_as::<_, Entry>(&format!("SELECT {ENTRY_COLS} FROM entries WHERE owner = $1 ORDER BY kind, name"))
        .bind(&owner)
        .fetch_all(&state.db)
        .await?
        .into_iter()
        .filter(|e| e.visible_to(user))
        .collect();
    if display.is_none() && entries.is_empty() {
        return Err(AppError::NotFound);
    }
    let display = display.flatten().unwrap_or_else(|| owner.clone());
    Ok(page(&OwnerPage { ctx: PageCtx::new(&state, v.0.as_ref()), owner, display, entries: entry_rows(&state, entries).await? })?.into_response())
}

pub async fn docs(State(state): State<AppState>, v: Visitor) -> AppResult<Response> {
    Ok(page(&DocsPage { ctx: PageCtx::new(&state, v.0.as_ref()), base_url: state.cfg.base_url.as_str().trim_end_matches('/').to_owned() })?.into_response())
}

async fn head_of(state: &AppState, e: &Entry, user: Option<&User>) -> AppResult<EntryHead> {
    let repo = tracker::repo_of(state, e.id).await?;
    let (review_status, review_note): (String, String) = if e.manageable_by(user) {
        sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT status, note FROM submissions WHERE entry_id = $1 AND status IN ('open', 'changes-requested', 'rejected') ORDER BY created_at DESC LIMIT 1",
        )
        .bind(e.id)
        .fetch_optional(&state.db)
        .await?
        .map(|(s, n)| (s, n.unwrap_or_default()))
        .unwrap_or_default()
    } else {
        Default::default()
    };
    Ok(EntryHead {
        slug: e.slug(),
        url: e.url(),
        kind: e.kind.clone(),
        summary: e.summary.clone().unwrap_or_default(),
        description_html: e.description.as_deref().map(markdown::render).unwrap_or_default(),
        visibility: e.visibility.clone(),
        verified: e.verified,
        curated: e.curated,
        can_manage: e.manageable_by(user),
        repo_url: repo.map(|r| r.url).unwrap_or_default(),
        review_status,
        review_note,
    })
}

async fn claims_of(state: &AppState, version_id: i64) -> AppResult<Vec<ClaimRow>> {
    let rows: Vec<(String, String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT kind, target_owner, target_name, range, note FROM claims WHERE version_id = $1 ORDER BY kind, target_owner, target_name",
    )
    .bind(version_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(k, o, n, r, note)| ClaimRow {
            kind: k.replace('-', " "),
            target: format!("{o}/{n}"),
            target_url: format!("/{o}/{n}"),
            range: r.unwrap_or_default(),
            note: note.unwrap_or_default(),
        })
        .collect())
}

pub async fn thorn_rows(state: &AppState, version_id: i64, caveats: &[(String, String)]) -> AppResult<Vec<ThornRow>> {
    let rows: Vec<(String, String, Option<String>, serde_json::Value)> =
        sqlx::query_as("SELECT arrangement, name, implements, facts FROM thorns WHERE version_id = $1 ORDER BY arrangement, name")
            .bind(version_id)
            .fetch_all(&state.db)
            .await?;
    let list = |f: &serde_json::Value, k: &str| {
        f[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default()
    };
    Ok(rows
        .into_iter()
        .map(|(a, n, imp, f)| {
            let mut requires = list(&f, "requires");
            let thorns = list(&f, "requires-thorns");
            if !thorns.is_empty() {
                requires = if requires.is_empty() { thorns } else { format!("{requires}; {thorns}") };
            }
            ThornRow {
                caveat: caveats.iter().find(|c| c.0 == n).map(|c| c.1.clone()).unwrap_or_default(),
                name: format!("{a}/{n}"),
                implements: imp.unwrap_or_default(),
                requires,
                inherits: list(&f, "inherits"),
            }
        })
        .collect())
}

/// Matches pinned repos against registered packages, by URL and frozen commit.
async fn pin_rows(state: &AppState, pins: &[cactup_ecosystem_common::sim::RepoPin]) -> AppResult<Vec<PinRow>> {
    let repos: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT e.id, e.owner, e.name, r.url FROM entry_repos r JOIN entries e ON e.id = r.entry_id WHERE e.kind = 'package' AND e.visibility = 'public'",
    )
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::new();
    for p in pins {
        let norm = normalize_url(&p.url);
        let mut registered = None;
        if let Some((id, o, n, _)) = repos.iter().find(|r| normalize_url(&r.3) == norm)
            && let Some(c) = &p.commit
        {
            let label: Option<(String, String)> =
                sqlx::query_as("SELECT track, version FROM versions WHERE entry_id = $1 AND commit = $2 ORDER BY sort_key DESC LIMIT 1")
                    .bind(id)
                    .bind(c)
                    .fetch_optional(&state.db)
                    .await?;
            registered = Some(match label {
                Some((t, v)) => {
                    let l = if t.is_empty() { v } else { format!("{t}:{v}") };
                    (format!("{o}/{n}@{l}"), format!("/{o}/{n}/{l}"))
                }
                None => (format!("{o}/{n}"), format!("/{o}/{n}")),
            });
        }
        out.push(PinRow {
            repo: p.name.clone(),
            url: p.url.clone(),
            git_ref: p.git_ref.clone().unwrap_or_default(),
            commit: p.commit.as_deref().or(p.sha256.as_deref()).map(|c| c.chars().take(12).collect()).unwrap_or_else(|| "unpinned".into()),
            registered,
        });
    }
    Ok(out)
}

fn tabs(base: &str, list: &[(&str, &str)], selected: &str) -> Vec<Tab> {
    list.iter()
        .map(|(id, label)| Tab { label: label.to_string(), url: format!("{base}?tab={id}"), selected: *id == selected })
        .collect()
}

#[derive(Deserialize, Default)]
pub struct EntryQ {
    tab: Option<String>,
    track: Option<String>,
}

pub async fn entry(State(state): State<AppState>, v: Visitor, Path((owner, name)): Path<(String, String)>, Query(q): Query<EntryQ>) -> AppResult<Response> {
    show(&state, &v, &owner, &name, None, q).await
}

pub async fn entry_version(
    State(state): State<AppState>,
    v: Visitor,
    Path((owner, name, version)): Path<(String, String, String)>,
    Query(q): Query<EntryQ>,
) -> AppResult<Response> {
    show(&state, &v, &owner, &name, Some(&version), q).await
}

async fn show(state: &AppState, v: &Visitor, owner: &str, name: &str, label: Option<&str>, q: EntryQ) -> AppResult<Response> {
    let user = v.user();
    let e = model::visible_entry(state, owner, name, user).await?;
    let versions = model::versions(state, e.id).await?;
    let ctx = PageCtx::new(state, v.0.as_ref());
    let head = head_of(state, &e, user).await?;
    match e.kind.as_str() {
        "package" => package_page(state, ctx, head, &e, versions, label, q).await,
        "stack" => stack_page(state, ctx, head, &e, versions, label).await,
        _ => sim_page(state, ctx, head, &e, versions, label, q).await,
    }
}

fn pick<'a>(versions: &'a [Version], label: Option<&str>, track: Option<&str>, default_track: Option<&str>) -> AppResult<Option<&'a Version>> {
    if let Some(l) = label {
        return versions.iter().find(|v| v.label() == l).map(Some).ok_or(AppError::NotFound);
    }
    let tracks = model::tracks_of(versions, default_track);
    let track = track.map(|t| if t == "default" { "" } else { t }).or(tracks.first().map(String::as_str)).unwrap_or("");
    Ok(model::latest_on(versions, track))
}

async fn package_page(state: &AppState, ctx: PageCtx, e: EntryHead, entry: &Entry, versions: Vec<Version>, label: Option<&str>, q: EntryQ) -> AppResult<Response> {
    let newest_manifest: Option<Manifest> =
        versions.iter().filter(|v| v.usable()).find_map(|v| v.manifest.clone()).and_then(|m| serde_json::from_value(m).ok());
    let default_track = newest_manifest.as_ref().and_then(|m| m.package.as_ref()).and_then(|p| p.default_track.clone());
    let current = pick(&versions, label, q.track.as_deref(), default_track.as_deref())?;
    let manifest: Option<Manifest> = current.and_then(|v| v.manifest.clone()).and_then(|m| serde_json::from_value(m).ok());
    let caveats: Vec<(String, String)> = manifest.as_ref().map(|m| m.caveats.iter().map(|c| (c.thorn.clone(), c.note.clone())).collect()).unwrap_or_default();
    let track_names = model::tracks_of(&versions, default_track.as_deref());
    let current_track = current.map(|v| v.track.clone()).unwrap_or_default();
    let tracks = track_names
        .iter()
        .map(|t| TrackTab {
            name: t.clone(),
            url: format!("{}?track={}", entry.url(), if t.is_empty() { "default" } else { t }),
            selected: *t == current_track,
            description: newest_manifest
                .as_ref()
                .and_then(|m| m.tracks.iter().find(|(k, _)| k.as_str() == t).and_then(|(_, i)| i.description.clone()))
                .unwrap_or_default(),
        })
        .collect();
    let tab = q.tab.unwrap_or_else(|| "readme".into());
    let (thorns, claims) = match current {
        Some(v) => (thorn_rows(state, v.id, &caveats).await?, claims_of(state, v.id).await?),
        None => (vec![], vec![]),
    };
    let used_by = sqlx::query_as::<_, Entry>(&format!(
        "SELECT {ENTRY_COLS} FROM entries WHERE visibility = 'public' AND kind <> 'package' AND id IN
         (SELECT v.entry_id FROM source_pins p JOIN versions v ON v.id = p.version_id WHERE p.url_norm = $1) ORDER BY updated_at DESC LIMIT 50"
    ))
    .bind(normalize_url(&e.repo_url))
    .fetch_all(&state.db)
    .await?;
    let repo = tracker::repo_of(state, entry.id).await?;
    let poll_error: String = sqlx::query_scalar::<_, Option<String>>("SELECT poll_error FROM entry_repos WHERE entry_id = $1")
        .bind(entry.id)
        .fetch_optional(&state.db)
        .await?
        .flatten()
        .unwrap_or_default();
    let version_note = match current {
        Some(v) if v.state == "invalid" => format!("This tag could not be published: {}", v.invalid_reason.as_deref().unwrap_or("")),
        Some(v) if v.yanked => "This version is yanked: still downloadable by exact version, never chosen by a range.".into(),
        _ => String::new(),
    };
    let add_cmd = match current {
        Some(v) if v.track.is_empty() => format!("cactup add {}@^{}", entry.slug(), v.version),
        Some(v) => format!("cactup add {}@{}:^{}", entry.slug(), v.track, v.version),
        None => String::new(),
    };
    let p = PackagePage {
        version: current.map(|v| version_row(entry, v, None)),
        readme_html: current.and_then(|v| v.readme_html.clone()).unwrap_or_default(),
        tabs: tabs(&entry.url(), &[("readme", "README"), ("thorns", "Thorns"), ("versions", "Versions"), ("usedby", "Used by")], &tab),
        tab,
        thorns,
        claims,
        caveats,
        versions: versions.iter().map(|v| version_row(entry, v, current.map(|c| c.id))).collect(),
        used_by: entry_rows(state, used_by).await?,
        tracks,
        add_cmd,
        version_note,
        poll_error,
        webhook_url: state.cfg.url(&format!("/hooks/github/{}", entry.id)),
        webhook_secret: if e.can_manage { repo.map(|r| r.webhook_secret).unwrap_or_default() } else { String::new() },
        ctx,
        e,
    };
    Ok(page(&p)?.into_response())
}

async fn stack_page(state: &AppState, ctx: PageCtx, e: EntryHead, entry: &Entry, versions: Vec<Version>, label: Option<&str>) -> AppResult<Response> {
    let current = pick(&versions, label, None, None)?;
    let (frozen, how, diff, recipe) = match current {
        Some(v) => {
            let row: Option<(String, String, serde_json::Value, Option<String>)> =
                sqlx::query_as("SELECT frozen, how, diff, recipe FROM stack_releases WHERE version_id = $1")
                    .bind(v.id)
                    .fetch_optional(&state.db)
                    .await?;
            match row {
                Some((f, how, d, r)) => (toml::from_str::<cactup_ecosystem_common::stack::FrozenStack>(&f).ok(), how, d, r),
                None => (None, String::new(), serde_json::Value::Null, None),
            }
        }
        None => (None, String::new(), serde_json::Value::Null, None),
    };
    let extends: Vec<(String, String)> = recipe
        .as_deref()
        .and_then(|r| Manifest::from_toml(r).ok())
        .and_then(|m| m.stack)
        .map(|s| s.extends.iter().map(|b| (b.to_string(), format!("/{}/{}/{}", b.owner, b.name, b.at.clone().unwrap_or_default()))).collect())
        .unwrap_or_default();
    let used_by = sqlx::query_as::<_, Entry>(&format!(
        "SELECT {ENTRY_COLS} FROM entries WHERE visibility = 'public' AND kind = 'stack' AND id <> $2 AND id IN
         (SELECT v.entry_id FROM stack_releases s JOIN versions v ON v.id = s.version_id WHERE s.recipe LIKE $1)"
    ))
    .bind(format!("%\"{}@%", entry.slug()))
    .bind(entry.id)
    .fetch_all(&state.db)
    .await?;
    let pins = match &frozen {
        Some(f) => pin_rows(state, &f.repos).await?,
        None => vec![],
    };
    let claims = match current {
        Some(v) => claims_of(state, v.id).await?,
        None => vec![],
    };
    let poll_error: String = sqlx::query_scalar::<_, Option<String>>("SELECT poll_error FROM entry_repos WHERE entry_id = $1")
        .bind(entry.id)
        .fetch_optional(&state.db)
        .await?
        .flatten()
        .unwrap_or_default();
    let p = StackPage {
        version: current.map(|v| version_row(entry, v, None)),
        releases: versions.iter().map(|v| version_row(entry, v, current.map(|c| c.id))).collect(),
        how: match how.as_str() {
            "tag" => "released by a git tag".into(),
            "snapshot" => "snapshot release".into(),
            other => other.to_owned(),
        },
        install_cmd: current.map(|v| format!("cactup install {}@{}", entry.slug(), v.label())).unwrap_or_default(),
        tip_cmd: format!("cactup install {}@head", entry.slug()),
        master_cmd: format!("cactup install {}@master", entry.slug()),
        frozen_text: frozen.as_ref().map(|f| f.thornlist.text.clone()).unwrap_or_default(),
        pins,
        diff: serde_json::from_value(diff).unwrap_or_default(),
        recipe: recipe.unwrap_or_default(),
        extends,
        claims,
        used_by: entry_rows(state, used_by).await?,
        repo_backed: !e.repo_url.is_empty(),
        poll_error,
        ctx,
        e,
    };
    Ok(page(&p)?.into_response())
}

pub async fn sim_file(state: &AppState, version_id: i64) -> AppResult<(String, crate::sims::SimIndex)> {
    let (content, index): (String, serde_json::Value) = sqlx::query_as("SELECT content, index FROM sim_files WHERE version_id = $1")
        .bind(version_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok((content, serde_json::from_value(index).unwrap_or_default()))
}

async fn sim_page(state: &AppState, ctx: PageCtx, e: EntryHead, entry: &Entry, versions: Vec<Version>, label: Option<&str>, q: EntryQ) -> AppResult<Response> {
    let current = pick(&versions, label, None, None)?.ok_or(AppError::NotFound)?;
    let (content, index) = sim_file(state, current.id).await?;
    let sim = SimFile::from_toml(&content).map_err(|e| AppError::Internal(anyhow::anyhow!("stored sim unreadable: {e}")))?;
    let tab = q.tab.unwrap_or_else(|| "parfile".into());
    let mut run = Vec::new();
    if let Some(r) = &sim.run {
        if let Some(t) = r.tasks {
            run.push(("Tasks".into(), t.to_string()));
        }
        if let Some(t) = r.cpus_per_task {
            run.push(("CPUs per task".into(), t.to_string()));
        }
        if let Some(t) = r.gpus_per_task {
            run.push(("GPUs per task".into(), t.to_string()));
        }
        if let Some(t) = &r.walltime {
            run.push(("Wall time".into(), t.clone()));
        }
    }
    let mut provenance = Vec::new();
    if let Some(p) = &sim.provenance {
        for (k, val) in [
            ("Machine", p.machine.clone()),
            ("Flavor", p.flavor.clone()),
            ("Optionlist", p.optionlist.clone()),
            ("Universe", p.universe.clone()),
            ("Base", p.base.as_ref().map(|b| b.to_string())),
            ("Exported by", p.exported_by.clone()),
            ("Exported at", p.exported_at.map(|d| d.to_string())),
        ] {
            if let Some(val) = val {
                provenance.push((k.to_owned(), val));
            }
        }
        if !p.flags.is_empty() {
            provenance.push(("Flags".into(), p.flags.join(" ")));
        }
    }
    let inputs = sim
        .inputs
        .iter()
        .map(|i| {
            (
                i.knob.clone(),
                i.description.clone().unwrap_or_default(),
                i.url.as_deref().map(|u| format!("{u}{}", i.sha256.as_deref().map(|s| format!(" · sha256 {s}")).unwrap_or_default())).unwrap_or_default(),
            )
        })
        .collect();
    let kind = match sim.parfile.kind {
        ParfileKind::Par => "",
        ParfileKind::Py => " (Python generator)",
    };
    let p = SimPage {
        tabs: tabs(
            &format!("{}/{}", entry.url(), current.label()),
            &[("parfile", "Parfile"), ("thornlist", "Thornlist"), ("pins", "Pins"), ("inputs", "Inputs"), ("run", "Run hints"), ("versions", "Versions")],
            &tab,
        ),
        tab,
        versions: versions.iter().map(|v| version_row(entry, v, Some(current.id))).collect(),
        thornlist_name: sim.thornlist.filename.clone(),
        thornlist: sim.thornlist.text.clone(),
        parfile_name: format!("{}{kind}", sim.parfile.filename),
        parfile: sim.parfile.text.clone(),
        pins: pin_rows(state, &sim.repos).await?,
        inputs,
        run,
        provenance,
        warnings: index.warnings,
        import_cmd: format!("cactup import {}@{}", entry.slug(), current.label()),
        download_url: format!("{}/{}/download.sim", entry.url(), current.label()),
        authors: sim.sim.authors.join(", "),
        license: sim.sim.license.clone().unwrap_or_default(),
        ctx,
        e,
    };
    Ok(page(&p)?.into_response())
}

/// `.sim` files and frozen stack thornlists.
pub async fn download(
    State(state): State<AppState>,
    v: Visitor,
    Path((owner, name, label, file)): Path<(String, String, String, String)>,
) -> AppResult<Response> {
    let e = model::visible_entry(&state, &owner, &name, v.user()).await?;
    let ver = model::version_by_label(&state, e.id, &label).await?.ok_or(AppError::NotFound)?;
    let (body, filename) = match (e.kind.as_str(), file.as_str()) {
        ("sim", "download.sim") => (sim_file(&state, ver.id).await?.0, format!("{name}-{label}.sim")),
        ("stack", "download.th") => {
            let f = stacks::frozen_of(&state, &ver).await?;
            (f.thornlist.text, format!("{name}-{}.th", label.replace(':', "-")))
        }
        _ => return Err(AppError::NotFound),
    };
    Ok((
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_owned()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename.replace(['"', '\\'], ""))),
        ],
        body,
    )
        .into_response())
}
