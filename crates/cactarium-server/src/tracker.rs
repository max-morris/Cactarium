//! Following repos: registering one, turning its version tags into frozen versions, and noticing
//! tags that move or vanish.
//!
//! A version is frozen the first time its tag is seen: the commit and tree are recorded and never
//! change. A tag that later points elsewhere is not followed: the version is marked `tag-moved`,
//! a tag event alerts the owner and admins, and the frozen commit keeps being served.

use std::collections::BTreeMap;
use std::time::Duration;

use cactup_ecosystem_common::ccl;
use cactup_ecosystem_common::manifest::{Manifest, PACKAGE_FILE, STACK_FILE};
use cactup_ecosystem_common::slug::Slug;
use cactup_ecosystem_common::stack::FrozenStack;
use cactup_ecosystem_common::version::TrackedVersion;
use serde_json::json;

use cactup_ecosystem_common::version::TagPattern;
use crate::audit::audit;
use crate::auth::{User, random_token};
use crate::error::{AppError, AppResult};
use crate::git::{self, GitPolicy, RemoteRef};
use crate::markdown;
use crate::model::{self, Entry, semver_sort_key};
use crate::publish::{self, NewEntry};
use crate::stacks;
use crate::state::AppState;

/// At most this many tags are ingested per sync; the rest follow on later polls.
const MAX_NEW_PER_SYNC: usize = 50;

fn policy(state: &AppState) -> GitPolicy {
    GitPolicy { allow_local: state.cfg.allow_local_repos }
}

/// How a repo's tags become versions: its manifest's `tag-pattern` if it has one, else `vX.Y.Z`
/// and `track/vX.Y.Z`; tags below its `since` are left out. The current rule is kept with the repo
/// (`entry_repos.tag_pattern`, `min_version`) so polling needn't read the manifest first; it is
/// refreshed from the manifest at registration, after each new version, on a curated update and
/// on a hand-over.
#[derive(Default)]
pub struct TagRule {
    pattern: Option<TagPattern>,
    since: Option<semver::Version>,
}

impl TagRule {
    pub fn of_manifest(m: &Manifest) -> TagRule {
        let (pattern, since) = match (&m.package, &m.stack) {
            (Some(p), _) => (p.tag_pattern.as_deref(), p.since.clone()),
            (_, Some(s)) => (s.tag_pattern.as_deref(), s.since.clone()),
            _ => (None, None),
        };
        // The manifest was validated, so the pattern parses.
        TagRule { pattern: pattern.and_then(|p| p.parse().ok()), since }
    }

    fn of(repo: &RepoRow) -> AppResult<TagRule> {
        Ok(TagRule {
            pattern: repo.tag_pattern.as_deref().map(str::parse).transpose().map_err(AppError::bad)?,
            since: repo
                .min_version
                .as_deref()
                .map(semver::Version::parse)
                .transpose()
                .map_err(AppError::bad)?,
        })
    }

    fn stored(&self) -> (Option<String>, Option<String>) {
        (
            self.pattern.as_ref().map(|p| p.as_str().to_owned()),
            self.since.as_ref().map(ToString::to_string),
        )
    }

    fn version(&self, tag: &str) -> Option<TrackedVersion> {
        let tv = match &self.pattern {
            Some(p) => p.version(tag)?,
            None => TrackedVersion::from_tag(tag)?,
        };
        self.since.as_ref().is_none_or(|s| tv.version >= *s).then_some(tv)
    }

    fn describe(&self) -> String {
        match &self.pattern {
            Some(p) => format!("tags matching {}", p.as_str()),
            None => "version tags (vX.Y.Z or track/vX.Y.Z)".to_owned(),
        }
    }
}

/// Keeps the repo's tag rule in step with a manifest.
async fn store_rule(state: &AppState, entry_id: i64, rule: &TagRule) -> AppResult<()> {
    let (pattern, since) = rule.stored();
    sqlx::query("UPDATE entry_repos SET tag_pattern = $2, min_version = $3 WHERE entry_id = $1")
        .bind(entry_id)
        .bind(pattern)
        .bind(since)
        .execute(&state.db)
        .await?;
    Ok(())
}

fn version_tags(refs: Vec<RemoteRef>, rule: &TagRule) -> Vec<(RemoteRef, TrackedVersion)> {
    let mut v: Vec<_> = refs.into_iter().filter_map(|r| rule.version(&r.name).map(|t| (r, t))).collect();
    v.sort_by(|a, b| (&a.1.track, &a.1.version).cmp(&(&b.1.track, &b.1.version)));
    // Two tags naming one version: the first wins.
    v.dedup_by(|b, a| a.1 == b.1);
    v
}

/// What a repo offers, read at its newest version tag.
pub struct Found {
    pub url: String,
    pub tag: String,
    pub manifests: Vec<(&'static str, Manifest)>,
    /// How its tags become versions, from the manifest on its default branch.
    pub rule: TagRule,
}

fn read_manifests(co: &git::Checkout, at: &str) -> AppResult<Vec<(&'static str, Manifest)>> {
    let mut manifests = Vec::new();
    for file in [PACKAGE_FILE, STACK_FILE] {
        if let Some(text) = git::read_in(co, file).map_err(AppError::bad)? {
            let m = Manifest::from_repo_file(file, &text)
                .map_err(|e| AppError::bad(format!("{file} at {at}: {e}")))?;
            manifests.push((file, m));
        }
    }
    Ok(manifests)
}

/// Looks at a repo before registering it: how its tags become versions (the default branch's
/// manifest may give a tag pattern), its newest version tag, and the manifests there.
pub async fn inspect(state: &AppState, url: &str) -> AppResult<Found> {
    let url = git::check_url(policy(state), url).await.map_err(AppError::bad)?;
    let head = git::resolve_ref(policy(state), &url, None).await.map_err(AppError::bad)?;
    let at_head = git::checkout(policy(state), &url, &head, None).await.map_err(AppError::bad)?;
    let rule = read_manifests(&at_head, "the default branch")?
        .first()
        .map(|(_, m)| TagRule::of_manifest(m))
        .unwrap_or_default();
    let refs = git::ls_tags(policy(state), &url).await.map_err(AppError::bad)?;
    let tags = version_tags(refs, &rule);
    // Newest on the default track, else newest of any track.
    let newest = tags
        .iter()
        .filter(|(_, t)| t.track.is_none())
        .max_by(|a, b| a.1.version.cmp(&b.1.version))
        .or_else(|| tags.iter().max_by(|a, b| a.1.version.cmp(&b.1.version)))
        .ok_or_else(|| AppError::bad(format!("the repo has no {} yet", rule.describe())))?;
    let co = git::checkout(policy(state), &url, &newest.0.commit, Some(&newest.0.name))
        .await
        .map_err(AppError::bad)?;
    let manifests = read_manifests(&co, &newest.0.name)?;
    if manifests.is_empty() {
        return Err(AppError::bad(format!(
            "no {PACKAGE_FILE} or {STACK_FILE} at {} (the newest version tag)",
            newest.0.name
        )));
    }
    Ok(Found { url, tag: newest.0.name.clone(), manifests, rule })
}

fn owners_of(m: &Manifest) -> Vec<String> {
    match (&m.package, &m.stack) {
        (Some(p), _) => p.owners.iter().map(|o| o.to_string()).collect(),
        (_, Some(s)) => s.owners.iter().map(|o| o.to_string()).collect(),
        _ => vec![],
    }
}

fn name_of(m: &Manifest) -> String {
    m.package
        .as_ref()
        .map(|p| p.name.to_string())
        .or_else(|| m.stack.as_ref().map(|s| s.name.to_string()))
        .unwrap_or_default()
}

fn summary_of(m: &Manifest) -> Option<String> {
    let d = m
        .package
        .as_ref()
        .and_then(|p| p.description.clone())
        .or_else(|| m.stack.as_ref().and_then(|s| s.description.clone()))?;
    Some(d.lines().next().unwrap_or("").chars().take(200).collect())
}

/// Registers every manifest a repo carries as an entry, then syncs its tags. The entries go under
/// the user's own name, or (admins only) under `namespace`, a name that is no user's, such as
/// `et`. That name must be in each manifest's `owners`: only someone who can push to the repo can
/// put it there.
pub async fn register(
    state: &AppState,
    user: &User,
    url: &str,
    namespace: Option<&str>,
) -> AppResult<Vec<Entry>> {
    let owner = match namespace.map(str::trim).filter(|n| !n.is_empty()) {
        None => user.username.clone(),
        Some(ns) => {
            ns.parse::<cactup_ecosystem_common::name::Owner>().map_err(AppError::bad)?;
            publish::check_namespace(state, user, ns).await?;
            ns.to_owned()
        }
    };
    let found = inspect(state, url).await?;
    let mut entries = Vec::new();
    for (file, m) in &found.manifests {
        if !owners_of(m).contains(&owner) {
            return Err(AppError::bad(format!(
                "{file} at {} does not list '{owner}' in owners; add it there to prove you control the repo",
                found.tag
            )));
        }
    }
    for (file, m) in found.manifests {
        let kind = if file == PACKAGE_FILE { "package" } else { "stack" };
        let entry = publish::create_entry(
            state,
            user,
            NewEntry {
                kind,
                owner: &owner,
                name: &name_of(&m),
                summary: summary_of(&m),
                description: None,
                curated: false,
            },
        )
        .await?;
        attach_repo(state, &entry, &found.url, file, None, &found.rule).await?;
        entries.push(entry);
    }
    // The registrant vouches for the tags that exist now; later tags are reviewed on their own.
    for e in &entries {
        sync_as(state, e, Some(user)).await?;
    }
    Ok(entries)
}

/// Admin-only: a package for a repo nobody on the Cactarium controls, with an overlay manifest
/// kept here instead of in the repo. Its `tag-pattern` and `since` say which upstream tags are
/// versions.
pub async fn register_curated(
    state: &AppState,
    admin: &User,
    owner: &str,
    url: &str,
    overlay: &str,
) -> AppResult<Entry> {
    let m = Manifest::from_repo_file(PACKAGE_FILE, overlay).map_err(AppError::bad)?;
    let url = git::check_url(policy(state), url).await.map_err(AppError::bad)?;
    let entry = publish::create_entry(
        state,
        admin,
        NewEntry {
            kind: "package",
            owner,
            name: &name_of(&m),
            summary: summary_of(&m),
            description: None,
            curated: true,
        },
    )
    .await?;
    attach_repo(state, &entry, &url, PACKAGE_FILE, Some(overlay), &TagRule::of_manifest(&m)).await?;
    // The admin vouches for the tags that exist now; later upstream tags are reviewed unless the
    // entry or its owner is trusted. A failure is kept as the repo's poll error.
    let _ = sync_as(state, &entry, Some(admin)).await;
    Ok(entry)
}

/// Admin-only: replaces a curated package's repo URL and overlay manifest (and so its tag rule),
/// then syncs. Versions already published stay as they are.
pub async fn update_curated(
    state: &AppState,
    admin: &User,
    entry: &Entry,
    url: &str,
    overlay: &str,
) -> AppResult<usize> {
    if !entry.curated {
        return Err(AppError::bad(format!(
            "{} is not curated (it uses its repo's manifest)",
            entry.slug()
        )));
    }
    let m = Manifest::from_repo_file(PACKAGE_FILE, overlay).map_err(AppError::bad)?;
    if name_of(&m) != entry.name {
        return Err(AppError::bad(format!(
            "the manifest names '{}', not '{}'",
            name_of(&m),
            entry.name
        )));
    }
    let (pattern, since) = TagRule::of_manifest(&m).stored();
    let url = git::check_url(policy(state), url).await.map_err(AppError::bad)?;
    if repo_of(state, entry.id).await?.is_some_and(|r| r.url != url) {
        same_history(state, entry, &url).await?;
    }
    sqlx::query("UPDATE entry_repos SET url = $2, overlay_manifest = $3, tag_pattern = $4, min_version = $5 WHERE entry_id = $1")
        .bind(entry.id)
        .bind(&url)
        .bind(overlay)
        .bind(&pattern)
        .bind(&since)
        .execute(&state.db)
        .await?;
    sqlx::query("UPDATE entries SET summary = COALESCE($2, summary) WHERE id = $1")
        .bind(entry.id)
        .bind(summary_of(&m))
        .execute(&state.db)
        .await?;
    audit(
        state,
        Some(admin.id),
        "curated.update",
        Some(&entry.slug()),
        json!({ "url": url, "tag_pattern": pattern, "since": since }),
        None,
    )
    .await?;
    sync_as(state, entry, Some(admin)).await
}

/// Admin-only: a curated package whose repo now carries its own cactarium.toml (on its default
/// branch, naming the entry's owner) stops using the overlay. Its name and versions stay; its tag
/// rule becomes the repo manifest's.
pub async fn hand_over(state: &AppState, admin: &User, entry: &Entry) -> AppResult<()> {
    let repo = repo_of(state, entry.id).await?.ok_or(AppError::NotFound)?;
    if !entry.curated || repo.overlay_manifest.is_none() {
        return Err(AppError::bad(format!("{} already uses its repo's manifest", entry.slug())));
    }
    let head = git::resolve_ref(policy(state), &repo.url, None).await.map_err(AppError::bad)?;
    let co = git::checkout(policy(state), &repo.url, &head, None)
        .await
        .map_err(AppError::bad)?;
    let text = git::read_in(&co, PACKAGE_FILE)
        .map_err(AppError::bad)?
        .ok_or_else(|| AppError::bad(format!("the repo's default branch has no {PACKAGE_FILE} yet")))?;
    let m = Manifest::from_repo_file(PACKAGE_FILE, &text).map_err(AppError::bad)?;
    if name_of(&m) != entry.name {
        return Err(AppError::bad(format!(
            "the repo's {PACKAGE_FILE} names '{}', not '{}'",
            name_of(&m),
            entry.name
        )));
    }
    if !owners_of(&m).contains(&entry.owner) {
        return Err(AppError::bad(format!(
            "the repo's {PACKAGE_FILE} doesn't list '{}' in owners",
            entry.owner
        )));
    }
    sqlx::query("UPDATE entry_repos SET overlay_manifest = NULL WHERE entry_id = $1")
        .bind(entry.id)
        .execute(&state.db)
        .await?;
    // From now on the repo's own manifest says how its tags become versions.
    store_rule(state, entry.id, &TagRule::of_manifest(&m)).await?;
    sqlx::query("UPDATE entries SET curated = FALSE, updated_at = now() WHERE id = $1")
        .bind(entry.id)
        .execute(&state.db)
        .await?;
    audit(state, Some(admin.id), "curated.hand-over", Some(&entry.slug()), json!({ "head": head }), None)
        .await
}

/// Checks that `url` holds the history the entry's published versions froze: every tagged version
/// whose tag is still where it was frozen has that tag at the same commit there, and every version
/// named by commit can be fetched from it. A moved repo (say, transferred to an organization) passes;
/// a different repo doesn't.
async fn same_history(state: &AppState, entry: &Entry, url: &str) -> AppResult<()> {
    let known: Vec<(String, String, Option<String>, Option<String>, bool, String)> = sqlx::query_as(
        "SELECT track, version, tag, commit, is_virtual, state FROM versions WHERE entry_id = $1 AND state <> 'invalid'",
    )
    .bind(entry.id)
    .fetch_all(&state.db)
    .await?;
    let remote: BTreeMap<String, String> = git::ls_tags(policy(state), url)
        .await
        .map_err(AppError::bad)?
        .into_iter()
        .map(|r| (r.name, r.commit))
        .collect();
    let mut problems = Vec::new();
    for (track, version, tag, commit, is_virtual, st) in &known {
        let label = if track.is_empty() { version.clone() } else { format!("{track}:{version}") };
        let Some(commit) = commit else { continue };
        if *is_virtual {
            if git::checkout(policy(state), url, commit, None).await.is_err() {
                problems
                    .push(format!("{label}: commit {} isn't there", &commit[..12.min(commit.len())]));
            }
        } else if let Some(tag) = tag
            && st == "ok"
        {
            match remote.get(tag) {
                Some(c) if c == commit => {}
                Some(_) => problems.push(format!("{label}: tag {tag} names another commit there")),
                None => problems.push(format!("{label}: there is no tag {tag} there")),
            }
        }
    }
    if !problems.is_empty() {
        problems.truncate(8);
        return Err(AppError::bad(format!(
            "{url} doesn't hold {}'s history: {}",
            entry.slug(),
            problems.join("; ")
        )));
    }
    Ok(())
}

/// Admin-only: points a registered entry at its repo's new URL (e.g. after the repo moved to another
/// GitHub owner), once [`same_history`] confirms it is the same repo. Versions keep their frozen
/// commits; stack releases that pinned the old URL keep it (GitHub redirects a moved repo's URL).
pub async fn move_repo(state: &AppState, admin: &User, entry: &Entry, new_url: &str) -> AppResult<()> {
    let repo = repo_of(state, entry.id)
        .await?
        .ok_or_else(|| AppError::bad(format!("{} has no repo", entry.slug())))?;
    let url = git::check_url(policy(state), new_url.trim()).await.map_err(AppError::bad)?;
    if url == repo.url {
        return Err(AppError::bad(format!("{} already uses {url}", entry.slug())));
    }
    same_history(state, entry, &url).await?;
    sqlx::query("UPDATE entry_repos SET url = $2, poll_error = NULL WHERE entry_id = $1")
        .bind(entry.id)
        .bind(&url)
        .execute(&state.db)
        .await?;
    audit(
        state,
        Some(admin.id),
        "repo.move",
        Some(&entry.slug()),
        json!({ "from": repo.url, "to": url }),
        None,
    )
    .await?;
    Ok(())
}

async fn attach_repo(
    state: &AppState,
    entry: &Entry,
    url: &str,
    file: &str,
    overlay: Option<&str>,
    rule: &TagRule,
) -> AppResult<()> {
    let (pattern, since) = rule.stored();
    sqlx::query("INSERT INTO entry_repos (entry_id, url, manifest_file, webhook_secret, overlay_manifest, tag_pattern, min_version) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(entry.id)
        .bind(url)
        .bind(file)
        .bind(random_token())
        .bind(overlay)
        .bind(pattern)
        .bind(since)
        .execute(&state.db)
        .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
pub struct RepoRow {
    pub url: String,
    pub manifest_file: String,
    pub webhook_secret: String,
    pub overlay_manifest: Option<String>,
    pub tag_pattern: Option<String>,
    pub min_version: Option<String>,
}

pub async fn repo_of(state: &AppState, entry_id: i64) -> AppResult<Option<RepoRow>> {
    Ok(sqlx::query_as::<_, RepoRow>(
        "SELECT url, manifest_file, webhook_secret, overlay_manifest, tag_pattern, min_version FROM entry_repos WHERE entry_id = $1",
    )
    .bind(entry_id)
    .fetch_optional(&state.db)
    .await?)
}

#[derive(sqlx::FromRow)]
struct Known {
    id: i64,
    tag: Option<String>,
    commit: Option<String>,
    state: String,
}

/// Brings an entry up to date with its repo's tags. Returns how many versions were added. A new
/// tag is reviewed unless the entry or its owner is trusted (see `publish::release_review`).
pub async fn sync(state: &AppState, entry: &Entry) -> AppResult<usize> {
    sync_as(state, entry, None).await
}

/// `sync`, with the tags found counted as published by `actor` (the user registering the repo).
async fn sync_as(state: &AppState, entry: &Entry, actor: Option<&User>) -> AppResult<usize> {
    let Some(repo) = repo_of(state, entry.id).await? else { return Ok(0) };
    let banned: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1 AND banned)")
            .bind(&entry.owner)
            .fetch_one(&state.db)
            .await?;
    if banned || entry.visibility == "hidden" {
        return Ok(0);
    }
    let result = sync_inner(state, entry, &repo, actor).await;
    let err = result.as_ref().err().map(|e| e.to_string());
    sqlx::query("UPDATE entry_repos SET last_polled_at = now(), poll_error = $2 WHERE entry_id = $1")
        .bind(entry.id)
        .bind(&err)
        .execute(&state.db)
        .await?;
    result
}

async fn sync_inner(
    state: &AppState,
    entry: &Entry,
    repo: &RepoRow,
    actor: Option<&User>,
) -> AppResult<usize> {
    let refs = git::ls_tags(policy(state), &repo.url).await.map_err(AppError::bad)?;
    let remote: BTreeMap<String, String> =
        refs.iter().map(|r| (r.name.clone(), r.commit.clone())).collect();
    let known: Vec<Known> = sqlx::query_as(
        "SELECT id, tag, commit, state FROM versions WHERE entry_id = $1 AND NOT is_virtual",
    )
    .bind(entry.id)
    .fetch_all(&state.db)
    .await?;
    let by_tag: BTreeMap<&str, &Known> =
        known.iter().filter_map(|k| k.tag.as_deref().map(|t| (t, k))).collect();

    for k in &known {
        let (Some(tag), Some(frozen)) = (&k.tag, &k.commit) else { continue };
        match remote.get(tag) {
            Some(now) if now != frozen && k.state != "tag-moved" => {
                mark(state, entry, k.id, "tag-moved", tag, frozen, Some(now)).await?;
            }
            None if k.state != "upstream-missing" && k.state != "invalid" => {
                mark(state, entry, k.id, "upstream-missing", tag, frozen, None).await?;
            }
            Some(now) if now == frozen && k.state == "upstream-missing" => {
                sqlx::query("UPDATE versions SET state = 'ok' WHERE id = $1")
                    .bind(k.id)
                    .execute(&state.db)
                    .await?;
            }
            _ => {}
        }
    }

    let mut added = 0;
    for (r, tv) in version_tags(refs, &TagRule::of(repo)?) {
        if by_tag.contains_key(r.name.as_str()) {
            continue;
        }
        if added == MAX_NEW_PER_SYNC {
            break;
        }
        ingest(state, entry, repo, &r, &tv, actor).await?;
        added += 1;
    }
    if added > 0 {
        publish::touch(state, entry.id).await?;
        // The newest version's manifest says how later tags become versions.
        let newest: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT manifest FROM versions WHERE entry_id = $1 AND manifest IS NOT NULL AND state <> 'invalid'
             ORDER BY (track = '') DESC, sort_key DESC LIMIT 1",
        )
        .bind(entry.id)
        .fetch_optional(&state.db)
        .await?
        .flatten();
        if let Some(m) = newest.and_then(|m| serde_json::from_value::<Manifest>(m).ok()) {
            store_rule(state, entry.id, &TagRule::of_manifest(&m)).await?;
        }
    }
    Ok(added)
}

#[allow(clippy::too_many_arguments)]
async fn mark(
    state: &AppState,
    entry: &Entry,
    version_id: i64,
    new_state: &str,
    tag: &str,
    frozen: &str,
    now: Option<&String>,
) -> AppResult<()> {
    sqlx::query("UPDATE versions SET state = $2 WHERE id = $1")
        .bind(version_id)
        .bind(new_state)
        .execute(&state.db)
        .await?;
    sqlx::query("INSERT INTO tag_events (entry_id, version_id, tag, frozen_commit, new_commit) VALUES ($1, $2, $3, $4, $5)")
        .bind(entry.id)
        .bind(version_id)
        .bind(tag)
        .bind(frozen)
        .bind(now)
        .execute(&state.db)
        .await?;
    audit(
        state,
        None,
        &format!("tag.{new_state}"),
        Some(&entry.slug()),
        json!({ "tag": tag, "frozen": frozen, "now": now }),
        None,
    )
    .await?;
    Ok(())
}

/// Freezes one tag as a version. A tag whose manifest is missing or wrong still becomes a version,
/// marked invalid with the reason, so it is not fetched again on every poll.
async fn ingest(
    state: &AppState,
    entry: &Entry,
    repo: &RepoRow,
    r: &RemoteRef,
    tv: &TrackedVersion,
    actor: Option<&User>,
) -> AppResult<()> {
    let track = tv.track.as_ref().map(|t| t.to_string()).unwrap_or_default();
    let base = |reason: Option<String>, tree: Option<String>| (reason, tree);
    let co = git::checkout(policy(state), &repo.url, &r.commit, Some(&r.name)).await;
    let (invalid, tree, prepared) = match co {
        Err(e) => {
            let (reason, tree) = base(Some(format!("cannot fetch the tagged commit: {e:#}")), None);
            (reason, tree, None)
        }
        Ok(co) => match prepare(state, entry, repo, &co, r, tv).await {
            Ok(p) => (None, Some(co.tree.clone()), Some(p)),
            Err(e) => (Some(e.to_string()), Some(co.tree.clone()), None),
        },
    };
    let manifest_json = prepared.as_ref().map(|p| p.manifest_json.clone());
    let readme = prepared.as_ref().and_then(|p| p.readme_html.clone());
    // An invalid tag is never served, so it needs no review.
    let review = if invalid.is_some() {
        "approved"
    } else {
        publish::release_review(state, entry, actor).await?
    };
    let vid: i64 = sqlx::query_scalar(
        "INSERT INTO versions (entry_id, track, version, sort_key, tag, commit, tree, state, invalid_reason, manifest, readme_html, review)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id",
    )
    .bind(entry.id)
    .bind(&track)
    .bind(tv.version.to_string())
    .bind(semver_sort_key(&tv.version))
    .bind(&r.name)
    .bind(&r.commit)
    .bind(&tree)
    .bind(if invalid.is_some() { "invalid" } else { "ok" })
    .bind(&invalid)
    .bind(&manifest_json)
    .bind(&readme)
    .bind(review)
    .fetch_one(&state.db)
    .await?;
    if let Some(p) = prepared {
        store_prepared(state, entry, vid, &track, p).await?;
    }
    publish::submit_release(state, entry, vid, review, actor).await?;
    audit(
        state,
        None,
        "version.ingest",
        Some(&entry.slug()),
        json!({ "tag": r.name, "commit": r.commit, "invalid": invalid, "review": review }),
        None,
    )
    .await?;
    Ok(())
}

/// A package's default-branch tip, read now: what `owner/pkg@head` (and `@master`) mean for a
/// package. Nothing is stored; the API caches it by commit.
pub struct PackageTip {
    pub commit: String,
    pub tree: String,
    pub thorns: Vec<(String, String, String, ccl::ThornFacts)>,
    /// (kind, target, range, note)
    pub claims: Vec<(String, String, Option<String>, Option<String>)>,
}

/// The commit a package's default branch names now.
pub async fn package_tip_commit(state: &AppState, entry: &Entry) -> AppResult<String> {
    let repo = repo_of(state, entry.id)
        .await?
        .ok_or_else(|| AppError::bad(format!("{} has no repo", entry.slug())))?;
    git::resolve_ref(policy(state), &repo.url, None).await.map_err(AppError::bad)
}

/// Reads a package at `commit` (its default branch's tip) the way a release is read: the manifest
/// (the curated one, for a curated package) and the thorns there.
pub async fn package_tip(state: &AppState, entry: &Entry, commit: &str) -> AppResult<PackageTip> {
    if entry.kind != "package" {
        return Err(AppError::bad(format!("{} is a {}, not a package", entry.slug(), entry.kind)));
    }
    let repo = repo_of(state, entry.id)
        .await?
        .ok_or_else(|| AppError::bad(format!("{} has no repo", entry.slug())))?;
    let co = git::checkout(policy(state), &repo.url, commit, None)
        .await
        .map_err(AppError::bad)?;
    let r = RemoteRef { name: "HEAD".into(), commit: commit.to_owned() };
    let tv = TrackedVersion { track: None, version: semver::Version::new(0, 0, 0) };
    let p = prepare(state, entry, &repo, &co, &r, &tv)
        .await
        .map_err(|e| AppError::bad(format!("{}'s default branch: {e}", entry.slug())))?;
    Ok(PackageTip {
        commit: commit.to_owned(),
        tree: co.tree.clone(),
        thorns: p.thorns,
        claims: p
            .claims
            .into_iter()
            .map(|(k, t, range, note)| (k.to_owned(), format!("{}/{}", t.owner, t.name), range, note))
            .collect(),
    })
}

struct Prepared {
    manifest_json: serde_json::Value,
    readme_html: Option<String>,
    summary: Option<String>,
    thorns: Vec<(String, String, String, ccl::ThornFacts)>,
    claims: Vec<(&'static str, Slug, Option<String>, Option<String>)>,
    frozen: Option<(FrozenStack, String, Option<String>)>,
}

async fn prepare(
    state: &AppState,
    entry: &Entry,
    repo: &RepoRow,
    co: &git::Checkout,
    r: &RemoteRef,
    tv: &TrackedVersion,
) -> AppResult<Prepared> {
    let text = match &repo.overlay_manifest {
        Some(o) => o.clone(),
        None => git::read_in(co, &repo.manifest_file)
            .map_err(AppError::bad)?
            .ok_or_else(|| AppError::bad(format!("no {} at this tag", repo.manifest_file)))?,
    };
    let m = Manifest::from_repo_file(&repo.manifest_file, &text).map_err(AppError::bad)?;
    if name_of(&m) != entry.name {
        return Err(AppError::bad(format!(
            "the manifest names '{}', not '{}'",
            name_of(&m),
            entry.name
        )));
    }
    if !entry.curated && !owners_of(&m).contains(&entry.owner) {
        return Err(AppError::bad(format!("the manifest's owners no longer include '{}'", entry.owner)));
    }
    let mut claims = Vec::new();
    for c in &m.fork_of {
        claims.push(("fork-of", c.target.clone(), None, c.note.clone()));
    }
    for (kind, list) in [
        ("depends-on", &m.depends_on),
        ("works-with", &m.works_with),
        ("incompatible-with", &m.incompatible_with),
    ] {
        for c in list {
            claims.push((
                kind,
                c.target.clone(),
                c.range.as_ref().map(|r| r.to_string()),
                c.note.clone(),
            ));
        }
    }
    let manifest_json = serde_json::to_value(&m).map_err(anyhow::Error::from)?;
    let mut p = Prepared {
        manifest_json,
        readme_html: None,
        summary: summary_of(&m),
        thorns: vec![],
        claims,
        frozen: None,
    };

    if let Some(pkg) = &m.package {
        let readme_path = pkg.readme.clone().unwrap_or_else(|| "README.md".into());
        p.readme_html = git::read_in(co, &readme_path).ok().flatten().map(|t| markdown::render(&t));
        let allow = pkg.thorns.as_ref();
        let root = co.path.clone();
        let scanned = tokio::task::spawn_blocking(move || ccl::scan_tree(&root))
            .await
            .map_err(anyhow::Error::from)?;
        for t in scanned {
            // A repo that is one thorn (the Einstein Toolkit's ExternalLibraries-* repos) names it,
            // and its arrangement, in the manifest.
            let (name, dir) = match (t.name.clone(), allow.map(Vec::as_slice), &pkg.arrangement) {
                (Some(n), _, _) => (n, t.dir.to_string_lossy().into_owned()),
                (None, Some([one]), Some(_)) => (one.clone(), ".".to_owned()),
                (None, _, _) => {
                    return Err(AppError::bad(
                        "the repo root is itself a thorn: name it and its arrangement in the manifest \
                         ([package] arrangement = \"ExternalLibraries\", thorns = [\"HDF5\"])",
                    ));
                }
            };
            if t.name.is_some() && allow.is_some_and(|a| !a.contains(&name)) {
                continue;
            }
            let arrangement = match (&t.arrangement, &pkg.arrangement) {
                (Some(a), _) => a.clone(),
                (None, Some(a)) => a.clone(),
                (None, None) => {
                    return Err(AppError::bad(
                        "thorns sit at the repo root; set [package] arrangement in cactarium.toml",
                    ));
                }
            };
            p.thorns.push((arrangement, name, dir, t.facts));
        }
        if p.thorns.is_empty() {
            return Err(AppError::bad("no thorns found (directories with an interface.ccl)"));
        }
    }
    if let Some(stack) = &m.stack {
        let own = match &stack.thornlist {
            Some(path) => Some(
                git::read_in(co, path)
                    .map_err(AppError::bad)?
                    .ok_or_else(|| AppError::bad(format!("'{path}' does not exist at this tag")))?,
            ),
            None => None,
        };
        let resolution = stacks::resolve(state, &entry.owner, stack, own.as_deref(), None).await?;
        let slug: Slug = format!("{}@{}", entry.slug(), tv).parse().map_err(AppError::bad)?;
        let filename = stack
            .thornlist
            .as_deref()
            .and_then(|p| p.rsplit('/').next())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{}.th", entry.name));
        let frozen = stacks::freeze(slug, &filename, resolution, Some(text.clone()))?;
        let toml = toml::to_string(&frozen).map_err(anyhow::Error::from)?;
        p.frozen = Some((frozen, toml, own));
    }
    let _ = r;
    Ok(p)
}

async fn store_prepared(
    state: &AppState,
    entry: &Entry,
    vid: i64,
    track: &str,
    p: Prepared,
) -> AppResult<()> {
    for (arr, name, dir, facts) in &p.thorns {
        sqlx::query("INSERT INTO thorns (version_id, arrangement, name, dir, implements, facts) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(vid)
            .bind(arr)
            .bind(name)
            .bind(dir)
            .bind(&facts.implements)
            .bind(serde_json::to_value(facts).map_err(anyhow::Error::from)?)
            .execute(&state.db)
            .await?;
    }
    for (kind, target, range, note) in &p.claims {
        sqlx::query("INSERT INTO claims (version_id, kind, target_owner, target_name, range, note) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(vid)
            .bind(kind)
            .bind(target.owner.as_str())
            .bind(target.name.as_str())
            .bind(range)
            .bind(note)
            .execute(&state.db)
            .await?;
    }
    if let Some((frozen, toml, own)) = &p.frozen {
        store_release(state, entry, vid, track, frozen, toml, "tag", frozen.recipe.clone(), own.clone())
            .await?;
    }
    if p.summary.is_some() {
        // Only a published release updates the public summary.
        sqlx::query("UPDATE entries SET summary = $2 WHERE id = $1 AND (SELECT review FROM versions WHERE id = $3) = 'approved'")
            .bind(entry.id)
            .bind(&p.summary)
            .bind(vid)
            .execute(&state.db)
            .await?;
    }
    Ok(())
}

/// Stores a stack release with its diff against the previous published release on the same track.
#[allow(clippy::too_many_arguments)]
pub async fn store_release(
    state: &AppState,
    entry: &Entry,
    vid: i64,
    track: &str,
    frozen: &FrozenStack,
    toml: &str,
    how: &str,
    recipe: Option<String>,
    own_thornlist: Option<String>,
) -> AppResult<()> {
    let prev: Option<String> = sqlx::query_scalar(
        "SELECT s.frozen FROM stack_releases s JOIN versions v ON v.id = s.version_id
         WHERE v.entry_id = $1 AND v.track = $2 AND v.id <> $3 AND v.review = 'approved'
           AND v.sort_key < (SELECT sort_key FROM versions WHERE id = $3)
         ORDER BY v.sort_key DESC LIMIT 1",
    )
    .bind(entry.id)
    .bind(track)
    .bind(vid)
    .fetch_optional(&state.db)
    .await?;
    let prev: Option<FrozenStack> = prev.and_then(|t| toml::from_str(&t).ok());
    let diff = stacks::diff(prev.as_ref(), frozen);
    sqlx::query("INSERT INTO stack_releases (version_id, how, frozen, recipe, own_thornlist, diff) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(vid)
        .bind(how)
        .bind(toml)
        .bind(recipe)
        .bind(own_thornlist)
        .bind(serde_json::to_value(&diff).map_err(anyhow::Error::from)?)
        .execute(&state.db)
        .await?;
    store_built_thorns(state, vid, &frozen.thornlist.text).await?;
    store_pins(state, vid, &frozen.repos).await
}

/// Records the thorns a stack release or a sim builds, so they can be found by thorn.
pub async fn store_built_thorns(state: &AppState, vid: i64, thornlist: &str) -> AppResult<()> {
    let Ok(list) = cactup_ecosystem_common::crl::parse(thornlist) else { return Ok(()) };
    for c in list.components().iter().filter(|c| c.checkout.contains('/') && !c.fetch_only) {
        sqlx::query(
            "INSERT INTO release_thorns (version_id, checkout) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(vid)
        .bind(&c.checkout)
        .execute(&state.db)
        .await?;
    }
    Ok(())
}

/// Fills in the thorn index for releases and sims published before it existed.
pub async fn backfill_built_thorns(state: &AppState) -> AppResult<()> {
    let stacks: Vec<(i64, String)> = sqlx::query_as(
        "SELECT version_id, frozen FROM stack_releases s WHERE NOT EXISTS (SELECT 1 FROM release_thorns r WHERE r.version_id = s.version_id)",
    )
    .fetch_all(&state.db)
    .await?;
    for (vid, frozen) in stacks {
        if let Ok(f) = toml::from_str::<cactup_ecosystem_common::stack::FrozenStack>(&frozen) {
            store_built_thorns(state, vid, &f.thornlist.text).await?;
        }
    }
    let sims: Vec<(i64, String)> = sqlx::query_as(
        "SELECT version_id, content FROM sim_files s WHERE NOT EXISTS (SELECT 1 FROM release_thorns r WHERE r.version_id = s.version_id)",
    )
    .fetch_all(&state.db)
    .await?;
    for (vid, content) in sims {
        if let Ok(sim) = cactup_ecosystem_common::sim::SimFile::from_toml(&content) {
            store_built_thorns(state, vid, &sim.thornlist.text).await?;
        }
    }
    Ok(())
}

pub async fn store_pins(
    state: &AppState,
    vid: i64,
    pins: &[cactup_ecosystem_common::sim::RepoPin],
) -> AppResult<()> {
    for p in pins {
        sqlx::query("INSERT INTO source_pins (version_id, repo, url, url_norm, git_ref, commit) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING")
            .bind(vid)
            .bind(&p.name)
            .bind(&p.url)
            .bind(git::normalize_url(&p.url))
            .bind(&p.git_ref)
            .bind(p.commit.as_ref().or(p.sha256.as_ref()))
            .execute(&state.db)
            .await?;
    }
    Ok(())
}

/// Admin-only: a curated version (a commit that exists upstream, named by the admin).
pub async fn add_virtual_version(
    state: &AppState,
    admin: &User,
    entry: &Entry,
    label: &str,
    commit: &str,
) -> AppResult<()> {
    let tv: TrackedVersion = label.parse().map_err(AppError::bad)?;
    let commit = commit.trim().to_ascii_lowercase();
    if !(commit.len() == 40 || commit.len() == 64) || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::bad("give the full commit id (40 hex digits)"));
    }
    let repo = repo_of(state, entry.id).await?.ok_or(AppError::NotFound)?;
    // The commit must exist upstream: fetching it proves that.
    let co = git::checkout(policy(state), &repo.url, &commit, None)
        .await
        .map_err(|e| AppError::bad(format!("that commit cannot be fetched: {e:#}")))?;
    let r = RemoteRef { name: tv.conventional_tag(), commit: commit.clone() };
    let track = tv.track.as_ref().map(|t| t.to_string()).unwrap_or_default();
    let prepared = prepare(state, entry, &repo, &co, &r, &tv).await?;
    let vid: i64 = sqlx::query_scalar(
        "INSERT INTO versions (entry_id, track, version, sort_key, tag, commit, tree, is_virtual, manifest, readme_html, published_by)
         VALUES ($1, $2, $3, $4, NULL, $5, $6, TRUE, $7, $8, $9) RETURNING id",
    )
    .bind(entry.id)
    .bind(&track)
    .bind(tv.version.to_string())
    .bind(semver_sort_key(&tv.version))
    .bind(&commit)
    .bind(&co.tree)
    .bind(&prepared.manifest_json)
    .bind(&prepared.readme_html)
    .bind(admin.id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => AppError::Conflict(format!("{label} already exists")),
        _ => e.into(),
    })?;
    store_prepared(state, entry, vid, &track, prepared).await?;
    audit(
        state,
        Some(admin.id),
        "version.virtual",
        Some(&entry.slug()),
        json!({ "version": label, "commit": commit }),
        None,
    )
    .await?;
    Ok(())
}

/// Polls every tracked repo whose last poll is older than the configured interval.
pub async fn poll_forever(state: AppState) {
    loop {
        if let Err(e) = poll_once(&state).await {
            tracing::warn!("poll failed: {e}");
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

async fn poll_once(state: &AppState) -> AppResult<()> {
    let due: Vec<i64> = sqlx::query_scalar(
        "SELECT entry_id FROM entry_repos WHERE last_polled_at IS NULL OR last_polled_at < now() - make_interval(secs => $1) ORDER BY last_polled_at NULLS FIRST LIMIT 20",
    )
    .bind(state.cfg.poll_interval as f64)
    .fetch_all(&state.db)
    .await?;
    for id in due {
        let entry = model::entry_by_id(state, id).await?;
        if let Err(e) = sync(state, &entry).await {
            tracing::info!("sync of {} failed: {e}", entry.slug());
        }
    }
    Ok(())
}
