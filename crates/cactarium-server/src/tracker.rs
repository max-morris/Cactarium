//! Following repos: registering one, turning its version tags into frozen versions, and noticing
//! tags that move or vanish.
//!
//! A version is frozen the first time its tag is seen: the commit and tree are recorded and never
//! change. A tag that later points elsewhere is not followed: the version is marked `tag-moved`,
//! a tag event alerts the owner and admins, and the frozen commit keeps being served.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use cactup_ecosystem_common::ccl;
use cactup_ecosystem_common::manifest::{Manifest, PACKAGE_FILE, SIM_FILE, STACK_FILE, SimForm};
use cactup_ecosystem_common::slug::Slug;
use cactup_ecosystem_common::stack::FrozenStack;
use cactup_ecosystem_common::version::TrackedVersion;
use serde_json::json;

use cactup_ecosystem_common::version::TagPattern;
use crate::claims::ClaimRec;
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
/// At most this many waiting tags (left unread earlier) are tried again per sync, after the new ones.
const MAX_WAITING_PER_SYNC: usize = 10;

/// Whether a sync honors waiting tags' backoff. The poller does; a sync someone asked for (the
/// button, the API, the command line, a registration) tries the waiting tags now, still at most
/// [`MAX_WAITING_PER_SYNC`] of them.
#[derive(Clone, Copy, PartialEq)]
pub enum Pace {
    Now,
    Background,
}

fn policy(state: &AppState) -> GitPolicy {
    GitPolicy { allow_local: state.cfg.allow_local_repos }
}

/// How a repo's tags become versions: its manifest's `tag-pattern` if it has one, else `vX.Y.Z`
/// and `track/vX.Y.Z`; tags below its `since` are left out. Each entry keeps its own rule, read
/// from its own manifest (`entry_repos.tag_pattern`, `min_version`), so polling needn't read the
/// manifest first. The rule picks candidate tags; a candidate is the entry's only when the manifest
/// inside it reads it as the same version under its own rule (see [`foreign_reason`]). The pattern
/// is set at registration, by "re-read tag rule", by a curated update and by a hand-over, never by
/// a tag: a new version's manifest may update `since`, but switching to another tag form is an
/// explicit act, so a manifest that drops or changes `tag-pattern` can't move the entry onto
/// another kind's tags.
#[derive(Clone, Default)]
pub struct TagRule {
    pattern: Option<TagPattern>,
    since: Option<semver::Version>,
}

impl TagRule {
    pub fn of_manifest(m: &Manifest) -> TagRule {
        let (pattern, since) = match (&m.package, &m.stack, &m.sim) {
            (Some(p), _, _) => (p.tag_pattern.as_deref(), p.since.clone()),
            (_, Some(s), _) => (s.tag_pattern.as_deref(), s.since.clone()),
            (_, _, Some(s)) => (s.tag_pattern.as_deref(), s.since.clone()),
            _ => (None, None),
        };
        // The manifest was validated, so the pattern parses.
        TagRule { pattern: pattern.and_then(|p| p.parse().ok()), since }
    }

    /// The rule an entry keeps with its repo.
    pub fn of_repo(repo: &RepoRow) -> AppResult<TagRule> {
        Self::of(repo)
    }

    pub fn since(&self) -> Option<&semver::Version> {
        self.since.as_ref()
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

    pub fn stored(&self) -> (Option<String>, Option<String>) {
        (
            self.pattern.as_ref().map(|p| p.as_str().to_owned()),
            self.since.as_ref().map(ToString::to_string),
        )
    }

    pub fn version(&self, tag: &str) -> Option<TrackedVersion> {
        let tv = match &self.pattern {
            Some(p) => p.version(tag)?,
            None => TrackedVersion::from_tag(tag)?,
        };
        self.since.as_ref().is_none_or(|s| tv.version >= *s).then_some(tv)
    }

    pub fn describe(&self) -> String {
        match &self.pattern {
            Some(p) => format!("tags matching {}", p.as_str()),
            None => "version tags (vX.Y.Z or track/vX.Y.Z)".to_owned(),
        }
    }

    /// The pattern as it acts among siblings: one that reads exactly the standard non-track form
    /// (`v{major}.{minor}.{patch}`) counts as no pattern, so it shares the standard tags with the
    /// kinds that declare none instead of claiming them.
    fn distinct_pattern(&self) -> Option<&TagPattern> {
        self.pattern.as_ref().filter(|p| p.as_str() != STANDARD_PATTERN)
    }

    fn same_pattern(&self, other: &TagRule) -> bool {
        self.distinct_pattern().map(TagPattern::as_str) == other.distinct_pattern().map(TagPattern::as_str)
    }
}

/// The standard non-track tag form, written as a pattern: declaring it is the same as declaring none.
const STANDARD_PATTERN: &str = "v{major}.{minor}.{patch}";

/// A tag's form, for telling tag schemes apart: its digits replaced, `sim-v#.#.#` for `sim-v1.2.0`.
fn tag_form(tag: &str) -> String {
    let mut out = String::new();
    for c in tag.chars() {
        if c.is_ascii_digit() {
            if !out.ends_with('#') {
                out.push('#');
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Locks an entry's rows for the rest of `tx` and returns whether it is still curated with an
/// overlay, at the URL the caller checked. Curated updates and hand-overs read the entry, then do
/// slow git work, then write: this is the re-check under the lock, so the two can't interleave
/// into an entry that is neither (not curated, yet still read through an overlay).
async fn still_curated_at(
    tx: &mut sqlx::PgConnection,
    entry_id: i64,
    url: &str,
) -> AppResult<bool> {
    let row: Option<(bool, bool, String)> = sqlx::query_as(
        "SELECT e.curated, r.overlay_manifest IS NOT NULL, r.url FROM entries e JOIN entry_repos r ON r.entry_id = e.id
         WHERE e.id = $1 FOR UPDATE",
    )
    .bind(entry_id)
    .fetch_optional(&mut *tx)
    .await?;
    Ok(row.is_some_and(|(curated, overlay, now)| curated && overlay && now == url))
}

const CURATED_CHANGED: &str = "the entry changed while this ran (another curated update, a hand-over or a move); reload and try again";

/// A manifest or `.sim` read at a version tag that this server can't read: invalid, unless the file
/// is only from a newer format generation than this server knows. That is not a fact about the
/// commit (an upgraded server reads it), so it is [`AppError::Upstream`]: the tag is left unread and
/// tried again at the next sync instead of being frozen as an invalid version.
pub fn unreadable_at_tag(e: cactup_ecosystem_common::Error) -> AppError {
    match e {
        cactup_ecosystem_common::Error::NewerFormat { .. } => {
            AppError::Upstream(format!("{e} (this server reads it once it is upgraded)"))
        }
        other => AppError::bad(other),
    }
}

/// Keeps the repo's tag rule in step with a manifest.
/// Moves an entry's `since` to what a new version's manifest says, only while its tag pattern is
/// still `pattern` (the one the sync read): a re-read of the rule in between wins. Never the
/// pattern itself, which only a re-read, a curated update or a hand-over sets.
async fn store_since(state: &AppState, entry_id: i64, since: Option<String>, pattern: Option<&str>) -> AppResult<()> {
    sqlx::query(
        "UPDATE entry_repos SET min_version = $2 WHERE entry_id = $1 AND tag_pattern IS NOT DISTINCT FROM $3 AND overlay_manifest IS NULL",
    )
    .bind(entry_id)
    .bind(since)
    .bind(pattern)
    .execute(&state.db)
    .await?;
    Ok(())
}

fn version_tags(refs: Vec<RemoteRef>, rule: &TagRule) -> Vec<(RemoteRef, TrackedVersion)> {
    let mut v: Vec<_> = refs.into_iter().filter_map(|r| rule.version(&r.name).map(|t| (r, t))).collect();
    // Two tags naming one version: the one written the rule's own way wins (see `spelling_rank`),
    // then the first by name.
    v.sort_by(|a, b| {
        (&a.1.track, &a.1.version, spelling_rank(rule, &a.0.name, &a.1), &a.0.name)
            .cmp(&(&b.1.track, &b.1.version, spelling_rank(rule, &b.0.name, &b.1), &b.0.name))
    });
    v.dedup_by(|b, a| a.1 == b.1);
    v
}

/// How a tag spells its version, best first: with a declared pattern, every tag it reads is its
/// own spelling; with none, the standard `[track/]vX.Y.Z` beats a bare `X.Y.Z` (say, an old
/// upstream tag that predates the repo's manifest), so that one never takes the release's version.
fn spelling_rank(rule: &TagRule, tag: &str, tv: &TrackedVersion) -> u8 {
    if rule.pattern.is_some() || tag == tv.conventional_tag() { 0 } else { 1 }
}

/// Whether an entry has tags in `req` that aren't read yet: waiting ones, or ones its rule picks
/// with neither a version nor a "not this entry's" record. When its repo can't be listed, that can't
/// be told, and the answer is yes (wait rather than freeze).
pub async fn unread_in_range(state: &AppState, entry_id: i64, req: &cactup_ecosystem_common::version::TrackedReq) -> AppResult<bool> {
    let Some(repo) = repo_of(state, entry_id).await? else { return Ok(false) };
    let rule = TagRule::of(&repo)?;
    let in_range = |tag: &str| rule.version(tag).is_some_and(|v| req.matches(&v));
    let waiting: Vec<String> = sqlx::query_scalar("SELECT tag FROM waiting_tags WHERE entry_id = $1")
        .bind(entry_id)
        .fetch_all(&state.db)
        .await?;
    if waiting.iter().any(|t| in_range(t)) {
        return Ok(true);
    }
    let Ok(refs) = git::ls_tags(policy(state), &repo.url).await else { return Ok(true) };
    let have: std::collections::BTreeSet<String> = sqlx::query_scalar(
        "SELECT CASE WHEN track = '' THEN version ELSE track || ':' || version END FROM versions WHERE entry_id = $1",
    )
    .bind(entry_id)
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .collect();
    let has_foreign: bool = sqlx::query_scalar("SELECT to_regclass('foreign_tags') IS NOT NULL").fetch_one(&state.db).await?;
    let foreign: std::collections::BTreeSet<String> = if has_foreign {
        sqlx::query_scalar("SELECT tag FROM foreign_tags WHERE entry_id = $1").bind(entry_id).fetch_all(&state.db).await?.into_iter().collect()
    } else {
        Default::default()
    };
    Ok(version_tags(refs, &rule)
        .iter()
        .any(|(r, tv)| req.matches(tv) && !have.contains(&tv.to_string()) && !foreign.contains(&r.name)))
}

fn read_manifests(co: &git::Checkout, at: &str) -> AppResult<Vec<(&'static str, Manifest)>> {
    let mut manifests = Vec::new();
    for file in [PACKAGE_FILE, STACK_FILE, SIM_FILE] {
        if let Some(text) = git::read_in(co, file).map_err(AppError::bad)? {
            let m = Manifest::from_repo_file(file, &text)
                .map_err(|e| AppError::bad(format!("{file} at {at}: {e}")))?;
            manifests.push((file, m));
        }
    }
    Ok(manifests)
}

fn owners_of(m: &Manifest) -> Vec<String> {
    match (&m.package, &m.stack, &m.sim) {
        (Some(p), _, _) => p.owners.iter().map(|o| o.to_string()).collect(),
        (_, Some(s), _) => s.owners.iter().map(|o| o.to_string()).collect(),
        (_, _, Some(s)) => s.owners.iter().map(|o| o.to_string()).collect(),
        _ => vec![],
    }
}

fn name_of(m: &Manifest) -> String {
    m.package
        .as_ref()
        .map(|p| p.name.to_string())
        .or_else(|| m.stack.as_ref().map(|s| s.name.to_string()))
        .or_else(|| m.sim.as_ref().map(|s| s.name.to_string()))
        .unwrap_or_default()
}

fn summary_of(m: &Manifest) -> Option<String> {
    let d = m
        .package
        .as_ref()
        .and_then(|p| p.description.clone())
        .or_else(|| m.stack.as_ref().and_then(|s| s.description.clone()))
        .or_else(|| m.sim.as_ref().and_then(|s| s.description.clone()))?;
    Some(d.lines().next().unwrap_or("").chars().take(200).collect())
}

/// The manifest files a repo may carry, in the order entries are made from them.
const MANIFEST_FILES: [&str; 3] = [PACKAGE_FILE, STACK_FILE, SIM_FILE];

fn kind_of(file: &str) -> &'static str {
    match file {
        PACKAGE_FILE => "package",
        STACK_FILE => "stack",
        _ => "sim",
    }
}

/// The newest of `tags` on the default track, else the newest of any track.
fn newest(tags: &[(RemoteRef, TrackedVersion)]) -> Option<&(RemoteRef, TrackedVersion)> {
    tags.iter()
        .filter(|(_, t)| t.track.is_none())
        .max_by(|a, b| a.1.version.cmp(&b.1.version))
        .or_else(|| tags.iter().max_by(|a, b| a.1.version.cmp(&b.1.version)))
}

/// Every entry whose repo is `url`, compared normalized (`https://github.com/x/y.git` and
/// `https://github.com/x/y` are one repo): the entries on one repo are each other's siblings.
pub async fn entries_on(state: &AppState, url: &str) -> AppResult<Vec<(Entry, String)>> {
    let norm = git::normalize_url(url);
    let rows: Vec<(i64, String, String)> =
        sqlx::query_as("SELECT entry_id, url, manifest_file FROM entry_repos ORDER BY entry_id").fetch_all(&state.db).await?;
    let mut out = Vec::new();
    for (id, u, file) in rows {
        if git::normalize_url(&u) == norm {
            out.push((model::entry_by_id(state, id).await?, file));
        }
    }
    Ok(out)
}

/// The other entries on the same repo as `entry_id`.
async fn siblings(state: &AppState, entry_id: i64, url: &str) -> AppResult<Vec<Entry>> {
    Ok(entries_on(state, url).await?.into_iter().map(|(e, _)| e).filter(|e| e.id != entry_id).collect())
}

/// One entry a registration would make: a manifest file, its manifest as it is at the tag the
/// entry is registered from, the rule that manifest gives, and that tag, checked out.
pub struct Planned {
    pub file: &'static str,
    pub kind: &'static str,
    pub name: String,
    pub manifest: Manifest,
    pub rule: TagRule,
    pub tag: RemoteRef,
    pub tv: TrackedVersion,
    co: Arc<git::Checkout>,
}

/// What registering a repo would do: the entries already on it, and the ones it would add.
pub struct Plan {
    pub url: String,
    pub owner: String,
    pub existing: Vec<(Entry, String)>,
    pub new: Vec<Planned>,
    /// What the plan leaves out and why (a manifest at the tag named that doesn't read it).
    pub notes: Vec<String>,
}

/// Where a registration reads its manifests: the newest tag of each entry's own rule, or one named
/// tag. A dry run can also name a tag that doesn't exist yet, with the commit it would name.
pub enum At<'a> {
    Newest,
    Tag(&'a str),
    Commit { tag: &'a str, commit: &'a str },
}

/// Works out what registering `url` under `owner` would add, without writing anything. Each
/// manifest's own rule finds its own newest tag (leaving out tags another kind's own tag-pattern
/// reads), and the manifest there must read that tag as that version (self-consistency). With a
/// tag named, only the manifests there that read it as one of their versions are planned, at it;
/// the others are left out, with a note (register again without the tag to add them). Entries already on the repo stay as they are; they
/// must be `owner`'s. Without an owner (a dry run), the repo's existing owner is assumed, else
/// the first owner the first new manifest lists.
pub async fn plan(state: &AppState, owner: Option<&str>, url: &str, at: At<'_>) -> AppResult<Plan> {
    let url = git::check_url(policy(state), url).await.map_err(AppError::bad)?;
    let existing = entries_on(state, &url).await?;
    if let Some(owner) = owner
        && let Some((e, _)) = existing.iter().find(|(e, _)| e.owner != owner)
    {
        return Err(AppError::bad(format!(
            "{url} is already registered, as {} under '{}'; only that owner can add its other manifests",
            e.slug(),
            e.owner
        )));
    }
    let have: Vec<&str> = existing.iter().map(|(_, f)| f.as_str()).collect();
    let refs = git::ls_tags(policy(state), &url).await.map_err(AppError::bad)?;
    let mut new = Vec::new();
    let mut notes = Vec::new();
    // The rules of the entries already on the repo: a tag another kind's own pattern reads isn't a
    // candidate for a kind without that pattern.
    let mut sibling_rules = Vec::new();
    for (e, _) in &existing {
        if let Some(r) = repo_of(state, e.id).await? {
            sibling_rules.push(TagRule::of(&r)?);
        }
    }
    // The tag to read, and a ref to fetch it by when a host won't serve a bare commit.
    let named = match &at {
        At::Newest => None,
        At::Tag(tag) => {
            let r = refs
                .iter()
                .find(|r| r.name == *tag)
                .cloned()
                .ok_or_else(|| AppError::bad(format!("{url} has no tag '{tag}'")))?;
            let via = r.name.clone();
            Some((r, via))
        }
        At::Commit { tag, commit } => match refs.iter().find(|r| r.name == *tag) {
            Some(r) => Some((r.clone(), r.name.clone())),
            None => {
                let full = git::resolve_ref(policy(state), &url, Some(commit))
                    .await
                    .or_else(|_| if commit.len() >= 40 { Ok(commit.to_string()) } else { Err(()) })
                    .map_err(|_| AppError::bad(format!("'{commit}' is no branch, tag or full commit id of {url}")))?;
                Some((RemoteRef { name: tag.to_string(), commit: full }, commit.to_string()))
            }
        },
    };
    // Each manifest to register, with its own rule (and its manifest at the named tag, if one).
    // With a tag named, the manifests at that tag; else those on the default branch, or with none
    // there, whatever the newest vX.Y.Z tag carries.
    let mut candidates: Vec<(&'static str, TagRule, Option<Manifest>)> = Vec::new();
    let mut named_co = None;
    let mut fallback = false;
    match &named {
        Some((r, via)) => {
            let co = Arc::new(git::checkout(policy(state), &url, &r.commit, Some(via)).await.map_err(AppError::bad)?);
            let found = read_manifests(&co, &r.name)?;
            if found.is_empty() {
                return Err(AppError::bad(format!("no {PACKAGE_FILE}, {STACK_FILE} or {SIM_FILE} at {}", r.name)));
            }
            for (file, m) in found {
                if !have.contains(&file) {
                    candidates.push((file, TagRule::of_manifest(&m), Some(m)));
                }
            }
            named_co = Some(co);
        }
        None => {
            let head = git::resolve_ref(policy(state), &url, None).await.map_err(AppError::bad)?;
            let at_head = git::checkout(policy(state), &url, &head, None).await.map_err(AppError::bad)?;
            let on_head = read_manifests(&at_head, "the default branch")?;
            fallback = on_head.is_empty();
            if fallback {
                candidates.extend(MANIFEST_FILES.iter().filter(|f| !have.contains(*f)).map(|f| (*f, TagRule::default(), None)));
            } else {
                candidates.extend(
                    on_head.iter().filter(|(f, _)| !have.contains(f)).map(|(f, m)| (*f, TagRule::of_manifest(m), None)),
                );
            }
        }
    }
    let all_rules: Vec<TagRule> = candidates.iter().map(|(_, r, _)| r.clone()).collect();
    for (i, (file, rule, at_named)) in candidates.into_iter().enumerate() {
        let others: Vec<&TagRule> =
            sibling_rules.iter().chain(all_rules.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, r)| r)).collect();
        let claimed = |tag: &str| others.iter().find_map(|o| claimed_by(tag, &rule, o));
        // At the named tag, when the manifest there reads it as one of its own versions.
        if let (Some(m), Some((r, _)), Some(co)) = (at_named.as_ref(), &named, &named_co) {
            match (rule.version(&r.name), claimed(&r.name)) {
                (Some(tv), None) => {
                    new.push(Planned { file, kind: kind_of(file), name: name_of(m), manifest: m.clone(), rule, tag: r.clone(), tv, co: co.clone() });
                    continue;
                }
                (_, why) => {
                    notes.push(format!(
                        "{file} at {} follows {}{}, so {} isn't one of its versions: it isn't registered now; register again without --tag to add it",
                        r.name,
                        rule.describe(),
                        why.map(|w| format!(" ({w})")).unwrap_or_default(),
                        r.name
                    ));
                    continue;
                }
            }
        }
        // Leaving out what others' patterns claim before tags naming one version are deduplicated, so
        // a claimed bare 1.0.0 can't hide this kind's own v1.0.0.
        let tags: Vec<(RemoteRef, TrackedVersion)> =
            version_tags(refs.iter().filter(|r| claimed(&r.name).is_none()).cloned().collect(), &rule);
        let Some((r, tv)) = newest(&tags) else {
            if fallback {
                continue;
            }
            return Err(AppError::bad(format!("{file} follows {}, and the repo has none of its tags yet", rule.describe())));
        };
        let co = Arc::new(git::checkout(policy(state), &url, &r.commit, Some(&r.name)).await.map_err(AppError::bad)?);
        let Some(text) = git::read_in(&co, file).map_err(AppError::bad)? else {
            if fallback {
                continue;
            }
            return Err(AppError::bad(format!(
                "{file} isn't at {}, its newest version tag; register with --tag naming a tag that has it",
                r.name
            )));
        };
        let m = Manifest::from_repo_file(file, &text).map_err(|e| AppError::bad(format!("{file} at {}: {e}", r.name)))?;
        let own = TagRule::of_manifest(&m);
        if own.version(&r.name).as_ref() != Some(tv) {
            return Err(AppError::bad(format!(
                "{file} at {} follows {}, not {}; register with --tag naming one of its own tags",
                r.name,
                own.describe(),
                rule.describe()
            )));
        }
        new.push(Planned { file, kind: kind_of(file), name: name_of(&m), manifest: m, rule: own, tag: r.clone(), tv: tv.clone(), co });
    }
    if named.is_none() && fallback && new.is_empty() && existing.is_empty() {
        return Err(match newest(&version_tags(refs, &TagRule::default())) {
            None => AppError::bad(format!("the repo has no {} yet", TagRule::default().describe())),
            Some((r, _)) => AppError::bad(format!(
                "no {PACKAGE_FILE}, {STACK_FILE} or {SIM_FILE} at {} (the newest version tag)",
                r.name
            )),
        });
    }
    if new.is_empty() && !notes.is_empty() {
        return Err(AppError::bad(format!("nothing to register at that tag: {}", notes.join("; "))));
    }
    if new.is_empty() {
        let list: Vec<String> = existing.iter().map(|(e, f)| format!("{} ({f})", e.slug())).collect();
        return Err(AppError::bad(format!("{url} already has every entry its manifests give: {}; nothing to add", list.join(", "))));
    }
    let owner = match owner {
        Some(o) => o.to_owned(),
        None => existing
            .first()
            .map(|(e, _)| e.owner.clone())
            .or_else(|| owners_of(&new[0].manifest).into_iter().next())
            .unwrap_or_default(),
    };
    for (i, p) in new.iter().enumerate() {
        if !owners_of(&p.manifest).contains(&owner) {
            return Err(AppError::bad(format!(
                "{} at {} does not list '{owner}' in owners; add it there to prove you control the repo",
                p.file, p.tag.name
            )));
        }
        // Every entry needs its own name: two manifests naming one would collide.
        if let Some(q) = new[..i].iter().find(|q| q.name == p.name) {
            return Err(AppError::bad(format!(
                "{} and {} both name '{}': each manifest becomes its own entry, so give them different names",
                q.file, p.file, p.name
            )));
        }
        if let Some(e) = model::find_entry(state, &owner, &p.name).await? {
            return Err(AppError::bad(format!("{} already exists (a {}), so {} can't be registered under that name", e.slug(), e.kind, p.file)));
        }
    }
    Ok(Plan { url, owner, existing, new, notes })
}

impl Plan {
    /// The entry a planned one would be, before it exists.
    fn provisional(&self, p: &Planned) -> (Entry, RepoRow) {
        let now = time::OffsetDateTime::now_utc();
        let (tag_pattern, min_version) = p.rule.stored();
        (
            Entry {
                id: 0,
                kind: p.kind.to_owned(),
                owner: self.owner.clone(),
                name: p.name.clone(),
                summary: None,
                description: None,
                visibility: "pending".to_owned(),
                verified: false,
                trusted: false,
                curated: false,
                created_by: None,
                created_at: now,
                updated_at: now,
            },
            RepoRow {
                url: self.url.clone(),
                manifest_file: p.file.to_owned(),
                webhook_secret: String::new(),
                overlay_manifest: None,
                tag_pattern,
                min_version,
                sim_form: sim_form_of(&p.manifest),
            },
        )
    }

    /// Reads each planned entry at its tag exactly as its first sync will, without storing anything.
    /// A sim pin that can't be checked yet (its package registered here, or not public yet) is
    /// returned as a note: the tag will wait for it rather than freeze. Any other failure is
    /// returned, naming the entry and tag.
    async fn prepare_all(&self, state: &AppState) -> AppResult<Vec<(String, Prepared)>> {
        let registering: Vec<String> =
            if self.new.iter().any(|p| p.kind == "package") { vec![git::normalize_url(&self.url)] } else { vec![] };
        let opts = PrepOpts { defer_pins: true, registering };
        let mut out = Vec::new();
        for p in &self.new {
            let (entry, repo) = self.provisional(p);
            let label = format!("{}@{}", entry.slug(), p.tv);
            let prepared = prepare(state, &entry, &repo, &p.co, &p.tag, &p.tv, &opts)
                .await
                .map_err(|e| AppError::bad(format!("{label} (tag {}): {e}", p.tag.name)))?;
            out.push((label, prepared));
        }
        Ok(out)
    }
}

/// What a registration made, and what its first versions wait for.
pub struct Registered {
    pub entries: Vec<Entry>,
    pub notes: Vec<String>,
}

/// Registers the manifests a repo carries as entries, then syncs their tags. The entries go under
/// the user's own name, or (admins only) under `namespace`, a name that is no user's, such as
/// `et`. That name must be in each manifest's `owners`: only someone who can push to the repo can
/// put it there. A repo that already has entries gets only the missing ones. Each new entry is
/// read at its newest tag (or `tag`) first, as its first sync will read it; if one fails, nothing
/// is written. The entries are created, attached and audited in one transaction.
pub async fn register(
    state: &AppState,
    user: &User,
    url: &str,
    namespace: Option<&str>,
    tag: Option<&str>,
) -> AppResult<Registered> {
    let owner = match namespace.map(str::trim).filter(|n| !n.is_empty()) {
        None => user.username.clone(),
        Some(ns) => {
            ns.parse::<cactup_ecosystem_common::name::Owner>().map_err(AppError::bad)?;
            publish::check_namespace(state, user, ns).await?;
            ns.to_owned()
        }
    };
    let at = match tag.map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => At::Tag(t),
        None => At::Newest,
    };
    let plan = plan(state, Some(&owner), url, at).await?;
    let mut notes = plan.notes.clone();
    for (label, p) in plan.prepare_all(state).await? {
        notes.extend(p.deferred.iter().map(|d| format!("{label} waits: {d}")));
    }
    let mut tx = state.db.begin().await?;
    let mut entries = Vec::new();
    for p in &plan.new {
        let entry = publish::create_entry_in(
            &mut tx,
            state,
            user,
            NewEntry {
                kind: p.kind,
                owner: &owner,
                name: &p.name,
                summary: summary_of(&p.manifest),
                description: None,
                curated: false,
            },
        )
        .await?;
        attach_repo(&mut tx, &entry, &plan.url, p.file, None, &p.rule, sim_form_of(&p.manifest).as_deref()).await?;
        entries.push(entry);
    }
    crate::audit::audit_with(
        &mut tx,
        Some(user.id),
        "repo.register",
        Some(&plan.url),
        json!({
            "entries": entries.iter().map(Entry::slug).collect::<Vec<_>>(),
            "from": plan.new.iter().map(|p| json!({ "file": p.file, "tag": p.tag.name })).collect::<Vec<_>>(),
            "beside": plan.existing.iter().map(|(e, _)| e.slug()).collect::<Vec<_>>(),
        }),
        None,
    )
    .await?;
    tx.commit().await?;
    // The registrant vouches for the tags that exist now; later tags are reviewed on their own.
    // The entries exist now, whatever the first sync says: a problem there is reported, kept as the
    // repo's poll error, and the poller tries again.
    for e in &entries {
        if let Err(err) = sync_as(state, e, Some(user), Pace::Now).await {
            notes.push(format!("{}: its first check of tags: {err}", e.slug()));
        }
    }
    Ok(Registered { entries, notes })
}

/// A dry run of registering `url` at `tag`: what each new entry would be and how its version
/// would read, and for each entry already on the repo, whether the tag is one of its versions and
/// how it would read. Nothing is written. With `commit`, a tag that doesn't exist yet is read as if
/// it named that commit (a branch or a full commit id), so a release can be checked before it is
/// tagged. Returns the report's lines and whether everything would be read cleanly.
pub async fn check(
    state: &AppState,
    url: &str,
    tag: &str,
    commit: Option<&str>,
    owner: Option<&str>,
) -> AppResult<(Vec<String>, bool)> {
    let at = match commit {
        Some(c) => At::Commit { tag, commit: c },
        None => At::Tag(tag),
    };
    let checked_url = git::check_url(policy(state), url).await.map_err(AppError::bad)?;
    let existing = entries_on(state, &checked_url).await?;
    let mut lines = Vec::new();
    let mut clean = true;
    match plan(state, owner, url, at).await {
        Ok(p) => {
            lines.extend(p.notes.iter().cloned());
            for planned in &p.new {
                lines.push(format!(
                    "new {} {}/{} from {} at {}: version {} (its rule: {})",
                    planned.kind,
                    p.owner,
                    planned.name,
                    planned.file,
                    planned.tag.name,
                    planned.tv,
                    planned.rule.describe()
                ));
            }
            match p.prepare_all(state).await {
                Ok(read) => {
                    for (label, prepared) in read {
                        if prepared.deferred.is_empty() {
                            lines.push(format!("  {label}: reads cleanly{}", sims_note(&prepared)));
                        } else {
                            lines.push(format!("  {label}: would wait (left unread, tried again): {}", prepared.deferred.join("; ")));
                        }
                    }
                }
                Err(e) => {
                    clean = false;
                    lines.push(format!("  would fail, so registering writes nothing: {e}"));
                }
            }
        }
        Err(AppError::BadRequest(m)) if m.contains("nothing to add") => lines.push("nothing new to register".into()),
        Err(e) => {
            clean = false;
            lines.push(format!("registering would fail: {e}"));
        }
    }
    // What the entries already on the repo would make of the tag.
    let refs = git::ls_tags(policy(state), &checked_url).await.map_err(AppError::bad)?;
    let remote_has_tag = refs.iter().any(|r| r.name == tag);
    let r = match refs.into_iter().find(|r| r.name == tag) {
        Some(r) => Some(r),
        None => match commit {
            Some(c) => git::resolve_ref(policy(state), &checked_url, Some(c))
                .await
                .ok()
                .or_else(|| (c.len() >= 40).then(|| c.to_owned()))
                .map(|commit| RemoteRef { name: tag.to_owned(), commit }),
            None => None,
        },
    };
    for (e, _) in &existing {
        let Some(repo) = repo_of(state, e.id).await? else { continue };
        let rule = TagRule::of(&repo)?;
        let Some(tv) = rule.version(tag) else {
            lines.push(format!("{}: {tag} isn't one of its tags (it follows {})", e.slug(), rule.describe()));
            continue;
        };
        let Some(r) = &r else { continue };
        let via = commit.filter(|_| r.name == tag && !remote_has_tag).unwrap_or(tag);
        let co = git::checkout(policy(state), &repo.url, &r.commit, Some(via)).await.map_err(AppError::bad)?;
        if let Some((_, why)) = foreign_reason(state, e, &repo, &co, r, &tv).await? {
            lines.push(format!("{}: {tag} would be recorded as not its own: {why}", e.slug()));
            continue;
        }
        match prepare(state, e, &repo, &co, r, &tv, &PrepOpts::default()).await {
            Ok(p) => lines.push(format!("{}@{tv}: reads cleanly{}", e.slug(), sims_note(&p))),
            Err(AppError::Upstream(why)) => lines.push(format!("{}@{tv}: would wait (left unread, tried again): {why}", e.slug())),
            Err(err) => {
                clean = false;
                lines.push(format!("{}@{tv}: would be an invalid version: {err}", e.slug()));
            }
        }
    }
    Ok((lines, clean))
}

fn sims_note(p: &Prepared) -> String {
    let named: Vec<&str> = p.sims.iter().map(|s| s.name.as_str()).filter(|n| !n.is_empty()).collect();
    if named.is_empty() { String::new() } else { format!(" (sims: {})", named.join(", ")) }
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
    attach_repo(&mut *state.db.acquire().await?, &entry, &url, PACKAGE_FILE, Some(overlay), &TagRule::of_manifest(&m), None).await?;
    // The admin vouches for the tags that exist now; later upstream tags are reviewed unless the
    // entry or its owner is trusted. A failure is kept as the repo's poll error.
    let _ = sync_as(state, &entry, Some(admin), Pace::Now).await;
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
    // No sync of this entry runs while its rule changes (see `reread_rule`).
    let lock = entry_sync_lock(entry.id);
    let one_at_a_time = lock.lock().await;
    let current = repo_of(state, entry.id).await?.map(|r| r.url).unwrap_or_default();
    if current != url {
        same_history(state, entry, &url).await?;
    }
    let mut tx = state.db.begin().await?;
    if !still_curated_at(&mut tx, entry.id, &current).await? {
        return Err(AppError::Conflict(CURATED_CHANGED.into()));
    }
    sqlx::query("UPDATE entry_repos SET url = $2, overlay_manifest = $3, tag_pattern = $4, min_version = $5 WHERE entry_id = $1")
        .bind(entry.id)
        .bind(&url)
        .bind(overlay)
        .bind(&pattern)
        .bind(&since)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE entries SET summary = COALESCE($2, summary) WHERE id = $1")
        .bind(entry.id)
        .bind(summary_of(&m))
        .execute(&mut *tx)
        .await?;
    crate::audit::audit_with(
        &mut tx,
        Some(admin.id),
        "curated.update",
        Some(&entry.slug()),
        json!({ "url": url, "tag_pattern": pattern, "since": since }),
        None,
    )
    .await?;
    // The rule may have changed: the repo's "not this entry's" judgments are made again.
    // The entry's own judgments, and claims on the repo it now reads; the old URL's other entries
    // are left alone.
    clear_foreign_on(&mut tx, state, entry.id, &url).await?;
    tx.commit().await?;
    drop(one_at_a_time);
    sync_as(state, entry, Some(admin), Pace::Now).await
}

/// Admin-only: a curated package whose repo now carries its own cactarium.toml (on its default
/// branch, naming the entry's owner) stops using the overlay. Its name and versions stay; its tag
/// rule becomes the repo manifest's.
pub async fn hand_over(state: &AppState, admin: &User, entry: &Entry) -> AppResult<()> {
    // No sync of this entry runs while its rule changes (see `reread_rule`).
    let lock = entry_sync_lock(entry.id);
    let _one_at_a_time = lock.lock().await;
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
    let mut tx = state.db.begin().await?;
    if !still_curated_at(&mut tx, entry.id, &repo.url).await? {
        return Err(AppError::Conflict(CURATED_CHANGED.into()));
    }
    // From now on the repo's own manifest says how its tags become versions.
    let (pattern, since) = TagRule::of_manifest(&m).stored();
    sqlx::query("UPDATE entry_repos SET overlay_manifest = NULL, tag_pattern = $2, min_version = $3 WHERE entry_id = $1")
        .bind(entry.id)
        .bind(pattern)
        .bind(since)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE entries SET curated = FALSE, updated_at = now() WHERE id = $1")
        .bind(entry.id)
        .execute(&mut *tx)
        .await?;
    crate::audit::audit_with(&mut tx, Some(admin.id), "curated.hand-over", Some(&entry.slug()), json!({ "head": head }), None)
        .await?;
    // The rule is the repo manifest's now: the repo's "not this entry's" judgments are made again.
    clear_foreign_on(&mut tx, state, entry.id, &repo.url).await?;
    tx.commit().await?;
    Ok(())
}

/// Admin-only: re-reads the published versions of a curated package with its current overlay
/// manifest. A curated package's manifest is metadata the Cactarium keeps, not repo content, so a
/// fix to it (dependencies added, a thorn list corrected) can apply to versions already published.
/// Each version keeps its commit and tree; its manifest, thorns and claims are replaced by what a
/// fresh ingest of that commit with the current overlay gives, in one transaction. A version that
/// can't be fetched or doesn't fit the overlay is left as it was and reported. An invalid version
/// (never served) that fits the corrected overlay becomes valid, with its review decided as for a
/// new release the admin vouches for. Returns (versions re-read, versions left with why).
pub async fn reapply_curated(state: &AppState, admin: &User, entry: &Entry) -> AppResult<(usize, Vec<String>)> {
    let repo = repo_of(state, entry.id).await?.ok_or(AppError::NotFound)?;
    if !entry.curated || repo.overlay_manifest.is_none() {
        return Err(AppError::bad(format!("{} isn't curated: its versions read the repo's own manifest", entry.slug())));
    }
    // The overlay's since bounds what it curates: an older version stays as it was (yank it if no
    // range should choose it any more).
    let since = Manifest::from_repo_file(PACKAGE_FILE, repo.overlay_manifest.as_deref().unwrap_or_default())
        .ok()
        .and_then(|m| m.package.and_then(|p| p.since));
    let (mut done, mut left) = (0, Vec::new());
    for v in model::all_versions(state, entry.id).await? {
        let label = v.label();
        // A yanked version is out of circulation: nothing to re-read it for.
        if v.yanked {
            continue;
        }
        if let (Some(since), Ok(tv)) = (&since, label.parse::<TrackedVersion>())
            && tv.version < *since
        {
            left.push(format!("{label}: older than the manifest's since ({since}), so not curated; yank it if no range should choose it"));
            continue;
        }
        let Some(commit) = v.commit.clone() else {
            left.push(format!("{label}: has no commit"));
            continue;
        };
        let tv: TrackedVersion = label.parse().map_err(AppError::bad)?;
        let r = RemoteRef { name: v.tag.clone().unwrap_or_else(|| tv.conventional_tag()), commit: commit.clone() };
        let co = match git::checkout(policy(state), &repo.url, &commit, v.tag.as_deref()).await {
            Ok(co) => co,
            Err(e) => {
                left.push(format!("{label}: cannot fetch {commit}: {e:#}"));
                continue;
            }
        };
        let p = match prepare(state, entry, &repo, &co, &r, &tv, &PrepOpts::default()).await {
            Ok(p) => p,
            Err(e) => {
                left.push(format!("{label}: {e}"));
                continue;
            }
        };
        // An invalid version was never served; once it fits, it is reviewed like a new release.
        let revived = v.state == "invalid";
        let review = if revived { Some(publish::release_review(state, entry, Some(admin)).await?) } else { None };
        let mut tx = state.db.begin().await?;
        for table in ["thorns", "claims"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE version_id = $1"))
                .bind(v.id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            "UPDATE versions SET manifest = $2, readme_html = $3, tree = $4, review = COALESCE($5, review),
                state = CASE WHEN state = 'invalid' THEN 'ok' ELSE state END,
                invalid_reason = CASE WHEN state = 'invalid' THEN NULL ELSE invalid_reason END
             WHERE id = $1",
        )
        .bind(v.id)
        .bind(&p.manifest_json)
        .bind(&p.readme_html)
        .bind(&co.tree)
        .bind(review)
        .execute(&mut *tx)
        .await?;
        if let Some(r) = review {
            publish::submit_release(&mut tx, entry, v.id, r, Some(admin)).await?;
        }
        store_prepared(&mut tx, entry, v.id, &v.track, p).await?;
        crate::audit::audit_with(
            &mut tx,
            Some(admin.id),
            "curated.reapply",
            Some(&entry.slug()),
            json!({ "version": label, "commit": commit }),
            None,
        )
        .await?;
        tx.commit().await?;
        done += 1;
    }
    if done > 0 {
        publish::touch(state, entry.id).await?;
    }
    Ok((done, left))
}

/// Owner or admin: re-reads an entry's tag rule from its manifest on the repo's default branch, or
/// at a named tag, and makes it the entry's rule. This is how an entry switches tag schemes (adds,
/// changes or drops `tag-pattern`, moves `since`): a new tag never does it on its own. At a named
/// tag, the manifest must read that tag as one of its versions. Tags recorded as not the entry's
/// are judged again under the new rule at the next sync, which this starts. Returns the new rule,
/// described.
pub async fn reread_rule(state: &AppState, user: &User, entry: &Entry, tag: Option<&str>) -> AppResult<String> {
    if !entry.manageable_by(Some(user)) {
        return Err(AppError::Forbidden);
    }
    let repo = repo_of(state, entry.id)
        .await?
        .ok_or_else(|| AppError::bad(format!("{} isn't released from a repo", entry.slug())))?;
    if repo.overlay_manifest.is_some() {
        return Err(AppError::bad(format!(
            "{} is curated: its tag rule is its overlay manifest's; change that instead",
            entry.slug()
        )));
    }
    let tag = tag.map(str::trim).filter(|t| !t.is_empty());
    // No sync of this entry runs meanwhile (in this process): one judging tags under the old rule
    // could otherwise record them after the re-read cleared those records. Across processes, the
    // records and `since` are written only under the rule they were judged by.
    let lock = entry_sync_lock(entry.id);
    let one_at_a_time = lock.lock().await;
    let (commit, at) = match tag {
        Some(t) => {
            let c = git::resolve_tag(policy(state), &repo.url, t)
                .await
                .map_err(AppError::bad)?
                .ok_or_else(|| AppError::bad(format!("the repo has no tag '{t}'")))?;
            (c, format!("tag {t}"))
        }
        None => (git::resolve_ref(policy(state), &repo.url, None).await.map_err(AppError::bad)?, "the default branch".to_owned()),
    };
    let co = git::checkout(policy(state), &repo.url, &commit, tag).await.map_err(AppError::bad)?;
    let text = git::read_in(&co, &repo.manifest_file)
        .map_err(AppError::bad)?
        .ok_or_else(|| AppError::bad(format!("there is no {} at {at}", repo.manifest_file)))?;
    let m = Manifest::from_repo_file(&repo.manifest_file, &text).map_err(|e| AppError::bad(format!("{} at {at}: {e}", repo.manifest_file)))?;
    if name_of(&m) != entry.name {
        return Err(AppError::bad(format!("{} at {at} names '{}', not '{}'", repo.manifest_file, name_of(&m), entry.name)));
    }
    if !owners_of(&m).contains(&entry.owner) {
        return Err(AppError::bad(format!("{} at {at} doesn't list '{}' in owners", repo.manifest_file, entry.owner)));
    }
    let rule = TagRule::of_manifest(&m);
    if let Some(t) = tag
        && rule.version(t).is_none()
    {
        return Err(AppError::bad(format!(
            "{} at {t} follows {}, which {t} isn't one of: re-read it from one of its own tags",
            repo.manifest_file,
            rule.describe()
        )));
    }
    let before = TagRule::of(&repo)?;
    let (pattern, since) = rule.stored();
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE entry_repos SET tag_pattern = $2, min_version = $3 WHERE entry_id = $1")
        .bind(entry.id)
        .bind(&pattern)
        .bind(&since)
        .execute(&mut *tx)
        .await?;
    clear_foreign_on(&mut tx, state, entry.id, &repo.url).await?;
    crate::audit::audit_with(
        &mut tx,
        Some(user.id),
        "repo.tag-rule",
        Some(&entry.slug()),
        json!({ "from": before.stored().0, "to": pattern, "since": since, "read_at": at, "commit": commit }),
        None,
    )
    .await?;
    tx.commit().await?;
    drop(one_at_a_time);
    match sync(state, entry).await {
        Ok(_) | Err(AppError::Upstream(_)) => {}
        Err(e) => return Err(e),
    }
    let mut said = rule.describe();
    if let Some(s) = &rule.since {
        said.push_str(&format!(", from {s} on"));
    }
    Ok(said)
}

/// Admin-only: reads an invalid version of a repo-released (not curated) entry again, at its frozen
/// commit, the way a new tag is read now. An invalid version was never served, so nothing depended
/// on it (the argument of migration 0009): one that now reads cleanly becomes valid and is reviewed
/// as a pushed tag is; one that isn't the entry's tag at all (another kind's, under the self-consistency
/// rule or the sibling backstop) is removed and recorded as not the entry's. A version that still
/// fails stays as it was, and the reason is returned as the error.
pub async fn reread_invalid(state: &AppState, admin: &User, entry: &Entry, label: &str) -> AppResult<String> {
    if !admin.is_admin() {
        return Err(AppError::Forbidden);
    }
    if entry.curated {
        return Err(AppError::bad(format!("{} is curated: use re-apply, which re-reads its versions with its overlay", entry.slug())));
    }
    let repo = repo_of(state, entry.id)
        .await?
        .ok_or_else(|| AppError::bad(format!("{} isn't released from a repo", entry.slug())))?;
    let v = model::any_version_by_label(state, entry.id, label.trim())
        .await?
        .ok_or_else(|| AppError::bad(format!("{} has no version {label}", entry.slug())))?;
    if v.state != "invalid" {
        return Err(AppError::bad(format!("{}@{label} isn't invalid", entry.slug())));
    }
    let (Some(tag), Some(commit)) = (v.tag.clone(), v.commit.clone()) else {
        return Err(AppError::bad(format!("{}@{label} has no tag and commit to read", entry.slug())));
    };
    let tv: TrackedVersion = v.label().parse().map_err(AppError::bad)?;
    // The frozen tag first; then any other tag naming exactly this version under the entry's rule
    // (say, the real v1.0.0 beside an old bare 1.0.0 that took the version), best spelling first.
    let rule = TagRule::of(&repo)?;
    let mut candidates = vec![RemoteRef { name: tag.clone(), commit: commit.clone() }];
    let others = git::ls_tags(policy(state), &repo.url)
        .await
        .map_err(|e| AppError::Upstream(format!("cannot list the repo's tags: {e:#}")))?;
    let mut others: Vec<RemoteRef> =
        others.into_iter().filter(|o| o.name != tag && rule.version(&o.name).as_ref() == Some(&tv)).collect();
    others.sort_by_key(|o| (spelling_rank(&rule, &o.name, &tv), o.name.clone()));
    candidates.extend(others);
    let (mut frozen_foreign, mut first_error) = (None, None);
    let mut found = None;
    for (i, r) in candidates.iter().enumerate() {
        let co = git::checkout(policy(state), &repo.url, &r.commit, Some(&r.name))
            .await
            .map_err(|e| AppError::Upstream(format!("cannot fetch {}: {e:#}", r.commit)))?;
        if let Some(judged) = foreign_reason(state, entry, &repo, &co, r, &tv).await? {
            if i == 0 {
                frozen_foreign = Some(judged);
            }
            continue;
        }
        match prepare(state, entry, &repo, &co, r, &tv, &PrepOpts::default()).await {
            Ok(p) => {
                found = Some((r.clone(), co, p));
                break;
            }
            Err(AppError::BadRequest(m)) => {
                first_error.get_or_insert(AppError::BadRequest(if i == 0 { m } else { format!("{} also fails: {m}", r.name) }));
            }
            Err(e) => return Err(e),
        }
    }
    let Some((r, co, p)) = found else {
        if let Some((kind, why)) = frozen_foreign {
            let mut tx = state.db.begin().await?;
            sqlx::query("DELETE FROM versions WHERE id = $1 AND state = 'invalid'").bind(v.id).execute(&mut *tx).await?;
            sqlx::query(
                "INSERT INTO foreign_tags (entry_id, tag, commit, reason, kind) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (entry_id, tag) DO UPDATE SET commit = EXCLUDED.commit, reason = EXCLUDED.reason, kind = EXCLUDED.kind, seen_at = now()",
            )
            .bind(entry.id)
            .bind(&tag)
            .bind(&commit)
            .bind(&why)
            .bind(kind)
            .execute(&mut *tx)
            .await?;
            crate::audit::audit_with(&mut tx, Some(admin.id), "version.reread", Some(&entry.slug()), json!({ "version": label, "tag": tag, "now": "not the entry's", "why": why }), None).await?;
            tx.commit().await?;
            return Ok(format!("{tag} isn't {}'s tag ({why}); the invalid version was removed", entry.slug()));
        }
        return Err(first_error.unwrap_or_else(|| AppError::bad(format!("{}@{label} still isn't readable", entry.slug()))));
    };
    // Reviewed as the tag would be if pushed now: the admin re-reading it doesn't vouch for it.
    let review = publish::release_review(state, entry, None).await?;
    let mut tx = state.db.begin().await?;
    // Possibly another tag of the same version: never served, so nothing depended on the old one.
    let n = sqlx::query(
        "UPDATE versions SET state = 'ok', invalid_reason = NULL, manifest = $2, readme_html = $3, tree = $4, review = $5,
                tag = $6, commit = $7
         WHERE id = $1 AND state = 'invalid'",
    )
    .bind(v.id)
    .bind(&p.manifest_json)
    .bind(&p.readme_html)
    .bind(&co.tree)
    .bind(review)
    .bind(&r.name)
    .bind(&r.commit)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(AppError::Conflict(format!("{}@{label} changed while this ran; reload and try again", entry.slug())));
    }
    store_prepared(&mut tx, entry, v.id, &v.track, p).await?;
    publish::submit_release(&mut tx, entry, v.id, review, None).await?;
    crate::audit::audit_with(&mut tx, Some(admin.id), "version.reread", Some(&entry.slug()), json!({ "version": label, "tag": r.name, "was": tag, "now": "valid", "review": review }), None).await?;
    tx.commit().await?;
    publish::touch(state, entry.id).await?;
    let from = if r.name == tag { String::new() } else { format!(", from {} (instead of {tag})", r.name) };
    Ok(format!("{}@{label} reads cleanly now{from}{}", entry.slug(), if review == "pending" { "; it awaits review" } else { "" }))
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

/// Admin-only: points a registered entry, and every other entry on the same repo, at the repo's new
/// URL (e.g. after the repo moved to another GitHub owner), once [`same_history`] confirms for
/// each that it is the same repo. All move together in one transaction, or none does. Versions
/// keep their frozen commits; stack releases that pinned the old URL keep it (GitHub redirects a
/// moved repo's URL). Returns the entries moved.
pub async fn move_repo(state: &AppState, admin: &User, entry: &Entry, new_url: &str) -> AppResult<Vec<Entry>> {
    let repo = repo_of(state, entry.id)
        .await?
        .ok_or_else(|| AppError::bad(format!("{} has no repo", entry.slug())))?;
    let url = git::check_url(policy(state), new_url.trim()).await.map_err(AppError::bad)?;
    if url == repo.url {
        return Err(AppError::bad(format!("{} already uses {url}", entry.slug())));
    }
    let all: Vec<Entry> = entries_on(state, &repo.url).await?.into_iter().map(|(e, _)| e).collect();
    for e in &all {
        same_history(state, e, &url).await?;
    }
    let mut tx = state.db.begin().await?;
    for e in &all {
        let from: String = sqlx::query_scalar("SELECT url FROM entry_repos WHERE entry_id = $1 FOR UPDATE")
            .bind(e.id)
            .fetch_one(&mut *tx)
            .await?;
        if git::normalize_url(&from) != git::normalize_url(&repo.url) {
            return Err(AppError::Conflict(format!("{} moved while this ran; reload and try again", e.slug())));
        }
        sqlx::query("UPDATE entry_repos SET url = $2, poll_error = NULL WHERE entry_id = $1")
            .bind(e.id)
            .bind(&url)
            .execute(&mut *tx)
            .await?;
        crate::audit::audit_with(
            &mut tx,
            Some(admin.id),
            "repo.move",
            Some(&e.slug()),
            json!({ "from": from, "to": url, "with": all.iter().map(Entry::slug).collect::<Vec<_>>() }),
            None,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(all)
}

#[allow(clippy::too_many_arguments)]
async fn attach_repo(
    db: &mut sqlx::PgConnection,
    entry: &Entry,
    url: &str,
    file: &str,
    overlay: Option<&str>,
    rule: &TagRule,
    sim_form: Option<&str>,
) -> AppResult<()> {
    let (pattern, since) = rule.stored();
    sqlx::query("INSERT INTO entry_repos (entry_id, url, manifest_file, webhook_secret, overlay_manifest, tag_pattern, min_version, sim_form) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
        .bind(entry.id)
        .bind(url)
        .bind(file)
        .bind(random_token())
        .bind(overlay)
        .bind(pattern)
        .bind(since)
        .bind(sim_form)
        .execute(&mut *db)
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
    /// For a sim entry: `file` or `files`, fixed when it was registered (the address depends on it).
    pub sim_form: Option<String>,
}

pub async fn repo_of(state: &AppState, entry_id: i64) -> AppResult<Option<RepoRow>> {
    Ok(sqlx::query_as::<_, RepoRow>(
        "SELECT url, manifest_file, webhook_secret, overlay_manifest, tag_pattern, min_version, sim_form FROM entry_repos WHERE entry_id = $1",
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
    sync_as(state, entry, None, Pace::Now).await
}

/// Syncs of one entry run one at a time: two at once would both see a tag as new and race to
/// store it. One lock per entry this process has synced; bounded by the entries.
static ENTRY_SYNCS: std::sync::LazyLock<std::sync::Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>> =
    std::sync::LazyLock::new(Default::default);

fn entry_sync_lock(id: i64) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = ENTRY_SYNCS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    locks.entry(id).or_default().clone()
}

/// How long a background sync (a webhook's or the poller's) may take before it is stopped. Each
/// version is stored in one transaction, so stopping one leaves no version half-stored.
const SYNC_BUDGET: Duration = Duration::from_secs(15 * 60);

/// Background syncs at once: the poller's and the webhooks' each have their own few, so neither a
/// flood of webhooks nor one slow repo can hold the other up.
static POLL_SYNCS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
static HOOK_SYNCS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// Entries with a webhook sync queued and not yet started.
static HOOK_QUEUED: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<i64>>> =
    std::sync::LazyLock::new(Default::default);

/// Syncs an entry in the background, for a webhook. Deliveries that arrive while one is queued add
/// nothing (the queued sync will see what they announce); one that arrives while a sync runs
/// queues one more, which starts when it ends.
pub fn sync_soon(state: AppState, entry_id: i64) {
    if !HOOK_QUEUED.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(entry_id) {
        return;
    }
    tokio::spawn(async move {
        let _permit = HOOK_SYNCS.acquire().await;
        HOOK_QUEUED.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&entry_id);
        if let Err(e) = budgeted_sync(&state, entry_id).await {
            tracing::info!("webhook sync of entry {entry_id} failed: {e}");
        }
    });
}

/// [`sync`] within [`SYNC_BUDGET`]; a sync stopped for time is recorded as the repo's poll error.
async fn budgeted_sync(state: &AppState, entry_id: i64) -> AppResult<usize> {
    let entry = model::entry_by_id(state, entry_id).await?;
    match tokio::time::timeout(SYNC_BUDGET, sync_as(state, &entry, None, Pace::Background)).await {
        Ok(r) => r,
        Err(_) => {
            let why = format!("reading the repo took over {} minutes and was stopped", SYNC_BUDGET.as_secs() / 60);
            sqlx::query("UPDATE entry_repos SET last_polled_at = now(), poll_error = $2 WHERE entry_id = $1")
                .bind(entry_id)
                .bind(&why)
                .execute(&state.db)
                .await?;
            Err(AppError::bad(why))
        }
    }
}

/// `sync`, with the tags found counted as published by `actor` (the user registering the repo).
async fn sync_as(state: &AppState, entry: &Entry, actor: Option<&User>, pace: Pace) -> AppResult<usize> {
    let lock = entry_sync_lock(entry.id);
    let _one_at_a_time = lock.lock().await;
    let Some(repo) = repo_of(state, entry.id).await? else { return Ok(0) };
    let banned: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1 AND banned)")
            .bind(&entry.owner)
            .fetch_one(&state.db)
            .await?;
    if banned || entry.visibility == "hidden" {
        // Marked as polled all the same: the poller takes the longest-unpolled repos first, and
        // these would otherwise take its slots every round.
        sqlx::query("UPDATE entry_repos SET last_polled_at = now() WHERE entry_id = $1")
            .bind(entry.id)
            .execute(&state.db)
            .await?;
        return Ok(0);
    }
    let result = sync_inner(state, entry, &repo, actor, pace).await;
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
    pace: Pace,
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
    // Versions the entry has, by label, whatever tag froze them: another tag naming one of them (a
    // bare 1.0.0 beside v1.0.0) is no new version, and would only collide.
    let have: std::collections::BTreeSet<String> = sqlx::query_scalar(
        "SELECT CASE WHEN track = '' THEN version ELSE track || ':' || version END FROM versions WHERE entry_id = $1",
    )
    .bind(entry.id)
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .collect();

    for k in &known {
        let (Some(tag), Some(frozen)) = (&k.tag, &k.commit) else { continue };
        match remote.get(tag) {
            // An invalid version is never served: a tag moving off it changes nothing (it stays
            // invalid, never "tag-moved", which would make it look like a usable version).
            Some(now) if now != frozen && k.state != "tag-moved" && k.state != "invalid" => {
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

    // Tags found not to be this entry's (see `foreign_reason`): skipped while they name the commit
    // they were judged at; a tag that moved is judged again, and one that is gone is forgotten.
    let foreign: BTreeMap<String, String> =
        sqlx::query_as::<_, (String, String)>("SELECT tag, commit FROM foreign_tags WHERE entry_id = $1")
            .bind(entry.id)
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .collect();
    let gone: Vec<&String> = foreign.keys().filter(|t| !remote.contains_key(*t)).collect();
    if !gone.is_empty() {
        sqlx::query("DELETE FROM foreign_tags WHERE entry_id = $1 AND tag = ANY($2)")
            .bind(entry.id)
            .bind(gone.iter().map(|t| t.as_str()).collect::<Vec<_>>())
            .execute(&state.db)
            .await?;
    }

    // Tags a sibling's own tag-pattern reads are the sibling's: recorded as not this entry's and left
    // out before tags naming one version are deduplicated, so a claimed bare 1.0.0 can't hide this
    // entry's own v1.0.0.
    let own_rule = TagRule::of(repo)?;
    let mut sibling_rules = Vec::new();
    if repo.overlay_manifest.is_none() {
        for sib in siblings(state, entry.id, &repo.url).await? {
            if let Some(r) = repo_of(state, sib.id).await? {
                sibling_rules.push((sib.slug(), TagRule::of(&r)?));
            }
        }
    }
    let mut refs_left = Vec::new();
    for r in refs {
        let claim = sibling_rules.iter().find_map(|(slug, theirs)| claimed_by(&r.name, &own_rule, theirs).map(|why| format!("it is {slug}'s release: {why}")));
        match claim {
            Some(why) if own_rule.version(&r.name).is_some() => {
                if !by_tag.contains_key(r.name.as_str()) && foreign.get(&r.name) != Some(&r.commit) {
                    record_foreign(state, entry, &r, ("claim", &why), repo.tag_pattern.as_deref()).await?;
                }
            }
            _ => refs_left.push(r),
        }
    }
    let refs = refs_left;
    // Tags left unread earlier (waiting_tags): tried again after the new ones, with backoff.
    let waiting = waiting_of(state, entry.id, &remote).await?;
    let (mut added, mut read) = (0, 0);
    // Tags that couldn't be read this time: left unread, so a later sync tries again. Only tags
    // read to a conclusion count toward MAX_NEW_PER_SYNC, so tags waiting can't hold up newer ones.
    let mut unfetched: Vec<String> = Vec::new();
    let candidates: Vec<(RemoteRef, TrackedVersion)> = version_tags(refs, &TagRule::of(repo)?)
        .into_iter()
        .filter(|(r, tv)| {
            !by_tag.contains_key(r.name.as_str()) && foreign.get(&r.name) != Some(&r.commit) && !have.contains(&tv.to_string())
        })
        .collect();
    let (retry, fresh): (Vec<_>, Vec<_>) =
        candidates.into_iter().partition(|(r, _)| waiting.get(&r.name).is_some_and(|w| w.commit == r.commit));
    // New tags that turn out to wait are capped too, so one sync (a registration's, say) never
    // tries hundreds of them; the rest are new again at the next sync.
    let (mut new_waiting, mut new_later) = (0, 0);
    for (r, tv) in &fresh {
        if read == MAX_NEW_PER_SYNC {
            break;
        }
        if new_waiting == MAX_WAITING_PER_SYNC {
            new_later += 1;
            continue;
        }
        match ingest(state, entry, repo, r, tv, actor).await {
            Ok(outcome) => {
                read += 1;
                if matches!(outcome, Ingested::Version) {
                    added += 1;
                }
                // A tag that waited at another commit and moved since.
                done_waiting(state, entry.id, &r.name).await?;
            }
            Err(AppError::Upstream(why)) => {
                new_waiting += 1;
                unfetched.push(wait(state, entry, r, why).await);
            }
            Err(e) => return Err(e),
        }
    }
    if new_later > 0 {
        unfetched.push(format!("{new_later} more new tag(s) not tried this time (at most {MAX_WAITING_PER_SYNC} new tags wait per check)"));
    }
    let (mut tried, mut later) = (0, 0);
    for (r, tv) in &retry {
        let w = &waiting[&r.name];
        if tried == MAX_WAITING_PER_SYNC || (pace == Pace::Background && w.next_try_at > time::OffsetDateTime::now_utc()) {
            later += 1;
            continue;
        }
        tried += 1;
        match ingest(state, entry, repo, r, tv, actor).await {
            Ok(outcome) => {
                if matches!(outcome, Ingested::Version) {
                    added += 1;
                }
                done_waiting(state, entry.id, &r.name).await?;
            }
            Err(AppError::Upstream(why)) => unfetched.push(wait(state, entry, r, why).await),
            Err(e) => return Err(e),
        }
    }
    if later > 0 {
        unfetched.push(format!("{later} more waiting tag(s) not tried this time (each backs off, up to 6 hours apart)"));
    }
    if added > 0 {
        publish::touch(state, entry.id).await?;
    }
    if added > 0 && repo.overlay_manifest.is_none() {
        // The newest version's manifest may move `since`; the tag form stays the entry's own
        // until someone re-reads the tag rule. A curated entry's rule is its overlay's.
        let newest: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT manifest FROM versions WHERE entry_id = $1 AND manifest IS NOT NULL AND state <> 'invalid'
             ORDER BY (track = '') DESC, sort_key DESC LIMIT 1",
        )
        .bind(entry.id)
        .fetch_optional(&state.db)
        .await?
        .flatten();
        if let Some(m) = newest.and_then(|m| serde_json::from_value::<Manifest>(m).ok()) {
            let rule = TagRule::of_manifest(&m);
            if rule.same_pattern(&TagRule::of(repo)?) {
                store_since(state, entry.id, rule.stored().1, repo.tag_pattern.as_deref()).await?;
            }
        }
    }
    // What couldn't be read is reported (it becomes the repo's poll error) and tried again.
    if !unfetched.is_empty() {
        return Err(AppError::Upstream(format!(
            "{} new version(s) read; {} tag(s) will be tried again at the next sync: {}",
            added,
            unfetched.len(),
            unfetched.join("; ")
        )));
    }
    Ok(added)
}

/// A tag left unread: when it was last judged, and when the poller may try it again.
struct Waiting {
    commit: String,
    next_try_at: time::OffsetDateTime,
}

/// The entry's waiting tags, forgetting those deleted upstream.
async fn waiting_of(state: &AppState, entry_id: i64, remote: &BTreeMap<String, String>) -> AppResult<BTreeMap<String, Waiting>> {
    let rows: Vec<(String, String, time::OffsetDateTime)> =
        sqlx::query_as("SELECT tag, commit, next_try_at FROM waiting_tags WHERE entry_id = $1")
            .bind(entry_id)
            .fetch_all(&state.db)
            .await?;
    let gone: Vec<&str> = rows.iter().filter(|(t, _, _)| !remote.contains_key(t)).map(|(t, _, _)| t.as_str()).collect();
    if !gone.is_empty() {
        sqlx::query("DELETE FROM waiting_tags WHERE entry_id = $1 AND tag = ANY($2)")
            .bind(entry_id)
            .bind(&gone)
            .execute(&state.db)
            .await?;
    }
    Ok(rows
        .into_iter()
        .filter(|(t, _, _)| remote.contains_key(t))
        .map(|(t, commit, next_try_at)| (t, Waiting { commit, next_try_at }))
        .collect())
}

/// Records that a tag is still waiting: its retry backs off exponentially (5 minutes, doubling, at
/// most 6 hours apart), starting over when the tag moves. Returns `why` with the next try's time.
/// Bookkeeping only: if recording fails, that is logged and `why` returned as it is, so the sync
/// goes on to the other tags.
async fn wait(state: &AppState, entry: &Entry, r: &RemoteRef, why: String) -> String {
    match record_wait(state, entry, r, &why).await {
        Ok(next) => format!("{why} (next automatic try after {})", model::fmt_time(next)),
        Err(e) => {
            tracing::error!("recording that {} waits at {}: {e}", entry.slug(), r.name);
            why
        }
    }
}

async fn record_wait(state: &AppState, entry: &Entry, r: &RemoteRef, why: &str) -> AppResult<time::OffsetDateTime> {
    let next: time::OffsetDateTime = sqlx::query_scalar(
        "INSERT INTO waiting_tags (entry_id, tag, commit, tries, reason, next_try_at)
         VALUES ($1, $2, $3, 1, $4, now() + interval '5 minutes')
         ON CONFLICT (entry_id, tag) DO UPDATE SET
           tries = CASE WHEN waiting_tags.commit = EXCLUDED.commit THEN LEAST(waiting_tags.tries + 1, 1000) ELSE 1 END,
           commit = EXCLUDED.commit, reason = EXCLUDED.reason,
           next_try_at = now() + LEAST(interval '6 hours', interval '5 minutes' *
             power(2, LEAST(CASE WHEN waiting_tags.commit = EXCLUDED.commit THEN waiting_tags.tries ELSE 0 END, 7)))
         RETURNING next_try_at",
    )
    .bind(entry.id)
    .bind(&r.name)
    .bind(&r.commit)
    .bind(why)
    .fetch_one(&state.db)
    .await?;
    Ok(next)
}

async fn done_waiting(state: &AppState, entry_id: i64, tag: &str) -> AppResult<()> {
    sqlx::query("DELETE FROM waiting_tags WHERE entry_id = $1 AND tag = $2")
        .bind(entry_id)
        .bind(tag)
        .execute(&state.db)
        .await?;
    Ok(())
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
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE versions SET state = $2 WHERE id = $1")
        .bind(version_id)
        .bind(new_state)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO tag_events (entry_id, version_id, tag, frozen_commit, new_commit) VALUES ($1, $2, $3, $4, $5)")
        .bind(entry.id)
        .bind(version_id)
        .bind(tag)
        .bind(frozen)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    crate::audit::audit_with(
        &mut tx,
        None,
        &format!("tag.{new_state}"),
        Some(&entry.slug()),
        json!({ "tag": tag, "frozen": frozen, "now": now }),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

fn short(commit: &str) -> &str {
    &commit[..10.min(commit.len())]
}

/// Why a candidate tag (one the entry's stored rule picks) is not the entry's at all, if it isn't:
///
/// - **Self-consistency:** the entry's own manifest inside the tag must read that tag as that
///   version under its own rule. A manifest that dropped or changed its `tag-pattern` reads it
///   otherwise (or not at all), so the tag belongs to another scheme, typically another kind on
///   the same repo, and must not become a version of this entry.
/// - **The sibling backstop:** for an entry with siblings (other entries on the same repo), a tag
///   without the entry's manifest file is a sibling's release (or from before this kind's manifest
///   existed), not a broken release of this entry.
///
/// Such a tag is recorded as not this entry's instead of frozen invalid, and judged again if it
/// moves. A manifest that can't be read decides nothing here: `prepare` reports it. A curated
/// entry reads its overlay at every tag, so its rule is consistent by construction.
async fn foreign_reason(
    state: &AppState,
    entry: &Entry,
    repo: &RepoRow,
    co: &git::Checkout,
    r: &RemoteRef,
    tv: &TrackedVersion,
) -> AppResult<Option<(&'static str, String)>> {
    if repo.overlay_manifest.is_some() {
        return Ok(None);
    }
    let sibs = siblings(state, entry.id, &repo.url).await?;
    // A kind that declares a tag-pattern follows only it; the kinds without one stay on the
    // standard form. So a tag a sibling's own pattern reads (bare 1.2.3 for {major}.{minor}.{patch},
    // say), which the standard form also reads, is that sibling's, not this entry's.
    let own = TagRule::of(repo)?;
    if own.version(&r.name).is_some() && own.pattern.as_ref().is_none_or(|p| p.version(&r.name).is_none()) {
        for sib in &sibs {
            let Some(theirs) = repo_of(state, sib.id).await? else { continue };
            if let Some(why) = claimed_by(&r.name, &own, &TagRule::of(&theirs)?) {
                return Ok(Some(("claim", format!("it is {}'s release: {why}", sib.slug()))));
            }
        }
    }
    // A file that can't be read decides nothing here: prepare reports it (an invalid version).
    let Ok(read) = git::read_in(co, &repo.manifest_file) else { return Ok(None) };
    let Some(text) = read else {
        if sibs.is_empty() {
            return Ok(None);
        }
        return Ok(Some((
            "backstop",
            format!("it has no {} (a release of another entry on this repo, or from before this one's manifest)", repo.manifest_file),
        )));
    };
    let Ok(m) = Manifest::from_repo_file(&repo.manifest_file, &text) else { return Ok(None) };
    // The form (one file or [sim.files]) is the entry's, fixed when it was registered: a manifest in
    // the other form is another scheme's, not a release of this entry.
    if let (Some(fixed), Some(here)) = (fixed_form(entry, repo), sim_form_of(&m))
        && fixed != here
    {
        return Ok(Some((
            "form",
            format!(
                "its {} uses {}, but this entry publishes {} (fixed when it was registered)",
                repo.manifest_file,
                form_words(&here),
                form_words(fixed)
            ),
        )));
    }
    Ok(inconsistent(&TagRule::of_manifest(&m), &repo.manifest_file, &r.name, tv).map(|why| ("consistency", why)))
}

/// Whether `tag` belongs to a sibling with its own tag-pattern, rather than to an entry following
/// `own`: the sibling's pattern reads it and `own`'s pattern (if any) doesn't, and the two patterns
/// differ (kinds with the same pattern share its tags). Says why.
fn claimed_by(tag: &str, own: &TagRule, theirs: &TagRule) -> Option<String> {
    let p = theirs.distinct_pattern()?;
    if own.same_pattern(theirs) || own.pattern.as_ref().is_some_and(|o| o.version(tag).is_some()) {
        return None;
    }
    p.version(tag).map(|_| format!("its tag-pattern {} reads {tag}", p.as_str()))
}

/// A repo-backed sim entry's fixed form. One without a stored form (registered by an older release,
/// after a rollback) publishes one file: older releases knew no other form.
fn fixed_form<'a>(entry: &Entry, repo: &'a RepoRow) -> Option<&'a str> {
    match repo.sim_form.as_deref() {
        Some(f) => Some(f),
        None if entry.kind == "sim" && repo.overlay_manifest.is_none() => Some("file"),
        None => None,
    }
}

/// A sim manifest's form: `file` or `files`; `None` for other manifests.
fn sim_form_of(m: &Manifest) -> Option<String> {
    m.sim.as_ref().map(|s| match s.form() {
        SimForm::File(_) => "file".to_owned(),
        SimForm::Files(_) => "files".to_owned(),
    })
}

fn form_words(form: &str) -> &'static str {
    if form == "files" { "several sims ([sim.files])" } else { "one sim (file)" }
}

/// Self-consistency: why the manifest's own rule `own` doesn't read `tag` as `tv`, if it doesn't.
fn inconsistent(own: &TagRule, file: &str, tag: &str, tv: &TrackedVersion) -> Option<String> {
    match own.version(tag) {
        Some(v) if v == *tv => None,
        Some(v) => Some(format!("its {file} reads {tag} as {v}, not {tv}")),
        None => Some(format!("its {file} follows {}, which {tag} isn't one of", own.describe())),
    }
}

/// After `entry_id`'s tag rule changes: forgets its own "not this entry's" judgments, and, on the
/// repo at `url`, the siblings' that are claims by a tag-pattern (which its old pattern may have
/// made). Each is judged again at its entry's next sync. The siblings' other judgments (no manifest
/// for them, another form, their own manifest's rule) don't depend on this entry's rule and stay.
async fn clear_foreign_on(db: &mut sqlx::PgConnection, state: &AppState, entry_id: i64, url: &str) -> AppResult<()> {
    let ids: Vec<i64> = entries_on(state, url).await?.into_iter().map(|(e, _)| e.id).collect();
    sqlx::query("DELETE FROM foreign_tags WHERE entry_id = $1 OR (entry_id = ANY($2) AND kind = 'claim')")
        .bind(entry_id)
        .bind(&ids)
        .execute(&mut *db)
        .await?;
    Ok(())
}

/// Records `r` as not `entry`'s tag, with why (replacing an earlier judgment of the same tag).
/// Only while the entry's tag rule is still `pattern`, the one the caller judged under: a re-read
/// of the rule (which clears these records) in between makes the judgment stale, and nothing is
/// written.
async fn record_foreign(state: &AppState, entry: &Entry, r: &RemoteRef, (kind, why): (&str, &str), pattern: Option<&str>) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO foreign_tags (entry_id, tag, commit, reason, kind)
         SELECT $1, $2, $3, $4, $6 WHERE EXISTS
           (SELECT 1 FROM entry_repos WHERE entry_id = $1 AND tag_pattern IS NOT DISTINCT FROM $5)
         ON CONFLICT (entry_id, tag) DO UPDATE SET commit = EXCLUDED.commit, reason = EXCLUDED.reason, kind = EXCLUDED.kind, seen_at = now()",
    )
    .bind(entry.id)
    .bind(&r.name)
    .bind(&r.commit)
    .bind(why)
    .bind(pattern)
    .bind(kind)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// What reading one tag came to.
enum Ingested {
    /// A version: valid, or invalid with the reason.
    Version,
    /// Not this entry's tag; recorded so, not frozen.
    Foreign,
}

/// Freezes one tag as a version. A tag whose manifest is missing or wrong still becomes a version,
/// marked invalid with the reason, so it is not fetched again on every poll. Only facts about the
/// commit make a version invalid: when `prepare` answers [`AppError::Upstream`] or fails on our
/// side, nothing is stored and the tag is tried again at the next sync. A tag that isn't this
/// entry's at all ([`foreign_reason`]) is recorded as such and becomes no version.
async fn ingest(
    state: &AppState,
    entry: &Entry,
    repo: &RepoRow,
    r: &RemoteRef,
    tv: &TrackedVersion,
    actor: Option<&User>,
) -> AppResult<Ingested> {
    let track = tv.track.as_ref().map(|t| t.to_string()).unwrap_or_default();
    let co = git::checkout(policy(state), &repo.url, &r.commit, Some(&r.name)).await;
    let (invalid, tree, prepared) = match co {
        // Too large is a fact about the commit: the version is stored invalid, as for a bad manifest.
        // On a repo carrying several entries, though, whose release it is can't be read, so it is
        // recorded as not this entry's (judged again if the tag moves) rather than frozen here.
        Err(e) if e.downcast_ref::<git::TooLarge>().is_some() => {
            if repo.overlay_manifest.is_none() && !siblings(state, entry.id, &repo.url).await?.is_empty() {
                record_foreign(state, entry, r, ("large", &format!("{e:#}, so whose release it is can't be read")), repo.tag_pattern.as_deref()).await?;
                return Ok(Ingested::Foreign);
            }
            (Some(format!("cannot index the tagged commit: {e:#}")), None, None)
        }
        // Any other fetch failure (the network, the host) is worth trying again: nothing is
        // stored, so the tag is read again at the next sync.
        Err(e) => {
            return Err(AppError::Upstream(format!("{}: cannot fetch {} ({}): {e:#}", entry.slug(), r.name, short(&r.commit))));
        }
        Ok(co) => {
            if let Some((kind, why)) = foreign_reason(state, entry, repo, &co, r, tv).await? {
                record_foreign(state, entry, r, (kind, &why), repo.tag_pattern.as_deref()).await?;
                return Ok(Ingested::Foreign);
            }
            match prepare(state, entry, repo, &co, r, tv, &PrepOpts::default()).await {
                Ok(p) => (None, Some(co.tree.clone()), Some(p)),
                // Not a fact about the commit (a newer format than this server reads, a pinned package
                // not public yet, a host that didn't answer): nothing is stored, so the tag is read
                // again at the next sync.
                Err(AppError::Upstream(why)) => {
                    return Err(AppError::Upstream(format!("{}: {} ({}): {why}", entry.slug(), r.name, short(&r.commit))));
                }
                // Our own failure (the database, say) says nothing about the commit either.
                Err(AppError::Internal(e)) => {
                    tracing::error!("reading {} at {}: {e:#}", entry.slug(), r.name);
                    return Err(AppError::Upstream(format!(
                        "{}: {} ({}): an internal error while reading it",
                        entry.slug(),
                        r.name,
                        short(&r.commit)
                    )));
                }
                Err(e) => (Some(e.to_string()), Some(co.tree.clone()), None),
            }
        }
    };
    let mut prepared = prepared;
    if let Some(p) = prepared.as_mut()
        && let Some(warning) = sorts_below_another_form(state, entry, &track, tv, &r.name).await?
    {
        p.smells.push(warning);
    }
    let manifest_json = prepared.as_ref().map(|p| p.manifest_json.clone());
    let readme = prepared.as_ref().and_then(|p| p.readme_html.clone());
    // An invalid tag is never served, so it needs no review.
    let review = if invalid.is_some() {
        "approved"
    } else {
        publish::release_review(state, entry, actor).await?
    };
    // The version and everything stored with it land together or not at all: a version is never
    // redone once its row exists, so a half-stored one would stay half-stored.
    let mut tx = state.db.begin().await?;
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
    .fetch_one(&mut *tx)
    .await?;
    if let Some(p) = prepared {
        store_prepared(&mut tx, entry, vid, &track, p).await?;
    }
    publish::submit_release(&mut tx, entry, vid, review, actor).await?;
    // A tag judged not this entry's earlier and since moved onto a release of it.
    sqlx::query("DELETE FROM foreign_tags WHERE entry_id = $1 AND tag = $2")
        .bind(entry.id)
        .bind(&r.name)
        .execute(&mut *tx)
        .await?;
    crate::audit::audit_with(
        &mut tx,
        None,
        "version.ingest",
        Some(&entry.slug()),
        json!({ "tag": r.name, "commit": r.commit, "invalid": invalid, "review": review }),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Ingested::Version)
}

/// A reviewer's warning when a new version sorts below a valid version of the same track that came
/// from a different tag form (`v2.3.0` beside a new `sim-v1.0.0`): ranges keep choosing the other
/// one, which usually means the entry switched tag schemes without renumbering.
async fn sorts_below_another_form(
    state: &AppState,
    entry: &Entry,
    track: &str,
    tv: &TrackedVersion,
    tag: &str,
) -> AppResult<Option<String>> {
    let higher: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT version, tag FROM versions WHERE entry_id = $1 AND track = $2 AND state <> 'invalid' AND sort_key > $3
         ORDER BY sort_key DESC",
    )
    .bind(entry.id)
    .bind(track)
    .bind(semver_sort_key(&tv.version))
    .fetch_all(&state.db)
    .await?;
    let form = tag_form(tag);
    Ok(higher.into_iter().find(|(_, t)| t.as_deref().is_some_and(|t| tag_form(t) != form)).map(|(v, t)| {
        format!(
            "this version ({tv}, tag {tag}) sorts below {v} (tag {}), which came from another tag form: ranges keep choosing {v}. \
             If the entry switched tag schemes, its new versions need to be numbered above the old ones",
            t.unwrap_or_default()
        )
    }))
}

/// A package's default-branch tip, read now: what `owner/pkg@head` (and `@master`) mean for a
/// package. Nothing is stored; the API caches it by commit.
pub struct PackageTip {
    pub commit: String,
    pub tree: String,
    /// A Cactus flesh (no thorns), per its manifest.
    pub flesh: bool,
    /// A library thorns build against (no thorns), per its manifest.
    pub library: bool,
    pub thorns: Vec<(String, String, String, ccl::ThornFacts)>,
    pub claims: Vec<ClaimRec>,
}

/// The commit a package's default branch names now.
pub async fn package_tip_commit(state: &AppState, entry: &Entry) -> AppResult<String> {
    let repo = repo_of(state, entry.id)
        .await?
        .ok_or_else(|| AppError::bad(format!("{} has no repo", entry.slug())))?;
    git::resolve_ref(policy(state), &repo.url, None).await.map_err(AppError::bad)
}

/// Reads a package at `commit` (its default branch's tip, or a commit someone named) the way a
/// release is read: the manifest (the curated one, for a curated package) and the thorns there.
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
    let p = prepare(state, entry, &repo, &co, &r, &tv, &PrepOpts::default())
        .await
        .map_err(|e| AppError::bad(format!("{} at commit {}: {e}", entry.slug(), &commit[..12.min(commit.len())])))?;
    let flesh = p.manifest_json["package"]["flesh"].as_bool().unwrap_or(false);
    let library = p.manifest_json["package"]["library"].as_bool().unwrap_or(false);
    Ok(PackageTip {
        commit: commit.to_owned(),
        tree: co.tree.clone(),
        flesh,
        library,
        thorns: p.thorns,
        claims: p.claims,
    })
}

struct Prepared {
    manifest_json: serde_json::Value,
    readme_html: Option<String>,
    summary: Option<String>,
    thorns: Vec<(String, String, String, ccl::ThornFacts)>,
    claims: Vec<ClaimRec>,
    frozen: Option<(FrozenStack, String, Option<String>)>,
    /// A sim entry published from its repo: every `.sim` the manifest names, each checked as an
    /// upload is. One, named "", for a `file` manifest; one per `[sim.files]` entry otherwise.
    sims: Vec<PreparedSim>,
    /// The manifest's own description, for a sim entry.
    sim_description: Option<String>,
    /// What reviewers should look at (deps.rs): stored with the version.
    smells: Vec<String>,
    /// Sim pins that can't be checked yet, when [`PrepOpts::defer_pins`] asked to hear them rather
    /// than fail: what the tag's first sync would wait for.
    deferred: Vec<String>,
}

struct PreparedSim {
    /// "" for the entry's only sim (`file`), else its `[sim.files]` name.
    name: String,
    checked: crate::sims::Checked,
}

/// How `prepare` reads a commit beyond the defaults (a sync's).
#[derive(Default)]
struct PrepOpts {
    /// Return sim pins that can't be checked yet as `deferred` instead of failing with
    /// [`AppError::Upstream`] (a registration's dry read).
    defer_pins: bool,
    /// Normalized URLs of packages being registered along with this entry: a pin to one is a
    /// package not public yet, not a repo nobody registered.
    registering: Vec<String>,
}

/// Reads one commit of an entry the way a version is read, checking everything a version must
/// satisfy, so that storing what it returns cannot fail on the content. Errors that are facts about
/// the commit are `BadRequest`; [`AppError::Upstream`] means the commit can't be judged right now.
async fn prepare(
    state: &AppState,
    entry: &Entry,
    repo: &RepoRow,
    co: &git::Checkout,
    r: &RemoteRef,
    tv: &TrackedVersion,
    opts: &PrepOpts,
) -> AppResult<Prepared> {
    let text = match &repo.overlay_manifest {
        Some(o) => o.clone(),
        None => match git::read_in(co, &repo.manifest_file).map_err(AppError::bad)? {
            Some(t) => t,
            // On a repo that carries other entries too, a tag without this entry's manifest is
            // most likely another entry's release, not a broken release of this one: left unread
            // rather than frozen invalid.
            None if !siblings(state, entry.id, &repo.url).await?.is_empty() => {
                return Err(AppError::Upstream(format!(
                    "no {} at this tag, and the repo carries other entries: probably another entry's release",
                    repo.manifest_file
                )));
            }
            None => return Err(AppError::bad(format!("no {} at this tag", repo.manifest_file))),
        },
    };
    let m = Manifest::from_repo_file(&repo.manifest_file, &text).map_err(unreadable_at_tag)?;
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
    let claims = ClaimRec::of_manifest(&m);
    let manifest_json = serde_json::to_value(&m).map_err(anyhow::Error::from)?;
    let mut p = Prepared {
        manifest_json,
        readme_html: None,
        summary: summary_of(&m),
        thorns: vec![],
        claims,
        frozen: None,
        sims: Vec::new(),
        sim_description: None,
        smells: Vec::new(),
        deferred: Vec::new(),
    };

    if let Some(pkg) = &m.package {
        let readme_path = pkg.readme.clone().unwrap_or_else(|| "README.md".into());
        // Up to 4 MB of markdown through the sanitizer: blocking work, off the async threads.
        if let Some(text) = git::read_in(co, &readme_path).ok().flatten() {
            p.readme_html = Some(
                tokio::task::spawn_blocking(move || markdown::render(&text))
                    .await
                    .map_err(anyhow::Error::from)?,
            );
        }
        // A flesh package is the Cactus flesh itself: checked by its files, and no thorns.
        if pkg.flesh {
            for marker in ["src/main/flesh.cc", "lib/sbin/CST"] {
                if !co.path.join(marker).is_file() {
                    return Err(AppError::bad(format!(
                        "[package] flesh = true, but this commit has no {marker}: it isn't a Cactus flesh"
                    )));
                }
            }
        }
        let allow = pkg.thorns.as_ref();
        // [package] root: where the thorns are, when not at the repo root (Kranc: Auxiliary/Cactus).
        // The crate checked it is a plain relative path; a folder that isn't there finds no thorns.
        let sub = pkg.root.clone().unwrap_or_default();
        let root = co.path.join(&sub);
        // A flesh or a library has no thorns to scan.
        let scanned = if pkg.flesh || pkg.library {
            Vec::new()
        } else {
            tokio::task::spawn_blocking(move || ccl::scan_tree(&root)).await.map_err(anyhow::Error::from)?
        };
        for t in scanned {
            // A repo that is one thorn (the Einstein Toolkit's ExternalLibraries-* repos) names it,
            // and its arrangement, in the manifest.
            // Thorn directories stay relative to the repo root, root folder included.
            let in_repo = |d: &std::path::Path| {
                let d = std::path::Path::new(&sub).join(d);
                let s = d.to_string_lossy().into_owned();
                if s.is_empty() { ".".to_owned() } else { s }
            };
            let (name, dir) = match (t.name.clone(), allow.map(Vec::as_slice), &pkg.arrangement) {
                (Some(n), _, _) => (n, in_repo(&t.dir)),
                (None, Some([one]), Some(_)) => (one.clone(), in_repo(std::path::Path::new(""))),
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
            // exclude-thorns: thorns that can't build aren't published.
            if pkg.exclude_thorns.contains(&name) {
                continue;
            }
            // The manifest's arrangement, when given, wins over the folder the thorn sits in:
            // GRHayL keeps GRHayLib under implementations/, which is no arrangement.
            let arrangement = match (&pkg.arrangement, &t.arrangement) {
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
        if p.thorns.is_empty() && !pkg.flesh && !pkg.library {
            return Err(AppError::bad("no thorns found (directories with an interface.ccl)"));
        }
        for c in &p.claims {
            if let Some(t) = c.needed_by.iter().find(|t| !p.thorns.iter().any(|(_, name, _, _)| name == *t)) {
                return Err(AppError::bad(format!(
                    "the dependency on {} is needed by '{t}', which is not one of this package's thorns",
                    c.target()
                )));
            }
        }
        // exclude-thorns names thorns the repo has: a name it doesn't is a typo.
        if !pkg.exclude_thorns.is_empty() {
            let root = co.path.join(pkg.root.clone().unwrap_or_default());
            let all = tokio::task::spawn_blocking(move || ccl::scan_tree(&root)).await.map_err(anyhow::Error::from)?;
            if let Some(x) = pkg.exclude_thorns.iter().find(|x| !all.iter().any(|t| t.name.as_deref() == Some(x.as_str()))) {
                return Err(AppError::bad(format!("exclude-thorns names '{x}', which this commit doesn't have")));
            }
        }
        // The CCL and the dependencies must agree; what reviewers should see comes back as smells.
        p.smells = crate::deps::check(state, &m, &p.thorns, &p.claims, &co.path).await?;
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
    if let Some(sim) = &m.sim {
        prepare_sims(state, entry, repo, co, tv, sim, opts, &mut p).await?;
    }
    let _ = r;
    Ok(p)
}

/// The sims of a sim entry at one commit: every file the manifest names, held to exactly what an
/// upload must satisfy, plus what only a repo has (`repo-file` inputs) and what only several sims
/// have (the stamp each will carry). All or nothing: a version missing one of its sims would freeze
/// silently incomplete, so one failing sim refuses the version, with every reason.
#[allow(clippy::too_many_arguments)]
async fn prepare_sims(
    state: &AppState,
    entry: &Entry,
    repo: &RepoRow,
    co: &git::Checkout,
    tv: &TrackedVersion,
    sim: &cactup_ecosystem_common::manifest::SimSection,
    opts: &PrepOpts,
    p: &mut Prepared,
) -> AppResult<()> {
    let named = matches!(sim.form(), SimForm::Files(_));
    // The form is the entry's, fixed at registration: switching it would change every address
    // (owner/name against owner/name/sim). A tag in the other form is recorded as not the entry's
    // before this runs (`foreign_reason`); here it is only a backstop for other readers.
    if let Some(fixed) = fixed_form(entry, repo)
        && fixed != if named { "files" } else { "file" }
    {
        return Err(AppError::bad(format!(
            "this manifest uses {}, but {} publishes {}: the form is fixed when the entry is registered",
            form_words(if named { "files" } else { "file" }),
            entry.slug(),
            form_words(fixed)
        )));
    }
    let (mut facts, mut passing) = (Vec::new(), Vec::new());
    for (name, file) in sim.sims() {
        let name = name.map(|n| n.to_string()).unwrap_or_default();
        let what = if named { format!("sim {name} ({file})") } else { format!("'{file}'") };
        match prepare_one_sim(state, entry, co, tv, &name, file, opts).await {
            Ok((checked, pins)) => {
                facts.extend(pins.facts.into_iter().map(|f| format!("{what}: {f}")));
                passing.extend(pins.passing.into_iter().map(|f| if named { format!("{what}: {f}") } else { f }));
                p.sims.push(PreparedSim { name, checked });
            }
            // A newer format than this server reads: the whole tag waits.
            Err(AppError::Upstream(why)) => return Err(AppError::Upstream(format!("{what}: {why}"))),
            Err(AppError::BadRequest(why)) => facts.push(if named { format!("{what}: {why}") } else { why }),
            Err(e) => return Err(e),
        }
    }
    if !facts.is_empty() {
        facts.extend(passing);
        let lead = if facts.len() > 1 && named { "these sims fail, so the version is refused: " } else { "" };
        return Err(AppError::bad(format!("{lead}{}", facts.join("; "))));
    }
    if !passing.is_empty() {
        if opts.defer_pins {
            p.deferred = passing;
        } else {
            return Err(AppError::Upstream(format!(
                "pins that can't be checked yet (the tag will be read again): {}",
                passing.join("; ")
            )));
        }
    }
    p.sim_description = sim.description.clone();
    Ok(())
}

/// One sim of a sim entry at one commit: its file checked as an upload is, its `repo-file` inputs,
/// and the stamp it will be stored with; its pins come back unjudged.
async fn prepare_one_sim(
    state: &AppState,
    entry: &Entry,
    co: &git::Checkout,
    tv: &TrackedVersion,
    name: &str,
    file: &str,
    opts: &PrepOpts,
) -> AppResult<(crate::sims::Checked, crate::sims::PinProblems)> {
    let text = git::read_in(co, file)
        .map_err(AppError::bad)?
        .ok_or_else(|| AppError::bad(format!("'{file}' does not exist at this tag")))?;
    let mut checked = crate::sims::check_at_tag(text.as_bytes())?;
    // Inputs read from this repo must be files at this tag (inside the repo, not via a link).
    for i in &checked.sim.inputs {
        let Some(f) = &i.repo_file else { continue };
        let path = co.path.join(f);
        let inside = std::fs::canonicalize(&path).is_ok_and(|real| {
            std::fs::canonicalize(&co.path).is_ok_and(|root| real.starts_with(root))
        });
        if !(inside && path.is_file()) {
            return Err(AppError::bad(format!(
                "input {}: '{f}' is not a file in the repo at this tag",
                i.knob
            )));
        }
    }
    // The stored copy will carry this stamp; making it now means storing it can't fail.
    crate::sims::stamped(entry, name, &tv.to_string(), &checked.sim)?;
    if !name.is_empty() && checked.sim.sim.name != name {
        checked.index.warnings.push(format!(
            "the manifest lists this sim as '{name}', but its file calls itself '{}'",
            checked.sim.sim.name
        ));
    }
    let pins = crate::sims::pin_problems(state, &checked.sim, &opts.registering).await?;
    Ok((checked, pins))
}

async fn store_prepared(
    db: &mut sqlx::PgConnection,
    entry: &Entry,
    vid: i64,
    track: &str,
    p: Prepared,
) -> AppResult<()> {
    sqlx::query("UPDATE versions SET smells = $2 WHERE id = $1")
        .bind(vid)
        .bind(&p.smells)
        .execute(&mut *db)
        .await?;
    for (arr, name, dir, facts) in &p.thorns {
        sqlx::query("INSERT INTO thorns (version_id, arrangement, name, dir, implements, facts) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(vid)
            .bind(arr)
            .bind(name)
            .bind(dir)
            .bind(&facts.implements)
            .bind(serde_json::to_value(facts).map_err(anyhow::Error::from)?)
            .execute(&mut *db)
            .await?;
    }
    for c in &p.claims {
        c.insert(&mut *db, vid).await?;
    }
    if let Some((frozen, toml, own)) = &p.frozen {
        store_release(db, entry, vid, track, frozen, toml, "tag", frozen.recipe.clone(), own.clone())
            .await?;
    }
    if !p.sims.is_empty() {
        let (label, review): (String, String) = sqlx::query_as(
            "SELECT CASE WHEN track = '' THEN version ELSE track || ':' || version END, review FROM versions WHERE id = $1",
        )
        .bind(vid)
        .fetch_one(&mut *db)
        .await?;
        let named = p.sims.iter().any(|s| !s.name.is_empty());
        for s in p.sims {
            // One sim's own text describes the entry only when it is the entry's only sim.
            let text = if named {
                crate::sims::EntryText::Leave
            } else {
                crate::sims::EntryText::FromSim { description: p.sim_description.as_deref() }
            };
            crate::sims::store_version(db, entry, vid, &label, &review, &s.name, s.checked, text).await?;
        }
        if named && review == "approved" {
            sqlx::query("UPDATE entries SET description = COALESCE($2, description), updated_at = now() WHERE id = $1")
                .bind(entry.id)
                .bind(&p.sim_description)
                .execute(&mut *db)
                .await?;
        }
    }
    if p.summary.is_some() {
        // Only a published release updates the public summary.
        sqlx::query("UPDATE entries SET summary = $2 WHERE id = $1 AND (SELECT review FROM versions WHERE id = $3) = 'approved'")
            .bind(entry.id)
            .bind(&p.summary)
            .bind(vid)
            .execute(&mut *db)
            .await?;
    }
    Ok(())
}

/// Stores a stack release with its diff against the previous published release on the same track.
#[allow(clippy::too_many_arguments)]
pub async fn store_release(
    db: &mut sqlx::PgConnection,
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
    .fetch_optional(&mut *db)
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
        .execute(&mut *db)
        .await?;
    store_built_thorns(db, vid, &frozen.thornlist.text).await?;
    store_pins(db, vid, "", &frozen.repos).await
}

/// Records the thorns a stack release or a sim builds, so they can be found by thorn.
pub async fn store_built_thorns(db: &mut sqlx::PgConnection, vid: i64, thornlist: &str) -> AppResult<()> {
    let Ok(list) = cactup_ecosystem_common::crl::parse(thornlist) else { return Ok(()) };
    for c in list.components().iter().filter(|c| c.checkout.contains('/') && !c.fetch_only) {
        sqlx::query(
            "INSERT INTO release_thorns (version_id, checkout) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(vid)
        .bind(&c.checkout)
        .execute(&mut *db)
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
    let mut db = state.db.acquire().await?;
    for (vid, frozen) in stacks {
        if let Ok(f) = toml::from_str::<cactup_ecosystem_common::stack::FrozenStack>(&frozen) {
            store_built_thorns(&mut db, vid, &f.thornlist.text).await?;
        }
    }
    let sims: Vec<(i64, String)> = sqlx::query_as(
        "SELECT version_id, content FROM sim_files s WHERE NOT EXISTS (SELECT 1 FROM release_thorns r WHERE r.version_id = s.version_id)",
    )
    .fetch_all(&state.db)
    .await?;
    for (vid, content) in sims {
        if let Ok(sim) = cactup_ecosystem_common::sim::SimFile::from_toml(&content) {
            store_built_thorns(&mut db, vid, &sim.thornlist.text).await?;
        }
    }
    Ok(())
}

/// Records the repos a stack release or a sim pins; `sim` names the sim of a multi-sim version
/// ("" otherwise), whose sims may pin the same repo at different commits.
pub async fn store_pins(
    db: &mut sqlx::PgConnection,
    vid: i64,
    sim: &str,
    pins: &[cactup_ecosystem_common::sim::RepoPin],
) -> AppResult<()> {
    for p in pins {
        sqlx::query("INSERT INTO source_pins (version_id, sim, repo, url, url_norm, git_ref, commit) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING")
            .bind(vid)
            .bind(sim)
            .bind(&p.name)
            .bind(&p.url)
            .bind(git::normalize_url(&p.url))
            .bind(&p.git_ref)
            .bind(p.commit.as_ref().or(p.sha256.as_ref()))
            .execute(&mut *db)
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
    let prepared = prepare(state, entry, &repo, &co, &r, &tv, &PrepOpts::default()).await?;
    let mut tx = state.db.begin().await?;
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
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => AppError::Conflict(format!("{label} already exists")),
        _ => e.into(),
    })?;
    store_prepared(&mut tx, entry, vid, &track, prepared).await?;
    crate::audit::audit_with(
        &mut tx,
        Some(admin.id),
        "version.virtual",
        Some(&entry.slug()),
        json!({ "version": label, "commit": commit }),
        None,
    )
    .await?;
    tx.commit().await?;
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
    // A few at a time, each within the budget: one slow repo can't hold up the others for long.
    let mut syncs = tokio::task::JoinSet::new();
    for id in due {
        let state = state.clone();
        syncs.spawn(async move {
            let _permit = POLL_SYNCS.acquire().await;
            if let Err(e) = budgeted_sync(&state, id).await {
                tracing::info!("sync of entry {id} failed: {e}");
            }
        });
    }
    while syncs.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: Option<&str>) -> TagRule {
        TagRule { pattern: pattern.map(|p| p.parse().unwrap()), since: None }
    }

    #[test]
    fn tag_forms_tell_schemes_apart() {
        assert_eq!(tag_form("v1.2.0"), "v#.#.#");
        assert_eq!(tag_form("v10.20.300"), "v#.#.#");
        assert_eq!(tag_form("sim-v1.0.0"), "sim-v#.#.#");
        assert_eq!(tag_form("ET_2026_05_v0"), "ET_#_#_v#");
        assert_ne!(tag_form("v2.3.0"), tag_form("sim-v1.0.0"));
    }

    /// Without a pattern every kind follows vX.Y.Z; with one, only its own tags.
    #[test]
    fn rules_pick_their_own_tags() {
        let plain = rule(None);
        let sims = rule(Some("sim-v{major}.{minor}.{patch}"));
        assert_eq!(plain.version("v1.2.0").unwrap().to_string(), "1.2.0");
        assert!(plain.version("sim-v1.2.0").is_none(), "sim-v isn't a vX.Y.Z tag");
        // `sim/v1.0.0` reads as a track named sim under the default rule: never use it for sims.
        assert_eq!(plain.version("sim/v1.0.0").unwrap().to_string(), "sim:1.0.0");
        assert_eq!(sims.version("sim-v1.2.0").unwrap().to_string(), "1.2.0");
        assert!(sims.version("v1.2.0").is_none());
        assert!(rule(Some("sim-v{major}.{minor}.{patch}")).same_pattern(&sims));
        assert!(!plain.same_pattern(&sims));
    }

    /// A kind with a tag-pattern follows only it; kinds without one stay on the standard form, so
    /// a tag a sibling's pattern reads isn't theirs, even when the standard form reads it too.
    #[test]
    fn a_siblings_pattern_claims_its_tags() {
        let plain = rule(None);
        let bare = rule(Some("{major}.{minor}.{patch}"));
        let slash = rule(Some("sim/v{major}.{minor}.{patch}"));
        assert!(plain.version("2.0.0").is_some(), "the standard form reads bare X.Y.Z");
        assert!(claimed_by("2.0.0", &plain, &bare).is_some());
        assert!(claimed_by("v2.0.0", &plain, &bare).is_none(), "its pattern doesn't read v2.0.0");
        assert!(claimed_by("sim/v1.0.0", &plain, &slash).is_some(), "an explicit sim/v pattern is claimed too");
        assert!(claimed_by("2.0.0", &bare, &rule(Some("{major}.{minor}.{patch}"))).is_none(), "the same pattern shares its tags");
        assert!(claimed_by("v2.0.0", &plain, &plain).is_none(), "no pattern claims nothing");
        // Declaring the standard form is declaring none: it shares the standard tags, never claims.
        let explicit = rule(Some("v{major}.{minor}.{patch}"));
        assert!(claimed_by("v1.2.0", &plain, &explicit).is_none());
        assert!(plain.same_pattern(&explicit) && explicit.same_pattern(&plain));
        assert!(claimed_by("2.0.0", &explicit, &bare).is_some(), "a different pattern still claims");
    }

    /// A tag the stored rule picks is the entry's only if the manifest inside reads it the same way.
    #[test]
    fn self_consistency() {
        let tv = |s: &str| s.parse::<TrackedVersion>().unwrap();
        let sims = rule(Some("sim-v{major}.{minor}.{patch}"));
        assert_eq!(inconsistent(&sims, SIM_FILE, "sim-v1.0.0", &tv("1.0.0")), None);
        // A later manifest that dropped its pattern doesn't read sim-v tags at all.
        let dropped = inconsistent(&rule(None), SIM_FILE, "sim-v2.0.0", &tv("2.0.0")).unwrap();
        assert!(dropped.contains("isn't one of"), "{dropped}");
        // One that reads the tag as another version.
        let other = rule(Some("sim-v{major}.{minor}"));
        assert!(inconsistent(&other, SIM_FILE, "sim-v2.0", &tv("2.1.0")).unwrap().contains("as 2.0.0"));
    }
}
