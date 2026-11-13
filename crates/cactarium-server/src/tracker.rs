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

/// How tags become versions under a manifest: its `tag-pattern` if it has one, else `vX.Y.Z` and
/// `track/vX.Y.Z`; tags below its `since` are left out. A repo entry's tag is read by the manifest in
/// the tag's own commit ([`judge`]); the rule stored with the repo (`entry_repos.tag_pattern`,
/// `min_version`) is then only what its page says it follows (its newest version's), and a hint of
/// the tags it may use while some are unexamined. A curated entry's stored rule, its overlay's,
/// decides which tags are versions.
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

    /// [`TagRule::describe`], with `since` when it has one.
    pub fn describe_with_since(&self) -> String {
        match &self.since {
            Some(s) => format!("{}, from {s} on", self.describe()),
            None => self.describe(),
        }
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

/// How a tag spells its version, best first: the spelling a declared pattern itself writes for it
/// (`rel-1.0` for `rel-{major}.{minor}`, no leading zeros), then the standard `[track/]vX.Y.Z`,
/// then any other (a bare `X.Y.Z`, say an old upstream tag that predates the repo's manifest, or
/// `rel-01.0`), so a stray spelling never takes the release's version by name.
fn spelling_rank(rule: &TagRule, tag: &str, tv: &TrackedVersion) -> u8 {
    if rule.pattern.as_ref().is_some_and(|p| tag == written_by(p.as_str(), tv)) {
        0
    } else if tag == tv.conventional_tag() {
        1
    } else {
        2
    }
}

/// The tag a pattern writes for a version: its placeholders filled in, without leading zeros.
fn written_by(pattern: &str, tv: &TrackedVersion) -> String {
    pattern
        .replace("{major}", &tv.version.major.to_string())
        .replace("{minor}", &tv.version.minor.to_string())
        .replace("{patch}", &tv.version.patch.to_string())
}

/// Whether an entry has tags in a range that aren't read yet.
#[derive(Clone, Copy, PartialEq)]
pub enum Unread {
    No,
    Yes,
    /// Its repo can't be listed right now: wait rather than freeze.
    CantTell,
}

/// Whether an entry has tags in `req` that aren't read yet: waiting ones, or ones its rule picks
/// with neither a version nor a "not a version" record.
pub async fn unread_in_range(state: &AppState, entry_id: i64, req: &cactup_ecosystem_common::version::TrackedReq) -> AppResult<Unread> {
    let Some(repo) = repo_of(state, entry_id).await? else { return Ok(Unread::No) };
    let Ok(refs) = git::ls_tags(policy(state), &repo.url).await else { return Ok(Unread::CantTell) };
    let remote: BTreeMap<String, String> = refs.iter().map(|r| (r.name.clone(), r.commit.clone())).collect();
    let by_tag: std::collections::BTreeSet<String> =
        sqlx::query_scalar("SELECT tag FROM versions WHERE entry_id = $1 AND tag IS NOT NULL")
            .bind(entry_id)
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .collect();
    let have = version_labels(state, entry_id).await?;
    let foreign: BTreeMap<String, String> =
        sqlx::query_as::<_, (String, String)>("SELECT tag, commit FROM foreign_tags WHERE entry_id = $1")
            .bind(entry_id)
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .collect();
    if repo.overlay_manifest.is_some() {
        // A curated entry: its overlay's rule decides which tags are versions.
        let rule = TagRule::of(&repo)?;
        let any = version_tags(refs, &rule)
            .iter()
            .any(|(r, tv)| req.matches(tv) && !have.contains(&tv.to_string()) && foreign.get(&r.name) != Some(&r.commit));
        return Ok(if any { Unread::Yes } else { Unread::No });
    }
    // A repo entry: a tag read as a version in range and not frozen yet counts; so does a tag not
    // examined yet (it could be any version, and is examined soon); a waiting one counts only if the
    // standard form or a pattern the entry is known to use reads it into the range; a tag recorded
    // as not a version never does.
    let reads: BTreeMap<String, (String, String)> =
        sqlx::query_as::<_, (String, String, String)>("SELECT tag, commit, label FROM tag_reads WHERE entry_id = $1")
            .bind(entry_id)
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .map(|(t, c, l)| (t, (c, l)))
            .collect();
    let waiting: BTreeMap<String, String> =
        sqlx::query_as::<_, (String, String)>("SELECT tag, commit FROM waiting_tags WHERE entry_id = $1")
            .bind(entry_id)
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .collect();
    let rules = known_rules(state, entry_id).await?;
    for (tag, commit) in &remote {
        if by_tag.contains(tag) || foreign.get(tag) == Some(commit) {
            continue;
        }
        match (reads.get(tag), waiting.get(tag)) {
            (Some((c, label)), _) if c == commit => {
                if label.parse::<TrackedVersion>().is_ok_and(|v| req.matches(&v)) && !have.contains(label) {
                    return Ok(Unread::Yes);
                }
            }
            (_, Some(c)) if c == commit => {
                if rules.iter().any(|r| r.version(tag).is_some_and(|v| req.matches(&v) && !have.contains(&v.to_string()))) {
                    return Ok(Unread::Yes);
                }
            }
            _ => return Ok(Unread::Yes),
        }
    }
    Ok(Unread::No)
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
    /// Why it can't be registered as it is (its manifest doesn't list the owner, its name is
    /// taken): shown in the preview; registering it is refused.
    pub problem: Option<String>,
    /// For the preview only: its manifest file isn't on the default branch (a kind the repo may
    /// have dropped; leave it unchecked to leave it out). Decides nothing.
    pub off_head: bool,
}

/// A manifest a registration leaves out, and why (registering again later adds it).
pub struct Skipped {
    pub file: &'static str,
    /// Its manifest's name, when one was read.
    pub name: Option<String>,
    pub note: String,
}

/// What registering a repo would do: the entries already on it, the ones it would add, and the
/// manifests it leaves out.
pub struct Plan {
    pub url: String,
    pub owner: String,
    pub existing: Vec<(Entry, String)>,
    pub new: Vec<Planned>,
    pub skipped: Vec<Skipped>,
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
                generation: 0,
            },
        )
    }
}

/// Where a registration reads its manifests: each entry's newest release tag, or one named tag. A
/// dry run can also name a tag that doesn't exist yet, with the commit it would name.
pub enum At<'a> {
    Newest,
    Tag(&'a str),
    Commit { tag: &'a str, commit: &'a str },
}

/// Works out what registering `url` under `owner` would add, without writing anything.
///
/// Without a tag named, each manifest file found at any tag starts from its newest release, found
/// the way syncing reads tags ([`discover`]): the newest tag whose own manifest at that commit
/// reads it as a version, with the claims of the siblings' manifests there (the entries already on
/// the repo, and the other new ones). The default branch decides nothing: a manifest there with no
/// release tag yet is left out with a note, and a release whose file isn't there is only marked.
///
/// With a tag named, only the manifests there that read it as one of their versions are planned,
/// at it; the others are left out, with a note (register again without the tag to add them).
///
/// Entries already on the repo stay as they are; they must be `owner`'s. Without an owner (a dry
/// run), the repo's existing owner is assumed, else the first owner the first new manifest lists.
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
    let mut skipped = Vec::new();
    match at {
        At::Newest => {
            // The default branch decides nothing here: what it carries is only shown (a manifest
            // there with no release yet is listed as skipped; a release whose file isn't there
            // anymore is marked), and its rules only order which tags are read first.
            let head = git::resolve_ref(policy(state), &url, None).await.map_err(AppError::bad)?;
            let at_head = git::checkout(policy(state), &url, &head, None).await.map_err(AppError::bad)?;
            let mut on_head: Vec<(&'static str, Option<Manifest>)> = Vec::new();
            for file in MANIFEST_FILES {
                if let Ok(Some(text)) = git::read_in(&at_head, file) {
                    on_head.push((file, Manifest::from_repo_file(file, &text).ok()));
                }
            }
            let head_rules: BTreeMap<&'static str, TagRule> =
                on_head.iter().filter_map(|(f, m)| m.as_ref().map(|m| (*f, TagRule::of_manifest(m)))).collect();
            let files: Vec<&'static str> = MANIFEST_FILES.iter().copied().filter(|f| !have.contains(f)).collect();
            if !files.is_empty() {
                let found = discover(state, &url, &refs, &files, &existing, &head_rules).await?;
                for file in &files {
                    match found.best.get(file) {
                        Some((r, tv)) => {
                            let co = Arc::new(git::checkout(policy(state), &url, &r.commit, Some(&r.name)).await.map_err(AppError::bad)?);
                            // The manifest at the tag, read as its first sync will read it, must read the
                            // tag as this version.
                            let Some(text) = git::read_in(&co, file).map_err(AppError::bad)? else {
                                return Err(AppError::bad(format!("{file} isn't at {} after all; register with --tag", r.name)));
                            };
                            let m = Manifest::from_repo_file(file, &text).map_err(|e| AppError::bad(format!("{file} at {}: {e}", r.name)))?;
                            let own = TagRule::of_manifest(&m);
                            if own.version(&r.name).as_ref() != Some(tv) {
                                return Err(AppError::bad(format!(
                                    "{file} at {} follows {}, which doesn't read {} as {tv}; register with --tag naming one of its own tags",
                                    r.name,
                                    own.describe(),
                                    r.name
                                )));
                            }
                            new.push(Planned {
                                file,
                                kind: kind_of(file),
                                name: name_of(&m),
                                manifest: m,
                                rule: own,
                                tag: r.clone(),
                                tv: tv.clone(),
                                co,
                                problem: None,
                                off_head: !on_head.iter().any(|(f, _)| f == file),
                            });
                        }
                        None => {
                            // Found at a tag, or on the default branch, with no release yet (or none
                            // among the tags read): shown, so the author sees it.
                            let read = found.seen.get(file).cloned().or_else(|| {
                                on_head.iter().find(|(f, _)| f == file).map(|(_, m)| match m {
                                    Some(m) => (TagRule::of_manifest(m), Some(name_of(m))),
                                    None => (TagRule::default(), None),
                                })
                            });
                            let Some((rule, name)) = read else { continue };
                            let note = if found.unread > 0 {
                                format!(
                                    "{file} follows {}, and none of the {} tags read of the repo's {} is one of its releases: it isn't registered now; register with --tag naming its newest release",
                                    rule.describe(),
                                    found.read,
                                    refs.len()
                                )
                            } else {
                                format!("{file} follows {}, and the repo has none of its tags yet: it isn't registered now; register again once it has one", rule.describe())
                            };
                            skipped.push(Skipped { file, name, note });
                        }
                    }
                }
                if found.seen.is_empty() && on_head.is_empty() && existing.is_empty() {
                    return Err(AppError::bad(if refs.is_empty() {
                        "the repo has no tags yet, and no manifest on its default branch".to_owned()
                    } else {
                        format!("no {PACKAGE_FILE}, {STACK_FILE} or {SIM_FILE} at any tag read, nor on the default branch")
                    }));
                }
            }
        }
        At::Tag(_) | At::Commit { .. } => {
            plan_at_tag(state, &url, &refs, &existing, &have, at, &mut new, &mut skipped).await?;
        }
    }
    if new.is_empty() && !skipped.is_empty() {
        let notes: Vec<&str> = skipped.iter().map(|s| s.note.as_str()).collect();
        return Err(AppError::bad(format!("nothing to register now: {}", notes.join("; "))));
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
    for i in 0..new.len() {
        let p = &new[i];
        let problem = if !owners_of(&p.manifest).contains(&owner) {
            Some(format!("{} at {} does not list '{owner}' in owners; add it there to prove you control the repo", p.file, p.tag.name))
        } else if let Some(q) = new[..i].iter().find(|q| q.name == p.name) {
            // Every entry needs its own name: two manifests naming one would collide.
            Some(format!("{} and {} both name '{}': each manifest becomes its own entry, so give them different names", q.file, p.file, p.name))
        } else if let Some(e) = model::find_entry(state, &owner, &p.name).await? {
            Some(format!("{} already exists (a {}), so {} can't be registered under that name", e.slug(), e.kind, p.file))
        } else {
            None
        };
        new[i].problem = problem;
    }
    Ok(Plan { url, owner, existing, new, skipped })
}

/// The manifests at a named tag (or a commit a dry run names) that read it as one of their
/// versions, without a sibling's pattern claiming it; the others are left out with a note.
#[allow(clippy::too_many_arguments)]
async fn plan_at_tag(
    state: &AppState,
    url: &str,
    refs: &[RemoteRef],
    existing: &[(Entry, String)],
    have: &[&str],
    at: At<'_>,
    new: &mut Vec<Planned>,
    skipped: &mut Vec<Skipped>,
) -> AppResult<()> {
    // The rules of the entries already on the repo: a tag another kind's own pattern reads isn't a
    // candidate for a kind without that pattern.
    let mut sibling_rules = Vec::new();
    for (e, _) in existing {
        if let Some(r) = repo_of(state, e.id).await? {
            sibling_rules.push(TagRule::of(&r)?);
        }
    }
    // The tag to read, and a ref to fetch it by when a host won't serve a bare commit.
    let (r, via) = match at {
        At::Newest => return Ok(()),
        At::Tag(tag) => {
            let r = refs.iter().find(|r| r.name == tag).cloned().ok_or_else(|| AppError::bad(format!("{url} has no tag '{tag}'")))?;
            let via = r.name.clone();
            (r, via)
        }
        At::Commit { tag, commit } => match refs.iter().find(|r| r.name == tag) {
            Some(r) => (r.clone(), r.name.clone()),
            None => {
                let full = git::resolve_ref(policy(state), url, Some(commit))
                    .await
                    .or_else(|_| if commit.len() >= 40 { Ok(commit.to_string()) } else { Err(()) })
                    .map_err(|_| AppError::bad(format!("'{commit}' is no branch, tag or full commit id of {url}")))?;
                (RemoteRef { name: tag.to_string(), commit: full }, commit.to_string())
            }
        },
    };
    let co = Arc::new(git::checkout(policy(state), url, &r.commit, Some(&via)).await.map_err(AppError::bad)?);
    let found = read_manifests(&co, &r.name)?;
    if found.is_empty() {
        return Err(AppError::bad(format!("no {PACKAGE_FILE}, {STACK_FILE} or {SIM_FILE} at {}", r.name)));
    }
    let candidates: Vec<(&'static str, Manifest)> = found.into_iter().filter(|(f, _)| !have.contains(f)).collect();
    let all_rules: Vec<TagRule> = candidates.iter().map(|(_, m)| TagRule::of_manifest(m)).collect();
    for (i, (file, m)) in candidates.into_iter().enumerate() {
        let rule = all_rules[i].clone();
        let others: Vec<&TagRule> =
            sibling_rules.iter().chain(all_rules.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, r)| r)).collect();
        let claimed = others.iter().find_map(|o| claimed_by(&r.name, &rule, o));
        match (rule.version(&r.name), claimed) {
            (Some(tv), None) => {
                new.push(Planned {
                    file,
                    kind: kind_of(file),
                    name: name_of(&m),
                    manifest: m,
                    rule,
                    tag: r.clone(),
                    tv,
                    co: co.clone(),
                    problem: None,
                    off_head: false,
                });
            }
            (_, why) => skipped.push(Skipped {
                file,
                name: Some(name_of(&m)),
                note: format!(
                    "{file} at {} follows {}{}, so {} isn't one of its versions: it isn't registered now; register again without --tag to add it",
                    r.name,
                    rule.describe(),
                    why.map(|w| format!(" ({w})")).unwrap_or_default(),
                    r.name
                ),
            }),
        }
    }
    Ok(())
}

/// What [`discover`] found: each file's newest release (tag and version), and for each file seen
/// at some tag, the rule and name of its manifest there (the likeliest newest first).
struct Discovered {
    best: BTreeMap<&'static str, (RemoteRef, TrackedVersion)>,
    seen: BTreeMap<&'static str, (TagRule, Option<String>)>,
    /// Tags read, and tags left unread (past the cap, or needing a checkout past its cap).
    read: usize,
    unread: usize,
}

/// Finds each manifest file's newest release the way syncing reads tags: a tag is a release of a
/// file when the file's manifest at the tag's commit reads it as a version under its own rule, and
/// no sibling's manifest there (an entry already on the repo, or another of `files`) claims it
/// ([`judge`]). At most the configured number of tags are read (likeliest first: those the
/// standard form, a default-branch manifest's rule or an existing entry's rule reads, newest
/// first, then the rest), and at most so many from a checkout. When the repo's manifests can't be
/// read right now, that is the error.
async fn discover(
    state: &AppState,
    url: &str,
    refs: &[RemoteRef],
    files: &[&'static str],
    existing: &[(Entry, String)],
    head_rules: &BTreeMap<&'static str, TagRule>,
) -> AppResult<Discovered> {
    let mut sib_rules: Vec<TagRule> = Vec::with_capacity(existing.len());
    for (e, _) in existing {
        sib_rules.push(unreadable_rule(state, e.id).await?);
    }
    let likely: Vec<TagRule> =
        std::iter::once(TagRule::default()).chain(head_rules.values().cloned()).chain(sib_rules.iter().cloned()).collect();
    let mut order: Vec<(Option<(bool, semver::Version)>, &RemoteRef)> = refs
        .iter()
        .map(|r| (likely.iter().filter_map(|rule| rule.version(&r.name)).map(|tv| (tv.track.is_none(), tv.version)).max(), r))
        .collect();
    order.sort_by(|a, b| match (&a.0, &b.0) {
        (Some(x), Some(y)) => y.cmp(x).then_with(|| a.1.name.cmp(&b.1.name)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => b.1.name.cmp(&a.1.name),
    });
    let cap = state.cfg.examine_per_sync;
    let tags: Vec<RemoteRef> = order.iter().take(cap).map(|(_, r)| (*r).clone()).collect();
    let all_files: Vec<String> = files.iter().map(|f| f.to_string()).chain(existing.iter().map(|(_, f)| f.clone())).collect();
    let mut checkouts = state.cfg.checkouts_per_sync;
    let mut out = Discovered { best: BTreeMap::new(), seen: BTreeMap::new(), read: 0, unread: refs.len() - tags.len() };
    // Best so far per file: (default track, version, -rank, tag) is largest for the newest.
    let mut rank_of: BTreeMap<&'static str, i32> = BTreeMap::new();
    for group in tags.chunks(25) {
        for (r, got) in group.iter().zip(read_tags(state, url, group, &all_files, &mut checkouts).await) {
            let reads = match got {
                TagFiles::Reads(reads) => reads,
                TagFiles::Not { .. } => {
                    out.read += 1;
                    continue;
                }
                TagFiles::Unexamined(why) if why == CHECKOUTS_USED || why.ends_with("isn't in the repo's history yet") => {
                    out.unread += 1;
                    continue;
                }
                TagFiles::Unexamined(why) => return Err(AppError::Upstream(why)),
            };
            out.read += 1;
            for (i, file) in files.iter().enumerate() {
                let Read::Text(text) = &reads[i] else { continue };
                let Ok(m) = Manifest::from_repo_file(file, text) else { continue };
                out.seen.entry(file).or_insert_with(|| (TagRule::of_manifest(&m), Some(name_of(&m))));
                // The entry it would be: named by its manifest, its owner checked later.
                let now = time::OffsetDateTime::now_utc();
                let provisional = Entry {
                    id: 0,
                    kind: kind_of(file).to_owned(),
                    owner: String::new(),
                    name: name_of(&m),
                    summary: None,
                    description: None,
                    visibility: "pending".to_owned(),
                    verified: false,
                    trusted: false,
                    curated: true,
                    created_by: None,
                    created_at: now,
                    updated_at: now,
                };
                let others: Vec<Sib> = files
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(j, f)| Sib { id: 0, slug: format!("the new entry from {f}"), file: f, read: reads[j].clone(), newest: head_rules.get(f).cloned() })
                    .chain(existing.iter().zip(&sib_rules).enumerate().map(|(k, ((e, f), rule))| Sib {
                        id: e.id,
                        slug: e.slug(),
                        file: f.as_str(),
                        read: reads[files.len() + k].clone(),
                        newest: Some(rule.clone()),
                    }))
                    .collect();
                let Exam::Version { tv, rank, error: None, .. } = judge(&provisional, file, None, &r.name, &reads[i], &others, None) else {
                    continue;
                };
                let better = match out.best.get(file) {
                    None => true,
                    Some((br, btv)) => {
                        let key = |tv: &TrackedVersion, rank: i32, name: &str| (tv.track.is_none(), tv.version.clone(), -rank, std::cmp::Reverse(name.to_owned()));
                        key(&tv, rank, &r.name) > key(btv, rank_of[file], &br.name)
                    }
                };
                if better {
                    out.best.insert(file, (r.clone(), tv));
                    rank_of.insert(file, rank);
                }
            }
        }
    }
    Ok(out)
}

/// One row of a registration's preview: an entry it would create (`new`), one already on the
/// repo (`existing`), a manifest it leaves out (`skipped`), or an entry that can't be registered
/// as it is (`fails`), with why in `note`. Serialized as the registration API will serve it.
#[derive(Clone, Debug, serde::Serialize)]
pub struct PreviewEntry {
    pub slug: String,
    pub kind: String,
    pub file: String,
    pub tag: Option<String>,
    pub version: Option<String>,
    pub rule: Option<String>,
    /// For a new entry: `reviewed` or `auto-approved`.
    pub review: Option<String>,
    pub status: &'static str,
    pub note: Option<String>,
    /// The manifest's name (what `--only` and the form's checkboxes name).
    #[serde(skip)]
    pub name: String,
    #[serde(skip)]
    pub commit: Option<String>,
}

/// What registering a repo would do, row by row, and a fingerprint of it: a registration confirmed
/// from a preview is refused when the repo has changed since.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Preview {
    pub url: String,
    pub owner: String,
    pub entries: Vec<PreviewEntry>,
    #[serde(skip)]
    pub fingerprint: String,
}

/// A preview, with the plan behind it and each new entry's reading (aligned with `plan.new`).
pub struct Previewed {
    pub preview: Preview,
    plan: Plan,
    prepared: Vec<Option<Prepared>>,
}

/// The dry run of registering `url` under `owner` (as `user`, if known: whether new entries are
/// reviewed depends on who registers them), writing nothing: [`plan`], then each new entry read at
/// its tag exactly as its first sync will read it.
pub async fn preview(state: &AppState, user: Option<&User>, owner: Option<&str>, url: &str, at: At<'_>) -> AppResult<Previewed> {
    let plan = plan(state, owner, url, at).await?;
    let registering: Vec<String> =
        if plan.new.iter().any(|p| p.kind == "package") { vec![git::normalize_url(&plan.url)] } else { vec![] };
    let opts = PrepOpts { defer_pins: true, registering };
    let skips = user.is_some_and(publish::skips_review) || publish::owner_trusted(state, &plan.owner).await?;
    let mut entries = Vec::new();
    for (e, file) in &plan.existing {
        entries.push(PreviewEntry {
            slug: e.slug(),
            kind: e.kind.clone(),
            file: file.clone(),
            tag: None,
            version: None,
            rule: None,
            review: None,
            status: "existing",
            note: Some("already registered".to_owned()),
            name: e.name.clone(),
            commit: None,
        });
    }
    let mut prepared = Vec::with_capacity(plan.new.len());
    for p in &plan.new {
        let slug = format!("{}/{}", plan.owner, p.name);
        let (status, note, ready) = match &p.problem {
            Some(why) => ("fails", why.clone(), None),
            None => {
                let (entry, repo) = plan.provisional(p);
                match prepare(state, &entry, &repo, &p.co, &p.tag, &p.tv, &opts).await {
                    Ok(r) if r.deferred.is_empty() => ("new", format!("reads cleanly{}{}", sims_note(&r), off_head_note(p)), Some(r)),
                    Ok(r) => ("new", format!("would wait (left unread, tried again): {}{}", r.deferred.join("; "), off_head_note(p)), Some(r)),
                    Err(e) => ("fails", e.to_string(), None),
                }
            }
        };
        entries.push(PreviewEntry {
            slug,
            kind: p.kind.to_owned(),
            file: p.file.to_owned(),
            tag: Some(p.tag.name.clone()),
            version: Some(p.tv.to_string()),
            rule: Some(p.rule.describe_with_since()),
            review: (status == "new").then(|| if skips { "auto-approved" } else { "reviewed" }.to_owned()),
            status,
            note: Some(note),
            name: p.name.clone(),
            commit: Some(p.tag.commit.clone()),
        });
        prepared.push(ready);
    }
    for s in &plan.skipped {
        entries.push(PreviewEntry {
            slug: s.name.as_ref().map(|n| format!("{}/{n}", plan.owner)).unwrap_or_default(),
            kind: kind_of(s.file).to_owned(),
            file: s.file.to_owned(),
            tag: None,
            version: None,
            rule: None,
            review: None,
            status: "skipped",
            note: Some(s.note.clone()),
            name: s.name.clone().unwrap_or_default(),
            commit: None,
        });
    }
    let mut h = <sha2::Sha256 as sha2::Digest>::new();
    for e in &entries {
        let line = format!(
            "{}|{}|{}|{}|{}|{}\n",
            e.status,
            e.slug,
            e.file,
            e.tag.as_deref().unwrap_or(""),
            e.commit.as_deref().unwrap_or(""),
            e.version.as_deref().unwrap_or("")
        );
        sha2::Digest::update(&mut h, line.as_bytes());
    }
    let fingerprint = hex::encode(&sha2::Digest::finalize(h)[..12]);
    Ok(Previewed { preview: Preview { url: plan.url.clone(), owner: plan.owner.clone(), entries, fingerprint }, plan, prepared })
}

/// The preview's mark on a release whose manifest file isn't on the default branch anymore.
fn off_head_note(p: &Planned) -> String {
    if p.off_head {
        format!("; {} isn't on the default branch (a kind the repo dropped? leave it unchecked, or use --only)", p.file)
    } else {
        String::new()
    }
}

/// The namespace a user registers under: `namespace` (theirs to publish under), else their own
/// name.
pub async fn registrant_owner(state: &AppState, user: &User, namespace: Option<&str>) -> AppResult<String> {
    match namespace.map(str::trim).filter(|n| !n.is_empty()) {
        None => Ok(user.username.clone()),
        Some(ns) => {
            ns.parse::<cactup_ecosystem_common::name::Owner>().map_err(AppError::bad)?;
            publish::check_namespace(state, user, ns).await?;
            Ok(ns.to_owned())
        }
    }
}

/// Why a registration confirmed from a preview is refused: the preview is out of date.
pub const PREVIEW_CHANGED: &str = "the repo changed since the preview (its tags or manifests, or the entries on it); check the new preview and confirm again";

/// What a registration made, and what its first versions wait for.
pub struct Registered {
    pub entries: Vec<Entry>,
    /// For each entry made: its manifest file, tag and version.
    pub from: Vec<(String, String, String)>,
    pub notes: Vec<String>,
}

/// Registers the manifests a repo carries as entries, then syncs their tags. The entries go under
/// the user's own name, or under `namespace` (an organization of theirs, or for admins, a name
/// that is no user's, such as `et`). That name must be in each manifest's `owners`: only someone
/// who can push to the repo can put it there. A repo that already has entries gets only the
/// missing ones. `only` names the new entries to register (by manifest name; empty: all of them),
/// and `expect` the fingerprint of the preview they were chosen from: when the repo has changed
/// since, nothing is registered ([`PREVIEW_CHANGED`]). Each new entry is read at its tag first,
/// as its first sync will read it; if one chosen can't be registered, nothing is. The entries are
/// created, attached and audited in one transaction.
#[allow(clippy::too_many_arguments)]
pub async fn register(
    state: &AppState,
    user: &User,
    url: &str,
    namespace: Option<&str>,
    tag: Option<&str>,
    only: &[String],
    expect: Option<&str>,
) -> AppResult<Registered> {
    let owner = registrant_owner(state, user, namespace).await?;
    let at = match tag.map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => At::Tag(t),
        None => At::Newest,
    };
    let Previewed { preview, plan, prepared } = preview(state, Some(user), Some(&owner), url, at).await?;
    if expect.is_some_and(|fp| fp != preview.fingerprint) {
        return Err(AppError::Conflict(PREVIEW_CHANGED.into()));
    }
    for name in only {
        if !plan.new.iter().any(|p| &p.name == name) {
            let names: Vec<&str> = plan.new.iter().map(|p| p.name.as_str()).collect();
            return Err(AppError::bad(format!("no new entry named '{name}' to register (new here: {})", names.join(", "))));
        }
    }
    let chosen = |p: &Planned| only.is_empty() || only.contains(&p.name);
    let failing: Vec<String> = preview
        .entries
        .iter()
        .filter(|e| e.status == "fails" && plan.new.iter().any(|p| p.name == e.name && p.file == e.file && chosen(p)))
        .map(|e| format!("{}@{} (tag {}): {}", e.slug, e.version.as_deref().unwrap_or(""), e.tag.as_deref().unwrap_or(""), e.note.as_deref().unwrap_or("")))
        .collect();
    if !failing.is_empty() {
        return Err(AppError::bad(format!("nothing was registered: {}", failing.join("; "))));
    }
    let mut notes: Vec<String> = plan.skipped.iter().map(|s| s.note.clone()).collect();
    for (p, r) in plan.new.iter().zip(&prepared) {
        let label = format!("{owner}/{}@{}", p.name, p.tv);
        if !chosen(p) {
            notes.push(format!("{owner}/{} ({}) isn't registered now: not chosen; register again to add it", p.name, p.file));
        } else if let Some(r) = r {
            notes.extend(r.deferred.iter().map(|d| format!("{label} waits: {d}")));
        }
    }
    let mut tx = state.db.begin().await?;
    let mut entries = Vec::new();
    let mut from = Vec::new();
    for p in plan.new.iter().filter(|p| chosen(p)) {
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
        from.push((p.file.to_owned(), p.tag.name.clone(), p.tv.to_string()));
    }
    // The entries already on the repo judge their tags again with the new ones as siblings (a new
    // sibling's pattern may claim tags they have read but not frozen).
    // A sync of one of them in flight (in this process or another, such as `just cli`) stores
    // nothing more once their repo's generation is bumped: it judged without the new siblings.
    // The bump waits for a sync's open write to finish (it holds the row), never for the sync.
    let ids: Vec<i64> = plan.existing.iter().map(|(e, _)| e.id).chain(entries.iter().map(|e| e.id)).collect();
    sqlx::query("UPDATE entry_repos SET generation = generation + 1 WHERE entry_id = ANY($1)").bind(&ids).execute(&mut *tx).await?;
    for (e, _) in &plan.existing {
        sqlx::query("DELETE FROM tag_reads WHERE entry_id = $1").bind(e.id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM foreign_tags WHERE entry_id = $1 AND kind IN ('claim', 'unreadable')").bind(e.id).execute(&mut *tx).await?;
    }
    crate::audit::audit_with(
        &mut tx,
        Some(user.id),
        "repo.register",
        Some(&plan.url),
        json!({
            "entries": entries.iter().map(Entry::slug).collect::<Vec<_>>(),
            "from": from.iter().map(|(file, tag, _)| json!({ "file": file, "tag": tag })).collect::<Vec<_>>(),
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
    Ok(Registered { entries, from, notes })
}

/// A preview as lines of text, for the command line.
pub fn preview_lines(p: &Preview) -> Vec<String> {
    let mut lines = Vec::new();
    for e in &p.entries {
        let (tag, version, rule) = (e.tag.as_deref().unwrap_or(""), e.version.as_deref().unwrap_or(""), e.rule.as_deref().unwrap_or(""));
        let note = e.note.as_deref().unwrap_or("");
        match e.status {
            "new" => {
                lines.push(format!(
                    "new {} {} from {} at {tag}: version {version} (its rule: {rule}; {})",
                    e.kind,
                    e.slug,
                    e.file,
                    e.review.as_deref().unwrap_or("")
                ));
                lines.push(format!("  {}@{version}: {note}", e.slug));
            }
            "fails" => lines.push(format!("fails {} {} from {} at {tag}: {note}", e.kind, e.slug, e.file)),
            "existing" => lines.push(format!("existing {} {} ({}): {note}", e.kind, e.slug, e.file)),
            _ => lines.push(format!("skipped {}: {note}", e.file)),
        }
    }
    lines
}

/// A dry run of registering `url` (at `tag`, if one): the preview registering shows, and with a
/// tag, for each entry already on the repo, whether the tag is one of its versions and how it would
/// read. Nothing is written. With `commit`, a tag that doesn't exist yet is read as if it named
/// that commit (a branch or a full commit id), so a release can be checked before it is tagged.
/// Returns the report's lines and whether everything would be read cleanly.
pub async fn check(
    state: &AppState,
    url: &str,
    tag: Option<&str>,
    commit: Option<&str>,
    owner: Option<&str>,
) -> AppResult<(Vec<String>, bool)> {
    let at = match (tag, commit) {
        (Some(tag), Some(c)) => At::Commit { tag, commit: c },
        (Some(tag), None) => At::Tag(tag),
        (None, _) => At::Newest,
    };
    let checked_url = git::check_url(policy(state), url).await.map_err(AppError::bad)?;
    let existing = entries_on(state, &checked_url).await?;
    let mut lines = Vec::new();
    let mut clean = true;
    match preview(state, None, owner, url, at).await {
        Ok(p) => {
            clean = !p.preview.entries.iter().any(|e| e.status == "fails");
            lines.extend(preview_lines(&p.preview));
        }
        Err(AppError::BadRequest(m)) if m.contains("nothing to add") => lines.push("nothing new to register".into()),
        Err(e) => {
            clean = false;
            lines.push(format!("registering would fail: {e}"));
        }
    }
    let Some(tag) = tag else { return Ok((lines, clean)) };
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
        let Some(r) = &r else { continue };
        // What the entry would make of the tag: a curated entry by its overlay's rule; a repo entry
        // by its own manifest at the tag's commit.
        let tv = if repo.overlay_manifest.is_some() {
            let rule = TagRule::of(&repo)?;
            match rule.version(tag) {
                Some(tv) => tv,
                None => {
                    lines.push(format!("{}: {tag} isn't one of its tags (it follows {})", e.slug(), rule.describe()));
                    continue;
                }
            }
        } else {
            let mut unlimited = usize::MAX;
            match examine(state, e, &repo, std::slice::from_ref(r), &mut unlimited).await?.pop() {
                Some(Exam::Version { tv, error: None, .. }) => tv,
                Some(Exam::Version { tv, error: Some(err), .. }) => {
                    clean = false;
                    lines.push(format!("{}@{tv}: would be an invalid version: {err}", e.slug()));
                    continue;
                }
                Some(Exam::Not { why, .. } | Exam::Claimed { why, .. }) => {
                    lines.push(format!("{}: {tag} wouldn't be read as a version: {why}", e.slug()));
                    continue;
                }
                Some(Exam::Wait(why) | Exam::Unexamined(why)) => {
                    lines.push(format!("{}: {tag} would wait (left unread, tried again): {why}", e.slug()));
                    continue;
                }
                None => continue,
            }
        };
        let via = commit.filter(|_| r.name == tag && !remote_has_tag).unwrap_or(tag);
        let co = git::checkout(policy(state), &repo.url, &r.commit, Some(via)).await.map_err(AppError::bad)?;
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
    // No sync of this entry runs while its rule changes.
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
    // The overlay may have changed its rule: this entry's tags are examined again.
    // The entry's own judgments, and claims on the repo it now reads; the old URL's other entries
    // are left alone.
    clear_foreign_on(&mut tx, entry.id).await?;
    tx.commit().await?;
    drop(one_at_a_time);
    sync_as(state, entry, Some(admin), Pace::Now).await
}

/// Admin-only: a curated package whose repo now carries its own cactarium.toml (on its default
/// branch, naming the entry's owner) stops using the overlay. Its name and versions stay; its tag
/// rule becomes the repo manifest's.
pub async fn hand_over(state: &AppState, admin: &User, entry: &Entry) -> AppResult<()> {
    // No sync of this entry runs while its rule changes.
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
    // Its tags are read by the repo's manifests now: they are examined again.
    clear_foreign_on(&mut tx, entry.id).await?;
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

/// Admin-only: a tag recorded as not a version of the entry (of any kind) is examined again under
/// the rules as they are now: its record goes (audited) and the entry is synced, which examines it
/// like a new tag and freezes it if it is a version now. No "not a version" outcome is final.
/// Returns what the tag is afterward.
pub async fn reexamine_tag(state: &AppState, admin: &User, entry: &Entry, tag: &str) -> AppResult<String> {
    if !admin.is_admin() {
        return Err(AppError::Forbidden);
    }
    let tag = tag.trim();
    repo_of(state, entry.id).await?.ok_or_else(|| AppError::bad(format!("{} isn't released from a repo", entry.slug())))?;
    {
        // Not while a sync of this entry (in this process) is between reading and writing.
        let lock = entry_sync_lock(entry.id);
        let _one_at_a_time = lock.lock().await;
        let mut tx = state.db.begin().await?;
        let row: Option<(String, String, String)> =
            sqlx::query_as("DELETE FROM foreign_tags WHERE entry_id = $1 AND tag = $2 RETURNING commit, kind, reason")
                .bind(entry.id)
                .bind(tag)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((commit, kind, reason)) = row else {
            return Err(AppError::bad(format!("{tag} isn't recorded as not a version of {}", entry.slug())));
        };
        crate::audit::audit_with(
            &mut tx,
            Some(admin.id),
            "tag.reexamine",
            Some(&entry.slug()),
            json!({ "tag": tag, "commit": commit, "kind": kind, "reason": reason }),
            None,
        )
        .await?;
        tx.commit().await?;
    }
    // Reviewed as the tag would be if pushed now: the admin doesn't vouch for it.
    let synced = sync_as(state, entry, None, Pace::Now).await;
    let now: Option<(String, String)> = sqlx::query_as("SELECT kind, reason FROM foreign_tags WHERE entry_id = $1 AND tag = $2")
        .bind(entry.id)
        .bind(tag)
        .fetch_optional(&state.db)
        .await?;
    let version: Option<String> = sqlx::query_scalar(
        "SELECT CASE WHEN track = '' THEN version ELSE track || ':' || version END || CASE WHEN state = 'invalid' THEN ' (invalid)' ELSE '' END
         FROM versions WHERE entry_id = $1 AND tag = $2",
    )
    .bind(entry.id)
    .bind(tag)
    .fetch_optional(&state.db)
    .await?;
    let read: Option<String> = sqlx::query_scalar("SELECT label FROM tag_reads WHERE entry_id = $1 AND tag = $2")
        .bind(entry.id)
        .bind(tag)
        .fetch_optional(&state.db)
        .await?;
    Ok(match (version, now, read) {
        (Some(v), _, _) => format!("{tag} examined again: it is now {}@{v}", entry.slug()),
        (None, Some((kind, reason)), _) => format!("{tag} examined again: still not a version ({kind}): {reason}"),
        (None, None, Some(label)) => format!("{tag} examined again: read as {label}, frozen once the tags that could also be it are read"),
        (None, None, None) => match synced {
            Err(e) => format!("{tag}'s record was cleared; it is examined at the next check ({e})"),
            Ok(_) => format!("{tag}'s record was cleared; it is examined at the next check"),
        },
    })
}

/// Admin-only: reads an invalid version of a repo-released (not curated) entry again, at its frozen
/// commit, the way a new tag is read now, or from another tag its own manifest reads as exactly that
/// version. An invalid version was never served, so nothing depended on it (the argument of
/// migration 0009): one that now reads cleanly becomes valid and is reviewed as a pushed tag is;
/// one whose tag is no version of the entry at all (examined per commit) is removed and recorded
/// so. A version that still fails stays as it was, and the reason is returned as the error.
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
    // The frozen tag first; then any other tag its own manifest reads as exactly this version (say,
    // the real v1.0.0 beside an old bare 1.0.0 that took the version), best spelling first. Only
    // tags that could be this version are examined: those the standard form or a rule the entry is
    // known to use reads as it, and those already read as it.
    let frozen = RemoteRef { name: tag.clone(), commit: commit.clone() };
    let all = git::ls_tags(policy(state), &repo.url)
        .await
        .map_err(|e| AppError::Upstream(format!("cannot list the repo's tags: {e:#}")))?;
    let rules = known_rules(state, entry.id).await?;
    let read_as: std::collections::BTreeSet<String> = sqlx::query_scalar("SELECT tag FROM tag_reads WHERE entry_id = $1 AND label = $2")
        .bind(entry.id)
        .bind(v.label())
        .fetch_all(&state.db)
        .await?
        .into_iter()
        .collect();
    let others: Vec<RemoteRef> = all
        .into_iter()
        .filter(|o| o.name != tag && (read_as.contains(&o.name) || rules.iter().any(|r| r.version(&o.name).as_ref() == Some(&tv))))
        .collect();
    let mut tags = vec![frozen.clone()];
    tags.extend(others);
    let mut unlimited = usize::MAX;
    let exams = examine(state, entry, &repo, &tags, &mut unlimited).await?;
    let mut candidates: Vec<(RemoteRef, i32)> = Vec::new();
    let mut frozen_foreign = None;
    for (i, (r, exam)) in tags.iter().zip(exams).enumerate() {
        match exam {
            Exam::Version { tv: read, rank, error: None, .. } if read == tv => candidates.push((r.clone(), if i == 0 { -1 } else { rank })),
            Exam::Not { kind, why } if i == 0 => frozen_foreign = Some((kind, why, None)),
            Exam::Claimed { by, why } if i == 0 => frozen_foreign = Some(("claim", why, Some(by))),
            Exam::Wait(why) | Exam::Unexamined(why) if i == 0 => return Err(AppError::Upstream(why)),
            _ => {}
        }
    }
    candidates.sort_by(|a, b| (a.1, &a.0.name).cmp(&(b.1, &b.0.name)));
    let mut first_error = None;
    let mut found = None;
    for (r, _) in &candidates {
        let co = git::checkout(policy(state), &repo.url, &r.commit, Some(&r.name))
            .await
            .map_err(|e| AppError::Upstream(format!("cannot fetch {}: {e:#}", r.commit)))?;
        match prepare(state, entry, &repo, &co, r, &tv, &PrepOpts::default()).await {
            Ok(p) => {
                found = Some((r.clone(), co, p));
                break;
            }
            Err(AppError::BadRequest(m)) => {
                first_error.get_or_insert(AppError::BadRequest(if r.name == tag { m } else { format!("{} also fails: {m}", r.name) }));
            }
            Err(e) => return Err(e),
        }
    }
    let Some((r, co, p)) = found else {
        if let Some((kind, why, by)) = frozen_foreign {
            let mut tx = state.db.begin().await?;
            sqlx::query("DELETE FROM versions WHERE id = $1 AND state = 'invalid'").bind(v.id).execute(&mut *tx).await?;
            forget_duplicates_of(&mut tx, entry.id, &v.label()).await?;
            record_foreign_in(&mut tx, entry.id, &frozen, (kind, &why), by).await?;
            crate::audit::audit_with(&mut tx, Some(admin.id), "version.reread", Some(&entry.slug()), json!({ "version": label, "tag": tag, "now": "not the entry's", "why": why }), None).await?;
            tx.commit().await?;
            return Ok(format!("{tag} isn't {}'s tag ({why}); the invalid version was removed", entry.slug()));
        }
        return Err(first_error.unwrap_or_else(|| AppError::bad(format!("{}@{label}: no tag of that version reads cleanly", entry.slug()))));
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
    // The tag read is the version's now; the one it was frozen from is no longer a version of it.
    for table in ["foreign_tags", "tag_reads"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE entry_id = $1 AND tag = $2")).bind(entry.id).bind(&r.name).execute(&mut *tx).await?;
    }
    if r.name != tag {
        sqlx::query(
            "INSERT INTO foreign_tags (entry_id, tag, commit, reason, kind) VALUES ($1, $2, $3, $4, 'duplicate')
             ON CONFLICT (entry_id, tag) DO UPDATE SET commit = EXCLUDED.commit, reason = EXCLUDED.reason, kind = EXCLUDED.kind, seen_at = now()",
        )
        .bind(entry.id)
        .bind(&tag)
        .bind(&commit)
        .bind(format!("version {label} is already another tag's"))
        .execute(&mut *tx)
        .await?;
    }
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
    /// Bumped when registering another entry on the repo clears this one's records: a sync
    /// stores nothing once it differs from the value the sync started with.
    pub generation: i64,
}

pub async fn repo_of(state: &AppState, entry_id: i64) -> AppResult<Option<RepoRow>> {
    Ok(sqlx::query_as::<_, RepoRow>(
        "SELECT url, manifest_file, webhook_secret, overlay_manifest, tag_pattern, min_version, sim_form, generation FROM entry_repos WHERE entry_id = $1",
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
    label: String,
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
    // As it is now, under the lock: a hand-over or a transfer may have changed it meanwhile.
    let entry = &model::entry_by_id(state, entry.id).await?;
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
    let result = match sync_inner(state, entry, &repo, actor, pace).await {
        // A registration on the repo cleared this entry's records meanwhile: nothing more was
        // stored, and the next sync reads the rest.
        Err(AppError::Conflict(m)) if m == STALE_SYNC => {
            tracing::info!("sync of {} stopped: {m}", entry.slug());
            Ok(0)
        }
        other => other,
    };
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
    let known = known_versions(state, entry.id).await?;
    let mut forgot = false;
    for k in &known {
        let (Some(tag), Some(frozen)) = (&k.tag, &k.commit) else { continue };
        match remote.get(tag) {
            // An invalid version was never served: when its tag moves, the tag is read again at its
            // new commit (the invalid row goes, recorded in the audit log).
            Some(now) if now != frozen && k.state == "invalid" => {
                forget_invalid(state, entry, k, tag, frozen, Some(now)).await?;
                forgot = true;
            }
            // Deleted upstream: an invalid version (never served) goes; the version's other tags,
            // if any, are examined again.
            None if k.state == "invalid" => {
                forget_invalid(state, entry, k, tag, frozen, None).await?;
                forgot = true;
            }
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
    let known = if forgot { known_versions(state, entry.id).await? } else { known };
    let by_tag: BTreeMap<&str, &Known> =
        known.iter().filter_map(|k| k.tag.as_deref().map(|t| (t, k))).collect();
    // Versions the entry has, by label, whatever tag froze them: another tag naming one of them (a
    // bare 1.0.0 beside v1.0.0) is no new version.
    let have = version_labels(state, entry.id).await?;

    // Tags found not to be versions of this entry: skipped while they name the commit they were
    // judged at; a tag that moved is judged again, and one that is gone is forgotten.
    let foreign = foreign_of(state, entry.id, &remote).await?;
    // Tags left unread earlier (waiting_tags): tried again after the new ones, with backoff.
    let waiting = waiting_of(state, entry.id, &remote).await?;
    let mut run = Run::default();
    if repo.overlay_manifest.is_some() {
        // A curated entry: its overlay manifest is read at every tag, so its stored rule decides.
        let candidates: Vec<Candidate> = version_tags(refs, &TagRule::of(repo)?)
            .into_iter()
            .filter(|(r, tv)| {
                !by_tag.contains_key(r.name.as_str()) && foreign.get(&r.name) != Some(&r.commit) && !have.contains(&tv.to_string())
            })
            .map(|(r, tv)| Candidate { r, tv, preset: None, note: None })
            .collect();
        ingest_all(state, entry, repo, actor, pace, candidates, &waiting, &mut run).await?;
    } else {
        examine_and_ingest(state, entry, repo, actor, pace, refs, &by_tag, &foreign, &waiting, &mut run).await?;
    }
    if run.added > 0 {
        publish::touch(state, entry.id).await?;
        // For a repo entry, the stored rule is only what its page says it follows: the newest
        // version's manifest's. Each tag is read by the manifest in it.
        if repo.overlay_manifest.is_none() {
            let newest = newest_rule(state, entry.id).await?;
            if let Some(rule) = newest {
                let (pattern, since) = rule.stored();
                sqlx::query("UPDATE entry_repos SET tag_pattern = $2, min_version = $3 WHERE entry_id = $1 AND overlay_manifest IS NULL")
                    .bind(entry.id)
                    .bind(pattern)
                    .bind(since)
                    .execute(&state.db)
                    .await?;
            }
        }
    }
    // What couldn't be read is reported (it becomes the repo's poll error) and tried again.
    if !run.unfetched.is_empty() {
        return Err(AppError::Upstream(format!(
            "{} new version(s) read; {} tag(s) will be tried again at the next sync: {}",
            run.added,
            run.unfetched.len(),
            run.unfetched.join("; ")
        )));
    }
    Ok(run.added)
}

/// What one sync did so far.
#[derive(Default)]
struct Run {
    added: usize,
    /// Tags read to a conclusion (a version, or not one), toward [`MAX_NEW_PER_SYNC`].
    read: usize,
    /// Why tags were left unread, for the poll error.
    unfetched: Vec<String>,
}

async fn known_versions(state: &AppState, entry_id: i64) -> AppResult<Vec<Known>> {
    Ok(sqlx::query_as(
        "SELECT id, tag, commit, state, CASE WHEN track = '' THEN version ELSE track || ':' || version END AS label
         FROM versions WHERE entry_id = $1 AND NOT is_virtual",
    )
        .bind(entry_id)
        .fetch_all(&state.db)
        .await?)
}

async fn version_labels(state: &AppState, entry_id: i64) -> AppResult<std::collections::BTreeSet<String>> {
    Ok(sqlx::query_scalar(
        "SELECT CASE WHEN track = '' THEN version ELSE track || ':' || version END FROM versions WHERE entry_id = $1",
    )
    .bind(entry_id)
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .collect())
}

/// The rule of the entry's newest valid version's manifest.
async fn newest_rule(state: &AppState, entry_id: i64) -> AppResult<Option<TagRule>> {
    let newest: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT manifest FROM versions WHERE entry_id = $1 AND manifest IS NOT NULL AND state <> 'invalid'
         ORDER BY (track = '') DESC, sort_key DESC LIMIT 1",
    )
    .bind(entry_id)
    .fetch_optional(&state.db)
    .await?
    .flatten();
    Ok(newest.and_then(|m| serde_json::from_value::<Manifest>(m).ok()).map(|m| TagRule::of_manifest(&m)))
}

/// The entry's "not a version" records (tag → commit), forgetting tags deleted upstream.
async fn foreign_of(state: &AppState, entry_id: i64, remote: &BTreeMap<String, String>) -> AppResult<BTreeMap<String, String>> {
    let foreign: BTreeMap<String, String> =
        sqlx::query_as::<_, (String, String)>("SELECT tag, commit FROM foreign_tags WHERE entry_id = $1")
            .bind(entry_id)
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .collect();
    let gone: Vec<&str> = foreign.keys().filter(|t| !remote.contains_key(*t)).map(String::as_str).collect();
    if !gone.is_empty() {
        sqlx::query("DELETE FROM foreign_tags WHERE entry_id = $1 AND tag = ANY($2)")
            .bind(entry_id)
            .bind(&gone)
            .execute(&state.db)
            .await?;
    }
    Ok(foreign.into_iter().filter(|(t, _)| remote.contains_key(t)).collect())
}

/// An invalid version whose tag moved (`now`) or was deleted upstream (`None`): it was never
/// served, so the row goes, and the tag (if it is still there) is read again at its new commit like
/// a new tag. Tags set aside as duplicates of its version are examined again too. Audited.
async fn forget_invalid(state: &AppState, entry: &Entry, k: &Known, tag: &str, frozen: &str, now: Option<&String>) -> AppResult<()> {
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM versions WHERE id = $1 AND state = 'invalid'").bind(k.id).execute(&mut *tx).await?;
    forget_duplicates_of(&mut tx, entry.id, &k.label).await?;
    let (action, then) = match now {
        Some(_) => ("version.invalid-tag-moved", "read again at the new commit"),
        None => ("version.invalid-tag-deleted", "removed; its version's other tags are examined again"),
    };
    crate::audit::audit_with(
        &mut tx,
        None,
        action,
        Some(&entry.slug()),
        json!({ "tag": tag, "version": k.label, "frozen": frozen, "now": now, "then": then }),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Forgets the records of tags set aside because `label` was another tag's: that version is gone,
/// so they are examined again.
async fn forget_duplicates_of(db: &mut sqlx::PgConnection, entry_id: i64, label: &str) -> AppResult<()> {
    sqlx::query("DELETE FROM foreign_tags WHERE entry_id = $1 AND kind = 'duplicate' AND reason = $2")
        .bind(entry_id)
        .bind(format!("version {label} is already another tag's"))
        .execute(&mut *db)
        .await?;
    Ok(())
}

/// A tag to freeze as a version: with `preset`, invalid with that reason, without reading the
/// commit; `note` goes to reviewers.
struct Candidate {
    r: RemoteRef,
    tv: TrackedVersion,
    preset: Option<String>,
    note: Option<String>,
}

/// Ingests candidate tags: new ones first (at most [`MAX_NEW_PER_SYNC`] concluded, and at most
/// [`MAX_WAITING_PER_SYNC`] that turn out to wait), then waiting ones (at most
/// [`MAX_WAITING_PER_SYNC`], honoring backoff in the background). A candidate with a reason
/// (`Some`) is frozen invalid with it, without reading the commit.
#[allow(clippy::too_many_arguments)]
async fn ingest_all(
    state: &AppState,
    entry: &Entry,
    repo: &RepoRow,
    actor: Option<&User>,
    pace: Pace,
    candidates: Vec<Candidate>,
    waiting: &BTreeMap<String, Waiting>,
    run: &mut Run,
) -> AppResult<()> {
    let (retry, fresh): (Vec<_>, Vec<_>) =
        candidates.into_iter().partition(|c| waiting.get(&c.r.name).is_some_and(|w| w.commit == c.r.commit));
    // New tags that turn out to wait are capped too, so one sync (a registration's, say) never
    // tries hundreds of them; the rest are new again at the next sync.
    let (mut new_waiting, mut new_later) = (0, 0);
    for Candidate { r, tv, preset, note } in &fresh {
        if run.read == MAX_NEW_PER_SYNC {
            break;
        }
        if new_waiting == MAX_WAITING_PER_SYNC {
            new_later += 1;
            continue;
        }
        match ingest(state, entry, repo, r, tv, actor, preset.as_deref(), note.as_deref()).await {
            Ok(outcome) => {
                run.read += 1;
                if matches!(outcome, Ingested::Version) {
                    run.added += 1;
                }
                // A tag that waited at another commit and moved since.
                done_waiting(state, entry.id, &r.name).await?;
            }
            Err(AppError::Upstream(why)) => {
                new_waiting += 1;
                run.unfetched.push(wait(state, entry, r, why).await);
            }
            Err(e) => return Err(e),
        }
    }
    if new_later > 0 {
        run.unfetched.push(format!("{new_later} more new tag(s) not tried this time (at most {MAX_WAITING_PER_SYNC} new tags wait per check)"));
    }
    let (mut tried, mut later) = (0, 0);
    for Candidate { r, tv, preset, note } in &retry {
        let w = &waiting[&r.name];
        if tried == MAX_WAITING_PER_SYNC || (pace == Pace::Background && w.next_try_at > time::OffsetDateTime::now_utc()) {
            later += 1;
            continue;
        }
        tried += 1;
        match ingest(state, entry, repo, r, tv, actor, preset.as_deref(), note.as_deref()).await {
            Ok(outcome) => {
                if matches!(outcome, Ingested::Version) {
                    run.added += 1;
                }
                done_waiting(state, entry.id, &r.name).await?;
            }
            Err(AppError::Upstream(why)) => run.unfetched.push(wait(state, entry, r, why).await),
            Err(e) => return Err(e),
        }
    }
    if later > 0 {
        run.unfetched.push(format!("{later} more waiting tag(s) not tried this time (each backs off, up to 6 hours apart)"));
    }
    Ok(())
}

/// What examining a tag for an entry found: what the entry's manifest at the tag's commit makes of
/// the tag.
#[derive(Clone, Debug, PartialEq)]
enum Exam {
    /// A version, `tv`, spelled with this rank ([`spelling_rank`] under the manifest's own rule).
    /// With `error`, the manifest is unreadable and the version is frozen invalid with it. `note`
    /// is for reviewers (a sibling manifest there that couldn't be read); `pattern` is the
    /// manifest's own `tag-pattern`, if any.
    Version { tv: TrackedVersion, rank: i32, error: Option<String>, note: Option<String>, pattern: Option<String> },
    /// Not a version of this entry: a kind (for `foreign_tags`) and why.
    Not { kind: &'static str, why: String },
    /// Not a version of this entry: taken as the sibling `by`'s, whose manifest at that commit
    /// can't be read, by that sibling's rule as it is now (a `claim`, examined again once that rule
    /// no longer reads the tag).
    Claimed { by: i64, why: String },
    /// A fact about the tag that can't be judged by this server yet (a newer format, its own or a
    /// sibling's at that commit): recorded as waiting, tried again with backoff.
    Wait(String),
    /// The repo couldn't be read right now, or this sync has used its checkouts: nothing is
    /// recorded, and the tag is examined again at the next sync.
    Unexamined(String),
}

/// Why a tag is [`Exam::Unexamined`] when the sync has used its checkouts.
const CHECKOUTS_USED: &str = "needs a checkout to be examined";

/// A manifest file as examining reads it.
#[derive(Clone, Debug)]
enum Read {
    Absent,
    Text(String),
    /// There, but not readable as text: why.
    Unreadable(String),
}

impl Read {
    fn of(file: &str, f: git::FileAt) -> Read {
        match f {
            git::FileAt::Absent => Read::Absent,
            git::FileAt::TooLarge(Some(n)) => Read::Unreadable(format!("{file} is larger than 4 MB ({n} bytes)")),
            git::FileAt::TooLarge(None) => Read::Unreadable(format!("{file} is larger than 4 MB")),
            git::FileAt::Content(bytes) => match String::from_utf8(bytes) {
                Ok(t) => Read::Text(t),
                Err(_) => Read::Unreadable(format!("'{file}' is not UTF-8 text")),
            },
            // Resolved by the caller; never judged.
            git::FileAt::NeedsCheckout | git::FileAt::NotCommit | git::FileAt::Unavailable => {
                Read::Unreadable(format!("{file} couldn't be read"))
            }
        }
    }
}

/// A sibling entry's manifest at a tag's commit, for [`judge`]: its id and slug, its file, the file
/// as read, and the rule it is taken to have when the file can't be read ([`unreadable_rule`]).
struct Sib<'a> {
    id: i64,
    slug: String,
    file: &'a str,
    read: Read,
    newest: Option<TagRule>,
}

/// The rank of a version read from an unreadable manifest: any readable one wins over it.
const UNREADABLE_RANK: i32 = 9;

/// The rule an entry's unreadable manifest is taken to have, given [`unreadable_rule`]'s answer.
fn rule_for_unreadable(newest: Option<&TagRule>) -> TagRule {
    newest.cloned().unwrap_or_default()
}

/// The rule an entry's manifest that can't be read is taken to have: its newest version's, else
/// the rule stored with its repo (its registration's manifest's while it has no version), else the
/// standard form. Never the standard form when the entry follows a pattern of its own.
async fn unreadable_rule(state: &AppState, entry_id: i64) -> AppResult<TagRule> {
    if let Some(n) = newest_rule(state, entry_id).await? {
        return Ok(n);
    }
    Ok(repo_of(state, entry_id).await?.and_then(|r| TagRule::of(&r).ok()).unwrap_or_default())
}

/// What the entry's manifest at a tag's commit makes of the tag (see the publishing docs): a tag
/// is a version exactly when the entry's manifest file is in its commit and that manifest's own
/// rule (`tag-pattern`, else `[track/]vX.Y.Z`, and its own `since`) reads it as one, the manifest
/// names the entry and lists its owner, the sims' form is the entry's, and no sibling's manifest at
/// that commit claims the tag. A readable sibling manifest claims it with its own pattern; a
/// sibling manifest there that can't be read claims it when the rule of the sibling's newest
/// version (the standard form when it has none) reads it. The entry's own manifest unreadable is a
/// version (invalid, with the error) when the rule of the entry's newest version (the standard form
/// when it has none) reads the tag and no sibling's manifest there reads it; otherwise it isn't one.
/// What the entry can settle alone (its manifest absent, its rule not reading the tag, another name)
/// is settled first; only a tag it would take waits for a sibling manifest of a newer format, which
/// may claim it.
fn judge(entry: &Entry, file: &str, form: Option<&str>, tag: &str, own: &Read, sibs: &[Sib], newest: Option<&TagRule>) -> Exam {
    let mut sib_rules: Vec<(&str, TagRule)> = Vec::new();
    // Siblings whose manifest here can't be read: id, slug, why, and the rule they are taken to have.
    let mut broken: Vec<(i64, &str, String, TagRule)> = Vec::new();
    let mut newer: Option<String> = None;
    for s in sibs {
        let why = match &s.read {
            Read::Absent => continue,
            Read::Unreadable(why) => why.clone(),
            Read::Text(text) => match Manifest::from_repo_file(s.file, text) {
                Ok(m) => {
                    sib_rules.push((s.slug.as_str(), TagRule::of_manifest(&m)));
                    continue;
                }
                Err(e @ cactup_ecosystem_common::Error::NewerFormat { .. }) => {
                    newer.get_or_insert(format!("{}'s {} at {tag}: {e}, so whether it claims {tag} can't be told yet", s.slug, s.file));
                    continue;
                }
                Err(e) => e.to_string(),
            },
        };
        broken.push((s.id, s.slug.as_str(), format!("{}'s {} at this commit can't be read ({why})", s.slug, s.file), rule_for_unreadable(s.newest.as_ref())));
    }
    // A broken sibling manifest is taken to follow its entry's rule. Against a manifest here that
    // can't be read either, it takes the tag when that rule reads it at all; against a readable one,
    // only as a readable one would: with a distinct pattern this one doesn't share.
    let broken_claim = |own: Option<&TagRule>| {
        broken
            .iter()
            .find_map(|(id, slug, why, r)| {
                let claims = match own {
                    None => r.version(tag).map(|_| format!("the rule it follows ({}) reads {tag}", r.describe_with_since())),
                    Some(own) => claimed_by(tag, own, r).map(|w| format!("by the rule it follows, {w}")),
                };
                claims.map(|c| (*id, format!("{why}, and {c}, so it is taken as {slug}'s")))
            })
            .map(|(by, why)| Exam::Claimed { by, why })
    };
    let notes: Vec<String> = broken.iter().map(|(_, _, why, _)| format!("{why}, so it claims nothing here")).collect();
    let note = (!notes.is_empty()).then(|| notes.join("; "));
    let unreadable = |error: String| {
        let rule = rule_for_unreadable(newest);
        let Some(tv) = rule.version(tag) else {
            return Exam::Not {
                kind: "unreadable",
                why: format!("{error}; {tag} isn't a version under the rule of the newest version ({})", rule.describe_with_since()),
            };
        };
        if let Some(why) = &newer {
            return Exam::Wait(why.clone());
        }
        if let Some((slug, _)) = sib_rules.iter().find(|(_, r)| r.version(tag).is_some()) {
            return Exam::Not { kind: "claim", why: format!("{error}; and {slug} reads {tag} as its own, so it isn't taken as this entry's") };
        }
        if let Some(claim) = broken_claim(None) {
            return claim;
        }
        Exam::Version { tv, rank: UNREADABLE_RANK, error: Some(error), note: note.clone(), pattern: None }
    };
    let text = match own {
        Read::Absent => return Exam::Not { kind: "absent", why: format!("no {file}") },
        Read::Unreadable(why) => return unreadable(why.clone()),
        Read::Text(t) => t,
    };
    let m = match Manifest::from_repo_file(file, text) {
        Ok(m) => m,
        Err(e @ cactup_ecosystem_common::Error::NewerFormat { .. }) => {
            return Exam::Wait(format!("{file} at {tag}: {e} (this server reads it once it is upgraded)"));
        }
        Err(e) => return unreadable(format!("{file}: {e}")),
    };
    let rule = TagRule::of_manifest(&m);
    let Some(tv) = rule.version(tag) else {
        return Exam::Not { kind: "rule", why: format!("its {file} follows {}, which {tag} isn't one of", rule.describe_with_since()) };
    };
    if name_of(&m) != entry.name {
        return Exam::Not { kind: "identity", why: format!("its {file} names '{}', not '{}'", name_of(&m), entry.name) };
    }
    if !entry.curated && !owners_of(&m).contains(&entry.owner) {
        return Exam::Not { kind: "identity", why: format!("its {file} doesn't list '{}' in owners", entry.owner) };
    }
    if let (Some(fixed), Some(here)) = (form, sim_form_of(&m))
        && fixed != here
    {
        return Exam::Not {
            kind: "form",
            why: format!("its {file} uses {}, but this entry publishes {} (fixed when it was registered)", form_words(&here), form_words(fixed)),
        };
    }
    if let Some(why) = newer {
        return Exam::Wait(why);
    }
    for (slug, theirs) in &sib_rules {
        if let Some(why) = claimed_by(tag, &rule, theirs) {
            return Exam::Not { kind: "claim", why: format!("it is {slug}'s release: {why}") };
        }
    }
    if let Some(claim) = broken_claim(Some(&rule)) {
        return claim;
    }
    let rank = i32::from(spelling_rank(&rule, tag, &tv));
    Exam::Version { tv, rank, error: None, note, pattern: rule.pattern.as_ref().map(|p| p.as_str().to_owned()) }
}

/// Files at a tag's commit, as [`read_tags`] reads them.
enum TagFiles {
    /// Each file asked for, in order.
    Reads(Vec<Read>),
    /// A fact about the tag that makes it no version of anything (a tree, a commit too large).
    Not { kind: &'static str, why: String },
    /// Couldn't be read now (see [`Exam::Unexamined`]).
    Unexamined(String),
}

/// Reads `files` at each tag's commit from the repo's history mirror; a file the mirror can't give
/// as plain content (a symbolic link, or a host that refuses blobs by id) is read from a checkout,
/// with `read_in`'s containment rules, while `checkouts` lasts (each one used counts down; past it,
/// the tag is unexamined). When the repo can't be read at all, every tag is unexamined.
async fn read_tags(state: &AppState, url: &str, tags: &[RemoteRef], files: &[String], checkouts: &mut usize) -> Vec<TagFiles> {
    let wants: Vec<(String, String)> = tags.iter().flat_map(|r| files.iter().map(|f| (r.commit.clone(), f.clone()))).collect();
    let got = match git::read_files_at(policy(state), url, &wants).await {
        Ok(f) => f,
        Err(e) => {
            let why = format!("cannot read the repo's manifests right now: {e:#}");
            return tags.iter().map(|_| TagFiles::Unexamined(why.clone())).collect();
        }
    };
    let mut out = Vec::with_capacity(tags.len());
    for (i, r) in tags.iter().enumerate() {
        let chunk: Vec<git::FileAt> = got[i * files.len()..(i + 1) * files.len()].to_vec();
        if chunk.iter().any(|f| matches!(f, git::FileAt::NotCommit)) {
            out.push(TagFiles::Not { kind: "not-commit", why: format!("{} names a tree or a file, not a commit", r.name) });
            continue;
        }
        if chunk.iter().any(|f| matches!(f, git::FileAt::Unavailable)) {
            out.push(TagFiles::Unexamined(format!("{}: its commit isn't in the repo's history yet", r.name)));
            continue;
        }
        let co = if chunk.iter().any(|f| matches!(f, git::FileAt::NeedsCheckout)) {
            if *checkouts == 0 {
                out.push(TagFiles::Unexamined(CHECKOUTS_USED.to_owned()));
                continue;
            }
            *checkouts -= 1;
            match git::checkout(policy(state), url, &r.commit, Some(&r.name)).await {
                Ok(co) => Some(co),
                // A fact about the commit, as when a version is frozen: whose release it is can't
                // be read, so it is no version (examined again if the tag moves).
                Err(e) if e.downcast_ref::<git::TooLarge>().is_some() => {
                    out.push(TagFiles::Not { kind: "large", why: format!("the tagged commit is too large to read: {e:#}") });
                    continue;
                }
                Err(e) => {
                    out.push(TagFiles::Unexamined(format!("{}: cannot fetch it ({e:#})", r.name)));
                    continue;
                }
            }
        } else {
            None
        };
        let reads: Vec<Read> = chunk
            .into_iter()
            .zip(files)
            .map(|(f, file)| match (f, &co) {
                (git::FileAt::NeedsCheckout, Some(co)) => match git::read_in(co, file) {
                    Ok(Some(text)) => Read::Text(text),
                    Ok(None) => Read::Absent,
                    Err(e) => Read::Unreadable(format!("{e:#}")),
                },
                (other, _) => Read::of(file, other),
            })
            .collect();
        out.push(TagFiles::Reads(reads));
    }
    out
}

/// Examines tags for an entry, reading its manifest (and its siblings', for claims) at each commit
/// from the repo's history mirror; a file the mirror can't give as plain content (a symbolic link,
/// or a host that refuses blobs by id) is read from a checkout, with `read_in`'s containment rules,
/// while `checkouts` lasts (each one used counts down; past it, the tag is unexamined). Each tag's
/// outcome stands alone; when the repo can't be read at all, every tag is [`Exam::Unexamined`].
async fn examine(state: &AppState, entry: &Entry, repo: &RepoRow, tags: &[RemoteRef], checkouts: &mut usize) -> AppResult<Vec<Exam>> {
    if tags.is_empty() {
        return Ok(Vec::new());
    }
    let sibs: Vec<(Entry, String)> = entries_on(state, &repo.url).await?.into_iter().filter(|(e, _)| e.id != entry.id).collect();
    let mut sib_newest: Vec<Option<TagRule>> = Vec::with_capacity(sibs.len());
    for (e, _) in &sibs {
        sib_newest.push(Some(unreadable_rule(state, e.id).await?));
    }
    let files: Vec<String> = std::iter::once(repo.manifest_file.clone()).chain(sibs.iter().map(|(_, f)| f.clone())).collect();
    let got = read_tags(state, &repo.url, tags, &files, checkouts).await;
    let newest = Some(unreadable_rule(state, entry.id).await?);
    let mut out = Vec::with_capacity(tags.len());
    for (r, got) in tags.iter().zip(got) {
        let reads = match got {
            TagFiles::Reads(reads) => reads,
            TagFiles::Not { kind, why } => {
                out.push(Exam::Not { kind, why });
                continue;
            }
            TagFiles::Unexamined(why) => {
                out.push(Exam::Unexamined(why));
                continue;
            }
        };
        let theirs: Vec<Sib> = sibs
            .iter()
            .zip(&sib_newest)
            .zip(reads.iter().skip(1))
            .map(|(((e, f), n), rd)| Sib { id: e.id, slug: e.slug(), file: f.as_str(), read: rd.clone(), newest: n.clone() })
            .collect();
        out.push(judge(entry, &repo.manifest_file, fixed_form(entry, repo), &r.name, &reads[0], &theirs, newest.as_ref()));
    }
    Ok(out)
}

/// Every rule a tag of the entry might be read by, for telling which versions an unexamined tag
/// could turn out to be: the standard form, the newest version's rule, the rule stored with the
/// repo (set at registration), the pattern of every version's manifest, and the pattern of every
/// manifest a pending read came from.
async fn known_rules(state: &AppState, entry_id: i64) -> AppResult<Vec<TagRule>> {
    let mut rules = vec![TagRule::default()];
    if let Some(n) = newest_rule(state, entry_id).await? {
        rules.push(n);
    }
    if let Some(repo) = repo_of(state, entry_id).await?
        && let Ok(stored) = TagRule::of(&repo)
    {
        rules.push(TagRule { pattern: stored.pattern, since: None });
    }
    let patterns: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT DISTINCT COALESCE(manifest->'package'->>'tag-pattern', manifest->'stack'->>'tag-pattern', manifest->'sim'->>'tag-pattern')
         FROM versions WHERE entry_id = $1 AND manifest IS NOT NULL
         UNION SELECT DISTINCT pattern FROM tag_reads WHERE entry_id = $1",
    )
    .bind(entry_id)
    .fetch_all(&state.db)
    .await?;
    for p in patterns.into_iter().flatten() {
        if let Ok(pattern) = p.parse() {
            rules.push(TagRule { pattern: Some(pattern), since: None });
        }
    }
    Ok(rules)
}

/// Tags examined per [`examine`] call while syncing: each group's outcomes are stored before the
/// next is read, so a sync stopped for time keeps what it examined.
const EXAMINE_GROUP: usize = 10;

/// What one sync may still examine: tags, and tags read from a checkout.
struct Budget {
    examine: usize,
    checkouts: usize,
}

/// A repo entry's tags, read per commit: new tags are examined (at most the configured number per
/// sync, standard spellings first, then by name), recording each outcome as it comes; then the tags
/// read as versions are frozen, one per version: the best spelling under its own manifest's rule,
/// then the first by name. A version is not frozen while a tag that could be read as it (under the
/// standard form or a rule the entry is known to use) is still unexamined or waiting, so which tag
/// wins doesn't depend on how the examining was paged or delayed. When freezing changes the rule
/// of the entry's newest version, tags set aside because their unreadable manifest's version wasn't
/// one under the old rule, and that the new rule reads, are examined again.
#[allow(clippy::too_many_arguments)]
async fn examine_and_ingest(
    state: &AppState,
    entry: &Entry,
    repo: &RepoRow,
    actor: Option<&User>,
    pace: Pace,
    refs: Vec<RemoteRef>,
    by_tag: &BTreeMap<&str, &Known>,
    foreign: &BTreeMap<String, String>,
    waiting: &BTreeMap<String, Waiting>,
    run: &mut Run,
) -> AppResult<()> {
    let reads = reads_of(state, entry.id, &refs).await?;
    let open: Vec<&RemoteRef> = refs
        .iter()
        .filter(|r| {
            !by_tag.contains_key(r.name.as_str())
                && foreign.get(&r.name) != Some(&r.commit)
                && reads.get(&r.name).map(|x| &x.commit) != Some(&r.commit)
        })
        .collect();
    // Tags whose examining waits (a newer format) are retried with backoff.
    let (mut retry, mut fresh): (Vec<&RemoteRef>, Vec<&RemoteRef>) =
        open.into_iter().partition(|r| waiting.get(&r.name).is_some_and(|w| w.commit == r.commit));
    let standard_first = |r: &&RemoteRef| {
        let standard = TrackedVersion::from_tag(&r.name).is_some_and(|tv| tv.conventional_tag() == r.name);
        (!standard, r.name.clone())
    };
    fresh.sort_by_key(standard_first);
    retry.sort_by_key(standard_first);
    let cap = state.cfg.examine_per_sync;
    let mut budget = Budget { examine: cap, checkouts: state.cfg.checkouts_per_sync };
    let now = time::OffsetDateTime::now_utc();
    let (retry_now, retry_later): (Vec<&RemoteRef>, Vec<&RemoteRef>) =
        retry.iter().partition(|r| pace == Pace::Now || waiting[&r.name].next_try_at <= now);
    let retry_skipped: Vec<&RemoteRef> = retry_later.into_iter().chain(retry_now.iter().skip(MAX_WAITING_PER_SYNC).copied()).collect();
    let retry_now: Vec<RemoteRef> = retry_now.into_iter().take(MAX_WAITING_PER_SYNC).cloned().collect();
    let batch: Vec<RemoteRef> = fresh.iter().take(budget.examine).map(|r| (*r).clone()).collect();
    budget.examine -= batch.len();
    // Tags that might yet be read as some version: not examined (beyond the cap, or the repo
    // unreadable), or waiting.
    let mut pending: Vec<RemoteRef> = fresh.iter().skip(cap).map(|r| (*r).clone()).chain(retry_skipped.into_iter().cloned()).collect();
    let unexamined = fresh.len() - batch.len();
    let all: Vec<RemoteRef> = batch.into_iter().chain(retry_now).collect();
    let mut left = Left::default();
    examine_and_record(state, entry, repo, &all, &mut budget, &mut pending, &mut left, run).await?;
    left.unexamined += unexamined;
    let mut held = freeze(state, entry, repo, actor, pace, &refs, &pending, waiting, run).await?;
    // The rule of the newest version as it is now may read tags whose unreadable manifest's
    // version wasn't one under the rule before: they are examined again, now if this sync still
    // may, else at the next.
    let mut again = unreadable_now_read(state, entry, &refs).await?;
    again.extend(claims_released(state, entry, repo, &refs).await?);
    if !again.is_empty() {
        let now: Vec<RemoteRef> = again.iter().take(budget.examine).cloned().collect();
        budget.examine -= now.len();
        left.unexamined += again.len() - now.len();
        pending.extend(again.into_iter().skip(now.len()));
        examine_and_record(state, entry, repo, &now, &mut budget, &mut pending, &mut left, run).await?;
        held = freeze(state, entry, repo, actor, pace, &refs, &pending, waiting, run).await?;
    }
    if held > 0 {
        run.unfetched.push(format!("{held} version(s) held until the tags that could also be them have been read"));
    }
    if let Some(why) = left.env {
        run.unfetched.push(format!("{why} (those tags are examined again at the next check)"));
    }
    if left.checkouts > 0 {
        run.unfetched.push(format!(
            "{} tag(s) need a checkout to be examined (a manifest that is a symbolic link, or a host that refuses files by id); at most {} per check, the rest at the next check",
            left.checkouts, state.cfg.checkouts_per_sync
        ));
    }
    if left.unexamined > 0 {
        run.unfetched.push(format!("{} tag(s) not examined yet (at most {cap} per check)", left.unexamined));
    }
    Ok(())
}

/// What examining left for a later sync.
#[derive(Default)]
struct Left {
    /// Why the repo couldn't be read (the first reason).
    env: Option<String>,
    /// Tags not examined for want of checkouts.
    checkouts: usize,
    /// Tags not examined for the cap.
    unexamined: usize,
}

/// Examines `tags` in groups of [`EXAMINE_GROUP`], storing each group's outcomes before reading
/// the next. Tags left unexamined or waiting are added to `pending`.
#[allow(clippy::too_many_arguments)]
async fn examine_and_record(
    state: &AppState,
    entry: &Entry,
    repo: &RepoRow,
    tags: &[RemoteRef],
    budget: &mut Budget,
    pending: &mut Vec<RemoteRef>,
    left: &mut Left,
    run: &mut Run,
) -> AppResult<()> {
    for group in tags.chunks(EXAMINE_GROUP) {
        let exams = examine(state, entry, repo, group, &mut budget.checkouts).await?;
        // The group's outcomes land together, and only while no registration on the repo has
        // cleared this entry's records since the sync started.
        let mut tx = state.db.begin().await?;
        still_current(&mut tx, entry.id, repo.generation).await?;
        let mut waits = Vec::new();
        for (r, exam) in group.iter().zip(exams) {
            match exam {
                Exam::Version { tv, rank, error, note, pattern } => {
                    sqlx::query(
                        "INSERT INTO tag_reads (entry_id, tag, commit, label, rank, error, note, pattern) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                         ON CONFLICT (entry_id, tag) DO UPDATE SET commit = EXCLUDED.commit, label = EXCLUDED.label,
                           rank = EXCLUDED.rank, error = EXCLUDED.error, note = EXCLUDED.note, pattern = EXCLUDED.pattern, seen_at = now()",
                    )
                    .bind(entry.id)
                    .bind(&r.name)
                    .bind(&r.commit)
                    .bind(tv.to_string())
                    .bind(rank)
                    .bind(&error)
                    .bind(&note)
                    .bind(&pattern)
                    .execute(&mut *tx)
                    .await?;
                    done_waiting_in(&mut tx, entry.id, &r.name).await?;
                }
                Exam::Not { kind, why } => {
                    record_foreign_in(&mut tx, entry.id, r, (kind, &why), None).await?;
                    done_waiting_in(&mut tx, entry.id, &r.name).await?;
                }
                Exam::Claimed { by, why } => {
                    record_foreign_in(&mut tx, entry.id, r, ("claim", &why), Some(by)).await?;
                    done_waiting_in(&mut tx, entry.id, &r.name).await?;
                }
                Exam::Wait(why) => {
                    waits.push((r, why));
                    pending.push(r.clone());
                }
                Exam::Unexamined(why) => {
                    if why == CHECKOUTS_USED {
                        left.checkouts += 1;
                    } else {
                        left.env.get_or_insert(why);
                    }
                    pending.push(r.clone());
                }
            }
        }
        tx.commit().await?;
        for (r, why) in waits {
            run.unfetched.push(wait(state, entry, r, why).await);
        }
    }
    Ok(())
}

/// Why a sync stops quietly: registering another entry on the repo cleared this entry's records
/// meanwhile, so what it judged without the new sibling isn't stored; the next sync goes on.
const STALE_SYNC: &str = "another entry was registered on the repo while this sync ran";

/// Locks the entry's repo row for the rest of `tx` (against a registration clearing its records)
/// and checks that its generation is still `generation`: else [`STALE_SYNC`].
async fn still_current(tx: &mut sqlx::PgConnection, entry_id: i64, generation: i64) -> AppResult<()> {
    let now: Option<i64> = sqlx::query_scalar("SELECT generation FROM entry_repos WHERE entry_id = $1 FOR SHARE")
        .bind(entry_id)
        .fetch_optional(&mut *tx)
        .await?;
    if now != Some(generation) {
        return Err(AppError::Conflict(STALE_SYNC.into()));
    }
    Ok(())
}

/// Forgets the entry's "not a version" records of tags taken as a sibling's whose manifest at that
/// commit couldn't be read, when that sibling's rule no longer reads them (its first version
/// frozen, say, or a version with another pattern), or it is no longer on the repo: those tags are
/// to be examined again, so "neither entry's" never lasts once the rule behind it changed. Returns
/// them.
async fn claims_released(state: &AppState, entry: &Entry, repo: &RepoRow, refs: &[RemoteRef]) -> AppResult<Vec<RemoteRef>> {
    let rows: Vec<(String, String, i64)> =
        sqlx::query_as("SELECT tag, commit, claimed_by FROM foreign_tags WHERE entry_id = $1 AND kind = 'claim' AND claimed_by IS NOT NULL")
            .bind(entry.id)
            .fetch_all(&state.db)
            .await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let on_repo: std::collections::BTreeSet<i64> = entries_on(state, &repo.url).await?.into_iter().map(|(e, _)| e.id).collect();
    let remote: BTreeMap<&str, &str> = refs.iter().map(|r| (r.name.as_str(), r.commit.as_str())).collect();
    let mut rules: BTreeMap<i64, TagRule> = BTreeMap::new();
    let mut again = Vec::new();
    for (tag, commit, by) in rows {
        if remote.get(tag.as_str()) != Some(&commit.as_str()) {
            continue;
        }
        let still = if on_repo.contains(&by) && by != entry.id {
            let rule = match rules.get(&by) {
                Some(r) => r.clone(),
                None => {
                    let r = unreadable_rule(state, by).await?;
                    rules.insert(by, r.clone());
                    r
                }
            };
            rule.version(&tag).is_some()
        } else {
            false
        };
        if !still {
            again.push(RemoteRef { name: tag, commit });
        }
    }
    if !again.is_empty() {
        let tags: Vec<&str> = again.iter().map(|r| r.name.as_str()).collect();
        sqlx::query("DELETE FROM foreign_tags WHERE entry_id = $1 AND kind = 'claim' AND claimed_by IS NOT NULL AND tag = ANY($2)")
            .bind(entry.id)
            .bind(&tags)
            .execute(&state.db)
            .await?;
    }
    Ok(again)
}

/// Forgets the entry's "not a version" records of tags whose manifest was unreadable and whose
/// version, under the entry's rule then ([`unreadable_rule`]), wasn't one, when its rule now reads
/// them (its first version frozen, say, or a version with another pattern): those tags are to be
/// examined again. Returns them.
async fn unreadable_now_read(state: &AppState, entry: &Entry, refs: &[RemoteRef]) -> AppResult<Vec<RemoteRef>> {
    let rule = unreadable_rule(state, entry.id).await?;
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT tag, commit FROM foreign_tags WHERE entry_id = $1 AND kind = 'unreadable'")
        .bind(entry.id)
        .fetch_all(&state.db)
        .await?;
    let remote: BTreeMap<&str, &str> = refs.iter().map(|r| (r.name.as_str(), r.commit.as_str())).collect();
    let again: Vec<RemoteRef> = rows
        .into_iter()
        .filter(|(t, c)| remote.get(t.as_str()) == Some(&c.as_str()) && rule.version(t).is_some())
        .map(|(name, commit)| RemoteRef { name, commit })
        .collect();
    if !again.is_empty() {
        let tags: Vec<&str> = again.iter().map(|r| r.name.as_str()).collect();
        sqlx::query("DELETE FROM foreign_tags WHERE entry_id = $1 AND kind = 'unreadable' AND tag = ANY($2)")
            .bind(entry.id)
            .bind(&tags)
            .execute(&state.db)
            .await?;
    }
    Ok(again)
}

/// Freezes the tags read as versions, one per version (see [`examine_and_ingest`]), holding the
/// versions a `pending` tag could turn out to be. Returns how many versions it held.
#[allow(clippy::too_many_arguments)]
async fn freeze(
    state: &AppState,
    entry: &Entry,
    repo: &RepoRow,
    actor: Option<&User>,
    pace: Pace,
    refs: &[RemoteRef],
    pending: &[RemoteRef],
    waiting: &BTreeMap<String, Waiting>,
    run: &mut Run,
) -> AppResult<usize> {
    let have = version_labels(state, entry.id).await?;
    // The versions an unexamined or waiting tag might turn out to be: not frozen yet.
    let rules = known_rules(state, entry.id).await?;
    let blocked: std::collections::BTreeSet<String> =
        pending.iter().flat_map(|r| rules.iter().filter_map(|rule| rule.version(&r.name).map(|tv| tv.to_string()))).collect();
    // An unreadable manifest's version follows the entry's rule as it is now.
    let newest = Some(unreadable_rule(state, entry.id).await?);
    let mut reads = reads_of(state, entry.id, refs).await?;
    let rejudged: Vec<(String, TagRead)> = reads.iter().filter(|(_, t)| t.error.is_some()).map(|(k, t)| (k.clone(), t.clone())).collect();
    for (tag, read) in rejudged {
        let rule = rule_for_unreadable(newest.as_ref());
        match rule.version(&tag) {
            Some(tv) if tv.to_string() == read.label => {}
            Some(tv) => {
                sqlx::query("UPDATE tag_reads SET label = $3 WHERE entry_id = $1 AND tag = $2")
                    .bind(entry.id)
                    .bind(&tag)
                    .bind(tv.to_string())
                    .execute(&state.db)
                    .await?;
                if let Some(t) = reads.get_mut(&tag) {
                    t.label = tv.to_string();
                }
            }
            None => {
                let why = format!(
                    "{}; {tag} isn't a version under the rule of the newest version ({})",
                    read.error.clone().unwrap_or_default(),
                    rule.describe_with_since()
                );
                record_foreign(state, entry, &RemoteRef { name: tag.clone(), commit: read.commit.clone() }, ("unreadable", &why)).await?;
                reads.remove(&tag);
            }
        }
    }
    let mut by_label: BTreeMap<String, Vec<(String, TagRead)>> = BTreeMap::new();
    for (tag, read) in reads {
        by_label.entry(read.label.clone()).or_default().push((tag, read));
    }
    let mut candidates = Vec::new();
    let mut held = 0;
    for (label, mut tags) in by_label {
        if have.contains(&label) {
            for (tag, read) in &tags {
                let why = format!("version {label} is already another tag's");
                record_foreign(state, entry, &RemoteRef { name: tag.clone(), commit: read.commit.clone() }, ("duplicate", &why)).await?;
            }
            continue;
        }
        if blocked.contains(&label) {
            held += 1;
            continue;
        }
        tags.sort_by(|a, b| (a.1.rank, &a.0).cmp(&(b.1.rank, &b.0)));
        let (tag, read) = tags.swap_remove(0);
        let tv: TrackedVersion = label.parse().map_err(AppError::bad)?;
        candidates.push(Candidate { r: RemoteRef { name: tag, commit: read.commit }, tv, preset: read.error, note: read.note });
    }
    ingest_all(state, entry, repo, actor, pace, candidates, waiting, run).await?;
    // The versions frozen now settle the other tags read as the same versions.
    let have = version_labels(state, entry.id).await?;
    let reads = reads_of(state, entry.id, refs).await?;
    for (tag, read) in reads {
        if have.contains(&read.label) && !version_tag_is(state, entry.id, &tag).await? {
            let why = format!("version {} is already another tag's", read.label);
            record_foreign(state, entry, &RemoteRef { name: tag.clone(), commit: read.commit }, ("duplicate", &why)).await?;
        }
    }
    Ok(held)
}

/// A tag read as a version and not frozen yet.
#[derive(Clone, Debug)]
struct TagRead {
    commit: String,
    label: String,
    rank: i32,
    error: Option<String>,
    note: Option<String>,
}

async fn version_tag_is(state: &AppState, entry_id: i64, tag: &str) -> AppResult<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM versions WHERE entry_id = $1 AND tag = $2)")
        .bind(entry_id)
        .bind(tag)
        .fetch_one(&state.db)
        .await?)
}

/// The entry's tags read as versions and not frozen yet, forgetting those deleted or moved upstream
/// (a moved tag is examined again) and those recorded as not versions since.
async fn reads_of(state: &AppState, entry_id: i64, refs: &[RemoteRef]) -> AppResult<BTreeMap<String, TagRead>> {
    let rows: Vec<(String, String, String, i32, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT r.tag, r.commit, r.label, r.rank, r.error, r.note FROM tag_reads r
         WHERE r.entry_id = $1 AND NOT EXISTS (SELECT 1 FROM foreign_tags f WHERE f.entry_id = r.entry_id AND f.tag = r.tag AND f.commit = r.commit)",
    )
    .bind(entry_id)
    .fetch_all(&state.db)
    .await?;
    let remote: BTreeMap<&str, &str> = refs.iter().map(|r| (r.name.as_str(), r.commit.as_str())).collect();
    let stale: Vec<&str> =
        rows.iter().filter(|(t, c, ..)| remote.get(t.as_str()) != Some(&c.as_str())).map(|(t, ..)| t.as_str()).collect();
    if !stale.is_empty() {
        sqlx::query("DELETE FROM tag_reads WHERE entry_id = $1 AND tag = ANY($2)")
            .bind(entry_id)
            .bind(&stale)
            .execute(&state.db)
            .await?;
    }
    Ok(rows
        .into_iter()
        .filter(|(t, c, ..)| remote.get(t.as_str()) == Some(&c.as_str()))
        .map(|(t, commit, label, rank, error, note)| (t, TagRead { commit, label, rank, error, note }))
        .collect())
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
    let mut c = state.db.acquire().await?;
    done_waiting_in(&mut c, entry_id, tag).await
}

async fn done_waiting_in(db: &mut sqlx::PgConnection, entry_id: i64, tag: &str) -> AppResult<()> {
    sqlx::query("DELETE FROM waiting_tags WHERE entry_id = $1 AND tag = $2")
        .bind(entry_id)
        .bind(tag)
        .execute(&mut *db)
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


/// After a curated entry's overlay changes (or is handed over to the repo's manifests): forgets its
/// own "not a version" judgments and pending reads, which were made under the old rule; its tags
/// are examined again at the next sync. Siblings' judgments read their own manifests and stay.
async fn clear_foreign_on(db: &mut sqlx::PgConnection, entry_id: i64) -> AppResult<()> {
    for table in ["foreign_tags", "tag_reads"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE entry_id = $1")).bind(entry_id).execute(&mut *db).await?;
    }
    Ok(())
}

/// Records `r` as not a version of `entry`, with a kind and why (replacing an earlier judgment of
/// the same tag).
async fn record_foreign(state: &AppState, entry: &Entry, r: &RemoteRef, (kind, why): (&str, &str)) -> AppResult<()> {
    let mut tx = state.db.begin().await?;
    record_foreign_in(&mut tx, entry.id, r, (kind, why), None).await?;
    tx.commit().await?;
    Ok(())
}

/// [`record_foreign`] in a transaction; `by` is the sibling a `claim` depends on the rule of.
async fn record_foreign_in(db: &mut sqlx::PgConnection, entry_id: i64, r: &RemoteRef, (kind, why): (&str, &str), by: Option<i64>) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO foreign_tags (entry_id, tag, commit, reason, kind, claimed_by) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (entry_id, tag) DO UPDATE SET commit = EXCLUDED.commit, reason = EXCLUDED.reason, kind = EXCLUDED.kind,
           claimed_by = EXCLUDED.claimed_by, seen_at = now()",
    )
    .bind(entry_id)
    .bind(&r.name)
    .bind(&r.commit)
    .bind(why)
    .bind(kind)
    .bind(by)
    .execute(&mut *db)
    .await?;
    sqlx::query("DELETE FROM tag_reads WHERE entry_id = $1 AND tag = $2").bind(entry_id).bind(&r.name).execute(&mut *db).await?;
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
#[allow(clippy::too_many_arguments)]
async fn ingest(
    state: &AppState,
    entry: &Entry,
    repo: &RepoRow,
    r: &RemoteRef,
    tv: &TrackedVersion,
    actor: Option<&User>,
    preset: Option<&str>,
    note: Option<&str>,
) -> AppResult<Ingested> {
    let track = tv.track.as_ref().map(|t| t.to_string()).unwrap_or_default();
    // A version whose manifest was found unreadable when examined: frozen invalid with that error,
    // nothing more to read.
    let co = match preset {
        Some(_) => Err(anyhow::anyhow!("not read")),
        None => git::checkout(policy(state), &repo.url, &r.commit, Some(&r.name)).await,
    };
    let (invalid, tree, prepared) = match co {
        Err(_) if preset.is_some() => (preset.map(str::to_owned), None, None),
        // Too large is a fact about the commit. For a curated entry the version is stored invalid,
        // as for a bad manifest. For a repo entry, whose release it is can't be read, so it is
        // recorded as not a version (as examining records it; judged again if the tag moves), and
        // another tag of the same version, if any, gets its turn.
        Err(e) if e.downcast_ref::<git::TooLarge>().is_some() => {
            if repo.overlay_manifest.is_none() {
                record_foreign(state, entry, r, ("large", &format!("the tagged commit is too large to read: {e:#}"))).await?;
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
    if let Some(p) = prepared.as_mut() {
        if let Some(warning) = sorts_below_another_form(state, entry, &track, tv, &r.name).await? {
            p.smells.push(warning);
        }
        if let Some(n) = note {
            p.smells.push(n.to_owned());
        }
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
    still_current(&mut tx, entry.id, repo.generation).await?;
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
    // A tag judged not this entry's earlier and since moved onto a release of it; its read is done.
    for table in ["foreign_tags", "tag_reads"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE entry_id = $1 AND tag = $2"))
            .bind(entry.id)
            .bind(&r.name)
            .execute(&mut *tx)
            .await?;
    }
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

    fn entry(name: &str) -> Entry {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        Entry {
            id: 1,
            kind: "sim".into(),
            owner: "max".into(),
            name: name.into(),
            summary: None,
            description: None,
            visibility: "public".into(),
            verified: false,
            trusted: false,
            curated: false,
            created_by: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn sims_manifest(pattern: Option<&str>) -> Read {
        let pat = pattern.map(|p| format!("tag-pattern = \"{p}\"\n")).unwrap_or_default();
        Read::Text(format!("format = 1\n\n[sim]\nname = \"s\"\nowners = [\"max\"]\nfile = \"a.sim\"\n{pat}"))
    }

    fn package_manifest(pattern: Option<&str>) -> Read {
        let pat = pattern.map(|p| format!("tag-pattern = \"{p}\"\n")).unwrap_or_default();
        Read::Text(format!("format = 1\n\n[package]\nname = \"p\"\nowners = [\"max\"]\n{pat}"))
    }

    /// Each tag is read by the manifest in its own commit.
    #[test]
    fn a_tag_is_read_by_the_manifest_in_its_commit() {
        let e = entry("s");
        let judge1 = |tag: &str, own: &Read| judge(&e, SIM_FILE, Some("file"), tag, own, &[], None);
        // No pattern: the standard form.
        assert!(matches!(judge1("v1.0.0", &sims_manifest(None)), Exam::Version { error: None, .. }));
        assert!(matches!(judge1("sim-v1.0.0", &sims_manifest(None)), Exam::Not { kind: "rule", .. }));
        // A pattern at this commit: only its tags, from here on, without any switch.
        assert!(matches!(judge1("sim-v2.0.0", &sims_manifest(Some("sim-v{major}.{minor}.{patch}"))), Exam::Version { .. }));
        assert!(matches!(judge1("v2.0.0", &sims_manifest(Some("sim-v{major}.{minor}.{patch}"))), Exam::Not { kind: "rule", .. }));
        // No manifest: never a version, whatever the repo.
        assert!(matches!(judge1("v1.0.0", &Read::Absent), Exam::Not { kind: "absent", .. }));
        // Unreadable: invalid when the newest version's rule (else the standard form) reads the tag.
        let broken = Read::Text("format = 1\n[sim\n".into());
        assert!(matches!(judge1("v1.1.0", &broken), Exam::Version { error: Some(_), .. }));
        assert!(matches!(judge1("sim-v1.1.0", &broken), Exam::Not { kind: "unreadable", .. }));
        let newest = rule(Some("sim-v{major}.{minor}.{patch}"));
        assert!(matches!(judge(&e, SIM_FILE, Some("file"), "sim-v1.1.0", &broken, &[], Some(&newest)), Exam::Version { error: Some(_), .. }));
        // ... and never the standard form when the newest version follows a pattern of its own.
        assert!(matches!(judge(&e, SIM_FILE, Some("file"), "v2026.6.0", &broken, &[], Some(&newest)), Exam::Not { kind: "unreadable", .. }));
        // A newer format waits.
        let newer = Read::Text("format = 99\n".into());
        assert!(matches!(judge1("v1.0.0", &newer), Exam::Wait(_)));
        // Another entry's name is not a version of this one.
        assert!(matches!(judge(&entry("other"), SIM_FILE, None, "v1.0.0", &sims_manifest(None), &[], None), Exam::Not { kind: "identity", .. }));
        // A sibling's own pattern at the same commit claims what the standard form would read.
        let sibs = vec![sib(PACKAGE_FILE, package_manifest(Some("{major}.{minor}.{patch}")), None)];
        assert!(matches!(judge(&e, SIM_FILE, None, "2.0.0", &sims_manifest(None), &sibs, None), Exam::Not { kind: "claim", .. }));
        assert!(matches!(judge(&e, SIM_FILE, None, "v2.0.0", &sims_manifest(None), &sibs, None), Exam::Version { .. }));
        // The manifest's pattern goes with its read, so its tags hold their versions while unread.
        let pat = "sim-v{major}.{minor}.{patch}";
        assert!(matches!(judge1("sim-v2.0.0", &sims_manifest(Some(pat))), Exam::Version { pattern: Some(p), .. } if p == pat));
    }

    fn sib(file: &'static str, read: Read, newest: Option<TagRule>) -> Sib<'static> {
        Sib { id: 2, slug: "max/p".to_owned(), file, read, newest }
    }

    /// An unreadable manifest never takes a tag a sibling reads, a broken sibling manifest claims
    /// tags by its entry's rule (as a readable one would, against a readable manifest), and a
    /// sibling manifest that can't be told yet makes a tag the entry would take wait.
    #[test]
    fn siblings_keep_their_tags() {
        let e = entry("s");
        let broken = Read::Text("format = 1\n[sim\n".into());
        let pkg = vec![sib(PACKAGE_FILE, package_manifest(None), None)];
        // The package reads v2026.6.0; the sims' broken manifest there doesn't take it.
        assert!(matches!(judge(&e, SIM_FILE, None, "v2026.6.0", &broken, &pkg, None), Exam::Not { kind: "claim", .. }));
        // A sibling manifest of a newer format may claim a tag the entry would take: wait.
        let newer = vec![sib(PACKAGE_FILE, Read::Text("format = 99\n".into()), None)];
        assert!(matches!(judge(&e, SIM_FILE, None, "2.0.0", &sims_manifest(None), &newer, None), Exam::Wait(_)));
        // ... but not one the entry settles alone: its rule doesn't read it, it has no manifest
        // there, or its unreadable manifest's rule doesn't read it.
        let pat = Some("sim-v{major}.{minor}.{patch}");
        assert!(matches!(judge(&e, SIM_FILE, None, "v2.0.0", &sims_manifest(pat), &newer, None), Exam::Not { kind: "rule", .. }));
        assert!(matches!(judge(&e, SIM_FILE, None, "v2.0.0", &Read::Absent, &newer, None), Exam::Not { kind: "absent", .. }));
        let sim_rule = rule(pat);
        assert!(matches!(judge(&e, SIM_FILE, None, "v2.0.0", &broken, &newer, Some(&sim_rule)), Exam::Not { kind: "unreadable", .. }));
        assert!(matches!(judge(&e, SIM_FILE, None, "sim-v2.0.0", &broken, &newer, Some(&sim_rule)), Exam::Wait(_)));
        // A broken sibling manifest is taken to follow its entry's rule (its newest version's, else
        // its registration's). Against a readable manifest it claims only as a readable one would,
        // with a distinct pattern: sharing v tags, the package keeps v2.0.0 ...
        let bad = Read::Text("format = 1\n[package\n".into());
        let shared = vec![sib(PACKAGE_FILE, bad.clone(), None)];
        assert!(matches!(judge(&e, SIM_FILE, None, "v2.0.0", &sims_manifest(None), &shared, None), Exam::Version { note: Some(_), .. }));
        // ... and a sibling following sim-v (no version yet: its registration's rule) never takes it.
        let simv = vec![sib(PACKAGE_FILE, bad.clone(), Some(rule(Some("sim-v{major}.{minor}.{patch}"))))];
        assert!(matches!(judge(&e, SIM_FILE, None, "v2.0.0", &sims_manifest(None), &simv, None), Exam::Version { note: Some(_), .. }));
        // A distinct pattern of its own that reads the tag takes it, as it would readable.
        let bare = vec![sib(PACKAGE_FILE, bad.clone(), Some(rule(Some("{major}.{minor}.{patch}"))))];
        assert!(matches!(judge(&e, SIM_FILE, None, "2.0.0", &sims_manifest(None), &bare, None), Exam::Claimed { by: 2, .. }));
        // Against a manifest here that can't be read either, it takes what its rule reads at all.
        assert!(matches!(judge(&e, SIM_FILE, None, "v2.0.0", &broken, &shared, None), Exam::Claimed { by: 2, .. }));
        assert!(matches!(judge(&e, SIM_FILE, None, "v2.0.0", &broken, &simv, None), Exam::Version { error: Some(_), .. }));
    }

    /// Among tags read as one version, the spelling the manifest's pattern writes wins, then the
    /// standard one, then any other.
    #[test]
    fn spellings_rank() {
        let tv = |s: &str| s.parse::<TrackedVersion>().unwrap();
        let rel = rule(Some("rel-{major}.{minor}"));
        assert_eq!(spelling_rank(&rel, "rel-1.0", &tv("1.0.0")), 0);
        assert_eq!(spelling_rank(&rel, "rel-01.0", &tv("1.0.0")), 2);
        assert_eq!(spelling_rank(&rule(None), "v1.0.0", &tv("1.0.0")), 1);
        assert_eq!(spelling_rank(&rule(None), "1.0.0", &tv("1.0.0")), 2);
    }
}
