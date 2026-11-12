//! Turning a stack definition into a release: one thornlist and a pin for every repo.
//!
//! Sources, highest priority first: the stack's own thornlist, then each `extends` base release in
//! order. Components are merged by checkout location, first wins. Then `enable` (un-`#DISABLED`s a
//! line in any source), `disable`, and repo overrides apply. Every repo is pinned from, in order:
//! the definition's `[[stack.pin]]` for it (a commit, a sha256, or a tag, which must exist), a
//! `!REPO_COMMIT` in the text, the definition's `pin-tag` (when the repo has that tag), the base
//! release's pin (when the repo still points where the base had it), or the branch's current head.
//!
//! A flat stack with nothing to merge keeps its thornlist verbatim; anything else is emitted fresh
//! with `!REPO_COMMIT` lines, so the downloaded `.th` is pinned on its own.
//!
//! The unpinned forms: `@head` keeps the definition's deliberate pins (`[[stack.pin]]` and
//! `pin-tag`, which are looked up) and leaves every other repo at its branch tip; `@master` drops
//! every branch and pin, so each repo follows its default branch.

use std::collections::{BTreeMap, BTreeSet};

use cactup_ecosystem_common::crl::{self, Component, ComponentType};
use cactup_ecosystem_common::crl_emit;
use cactup_ecosystem_common::sim::{RepoPin, ThornlistText};
use cactup_ecosystem_common::slug::{Slug, Tip};
use cactup_ecosystem_common::stack::{FrozenStack, StackPin, StackSection};
use cactup_ecosystem_common::version::TrackedReq;
use serde::Serialize;

use crate::error::{AppError, AppResult};
use crate::git::{self, GitPolicy};
use crate::model::{self, Version};
use crate::state::AppState;

/// Remote lookups run at once while resolving one stack.
const LOOKUPS_AT_ONCE: usize = 8;

/// A repo whose pin changed between two releases.
#[derive(Clone, Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct RepoMove {
    pub repo: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// Loads a base stack's release. Only public stacks, or the extending stack owner's own, can be
/// bases; anything else is reported exactly like a release that does not exist. The message is the
/// same either way, but a stack entry that exists and isn't usable yet (awaiting review, or the
/// release not read yet) is [`AppError::Upstream`], so a tag that needs it waits instead of
/// freezing invalid; no stack of that name at all is a fact.
pub async fn load_release(state: &AppState, owner: &str, slug: &Slug) -> AppResult<FrozenStack> {
    let msg = format!("base stack release '{slug}' is not available");
    let exact = slug.exact().map_err(|_| AppError::bad(&msg))?;
    let found = model::find_entry(state, slug.owner.as_str(), slug.name.as_str())
        .await?
        .filter(|e| e.kind == "stack");
    let Some(entry) = found else { return Err(AppError::bad(&msg)) };
    if !(entry.visibility == "public" || (entry.owner == owner && entry.visibility != "hidden")) {
        return Err(AppError::Upstream(msg));
    }
    let v = model::version_by_label(state, entry.id, &exact.to_string())
        .await?
        .filter(Version::valid)
        .ok_or(AppError::Upstream(msg))?;
    frozen_of(state, &v).await
}

pub async fn frozen_of(state: &AppState, v: &Version) -> AppResult<FrozenStack> {
    let text: String = sqlx::query_scalar("SELECT frozen FROM stack_releases WHERE version_id = $1")
        .bind(v.id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    toml::from_str(&text)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("stored release is unreadable: {e}")))
}

fn enable_lines(text: &str, enable: &[String]) -> String {
    if enable.is_empty() {
        return text.to_owned();
    }
    text.lines()
        .map(|line| {
            let t = line.trim();
            match t.strip_prefix("#DISABLED").map(str::trim) {
                Some(thorn) if enable.iter().any(|e| e == thorn) => thorn.to_owned(),
                _ => line.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + if text.ends_with('\n') { "\n" } else { "" }
}

fn checkout_key(c: &Component, root: &str) -> String {
    let joined = crl::lexical_canonicalize(&format!("{}/{}", c.target, c.checkout));
    joined.strip_prefix(&format!("{root}/")).unwrap_or(&joined).to_owned()
}

/// What resolution produced, before it is wrapped as a release.
pub struct Resolution {
    pub root: String,
    pub text: String,
    /// One per repo. Under `@head` or `@master`, repos left on their branch tips have no commit.
    pub pins: Vec<RepoPin>,
}

/// Resolves a definition into a release, or with `tip` into one of the unpinned forms.
pub async fn resolve(
    state: &AppState,
    owner: &str,
    section: &StackSection,
    own_text: Option<&str>,
    tip: Option<Tip>,
) -> AppResult<Resolution> {
    let policy = GitPolicy { allow_local: state.cfg.allow_local_repos };

    // Sources in priority order: (label, text, base pins).
    let mut sources: Vec<(String, String, BTreeMap<String, RepoPin>)> = Vec::new();
    if let Some(t) = own_text {
        sources.push(("the stack's thornlist".into(), t.to_owned(), BTreeMap::new()));
    }
    for base in &section.extends {
        let f = load_release(state, owner, base).await?;
        let pins = f.repos.iter().map(|p| (p.name.clone(), p.clone())).collect();
        sources.push((base.to_string(), f.thornlist.text, pins));
    }

    let mut root: Option<String> = None;
    let mut merged: Vec<Component> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut disabled: BTreeSet<String> = BTreeSet::new();
    let mut base_pins: BTreeMap<String, RepoPin> = BTreeMap::new();
    for (label, text, pins) in &sources {
        let parse = |t: &str| crl::parse(t).map_err(|e| AppError::bad(format!("{label}: {e:#}")));
        // Enabling a checkout-only thorn (on the !CHECKOUT line) builds it; enabling one that is
        // only a #DISABLED line adds its checkout. Uncommenting the #DISABLED line of a
        // checkout-only thorn would check it out twice.
        let mut list = parse(text)?;
        let missing: Vec<String> = section
            .enable
            .iter()
            .filter(|t| !list.components().iter().any(|c| &c.checkout == *t))
            .cloned()
            .collect();
        if !missing.is_empty() {
            list = parse(&enable_lines(text, &missing))?;
        }
        match &root {
            None => root = Some(list.root().to_owned()),
            Some(r) if r != list.root() && list.root() != "." => {
                return Err(AppError::bad(format!(
                    "{label} uses ROOT '{}', but an earlier source uses '{r}'",
                    list.root()
                )));
            }
            _ => {}
        }
        let r = root.clone().unwrap_or_else(|| ".".into());
        for c in list.components() {
            if seen.insert(checkout_key(c, &r)) {
                let mut c = c.clone();
                if section.enable.contains(&c.checkout) {
                    c.fetch_only = false;
                }
                merged.push(c);
            }
        }
        disabled.extend(list.disabled_thorns().iter().cloned());
        for (k, p) in pins {
            base_pins.entry(k.clone()).or_insert_with(|| p.clone());
        }
    }
    let root = root.unwrap_or_else(|| ".".into());
    for t in &section.enable {
        disabled.remove(t);
    }
    for t in &section.disable {
        let before = merged.len();
        merged.retain(|c| &c.checkout != t);
        if merged.len() == before && !disabled.contains(t) {
            return Err(AppError::bad(format!("cannot disable '{t}': no source checks it out")));
        }
        disabled.insert(t.clone());
    }

    // Overrides redirect a repo; the pin is then looked up afresh.
    for o in &section.overrides {
        let hits: Vec<usize> = (0..merged.len()).filter(|&i| merged[i].repo == o.repo).collect();
        if hits.is_empty() {
            return Err(AppError::bad(format!("override of '{}': no source uses that repo", o.repo)));
        }
        let (url, branch, commit) = match &o.package {
            Some(p) => {
                let (url, tag, commit) = resolve_package(state, p).await?;
                (Some(url), Some(tag), Some(commit))
            }
            None => (o.url.clone(), o.git_ref.clone(), None),
        };
        for i in hits {
            let c = &mut merged[i];
            if c.name.is_none() {
                // Keep the repo's name (and so its pin key) stable when the URL's basename changes.
                c.name = Some(o.repo.clone());
            }
            if let Some(u) = &url {
                c.url = Some(u.clone());
            }
            if let Some(b) = &branch {
                c.branch = Some(b.clone());
            }
            c.commit = commit.clone();
        }
        base_pins.remove(&o.repo);
    }

    if tip == Some(Tip::Master) {
        for c in merged.iter_mut() {
            c.branch = None;
            c.commit = None;
        }
        base_pins.clear();
    }

    check_collisions(&merged)?;

    // One pin per repo; every component of a repo must agree on where it comes from.
    let def_pins: BTreeMap<&str, &StackPin> =
        section.pins.iter().map(|p| (p.name.as_str(), p)).collect();
    if let Some(p) = section.pins.iter().find(|p| !merged.iter().any(|c| c.repo == p.name)) {
        return Err(AppError::bad(format!(
            "[[stack.pin]] names repo '{}', which no source uses",
            p.name
        )));
    }
    let mut by_repo: BTreeMap<String, &Component> = BTreeMap::new();
    for c in merged.iter().filter(|c| c.ty != ComponentType::Ignore) {
        match by_repo.get(&c.repo) {
            Some(first)
                if (first.url.as_ref(), first.branch.as_ref(), first.commit.as_ref())
                    != (c.url.as_ref(), c.branch.as_ref(), c.commit.as_ref()) =>
            {
                return Err(AppError::bad(format!(
                    "repo '{}' is checked out from conflicting sources ({} and {})",
                    c.repo,
                    describe(first),
                    describe(c)
                )));
            }
            Some(_) => {}
            None => {
                by_repo.insert(c.repo.clone(), c);
            }
        }
    }
    // Pins that need a lookup are resolved concurrently, a few at a time: a full ET-sized list
    // names about 80 repos, and one at a time that took over half a minute.
    let mut pins = Vec::new();
    let mut lookups: Vec<(usize, String, Lookup)> = Vec::new();
    let deliberate = tip != Some(Tip::Master);
    let pin_tag = section.pin_tag.as_deref().filter(|_| deliberate);
    for (repo, c) in &by_repo {
        let url = c.url.clone().unwrap_or_default();
        let mut pin = RepoPin {
            name: repo.clone(),
            url: url.clone(),
            git_ref: c.branch.clone(),
            commit: None,
            sha256: None,
            cactarium: None,
            dirty: false,
        };
        let base = base_pins.get(repo).filter(|b| b.url == url && b.git_ref == c.branch);
        let git = c.ty == ComponentType::Git;
        if let Some(p) = def_pins.get(repo.as_str()).filter(|_| deliberate) {
            match &p.tag {
                Some(t) if git => lookups.push((pins.len(), url.clone(), Lookup::Tag(t.clone()))),
                Some(_) => {
                    return Err(AppError::bad(format!(
                        "repo '{repo}' is not a git repo; it can't be pinned by tag"
                    )));
                }
                None => {
                    pin.commit = p.commit.clone();
                    pin.sha256 = p.sha256.clone();
                }
            }
        } else if c.commit.is_some() {
            pin.commit = c.commit.clone();
        } else if let Some(t) = pin_tag.filter(|_| git) {
            // Without the tag, the repo falls through to its base pin, else its branch.
            let fallback = match base {
                Some(b) => Fallback::Base(Box::new(b.clone())),
                None if tip.is_some() => Fallback::Unpinned,
                None => Fallback::Branch(c.branch.clone()),
            };
            lookups.push((pins.len(), url.clone(), Lookup::TagElse(t.to_owned(), fallback)));
        } else if let Some(b) = base {
            pin.commit = b.commit.clone();
            pin.sha256 = b.sha256.clone();
            pin.cactarium = b.cactarium.clone();
        } else {
            match c.ty {
                ComponentType::Git if tip.is_some() => {}
                ComponentType::Git => {
                    lookups.push((pins.len(), url.clone(), Lookup::Branch(c.branch.clone())))
                }
                ComponentType::Http | ComponentType::Https | ComponentType::Ftp => {
                    return Err(AppError::bad(format!(
                        "repo '{repo}' is a download; pin it with a sha256 in [[stack.pin]]"
                    )));
                }
                other => {
                    return Err(AppError::bad(format!(
                        "repo '{repo}' is {other:?}; only git repos and downloads can be pinned"
                    )));
                }
            }
        }
        pins.push(pin);
    }
    let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(LOOKUPS_AT_ONCE));
    let mut set = tokio::task::JoinSet::new();
    for (i, url, lookup) in lookups {
        let gate = gate.clone();
        set.spawn(async move {
            let _permit = gate.acquire_owned().await;
            (i, lookup.run(policy, &url).await)
        });
    }
    while let Some(done) = set.join_next().await {
        let (i, result) = done.map_err(anyhow::Error::from)?;
        // A ref the repo says it doesn't have is a fact about the definition; a repo that couldn't
        // be read (the network, the host) is not, and a tag read now is tried again later.
        let result = result.map_err(|e| {
            let why = format!("repo '{}': {e:#}", pins[i].name);
            if e.downcast_ref::<git::Missing>().is_some() { AppError::bad(why) } else { AppError::Upstream(why) }
        });
        match result? {
            Found::Commit(c) => pins[i].commit = Some(c),
            Found::Base(b) => {
                pins[i].commit = b.commit;
                pins[i].sha256 = b.sha256;
                pins[i].cactarium = b.cactarium;
            }
            Found::Unpinned => {}
        }
    }
    let resolved_commits: BTreeMap<String, String> = pins
        .iter()
        .filter_map(|p| p.commit.clone().map(|c| (p.name.clone(), c)))
        .collect();

    let untouched = tip.is_none()
        && section.extends.is_empty()
        && section.enable.is_empty()
        && section.disable.is_empty();
    let text = match own_text {
        Some(t) if untouched => t.to_owned(),
        _ => {
            for c in merged.iter_mut() {
                if c.ty == ComponentType::Git
                    && let Some(cm) = resolved_commits.get(&c.repo)
                {
                    c.commit = Some(cm.clone());
                }
            }
            let mut sources_line = vec!["Generated by the Cactarium from:".to_owned()];
            sources_line.extend(sources.iter().map(|(l, _, _)| format!("  {l}")));
            let disabled: Vec<String> = disabled.into_iter().collect();
            crl_emit::emit(&root, &merged, &disabled, Some(&sources_line.join("\n")))
        }
    };
    Ok(Resolution { root, text, pins })
}

/// A pin that needs the remote repo.
enum Lookup {
    /// The branch's current head (None: the default branch).
    Branch(Option<String>),
    /// A tag a `[[stack.pin]]` names: it must exist.
    Tag(String),
    /// The definition's `pin-tag`, if the repo has it.
    TagElse(String, Fallback),
}

/// What a repo without the `pin-tag` gets instead.
enum Fallback {
    Base(Box<RepoPin>),
    Branch(Option<String>),
    /// Under `@head`: the branch tip, left unpinned.
    Unpinned,
}

enum Found {
    Commit(String),
    Base(Box<RepoPin>),
    Unpinned,
}

impl Lookup {
    async fn run(self, policy: GitPolicy, url: &str) -> anyhow::Result<Found> {
        Ok(match self {
            Lookup::Branch(b) => Found::Commit(git::resolve_ref(policy, url, b.as_deref()).await?),
            Lookup::Tag(t) => match git::resolve_tag(policy, url, &t).await? {
                Some(c) => Found::Commit(c),
                None => return Err(git::Missing(format!("{url} has no tag '{t}' (named by its [[stack.pin]])")).into()),
            },
            Lookup::TagElse(t, fallback) => match git::resolve_tag(policy, url, &t).await? {
                Some(c) => Found::Commit(c),
                None => match fallback {
                    Fallback::Base(b) => Found::Base(b),
                    Fallback::Branch(b) => {
                        Found::Commit(git::resolve_ref(policy, url, b.as_deref()).await?)
                    }
                    Fallback::Unpinned => Found::Unpinned,
                },
            },
        })
    }
}

fn describe(c: &Component) -> String {
    format!(
        "{}{}{}",
        c.url.as_deref().unwrap_or("?"),
        c.branch.as_deref().map(|b| format!(" {b}")).unwrap_or_default(),
        c.commit
            .as_deref()
            .map(|b| format!(" @{}", &b[..10.min(b.len())]))
            .unwrap_or_default()
    )
}

/// Cactus thorn names are global: two different checkouts with the same thorn name cannot both be
/// built. Checkout-only thorns (on a !CHECKOUT line) are not built, so they never collide.
fn check_collisions(components: &[Component]) -> AppResult<()> {
    let mut by_name: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for c in components
        .iter()
        .filter(|c| c.ty != ComponentType::Ignore && !c.fetch_only && c.checkout.contains('/'))
    {
        let thorn = c.checkout.rsplit('/').next().unwrap_or_default();
        by_name.entry(thorn.to_ascii_lowercase()).or_default().insert(&c.checkout);
    }
    let clashes: Vec<String> = by_name
        .values()
        .filter(|s| s.len() > 1)
        .map(|s| s.iter().copied().collect::<Vec<_>>().join(" vs "))
        .collect();
    if clashes.is_empty() {
        Ok(())
    } else {
        Err(AppError::bad(format!(
            "thorn names collide (Cactus thorn names are global; disable one of each): {}",
            clashes.join("; ")
        )))
    }
}

/// `owner/pkg@range` → (repo url, tag, frozen commit) of the best matching usable version.
pub async fn resolve_package(state: &AppState, slug: &Slug) -> AppResult<(String, String, String)> {
    let req: TrackedReq = slug.req().map_err(AppError::bad)?;
    let entry = model::find_entry(state, slug.owner.as_str(), slug.name.as_str())
        .await?
        .filter(|e| e.kind == "package")
        .ok_or_else(|| AppError::bad(format!("package '{}' does not exist", slug.entry())))?;
    // A package that exists but isn't public yet, or has no matching version yet, may become
    // usable without a new commit of this stack: a tag that needs it waits.
    if entry.visibility != "public" {
        return Err(AppError::Upstream(format!("package '{}' isn't public yet", slug.entry())));
    }
    let vs = model::versions(state, entry.id).await?;
    let best = vs
        .iter()
        .filter(|v| v.usable())
        .filter_map(|v| model::tracked(v).map(|t| (t, v)))
        .filter(|(t, _)| req.matches(t))
        .max_by(|a, b| a.0.version.cmp(&b.0.version))
        .ok_or_else(|| AppError::Upstream(format!("no version of '{}' matches '{req}' yet", slug.entry())))?
        .1;
    let url: String = sqlx::query_scalar("SELECT url FROM entry_repos WHERE entry_id = $1")
        .bind(entry.id)
        .fetch_one(&state.db)
        .await?;
    let tag = best.tag.clone().unwrap_or_else(|| best.label());
    let commit = best
        .commit
        .clone()
        .ok_or_else(|| AppError::bad("that package version has no commit"))?;
    Ok((url, tag, commit))
}

/// Wraps a resolution as a release.
pub fn freeze(
    slug: Slug,
    filename: &str,
    r: Resolution,
    recipe: Option<String>,
) -> AppResult<FrozenStack> {
    let f = FrozenStack {
        format: 1,
        stack: slug,
        root: r.root,
        thornlist: ThornlistText { filename: filename.to_owned(), text: r.text, untracked: vec![] },
        repos: r.pins,
        recipe,
    };
    f.validate().map_err(AppError::bad)?;
    Ok(f)
}

/// What moved between the previous release on the same track and this one.
pub fn diff(prev: Option<&FrozenStack>, next: &FrozenStack) -> Vec<RepoMove> {
    let Some(prev) = prev else { return Vec::new() };
    let pin = |p: &RepoPin| p.commit.clone().or(p.sha256.clone());
    let old: BTreeMap<&str, Option<String>> =
        prev.repos.iter().map(|p| (p.name.as_str(), pin(p))).collect();
    let new: BTreeMap<&str, Option<String>> =
        next.repos.iter().map(|p| (p.name.as_str(), pin(p))).collect();
    let mut out = Vec::new();
    for (k, v) in &new {
        match old.get(k) {
            Some(o) if o == v => {}
            Some(o) => out.push(RepoMove { repo: k.to_string(), from: o.clone(), to: v.clone() }),
            None => out.push(RepoMove { repo: k.to_string(), from: None, to: v.clone() }),
        }
    }
    for (k, o) in &old {
        if !new.contains_key(k) {
            out.push(RepoMove { repo: k.to_string(), from: o.clone(), to: None });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabling_uncomments_disabled_lines() {
        let t = "!CHECKOUT =\nA/B\n#DISABLED A/C\n  #DISABLED   A/D\n";
        assert_eq!(enable_lines(t, &["A/C".into(), "A/D".into()]), "!CHECKOUT =\nA/B\nA/C\nA/D\n");
    }

    #[test]
    fn collisions_are_found() {
        let list = crl::parse(
            "!CRL_VERSION = 1.0\n!TARGET = a\n!TYPE = git\n!URL = https://x/r.git\n!CHECKOUT =\nCarpet/Multipole\nSpacetimeX/multipole\n",
        )
        .unwrap();
        let e = check_collisions(list.components()).unwrap_err().to_string();
        assert!(e.contains("Carpet/Multipole vs SpacetimeX/multipole"), "{e}");
        // Checkout-only thorns are not built, so they cannot collide.
        let only = crl::parse(
            "!CRL_VERSION = 1.0\n!TARGET = a\n!TYPE = git\n!URL = https://x/r.git\n!CHECKOUT = Carpet/Multipole\nSpacetimeX/multipole\n",
        )
        .unwrap();
        check_collisions(only.components()).unwrap();
    }
}
