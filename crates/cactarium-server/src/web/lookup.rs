//! What the Cactarium knows of things named outside it: which package a pinned commit is
//! (`POST /lookup`), whether a pinned download was reviewed, and which published thorns meet a CCL
//! requirement (`GET /providers`). Anonymous reads, under the same review and visibility rules as
//! every other read ([`Reviewer`]).

use std::collections::{BTreeMap, HashMap};

use axum::Json;
use axum::extract::{Query, State};
use axum::response::{AppendHeaders, IntoResponse, Response};
use cactup_ecosystem_common::api::{
    DownloadInfo, LookedUp, LookupRequest, PinInfo, Provider, Providers, ProvidersQuery,
};
use cactup_ecosystem_common::ccl::{self, ThornFacts};

use crate::claims::ClaimRec;
use crate::error::{ApiResult, AppError};
use crate::git::{self, GitPolicy};
use crate::model::{self, ENTRY_COLS, Entry, Version};
use crate::security::ClientIp;
use crate::state::AppState;
use crate::web::api::{Reviewer, entry_servable, frozen_at, servable, unreviewed_mark};

/// How many package repos one lookup may bring up to date to answer `commit-known` for commits
/// their mirrors lack (each is fetched at most once a minute anyway); past that, the answer is
/// `null` (can't tell just now) rather than a guess.
const MIRROR_UPDATES_PER_LOOKUP: usize = 8;
/// How many mirror updates all lookups together may ask for in a minute, whoever asks: cycling
/// through unfrozen commits can't keep the lookups' slot busy, nor send a stream of fetches to a
/// forge.
const MIRROR_UPDATES_PER_MINUTE: u32 = 30;
/// How many distinct packages one lookup reads the history mirrors of (`git cat-file`); past
/// that, `commit-known` for a commit no version froze is `null`.
const MIRROR_READS_PER_LOOKUP: usize = 50;

/// The lookups' shared per-minute budget of mirror updates.
static UPDATE_BUDGET: std::sync::Mutex<Option<(std::time::Instant, u32)>> = std::sync::Mutex::new(None);

/// Takes one mirror update from the budget, if any is left this minute.
fn take_update() -> bool {
    take_from(&UPDATE_BUDGET, std::time::Instant::now(), MIRROR_UPDATES_PER_MINUTE)
}

/// Takes one from a per-minute `budget` of `per_minute` at `now`: a minute starts with its first
/// take.
fn take_from(budget: &std::sync::Mutex<Option<(std::time::Instant, u32)>>, now: std::time::Instant, per_minute: u32) -> bool {
    let mut b = budget.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (start, used) = match *b {
        Some((start, used)) if now.duration_since(start) < std::time::Duration::from_secs(60) => (start, used),
        _ => (now, 0),
    };
    if used >= per_minute {
        *b = Some((start, used));
        return false;
    }
    *b = Some((start, used + 1));
    true
}

/// `POST /lookup`: for each pin, the package whose repo it is and the version that froze its
/// commit; for each download, its review. Both lists in request order.
pub async fn lookup(
    State(state): State<AppState>,
    ip: ClientIp,
    reviewer: Reviewer,
    Json(req): Json<LookupRequest>,
) -> ApiResult<Response> {
    state.limiter.check("lookup", ip.0, 60)?;
    req.validate().map_err(AppError::bad)?;
    let packages = package_repos(&state, &reviewer).await?;
    let mut unreviewed = false;

    // The packages the pins name, each read once, with the commits asked of it.
    let mut found: Vec<Option<usize>> = Vec::with_capacity(req.pins.len());
    let mut asked: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for p in &req.pins {
        let i = model::find_repo(&p.url, &packages, |(_, url)| url).map(|hit| {
            packages.iter().position(|c| std::ptr::eq(c, hit)).expect("found among them")
        });
        if let Some(i) = i {
            asked.entry(i).or_default().push(p.commit.clone());
        }
        found.push(i);
    }
    let mut known: HashMap<usize, Known> = HashMap::new();
    let policy = GitPolicy { allow_local: state.cfg.allow_local_repos };
    let mut updates = MIRROR_UPDATES_PER_LOOKUP;
    let mut reads = MIRROR_READS_PER_LOOKUP;
    for (i, commits) in &asked {
        let (e, url) = &packages[*i];
        let versions: Vec<Version> =
            model::all_versions(&state, e.id).await?.into_iter().filter(|v| servable(v, &reviewer)).collect();
        // Commits no version froze: does the repo's history have them? Answered from the kept
        // mirror (brought up to date for a few repos per lookup), never by cloning a new one.
        let mut unfrozen: Vec<String> = commits.iter().filter(|c| frozen_at(&versions, c).is_none()).cloned().collect();
        unfrozen.sort();
        unfrozen.dedup();
        let history = if unfrozen.is_empty() || reads == 0 {
            HashMap::new()
        } else {
            reads -= 1;
            let answer = git::mirror_has_commits(policy, url, &unfrozen, || updates > 0 && take_update()).await;
            if answer.as_ref().is_some_and(|a| a.updated) {
                updates -= 1;
            }
            answer.map(|a| unfrozen.iter().cloned().zip(a.has).collect()).unwrap_or_default()
        };
        let newest = versions.iter().filter(|v| v.track.is_empty()).max_by(|a, b| a.sort_key.cmp(&b.sort_key)).or(versions.first()).cloned();
        known.insert(*i, Known { versions, history, newest });
    }

    let mut pins = Vec::with_capacity(req.pins.len());
    // Each version's fork-of targets, read once however many pins name it.
    let mut forks: HashMap<i64, Vec<String>> = HashMap::new();
    for (p, i) in req.pins.iter().zip(&found) {
        let Some(i) = i else {
            pins.push(PinInfo {
                url: p.url.clone(),
                commit: p.commit.clone(),
                package: None,
                version: None,
                flesh: false,
                fork_of: vec![],
                commit_known: None,
                review: None,
            });
            continue;
        };
        let (e, _) = &packages[*i];
        let k = &known[i];
        let v = frozen_at(&k.versions, &p.commit);
        let fork_of = match v {
            Some(v) if forks.contains_key(&v.id) => forks[&v.id].clone(),
            Some(v) => {
                let targets: Vec<String> =
                    ClaimRec::of_version(&state.db, v.id).await?.iter().filter(|c| c.kind == "fork-of").map(claim_target).collect();
                forks.insert(v.id, targets.clone());
                targets
            }
            None => vec![],
        };
        let review = v.filter(|v| !v.approved()).map(|_| "pending".to_owned());
        unreviewed |= review.is_some() || e.visibility != "public";
        pins.push(PinInfo {
            url: p.url.clone(),
            commit: p.commit.clone(),
            package: Some(e.slug()),
            version: v.map(Version::label),
            // Exact only for a commit a version froze: for any other, the newest version's value,
            // a hint (the commit's own manifest isn't read; `fork-of` stays empty there).
            flesh: flesh(v.or(k.newest.as_ref())),
            fork_of,
            commit_known: if v.is_some() { Some(true) } else { k.history.get(&p.commit).copied().flatten() },
            review,
        });
    }
    // A download being fetched, or whose fetch failed, awaits review: its review is `pending`.
    let downloads = crate::web::downloads::statuses_of(&state, &req.downloads).await?;
    let downloads = req
        .downloads
        .iter()
        .zip(downloads)
        .map(|(d, st)| DownloadInfo { url: d.url.clone(), sha256: d.sha256.clone(), review: st.map(|s| s.review) })
        .collect();
    Ok((AppendHeaders(unreviewed_mark(unreviewed)), Json(LookedUp { pins, downloads })).into_response())
}

/// What one lookup read of a package: the versions the request may be served, the newest of them
/// (for the package's facts when no version froze a commit), and what its history says of the
/// commits no version froze (`None`: can't tell just now).
struct Known {
    versions: Vec<Version>,
    history: HashMap<String, Option<bool>>,
    newest: Option<Version>,
}

/// The package entries this request may see, with their repo URLs: public ones first (then
/// pending ones, for an admin reviewer), oldest first, so a URL two entries share names the
/// public, older one.
async fn package_repos(state: &AppState, reviewer: &Reviewer) -> ApiResult<Vec<(Entry, String)>> {
    let cols = ENTRY_COLS.split(", ").map(|c| format!("e.{c}")).collect::<Vec<_>>().join(", ");
    let rows: Vec<Entry> = sqlx::query_as(&format!(
        "SELECT {cols} FROM entries e JOIN entry_repos r ON r.entry_id = e.id
         WHERE e.kind = 'package' AND e.visibility IN ('public', 'pending')
         ORDER BY e.visibility = 'public' DESC, e.created_at, e.id"
    ))
    .fetch_all(&state.db)
    .await
    .map_err(AppError::from)?;
    let urls: Vec<(i64, String)> = sqlx::query_as(
        "SELECT r.entry_id, r.url FROM entry_repos r JOIN entries e ON e.id = r.entry_id WHERE e.kind = 'package'",
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::from)?;
    let urls: HashMap<i64, String> = urls.into_iter().collect();
    Ok(rows
        .into_iter()
        .filter(|e| entry_servable(e, reviewer))
        .filter_map(|e| urls.get(&e.id).cloned().map(|u| (e, u)))
        .collect())
}

/// A claim's target as a `.sim` or a manifest writes it: `owner/name@<range>`, `owner/name#<sha>`,
/// or a bare `owner/name`.
fn claim_target(c: &ClaimRec) -> String {
    match (&c.range, &c.sha) {
        (Some(r), _) => format!("{}/{}@{r}", c.owner, c.name),
        (None, Some(s)) => format!("{}/{}#{s}", c.owner, c.name),
        (None, None) => format!("{}/{}", c.owner, c.name),
    }
}

/// Whether a version's manifest says the package is a Cactus flesh.
fn flesh(v: Option<&Version>) -> bool {
    v.and_then(|v| v.manifest.as_ref()).and_then(|m| m["package"]["flesh"].as_bool()).unwrap_or(false)
}

/// `GET /providers`: the thorns that meet one CCL requirement, in the newest version this request
/// may be served of each package and track (valid, not yanked; approved, or awaiting review for a
/// request that asked and may). Older versions aren't searched.
pub async fn providers(
    State(state): State<AppState>,
    reviewer: Reviewer,
    Query(q): Query<ProvidersQuery>,
) -> ApiResult<Response> {
    let need = q.need().map_err(AppError::bad)?;
    // The thorns that might meet it, found by index; `ccl::meets` has the last word.
    let (cond, key) = crate::closure::need_index(&need);
    let candidates: Vec<(i64, i64)> = sqlx::query_as(&format!(
        "SELECT DISTINCT v.entry_id, v.id FROM thorns t JOIN versions v ON v.id = t.version_id JOIN entries e ON e.id = v.entry_id
         WHERE e.kind = 'package' AND e.visibility IN ('public', 'pending') AND NOT v.yanked AND v.state <> 'invalid'
           AND v.review IN ('approved', 'pending') AND ({cond})"
    ))
    .bind(need.name())
    .bind(key)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::from)?;
    let mut by_entry: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
    for (entry, version) in candidates {
        by_entry.entry(entry).or_default().push(version);
    }
    let mut out: Vec<(String, String, Provider)> = Vec::new();
    let mut unreviewed = false;
    for (entry_id, hits) in by_entry {
        let e = model::entry_by_id(&state, entry_id).await?;
        if !entry_servable(&e, &reviewer) {
            continue;
        }
        let versions: Vec<Version> = model::all_versions(&state, e.id)
            .await?
            .into_iter()
            .filter(|v| servable(v, &reviewer) && !v.yanked)
            .collect();
        for v in newest_per_track(&versions).into_iter().filter(|v| hits.contains(&v.id)) {
            let thorns: Vec<(String, String, serde_json::Value)> =
                sqlx::query_as("SELECT arrangement, name, facts FROM thorns WHERE version_id = $1 ORDER BY arrangement, name")
                    .bind(v.id)
                    .fetch_all(&state.db)
                    .await
                    .map_err(AppError::from)?;
            for (arrangement, thorn, facts) in thorns {
                let facts: ThornFacts = serde_json::from_value(facts).unwrap_or_default();
                if !ccl::meets(&thorn, &facts, &need) {
                    continue;
                }
                let review = (!v.approved()).then(|| "pending".to_owned());
                unreviewed |= review.is_some() || e.visibility != "public";
                out.push((
                    e.slug(),
                    v.track.clone(),
                    Provider { package: e.slug(), version: v.label(), arrangement, thorn, review },
                ));
            }
        }
    }
    // By package, the default track first, then by thorn.
    out.sort_by(|a, b| (&a.0, &a.1, &a.2.arrangement, &a.2.thorn).cmp(&(&b.0, &b.1, &b.2.arrangement, &b.2.thorn)));
    let providers = out.into_iter().map(|(_, _, p)| p).collect();
    Ok((AppendHeaders(unreviewed_mark(unreviewed)), Json(Providers { providers })).into_response())
}

/// The newest of `versions` on each track (by semver), the default track first.
fn newest_per_track(versions: &[Version]) -> Vec<&Version> {
    let mut best: BTreeMap<&str, &Version> = BTreeMap::new();
    for v in versions {
        let newer = best.get(v.track.as_str()).is_none_or(|b| model::tracked(v).map(|t| t.version) > model::tracked(b).map(|t| t.version));
        if newer {
            best.insert(&v.track, v);
        }
    }
    best.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::api::tests::version;

    /// The lookups' update budget: so many a minute, whoever asks, and a new minute starts afresh.
    #[test]
    fn updates_are_budgeted_per_minute() {
        let budget = std::sync::Mutex::new(None);
        let t0 = std::time::Instant::now();
        assert!((0..3).all(|_| take_from(&budget, t0, 3)));
        assert!(!take_from(&budget, t0 + std::time::Duration::from_secs(59), 3));
        assert!(take_from(&budget, t0 + std::time::Duration::from_secs(61), 3));
    }

    #[test]
    fn newest_of_each_track() {
        let c = "3f2c9e1a00112233445566778899aabbccddeeff";
        let vs = [
            version(1, "1.2.0", c, "approved"),
            version(2, "1.10.0", c, "approved"),
            version(3, "mixed-precision:2.0.0", c, "approved"),
            version(4, "mixed-precision:1.9.0", c, "approved"),
        ];
        let got: Vec<String> = newest_per_track(&vs).iter().map(|v| v.label()).collect();
        assert_eq!(got, ["1.10.0", "mixed-precision:2.0.0"]);
    }

    #[test]
    fn claim_targets_as_written() {
        let fork = |range: Option<&str>, sha: Option<&str>| ClaimRec {
            kind: "fork-of".into(),
            owner: "et".into(),
            name: "carpet".into(),
            range: range.map(Into::into),
            sha: sha.map(Into::into),
            needs: vec![],
            needed_by: vec![],
            into: None,
            alternatives: vec![],
            note: None,
        };
        assert_eq!(claim_target(&fork(Some("=2026.5.1"), None)), "et/carpet@=2026.5.1");
        assert_eq!(claim_target(&fork(None, Some("3f2c9e1"))), "et/carpet#3f2c9e1");
        assert_eq!(claim_target(&fork(None, None)), "et/carpet");
    }
}
