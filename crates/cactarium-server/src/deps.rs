//! The dependency check every package version passes, and what reviewers should look at.
//!
//! A thorn's CCL says what it needs (implementations it inherits or befriends, capabilities and
//! thorns it requires, functions it requires), and its sources which `USES INCLUDE` headers it
//! can't compile without (included outside any conditional); a `[[dependency]]` says which thorns
//! of which package supply that (`needs`). The Cactarium hosts only what works as delivered, so a
//! version is refused unless the two agree: every hard CCL requirement of every published thorn is
//! met by the package itself, or by the `needs` thorns of a dependency that applies to that thorn
//! (for an `any-of`, by every alternative). A header counts only where some thorn the Cactarium
//! knows of provides it, and none that does is optional to the thorn (`ccl::counts`, through
//! `closure::counts`): one nothing provides is a hook, and compiles empty.
//! Smells are what a reviewer should look at but that don't block:
//! needs the CCL doesn't explain, includes that reach another thorn's sources by path, and so on.
//!
//! What a requirement is and what meets it is the crate's (`ccl::needs_of`, `meets`, `unmet`),
//! shared with CactUp's composition and trim, so the two can't disagree about what a thorn needs.

use std::path::Path;

use cactup_ecosystem_common::ccl::{Need, ThornFacts, meets, unmet};
use cactup_ecosystem_common::manifest::Manifest;
use cactup_ecosystem_common::version::{TrackedReq, TrackedVersion};

use crate::claims::{Alt, ClaimRec};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// A published thorn as `prepare` scanned it: (arrangement, name, directory in the repo, facts).
pub type Thorn = (String, String, String, ThornFacts);

/// The version of a dependency's target that the check reads: the newest one on the Cactarium
/// within its range (or at its commit), reviewed or awaiting review (a rejected one never counts).
/// One awaiting review, or of an entry that isn't public, makes the dependent wait ([`judge`]).
struct TargetVersion {
    label: String,
    flesh: bool,
    library: bool,
    thorns: Vec<(String, ThornFacts)>,
    /// `approved` or `pending`.
    review: String,
    /// The target entry's visibility: `public`, `pending` (awaiting its first review) or `hidden`.
    visibility: String,
}

/// How a commit's dependencies are read: as a version to freeze, or as a tip read now for someone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Reading {
    /// A version to freeze (a tag, a registration's preview, a snapshot release): every target
    /// the Cactarium has counts, and one awaiting review, or not public, makes it wait ([`judge`]).
    /// What it reports goes to the entry's managers and the admins.
    #[default]
    Freeze,
    /// A branch tip or commit read now for a requester, which freezes nothing: only what that
    /// requester could be served counts (public entries and approved versions; versions awaiting
    /// review of public entries when `releases`, entries awaiting their first review when
    /// `entries`, as the include-unreviewed rules allow), and nothing waits. Anything else is no
    /// version at all, so an answer never names it.
    Tip { releases: bool, entries: bool },
}

/// Which target entries (by visibility) and versions (by review) count: all of them when freezing
/// (a wait decides), what the requester could be served for a tip.
fn counted(reading: Reading) -> (Vec<&'static str>, Vec<&'static str>) {
    match reading {
        Reading::Freeze => (vec!["public", "pending", "hidden"], vec!["approved", "pending"]),
        Reading::Tip { releases, entries } => (
            if entries { vec!["public", "pending"] } else { vec!["public"] },
            if releases { vec!["approved", "pending"] } else { vec!["approved"] },
        ),
    }
}

async fn target_version(state: &AppState, alt: &Alt, reading: Reading) -> AppResult<Option<TargetVersion>> {
    let (entries, releases) = counted(reading);
    let rows: Vec<(i64, String, String, Option<String>, Option<serde_json::Value>, String, String)> = sqlx::query_as(
        "SELECT v.id, v.track, v.version, v.commit, v.manifest, v.review, e.visibility FROM versions v JOIN entries e ON e.id = v.entry_id
         WHERE e.owner = $1 AND e.name = $2 AND e.kind = 'package' AND v.state <> 'invalid' AND v.invalid_reason IS NULL
           AND v.review = ANY($3) AND e.visibility = ANY($4)
         ORDER BY v.sort_key DESC",
    )
    .bind(&alt.owner)
    .bind(&alt.name)
    .bind(&releases)
    .bind(&entries)
    .fetch_all(&state.db)
    .await?;
    let req: Option<TrackedReq> = match (&alt.sha, &alt.range) {
        (Some(_), _) => None,
        (None, Some(r)) => match r.parse() {
            Ok(q) => Some(q),
            Err(_) => return Ok(None),
        },
        (None, None) => Some(TrackedReq::any()),
    };
    let chosen = rows.into_iter().find(|(_, track, version, commit, ..)| match (&alt.sha, &req) {
        (Some(sha), _) => commit.as_deref().is_some_and(|c| c.starts_with(sha.as_str())),
        (None, Some(q)) => {
            let label = if track.is_empty() { version.clone() } else { format!("{track}:{version}") };
            label.parse::<TrackedVersion>().is_ok_and(|v| q.matches(&v))
        }
        (None, None) => false,
    });
    let Some((id, track, version, _, manifest, review, visibility)) = chosen else { return Ok(None) };
    let thorns: Vec<(String, serde_json::Value)> =
        sqlx::query_as("SELECT name, facts FROM thorns WHERE version_id = $1 ORDER BY name")
            .bind(id)
            .fetch_all(&state.db)
            .await?;
    Ok(Some(TargetVersion {
        label: if track.is_empty() { version } else { format!("{track}:{version}") },
        flesh: manifest.as_ref().and_then(|m| m["package"]["flesh"].as_bool()).unwrap_or(false),
        library: manifest.as_ref().and_then(|m| m["package"]["library"].as_bool()).unwrap_or(false),
        thorns: thorns
            .into_iter()
            .map(|(n, f)| (n, serde_json::from_value(f).unwrap_or_default()))
            .collect(),
        review,
        visibility,
    }))
}

/// Why a dependent can't be judged against a target version yet, if it can't: the target entry
/// isn't public (it awaits its first review, or an admin hid it), or the version awaits review.
/// Clients aren't served either, so the dependent waits (left unread, tried again) until it is
/// reviewed rather than freeze against something nobody can install; once it is approved the
/// dependent is read against it, and once it is rejected, against the next version in range.
/// The words name no version nor say why a package isn't public: they reach the dependent's
/// registrant and its version page, who may not see the target.
fn judge(target: &str, tv: &TargetVersion) -> Option<String> {
    if tv.visibility != "public" {
        return Some(no_public_version(target, ""));
    }
    (tv.review == "pending").then(|| {
        format!("the dependency on {target}: the newest version of {target} in its range awaits review; this waits until it is reviewed")
    })
}

/// What a dependent waits for when the Cactarium has no public version of its target in range: one
/// not registered yet, not public yet, or with none in range yet, said alike.
fn no_public_version(target: &str, at: &str) -> String {
    format!("the dependency on {target}{at}: the Cactarium has no public version of that package in that range yet; this waits until it has")
}

/// Whether the target of `alt` has tags in its range not read yet (see
/// `tracker::unread_in_range`): a version of it may yet supply what is missing.
async fn alt_unread(state: &AppState, alt: &Alt) -> AppResult<crate::tracker::Unread> {
    use crate::tracker::Unread;
    let req = match (&alt.sha, &alt.range) {
        (Some(_), _) => None,
        (None, Some(r)) => r.parse::<TrackedReq>().ok(),
        (None, None) => Some(TrackedReq::any()),
    };
    let target_id: Option<i64> = sqlx::query_scalar("SELECT id FROM entries WHERE owner = $1 AND name = $2")
        .bind(&alt.owner)
        .bind(&alt.name)
        .fetch_optional(&state.db)
        .await?;
    Ok(match (req, target_id) {
        (Some(req), Some(id)) => crate::tracker::unread_in_range(state, id, &req).await?,
        _ => Unread::No,
    })
}

/// The thorn among a dependency's `needs` that meets `need`, of the target version's `thorns`.
fn supplier(needs: &[String], thorns: &[(String, ThornFacts)], need: &Need) -> Option<String> {
    needs.iter().find(|n| thorns.iter().any(|(t, f)| t == *n && meets(t, f, need))).cloned()
}

/// Whether a library's checkout can't go at `path`: something is there already (a file, or a
/// folder with anything in it).
fn occupied(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Err(_) => false,
        Ok(m) if m.is_dir() => std::fs::read_dir(path).is_ok_and(|mut d| d.next().is_some()),
        Ok(_) => true,
    }
}

/// Whose dependencies are checked: a package's (its thorns' CCL is checked against the targets'
/// `needs` thorns, and `needs` and `into` must fit each target) or a stack's (its own thornlist
/// names the thorns it builds: `needs`, when given, must exist in the target, and nothing more).
#[derive(Clone, Copy)]
enum Of<'a> {
    Package { repo: &'a Path },
    Stack,
}

/// Each dependency with the target version every alternative resolves to, what is wrong (facts
/// about the commit) and what may become true without a new commit (a version read at a tag waits
/// for these instead of freezing invalid).
struct Resolution<'a> {
    deps: Vec<(&'a ClaimRec, Vec<(Alt, TargetVersion)>)>,
    problems: Vec<String>,
    waiting: Vec<String>,
}

/// `reading` says which targets count and whether what awaits review makes it wait ([`Reading`]).
async fn resolve_dependencies<'a>(state: &AppState, claims: &'a [ClaimRec], of: Of<'_>, reading: Reading) -> AppResult<Resolution<'a>> {
    let mut r = Resolution { deps: Vec::new(), problems: Vec::new(), waiting: Vec::new() };
    let what = match of {
        Of::Package { .. } => "package",
        Of::Stack => "stack",
    };
    for c in claims.iter().filter(|c| c.kind == "dependency") {
        let mut resolved = Vec::new();
        for alt in c.options() {
            let at = match (&alt.range, &alt.sha) {
                (Some(r), _) => format!("@{r}"),
                (None, Some(h)) => format!("#{h}"),
                (None, None) => String::new(),
            };
            match target_version(state, &alt, reading).await? {
                None => {
                    // Only a public entry's kind is told: another's existence isn't anyone's to learn.
                    let kind: Option<String> = sqlx::query_scalar("SELECT kind FROM entries WHERE owner = $1 AND name = $2 AND visibility = 'public'")
                        .bind(&alt.owner)
                        .bind(&alt.name)
                        .fetch_optional(&state.db)
                        .await?;
                    match kind.as_deref() {
                        Some(k) if k != "package" => r.problems.push(format!(
                            "the dependency on {}: that is a {k}; a {what} depends on packages, whose thorns it names in needs (say works-with for a {k})",
                            alt.target()
                        )),
                        _ => r.waiting.push(no_public_version(&alt.target(), &at)),
                    }
                }
                Some(tv) => {
                    if reading == Reading::Freeze && let Some(why) = judge(&alt.target(), &tv) {
                        r.waiting.push(why);
                        continue;
                    }
                    let at = format!("{}@{}", alt.target(), tv.label);
                    match of {
                        // needs exactly when the target has thorns; into exactly when it is a library.
                        Of::Package { repo } => {
                            match (tv.library, tv.flesh, &c.into) {
                                (true, _, _) if !c.alternatives.is_empty() => r.problems.push(format!(
                                    "{at} is a library, which can't be an alternative in an any-of: depend on it with target and into"
                                )),
                                (true, _, None) => r.problems.push(format!(
                                    "{at} is a library: say where its checkout goes with into = \"<folder in this repo>\" on the dependency{}",
                                    if alt.needs.is_empty() { "" } else { ", and drop needs (a library has no thorns)" }
                                )),
                                (false, _, Some(into)) => r.problems.push(format!(
                                    "the dependency on {} gives into = \"{into}\", but {at} isn't a library (library = true): drop into",
                                    alt.target()
                                )),
                                (false, true, _) if !alt.needs.is_empty() => r.problems.push(format!(
                                    "{at} is a flesh, which has no thorns: drop the needs of the dependency on {}",
                                    alt.target()
                                )),
                                (false, false, _) if alt.needs.is_empty() => r.problems.push(format!(
                                    "the dependency on {} has no needs, but {at} has thorns: name the ones this package uses",
                                    alt.target()
                                )),
                                _ => {}
                            }
                            if let Some(into) = &c.into
                                && tv.library
                                && occupied(&repo.join(into))
                            {
                                r.problems.push(format!(
                                    "the dependency on {} puts its checkout into {into}, which this commit already has: choose a folder the repo doesn't use",
                                    alt.target()
                                ));
                            }
                        }
                        // A stack's needs are optional, but a flesh or a library has no thorns to name.
                        Of::Stack if (tv.flesh || tv.library) && !alt.needs.is_empty() => r.problems.push(format!(
                            "{at} is a {}, which has no thorns: drop the needs of the dependency on {}",
                            if tv.flesh { "flesh" } else { "library" },
                            alt.target()
                        )),
                        Of::Stack => {}
                    }
                    let missing: Vec<&String> = alt
                        .needs
                        .iter()
                        .filter(|n| !tv.flesh && !tv.library && !tv.thorns.iter().any(|(t, _)| t == *n))
                        .collect();
                    if !missing.is_empty() {
                        // A version of the target in range that isn't read yet (released together
                        // with this one, say) may have them: then this waits rather than freezing.
                        use crate::tracker::Unread;
                        let unread = alt_unread(state, &alt).await?;
                        for n in missing {
                            let said = format!("the dependency on {} needs {n}, which {}@{} doesn't have", alt.target(), alt.target(), tv.label);
                            match unread {
                                Unread::Yes => r.waiting.push(format!("{said}, and a version of it in range isn't read yet")),
                                Unread::CantTell => r.waiting.push(format!(
                                    "{said}, and its repo can't be listed right now to see whether a version in range not read yet has it"
                                )),
                                Unread::No => r.problems.push(said),
                            }
                        }
                    }
                    resolved.push((alt, tv));
                }
            }
        }
        r.deps.push((c, resolved));
    }
    Ok(r)
}

/// Refuses what [`resolve_dependencies`] found wrong, with every problem (and what waits beside
/// them); else, when something waits, [`AppError::Upstream`] (the tag is left unread and tried
/// again; a person publishing now sees it as an error, `stacks::for_a_person`).
fn refuse(mut problems: Vec<String>, mut waiting: Vec<String>) -> AppResult<()> {
    problems.dedup();
    waiting.dedup();
    if !problems.is_empty() {
        problems.extend(waiting);
        return Err(AppError::bad(problems.join("; ")));
    }
    if !waiting.is_empty() {
        return Err(AppError::Upstream(waiting.join("; ")));
    }
    Ok(())
}

/// Checks a stack release's dependencies as a package version's are checked, but for the CCL (its
/// own thornlist names what it builds): each target (every alternative of an any-of) is a package
/// with a version on the Cactarium in range (or at the commit) that has the `needs` thorns, if any
/// are named. A target awaiting review, or not public, makes the release wait ([`judge`]).
pub async fn check_stack(state: &AppState, claims: &[ClaimRec]) -> AppResult<()> {
    let r = resolve_dependencies(state, claims, Of::Stack, Reading::Freeze).await?;
    refuse(r.problems, r.waiting)
}

/// Checks a package version's dependencies against its thorns' CCL. `own` is what will be
/// published; `repo` is the checkout (for the includes reviewers should see). Returns the smells,
/// or refuses with every problem and, where it can tell, the line that fixes it. `reading` says
/// which targets count, and whether one awaiting review makes it wait ([`Reading`]).
pub async fn check(
    state: &AppState,
    m: &Manifest,
    own: &[Thorn],
    claims: &[ClaimRec],
    repo: &Path,
    reading: Reading,
) -> AppResult<Vec<String>> {
    let Some(pkg) = &m.package else { return Ok(Vec::new()) };
    let mut smells: Vec<String> = Vec::new();
    let Resolution { deps, mut problems, waiting } =
        resolve_dependencies(state, claims, Of::Package { repo }, reading).await?;

    // The CCL can only be checked against what the dependencies resolve to: with one still missing,
    // the facts found so far decide, else the version waits.
    if !waiting.is_empty() {
        return refuse(problems, waiting).map(|()| Vec::new());
    }

    // Every hard CCL requirement of every published thorn is met. One unmet while an applicable
    // dependency has a version in range not read yet waits for it.
    let mut ccl_waiting: Vec<String> = Vec::new();
    let mut explained: Vec<(String, String)> = Vec::new(); // (target, needs thorn) some requirement used
    // The thorns a header counts by (`ccl::counts`): the package's own, every dependency target's
    // version read here, and every published thorn (`closure::counts`). One that nothing provides
    // compiles empty (a hook), so it never refuses.
    let known: Vec<&ThornFacts> = own
        .iter()
        .map(|(_, _, _, f)| f)
        .chain(deps.iter().flat_map(|(_, opts)| opts.iter().flat_map(|(_, tv)| tv.thorns.iter().map(|(_, f)| f))))
        .collect();
    let mut headers = std::collections::HashMap::new();
    for (arr, name, _, facts) in own {
        // What CactUp reads a thorn's requirements as, and meets them by (the crate's `ccl`): the
        // needs the package's own thorns leave unmet.
        for need in unmet(facts, own.iter().map(|(_, n, _, f)| (n.as_str(), f))) {
            if !crate::closure::counts(state, facts, &need, &known, &mut headers).await? {
                continue;
            }
            let applicable: Vec<&(&ClaimRec, Vec<(Alt, TargetVersion)>)> = deps
                .iter()
                .filter(|(c, opts)| (c.needed_by.is_empty() || c.needed_by.contains(name)) && !opts.is_empty())
                .collect();
            let mut met = false;
            for (_, opts) in &applicable {
                let supplies = |(alt, tv): &(Alt, TargetVersion)| supplier(&alt.needs, &tv.thorns, &need);
                let found: Vec<Option<String>> = opts.iter().map(supplies).collect();
                if found.iter().all(Option::is_some) {
                    met = true;
                    for ((alt, _), n) in opts.iter().zip(found.into_iter().flatten()) {
                        explained.push((alt.target(), n));
                    }
                    break;
                }
            }
            if met {
                continue;
            }
            // Where it can tell, say which line fixes it: a thorn of a dependency that would meet it.
            let hint = applicable.iter().find_map(|(c, opts)| {
                opts.iter().find_map(|(alt, tv)| {
                    tv.thorns
                        .iter()
                        .find(|(t, f)| meets(t, f, &need))
                        .map(|(t, _)| format!(": add \"{t}\" to the needs of the dependency on {}", if c.alternatives.is_empty() { alt.target() } else { format!("{} (in its any-of)", alt.target()) }))
                })
            });
            // A header counts only where a published thorn provides it: name that one.
            let hint = match (hint, &need) {
                (Some(h), _) => Some(h),
                (None, Need::Include(_)) => crate::closure::providers(state, &need).await?.into_iter().next().map(|(thorn, package)| {
                    let short = thorn.rsplit('/').next().unwrap_or(&thorn).to_owned();
                    format!(": add a [[dependency]] on {package} with \"{short}\" in its needs ({thorn} provides it), or exclude-thorns this thorn if it can't build")
                }),
                (None, _) => None,
            };
            let said = format!(
                "{arr}/{name} {}, which neither this package nor a dependency's needs supplies{}",
                need,
                hint.unwrap_or_else(|| ": add a [[dependency]] on the package that provides it, with needs naming its thorn, or exclude-thorns this thorn if it can't build".to_owned())
            );
            let mut unread = None;
            'deps: for (_, opts) in &applicable {
                for (alt, _) in opts {
                    if alt_unread(state, alt).await? != crate::tracker::Unread::No {
                        unread = Some(alt.target());
                        break 'deps;
                    }
                }
            }
            match unread {
                Some(t) => ccl_waiting.push(format!("{said}; {t} has a version in range not read yet, which may supply it")),
                None => problems.push(said),
            }
        }
    }
    if !problems.is_empty() {
        problems.dedup();
        problems.extend(ccl_waiting);
        return Err(AppError::bad(problems.join("; ")));
    }
    if !ccl_waiting.is_empty() {
        ccl_waiting.dedup();
        return Err(AppError::Upstream(ccl_waiting.join("; ")));
    }

    // Smells for reviewers: needs no CCL requirement explains (fine for a header included by path,
    // but worth a look), and includes that climb out of a thorn's own directory.
    for (c, opts) in &deps {
        for (alt, tv) in opts {
            for n in &alt.needs {
                if !explained.iter().any(|(t, e)| *t == alt.target() && e == n) {
                    smells.push(format!(
                        "the dependency on {} needs {n}, which no CCL requirement{} points to: check why it is needed (a header included by path, say)",
                        alt.target(),
                        if c.needed_by.is_empty() { String::new() } else { format!(" of {}", c.needed_by.join(", ")) }
                    ));
                }
            }
            let _ = tv;
        }
    }
    let dirs: Vec<(String, String, bool)> = own
        .iter()
        .map(|(_, n, d, f)| (n.clone(), d.clone(), f.inherits.iter().any(|i| i.eq_ignore_ascii_case("Driver"))))
        .collect();
    let root = repo.to_path_buf();
    let reaching = tokio::task::spawn_blocking(move || {
        dirs.into_iter()
            .flat_map(|(name, dir, any_driver)| {
                includes_leaving(&root, &dir).into_iter().map(move |(file, inc)| (name.clone(), any_driver, file, inc))
            })
            .collect::<Vec<_>>()
    })
    .await
    .map_err(anyhow::Error::from)?;
    let mut said: Vec<String> = Vec::new();
    for (name, any_driver, file, inc) in reaching {
        let line = format!("{name} includes {inc} by path ({file}): it reaches outside its own directory, into another thorn's sources");
        if !said.contains(&line) {
            said.push(line.clone());
            smells.push(line);
            if any_driver {
                smells.push(format!(
                    "{name} inherits Driver (any driver) but reaches into another thorn's sources by path: it may need one driver in particular"
                ));
            }
        }
    }
    if !pkg.exclude_thorns.is_empty() {
        smells.push(format!("exclude-thorns leaves out {}: they aren't published", pkg.exclude_thorns.join(", ")));
    }
    smells.dedup();
    Ok(smells)
}

/// The `#include "../../…"` lines in a thorn's sources whose target lies outside the thorn's
/// directory, as (file, included path). Bounded: at most 2000 files of at most 1 MB each.
fn includes_leaving(repo: &Path, thorn_dir: &str) -> Vec<(String, String)> {
    let base = repo.join(thorn_dir);
    let Ok(base_real) = base.canonicalize() else { return Vec::new() };
    let re = regex::Regex::new(r#"(?m)^\s*#\s*include\s*["<]((?:\.\./){2,}[^">]+)[">]"#).expect("include pattern");
    let mut out = Vec::new();
    let mut stack = vec![base.clone()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(t) = e.file_type() else { continue };
            if t.is_dir() {
                stack.push(p);
                continue;
            }
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            if !matches!(ext, "c" | "cc" | "cxx" | "cpp" | "h" | "hh" | "hxx" | "hpp" | "F" | "F90" | "f90" | "cu") {
                continue;
            }
            seen += 1;
            if seen > 2000 || e.metadata().map(|m| m.len()).unwrap_or(0) > 1 << 20 {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else { continue };
            for cap in re.captures_iter(&text) {
                let inc = cap[1].to_owned();
                let target = p.parent().unwrap_or(&base).join(&inc);
                // Lexically: the target need not exist (it is in another repo).
                let mut norm = std::path::PathBuf::new();
                for c in target.components() {
                    match c {
                        std::path::Component::ParentDir => {
                            norm.pop();
                        }
                        c => norm.push(c),
                    }
                }
                let parent_real = p.parent().and_then(|d| d.canonicalize().ok());
                let leaves = match parent_real {
                    Some(pr) => {
                        let rel = pr.join(&inc);
                        let mut n = std::path::PathBuf::new();
                        for c in rel.components() {
                            match c {
                                std::path::Component::ParentDir => {
                                    n.pop();
                                }
                                c => n.push(c),
                            }
                        }
                        !n.starts_with(&base_real)
                    }
                    None => !norm.starts_with(&base),
                };
                if leaves {
                    let file = p.strip_prefix(repo).unwrap_or(&p).to_string_lossy().into_owned();
                    out.push((file, inc));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(interface: &str, configuration: Option<&str>) -> ThornFacts {
        ThornFacts::scan(interface, configuration)
    }

    /// The package's own thorns meet what they can, by the crate's rule: names compare
    /// case-insensitively, each need is read once, and words an older scanner stored that are no
    /// CCL names make no need (nothing could meet them).
    #[test]
    fn own_thorns_meet_needs_by_the_shared_rule() {
        let z4c = facts("IMPLEMENTS: Z4c\nINHERITS: ADMBase, admbase, CarpetX\nREQUIRES FUNCTION GetLevel", Some("REQUIRES Loop\n"));
        let admbase = facts("IMPLEMENTS: ADMBASE", None);
        let own = [("Z4c", &z4c), ("ADMBase", &admbase)];
        let left: Vec<String> = unmet(&z4c, own).iter().map(ToString::to_string).collect();
        assert_eq!(left, ["inherits or befriends CarpetX", "requires the capability Loop", "requires the function GetLevel"]);
        let old: ThornFacts = serde_json::from_value(serde_json::json!({
            "implements": "X", "inherits": ["b@d"], "friends": [], "requires-functions": ["Get X"], "uses-functions": [],
            "provides-functions": [], "uses-includes": [], "requires": [], "requires-thorns": ["no/pe"], "optional": [], "provides": []
        }))
        .unwrap();
        assert!(unmet(&old, []).is_empty(), "no CCL name, no need");
    }

    /// A dependency supplies a need through one of its `needs` thorns that meets it; a thorn
    /// without an IMPLEMENTS line implements nothing, even what its name spells.
    #[test]
    fn a_dependency_supplies_through_its_needs() {
        let carpetx = facts("IMPLEMENTS: driver\nPROVIDES FUNCTION GetLevel WITH X LANGUAGE C", None);
        let loop_ = facts("IMPLEMENTS: Loop", Some("PROVIDES Loop\n{\n}\n"));
        let bare = facts("INHERITS: grid", None);
        let thorns = vec![("CarpetX".to_owned(), carpetx), ("Loop".to_owned(), loop_), ("Grid".to_owned(), bare)];
        let needs = ["CarpetX".to_owned(), "Loop".to_owned()];
        assert_eq!(supplier(&needs, &thorns, &Need::Implementation("Driver".into())).as_deref(), Some("CarpetX"));
        assert_eq!(supplier(&needs, &thorns, &Need::Capability("loop".into())).as_deref(), Some("Loop"));
        assert_eq!(supplier(&needs, &thorns, &Need::Function("GetLevel".into())).as_deref(), Some("CarpetX"));
        assert_eq!(supplier(&needs[..1], &thorns, &Need::Capability("Loop".into())), None, "not among its needs");
        let all = ["Grid".to_owned()];
        assert_eq!(supplier(&all, &thorns, &Need::Implementation("Grid".into())), None);
        assert_eq!(supplier(&all, &thorns, &Need::Thorn("grid".into())).as_deref(), Some("Grid"));
    }

    /// A dependent waits while its target version awaits review or the target entry isn't public;
    /// an approved version of a public package is judged.
    #[test]
    fn targets_awaiting_review_make_dependents_wait() {
        let tv = |review: &str, visibility: &str| TargetVersion {
            label: "2026.5.1".into(),
            flesh: false,
            library: false,
            thorns: vec![],
            review: review.into(),
            visibility: visibility.into(),
        };
        assert_eq!(judge("et/carpet", &tv("approved", "public")), None);
        let pending = judge("et/carpet", &tv("pending", "public")).unwrap();
        assert!(pending.contains("in its range awaits review") && !pending.contains("2026.5.1"), "{pending}");
        for vis in ["pending", "hidden"] {
            let why = judge("et/carpet", &tv("approved", vis)).unwrap();
            assert_eq!(why, no_public_version("et/carpet", ""), "a hidden or pending target is said like a missing one");
            assert!(!why.contains("hidden") && !why.contains("review"), "{why}");
        }
    }

    /// Problems refuse (with what waits beside them); what only waits is Upstream, which leaves a
    /// tag unread.
    #[test]
    fn problems_refuse_and_waits_wait() {
        assert!(refuse(vec![], vec![]).is_ok());
        match refuse(vec!["a".into(), "a".into()], vec!["w".into()]) {
            Err(AppError::BadRequest(m)) => assert_eq!(m, "a; w"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(refuse(vec![], vec!["w".into()]), Err(AppError::Upstream(m)) if m == "w"));
    }

    /// The headers curated packages' thorns can't compile without are supplied by the package
    /// itself or by its dependencies' needs, as the check now requires: the curated manifests
    /// (CACTARIUM_TEST_CURATE, a curate.toml) read against a tree of their repos at the curated
    /// versions (CACTARIUM_TEST_REPOS, one directory per repo, named as the URL's last part), with
    /// every thorn there standing for the registry's. Prints what each package leaves unmet.
    #[test]
    fn curated_manifests_supply_their_headers() {
        use cactup_ecosystem_common::ccl;
        let (Some(curate), Some(repos)) = (std::env::var_os("CACTARIUM_TEST_CURATE"), std::env::var_os("CACTARIUM_TEST_REPOS")) else {
            return;
        };
        let curate = std::path::PathBuf::from(curate);
        let repos = std::path::PathBuf::from(repos);
        let file: toml::Value = toml::from_str(&std::fs::read_to_string(&curate).unwrap()).unwrap();
        let dirs: Vec<std::path::PathBuf> = std::fs::read_dir(&repos).unwrap().flatten().map(|e| e.path()).collect();
        // (slug, manifest, thorns as (name, facts)).
        let mut packages: Vec<(String, Manifest, Vec<(String, ThornFacts)>)> = Vec::new();
        for p in file["package"].as_array().unwrap() {
            let url = p["url"].as_str().unwrap();
            let base = url.trim_end_matches('/').trim_end_matches(".git").rsplit('/').next().unwrap().to_ascii_lowercase();
            let text = std::fs::read_to_string(curate.parent().unwrap().join(p["manifest"].as_str().unwrap())).unwrap();
            let m = Manifest::from_repo_file(cactup_ecosystem_common::manifest::PACKAGE_FILE, &text).unwrap();
            let pkg = m.package.clone().unwrap();
            let slug = format!("{}/{}", p["owner"].as_str().unwrap(), pkg.name);
            let Some(dir) = dirs.iter().find(|d| d.file_name().is_some_and(|n| n.to_string_lossy().to_ascii_lowercase() == base)) else {
                eprintln!("{slug}: no repo {base} in the tree");
                continue;
            };
            let root = dir.join(pkg.root.clone().unwrap_or_default());
            let mut thorns = Vec::new();
            for t in ccl::scan_tree(&root) {
                let name = match (&t.name, pkg.thorns.as_deref()) {
                    (Some(n), _) => n.clone(),
                    (None, Some([one])) => one.clone(),
                    _ => continue,
                };
                if pkg.thorns.as_ref().is_some_and(|a| !a.contains(&name)) || pkg.exclude_thorns.contains(&name) {
                    continue;
                }
                thorns.push((name, t.facts));
            }
            packages.push((slug, m, thorns));
        }
        let registry: Vec<&ThornFacts> = packages.iter().flat_map(|(_, _, t)| t.iter().map(|(_, f)| f)).collect();
        let mut left: Vec<String> = Vec::new();
        for (slug, m, own) in &packages {
            let claims = ClaimRec::of_manifest(m);
            for (name, facts) in own {
                for need in unmet(facts, own.iter().map(|(n, f)| (n.as_str(), f))) {
                    // Only headers: the other needs were checked when these versions were frozen.
                    if !matches!(need, Need::Include(_)) || !ccl::counts(facts, &need, registry.iter().copied()) {
                        continue;
                    }
                    let met = claims.iter().filter(|c| c.kind == "dependency" && (c.needed_by.is_empty() || c.needed_by.contains(name))).any(|c| {
                        c.options().iter().all(|alt| {
                            let target = packages.iter().find(|(s, _, _)| *s == alt.target());
                            target.is_some_and(|(_, _, thorns)| supplier(&alt.needs, thorns, &need).is_some())
                        })
                    });
                    if !met {
                        let by: Vec<String> = packages
                            .iter()
                            .flat_map(|(s, _, t)| t.iter().filter(|(n, f)| meets(n, f, &need)).map(move |(n, _)| format!("{s} {n}")))
                            .collect();
                        left.push(format!("{slug}: {name} {need} (provided by {})", by.join(", ")));
                    }
                }
            }
        }
        eprintln!("{} packages read; unmet headers:\n{}", packages.len(), left.join("\n"));
        assert!(left.is_empty(), "{} unmet", left.len());
    }

    /// A tip read counts only what its requester could be served; freezing counts every target
    /// and lets a wait decide. Rejected versions and hidden entries never count for a tip.
    #[test]
    fn tips_count_only_what_the_requester_sees() {
        assert_eq!(Reading::default(), Reading::Freeze);
        assert_eq!(counted(Reading::Freeze), (vec!["public", "pending", "hidden"], vec!["approved", "pending"]));
        assert_eq!(counted(Reading::Tip { releases: false, entries: false }), (vec!["public"], vec!["approved"]));
        assert_eq!(counted(Reading::Tip { releases: true, entries: false }), (vec!["public"], vec!["approved", "pending"]));
        assert_eq!(counted(Reading::Tip { releases: true, entries: true }), (vec!["public", "pending"], vec!["approved", "pending"]));
    }
}
