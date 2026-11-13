//! The dependency check every package version passes, and what reviewers should look at.
//!
//! A thorn's CCL says what it needs (implementations it inherits or befriends, capabilities and
//! thorns it requires, functions it requires); a `[[dependency]]` says which thorns of which
//! package supply that (`needs`). The Cactarium hosts only what works as delivered, so a version is
//! refused unless the two agree: every hard CCL requirement of every published thorn is met by the
//! package itself, or by the `needs` thorns of a dependency that applies to that thorn (for an
//! `any-of`, by every alternative). Smells are what a reviewer should look at but that don't block:
//! needs the CCL doesn't explain, includes that reach another thorn's sources by path, and so on.

use std::path::Path;

use cactup_ecosystem_common::ccl::ThornFacts;
use cactup_ecosystem_common::manifest::Manifest;
use cactup_ecosystem_common::version::{TrackedReq, TrackedVersion};

use crate::claims::{Alt, ClaimRec};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// A published thorn as `prepare` scanned it: (arrangement, name, directory in the repo, facts).
pub type Thorn = (String, String, String, ThornFacts);

/// A hard CCL requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Need {
    Impl(String),
    Cap(String),
    Thorn(String),
    Func(String),
}

impl Need {
    fn says(&self) -> String {
        match self {
            Need::Impl(i) => format!("inherits or befriends {i}"),
            Need::Cap(c) => format!("requires the capability {c}"),
            Need::Thorn(t) => format!("requires the thorn {t}"),
            Need::Func(f) => format!("requires the function {f}"),
        }
    }
}

fn needs_of(f: &ThornFacts) -> Vec<Need> {
    let mut v: Vec<Need> = Vec::new();
    v.extend(f.inherits.iter().chain(&f.friends).map(|i| Need::Impl(i.clone())));
    v.extend(f.requires.iter().map(|c| Need::Cap(c.clone())));
    v.extend(f.requires_thorns.iter().map(|t| Need::Thorn(t.clone())));
    v.extend(f.requires_functions.iter().map(|x| Need::Func(x.clone())));
    v.dedup();
    v
}

/// Whether thorn `name` (with `facts`) meets the requirement. CCL names are case-insensitive.
fn meets(name: &str, facts: &ThornFacts, need: &Need) -> bool {
    let eq = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    match need {
        Need::Impl(i) => facts.implements.as_deref().is_some_and(|x| eq(x, i)),
        Need::Cap(c) => facts.provides.iter().any(|p| eq(p, c)),
        Need::Thorn(t) => eq(name, t),
        Need::Func(x) => facts.provides_functions.iter().any(|p| eq(p, x)),
    }
}

/// The version of a dependency's target that the check reads: the newest one on the Cactarium
/// within its range (or at its commit), reviewed or awaiting review.
struct TargetVersion {
    label: String,
    flesh: bool,
    library: bool,
    thorns: Vec<(String, ThornFacts)>,
}

async fn target_version(state: &AppState, alt: &Alt) -> AppResult<Option<TargetVersion>> {
    let rows: Vec<(i64, String, String, Option<String>, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT v.id, v.track, v.version, v.commit, v.manifest FROM versions v JOIN entries e ON e.id = v.entry_id
         WHERE e.owner = $1 AND e.name = $2 AND e.kind = 'package' AND v.state <> 'invalid'
           AND v.review IN ('approved', 'pending')
         ORDER BY v.sort_key DESC",
    )
    .bind(&alt.owner)
    .bind(&alt.name)
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
    let chosen = rows.into_iter().find(|(_, track, version, commit, _)| match (&alt.sha, &req) {
        (Some(sha), _) => commit.as_deref().is_some_and(|c| c.starts_with(sha.as_str())),
        (None, Some(q)) => {
            let label = if track.is_empty() { version.clone() } else { format!("{track}:{version}") };
            label.parse::<TrackedVersion>().is_ok_and(|v| q.matches(&v))
        }
        (None, None) => false,
    });
    let Some((id, track, version, _, manifest)) = chosen else { return Ok(None) };
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
    }))
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

/// Whether a library's checkout can't go at `path`: something is there already (a file, or a
/// folder with anything in it).
fn occupied(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Err(_) => false,
        Ok(m) if m.is_dir() => std::fs::read_dir(path).is_ok_and(|mut d| d.next().is_some()),
        Ok(_) => true,
    }
}

/// Checks a package version's dependencies against its thorns' CCL. `own` is what will be
/// published; `repo` is the checkout (for the includes reviewers should see). Returns the smells,
/// or refuses with every problem and, where it can tell, the line that fixes it.
pub async fn check(state: &AppState, m: &Manifest, own: &[Thorn], claims: &[ClaimRec], repo: &Path) -> AppResult<Vec<String>> {
    let Some(pkg) = &m.package else { return Ok(Vec::new()) };
    let mut problems: Vec<String> = Vec::new();
    // What may become true without a new commit: a target nobody registered yet, or one with no
    // version in range yet. A version read at a tag waits for these instead of freezing invalid.
    let mut waiting: Vec<String> = Vec::new();
    let mut smells: Vec<String> = Vec::new();

    // Each dependency, with the target version every alternative resolves to.
    let mut deps: Vec<(&ClaimRec, Vec<(Alt, TargetVersion)>)> = Vec::new();
    for c in claims.iter().filter(|c| c.kind == "dependency") {
        let mut resolved = Vec::new();
        for alt in c.options() {
            let at = match (&alt.range, &alt.sha) {
                (Some(r), _) => format!("@{r}"),
                (None, Some(h)) => format!("#{h}"),
                (None, None) => String::new(),
            };
            match target_version(state, &alt).await? {
                None => {
                    let kind: Option<String> = sqlx::query_scalar("SELECT kind FROM entries WHERE owner = $1 AND name = $2")
                        .bind(&alt.owner)
                        .bind(&alt.name)
                        .fetch_optional(&state.db)
                        .await?;
                    problems.push(match kind.as_deref() {
                        Some(k) if k != "package" => format!(
                            "the dependency on {}: that is a {k}; a package depends on packages, whose thorns it names in needs (say works-with for a {k})",
                            alt.target()
                        ),
                        _ => {
                            waiting.push(format!(
                                "the dependency on {}{at}: the Cactarium has no version of that package in that range yet; publish it first",
                                alt.target()
                            ));
                            continue;
                        }
                    });
                }
                Some(tv) => {
                    let at = format!("{}@{}", alt.target(), tv.label);
                    // needs exactly when the target has thorns; into exactly when it is a library.
                    match (tv.library, tv.flesh, &c.into) {
                        (true, _, _) if !c.alternatives.is_empty() => problems.push(format!(
                            "{at} is a library, which can't be an alternative in an any-of: depend on it with target and into"
                        )),
                        (true, _, None) => problems.push(format!(
                            "{at} is a library: say where its checkout goes with into = \"<folder in this repo>\" on the dependency{}",
                            if alt.needs.is_empty() { "" } else { ", and drop needs (a library has no thorns)" }
                        )),
                        (false, _, Some(into)) => problems.push(format!(
                            "the dependency on {} gives into = \"{into}\", but {at} isn't a library (library = true): drop into",
                            alt.target()
                        )),
                        (false, true, _) if !alt.needs.is_empty() => problems.push(format!(
                            "{at} is a flesh, which has no thorns: drop the needs of the dependency on {}",
                            alt.target()
                        )),
                        (false, false, _) if alt.needs.is_empty() => problems.push(format!(
                            "the dependency on {} has no needs, but {at} has thorns: name the ones this package uses",
                            alt.target()
                        )),
                        _ => {}
                    }
                    if let Some(into) = &c.into
                        && tv.library
                        && occupied(&repo.join(into))
                    {
                        problems.push(format!(
                            "the dependency on {} puts its checkout into {into}, which this commit already has: choose a folder the repo doesn't use",
                            alt.target()
                        ));
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
                                Unread::Yes => waiting.push(format!("{said}, and a version of it in range isn't read yet")),
                                Unread::CantTell => waiting.push(format!(
                                    "{said}, and its repo can't be listed right now to see whether a version in range not read yet has it"
                                )),
                                Unread::No => problems.push(said),
                            }
                        }
                    }
                    resolved.push((alt, tv));
                }
            }
        }
        deps.push((c, resolved));
    }

    // The CCL can only be checked against what the dependencies resolve to: with one still missing,
    // the facts found so far decide, else the version waits.
    if !waiting.is_empty() {
        if !problems.is_empty() {
            problems.extend(waiting);
            return Err(AppError::bad(problems.join("; ")));
        }
        return Err(AppError::Upstream(waiting.join("; ")));
    }

    // Every hard CCL requirement of every published thorn is met. One unmet while an applicable
    // dependency has a version in range not read yet waits for it.
    let mut ccl_waiting: Vec<String> = Vec::new();
    let mut explained: Vec<(String, String)> = Vec::new(); // (target, needs thorn) some requirement used
    for (arr, name, _, facts) in own {
        for need in needs_of(facts) {
            if own.iter().any(|(_, n, _, f)| meets(n, f, &need)) {
                continue;
            }
            let applicable: Vec<&(&ClaimRec, Vec<(Alt, TargetVersion)>)> = deps
                .iter()
                .filter(|(c, opts)| (c.needed_by.is_empty() || c.needed_by.contains(name)) && !opts.is_empty())
                .collect();
            let mut met = false;
            for (_, opts) in &applicable {
                let supplies = |(alt, tv): &(Alt, TargetVersion)| {
                    alt.needs.iter().find(|n| tv.thorns.iter().any(|(t, f)| t == *n && meets(t, f, &need))).cloned()
                };
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
            let said = format!(
                "{arr}/{name} {}, which neither this package nor a dependency's needs supplies{}",
                need.says(),
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
