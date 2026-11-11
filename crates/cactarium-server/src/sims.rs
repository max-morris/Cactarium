//! Publishing `.sim` files.
//!
//! A published sim must be fully specified (every repo pinned, nothing dirty or untracked), and
//! its `[[repo]]` table must name exactly the repos its thornlist checks out. The registry stamps
//! `[sim] cactarium = "owner/name@N"` into the stored copy; the thornlist and parfile stay verbatim.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use cactup_ecosystem_common::crl::{self, ComponentType};
use cactup_ecosystem_common::name::Name;
use cactup_ecosystem_common::sim::SimFile;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::audit::audit;
use crate::auth::User;
use crate::error::{AppError, AppResult};
use crate::model::{self, Entry, semver_sort_key};
use crate::publish::{self, NewEntry};
use crate::state::AppState;
use crate::tracker;

pub const MAX_SIM_BYTES: usize = 1024 * 1024;

/// What the registry derives from a sim for search and review.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SimIndex {
    pub thorns: Vec<String>,
    pub repos: Vec<String>,
    pub inputs: Vec<String>,
    pub vars: Vec<String>,
    /// Things a reviewer should look at; none of them blocks publishing.
    pub warnings: Vec<String>,
}

/// The result of checking a sim before it is published.
pub struct Checked {
    pub sim: SimFile,
    pub index: SimIndex,
}

static PRIVATE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(/home/[A-Za-z0-9_.-]+|/Users/[A-Za-z0-9_.-]+|/scratch[0-9]*/|/work/|/ddn[A-Za-z0-9]*/|/project/)"#)
        .expect("valid regex")
});

/// Checks a `.sim` upload. Errors are reasons it cannot be published.
pub fn check(bytes: &[u8]) -> AppResult<Checked> {
    if bytes.len() > MAX_SIM_BYTES {
        return Err(AppError::bad("the .sim file is larger than 1 MB"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| AppError::bad("the .sim file is not UTF-8 text"))?;
    let sim = SimFile::from_toml(text).map_err(AppError::bad)?;
    let problems = sim.unspecified();
    if !problems.is_empty() {
        let list: Vec<String> = problems.iter().map(|p| p.to_string()).collect();
        return Err(AppError::bad(format!(
            "only fully specified sims can be published: {}. Export with cactup sim export, which pins every repo",
            list.join("; ")
        )));
    }
    let list = crl::parse(&sim.thornlist.text)
        .map_err(|e| AppError::bad(format!("the thornlist does not parse: {e:#}")))?;
    let crl_repos: BTreeSet<String> = list
        .components()
        .iter()
        .filter(|c| c.ty != ComponentType::Ignore)
        .map(|c| c.repo.clone())
        .collect();
    let pinned: BTreeSet<String> = sim.repos.iter().map(|r| r.name.clone()).collect();
    let missing: Vec<&String> = crl_repos.difference(&pinned).collect();
    if !missing.is_empty() {
        return Err(AppError::bad(format!(
            "the thornlist checks out repos with no [[repo]] pin: {}",
            missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        )));
    }
    let extra: Vec<&String> = pinned.difference(&crl_repos).collect();
    if !extra.is_empty() {
        return Err(AppError::bad(format!(
            "[[repo]] pins repos the thornlist never checks out: {}",
            extra.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        )));
    }
    if list.root() != sim.sim.root && !(list.root() == "." && sim.sim.root.is_empty()) {
        return Err(AppError::bad(format!(
            "[sim] root is '{}' but the thornlist's ROOT is '{}'",
            sim.sim.root,
            list.root()
        )));
    }
    let mut warnings = Vec::new();
    let par = &sim.parfile.text;
    let comments = cactup_ecosystem_common::par::comment_spans(par);
    let in_comment = |at: usize| comments.iter().any(|c| c.contains(&at));
    let mut found: BTreeSet<String> = BTreeSet::new();
    for m in PRIVATE_PATH.find_iter(par).filter(|m| !in_comment(m.start())) {
        found.insert(m.as_str().trim_end_matches('/').to_owned());
    }
    if !found.is_empty() {
        warnings.push(format!(
            "the parfile mentions machine-specific paths ({}); consider an @KNOB(...)@ input instead",
            found.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    // Not a problem, but what an import fetches and writes is worth a reviewer's look.
    for i in sim.inputs.iter().filter(|i| i.unpack) {
        warnings.push(format!(
            "input {} {} {}{}",
            i.knob,
            if i.repo_file.is_some() { "unpacks the repo's" } else { "downloads and unpacks" },
            i.url.as_deref().or(i.repo_file.as_deref()).unwrap_or("?"),
            match i.fixups.len() {
                0 => String::new(),
                n => format!(", then edits {n} line(s) in it"),
            }
        ));
    }
    if sim.sim.license.is_none() {
        warnings
            .push("no license: others can view it but may not know whether they can reuse it".into());
    }
    // Exactly cactup's lexing: comments and @@ escapes are not uses, and a knob with a default in
    // every use is optional.
    match cactup_ecosystem_common::par::references(par) {
        Ok(refs) if sim.parfile.kind == cactup_ecosystem_common::sim::ParfileKind::Par => {
            for k in refs.knobs.iter().filter(|k| !k.optional) {
                if !sim.inputs.iter().any(|i| i.knob == k.name) {
                    warnings.push(format!(
                        "the parfile needs @KNOB({})@ but declares no [[input]] for it",
                        k.name
                    ));
                }
            }
            for e in refs.env.iter().filter(|e| !e.optional) {
                warnings.push(format!("the parfile needs the environment variable {} (@ENV({})@), so it is not self-contained", e.name, e.name));
            }
        }
        Ok(_) => {}
        Err(e) if sim.parfile.kind == cactup_ecosystem_common::sim::ParfileKind::Par => {
            warnings.push(format!("cactup would refuse this parfile at submit time: {e}"));
        }
        Err(_) => {}
    }
    let index = SimIndex {
        // The thorns the build compiles: checkout-only ones (on a !CHECKOUT line) are fetched, not built.
        thorns: list
            .components()
            .iter()
            .filter(|c| c.checkout.contains('/') && !c.fetch_only)
            .map(|c| c.checkout.clone())
            .collect(),
        repos: crl_repos.into_iter().collect(),
        inputs: sim.inputs.iter().map(|i| i.knob.clone()).collect(),
        vars: sim.parfile.vars.clone(),
        warnings,
    };
    Ok(Checked { sim, index })
}

/// Publishes a checked sim as a version of `owner/name`: `owner` is the user or one of their
/// organizations (default: the user), `name` defaults to the file's (creating the entry if new).
/// `version` is the semver version to publish (default: the next major, 1.0.0, 2.0.0, …), so
/// `owner/name@1` means 1.x.x as for packages and stacks. Returns the entry, the version and
/// whether it is approved or waits for review.
pub async fn publish(
    state: &AppState,
    user: &User,
    owner: Option<&str>,
    name: Option<&str>,
    version: Option<&str>,
    checked: Checked,
) -> AppResult<(Entry, String, &'static str)> {
    let Checked { sim, index } = checked;
    let owner = owner
        .map(str::trim)
        .filter(|o| !o.is_empty())
        .unwrap_or(&user.username)
        .to_owned();
    publish::check_namespace(state, user, &owner).await?;
    let name = name
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| sim.sim.name.clone());
    name.parse::<Name>().map_err(AppError::bad)?;
    let entry = match model::find_entry(state, &owner, &name).await? {
        Some(e) if e.kind != "sim" => {
            return Err(AppError::Conflict(format!("{} is a {}, not a sim", e.slug(), e.kind)));
        }
        Some(e) => e,
        None => {
            publish::create_entry(
                state,
                user,
                NewEntry {
                    kind: "sim",
                    owner: &owner,
                    name: &name,
                    summary: sim.sim.summary.clone(),
                    description: sim.sim.description.clone(),
                    curated: false,
                },
            )
            .await?
        }
    };
    if let Some(i) = sim.inputs.iter().find(|i| i.repo_file.is_some()) {
        return Err(AppError::bad(format!(
            "input {} reads a file from the sim's repo (repo-file), so only a sim published from its repo can carry it; give it a url and sha256 instead",
            i.knob
        )));
    }
    if tracker::repo_of(state, entry.id).await?.is_some() {
        return Err(AppError::bad(format!(
            "{} is released from its repo; push a version tag instead",
            entry.slug()
        )));
    }
    let v = match version.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => semver::Version::parse(v.strip_prefix('v').unwrap_or(v))
            .map_err(|e| AppError::bad(format!("version '{v}' is not X.Y.Z: {e}")))?,
        None => {
            let existing: Vec<String> =
                sqlx::query_scalar("SELECT version FROM versions WHERE entry_id = $1")
                    .bind(entry.id)
                    .fetch_all(&state.db)
                    .await?;
            let major = existing
                .iter()
                .filter_map(|v| semver::Version::parse(v).ok())
                .map(|v| v.major)
                .max();
            semver::Version::new(major.map_or(1, |m| m + 1), 0, 0)
        }
    };
    let label = v.to_string();
    if model::any_version_by_label(state, entry.id, &label).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "{}@{label} already exists; versions never change",
            entry.slug()
        )));
    }
    let review = publish::release_review(state, &entry, Some(user)).await?;
    let vid: i64 = sqlx::query_scalar(
        "INSERT INTO versions (entry_id, track, version, sort_key, published_by, review) VALUES ($1, '', $2, $3, $4, $5) RETURNING id",
    )
    .bind(entry.id)
    .bind(&label)
    .bind(semver_sort_key(&v))
    .bind(user.id)
    .bind(review)
    .fetch_one(&state.db)
    .await?;
    let sha = store_version(state, &entry, vid, &label, review, Checked { sim, index }, None).await?;
    publish::submit_release(state, &entry, vid, review, Some(user)).await?;
    audit(
        state,
        Some(user.id),
        "sim.publish",
        Some(&entry.slug()),
        json!({ "version": label, "sha256": sha, "review": review }),
        None,
    )
    .await?;
    Ok((entry, label, review))
}

/// Stores a checked sim as version `vid` (`label`) of `entry`: stamps it with `owner/name@label`,
/// keeps the file, its pins and the thorns it builds. For a sim published from its repo,
/// `description` is the manifest's, which wins over the file's. Returns the stored file's sha256.
pub async fn store_version(
    state: &AppState,
    entry: &Entry,
    vid: i64,
    label: &str,
    review: &str,
    checked: Checked,
    description: Option<&str>,
) -> AppResult<String> {
    let Checked { mut sim, index } = checked;
    sim.sim.cactarium = Some(format!("{}@{label}", entry.slug()).parse().map_err(AppError::bad)?);
    let stored = sim.to_toml().map_err(AppError::bad)?;
    let sha = hex::encode(Sha256::digest(stored.as_bytes()));
    let mut tx = state.db.begin().await?;
    sqlx::query("INSERT INTO sim_files (version_id, sha256, content, index) VALUES ($1, $2, $3, $4)")
        .bind(vid)
        .bind(&sha)
        .bind(&stored)
        .bind(serde_json::to_value(&index).map_err(anyhow::Error::from)?)
        .execute(&mut *tx)
        .await?;
    // A release waiting in review doesn't change what the public page says yet.
    if review == "approved" {
        sqlx::query("UPDATE entries SET summary = COALESCE($2, summary), description = COALESCE($3, description), updated_at = now() WHERE id = $1")
            .bind(entry.id)
            .bind(&sim.sim.summary)
            .bind(description.map(str::to_owned).or(sim.sim.description.clone()))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    tracker::store_pins(state, vid, &sim.repos).await?;
    tracker::store_built_thorns(state, vid, &sim.thornlist.text).await?;
    Ok(sha)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "3f2c9e1a00112233445566778899aabbccddeeff";

    fn sim(extra_repo: bool, par: &str) -> String {
        let mut s = format!(
            r#"format = 1
[sim]
name = "qc0"
root = "Cactus"
[thornlist]
filename = "qc0.th"
text = '''
!CRL_VERSION = 1.0
!DEFINE ROOT = Cactus
!TARGET = $ROOT/arrangements
!TYPE = git
!URL = https://github.com/x/CarpetX.git
!REPO_PATH = $2
!CHECKOUT =
CarpetX/CarpetX
CarpetX/Loop
'''
[parfile]
filename = "qc0.par"
kind = "par"
text = '''
{par}
'''
[[repo]]
name = "CarpetX"
url = "https://github.com/x/CarpetX.git"
commit = "{SHA}"
"#
        );
        if extra_repo {
            s.push_str(&format!(
                "[[repo]]\nname = \"Other\"\nurl = \"https://x/o.git\"\ncommit = \"{SHA}\"\n"
            ));
        }
        s
    }

    #[test]
    fn accepts_a_consistent_sim_and_warns_about_paths() {
        let c = check(sim(false, "x::f = \"/home/someone/id.info\"\ny = \"@KNOB(id)@\"").as_bytes())
            .unwrap();
        assert_eq!(c.index.repos, ["CarpetX"]);
        assert_eq!(c.index.thorns, ["CarpetX/CarpetX", "CarpetX/Loop"]);
        let w = c.index.warnings.join("\n");
        assert!(w.contains("/home/someone"), "{w}");
        assert!(w.contains("@KNOB(id)@"), "{w}");
    }

    /// Paths and knob syntax mentioned in comments are no use.
    #[test]
    fn comments_are_not_uses() {
        let par = "# results go to /work/me; @KNOB(name)@ is the required form\ny = \"@KNOB-OPTIONAL(mail, none)@\"";
        let c = check(sim(false, par).as_bytes()).unwrap();
        let w = c.index.warnings.join("\n");
        assert!(!w.contains("/work") && !w.contains("KNOB"), "{w}");
    }

    /// A real parfile that documents @KNOB(name)@ and /work in its comments (neither is a use) and
    /// needs `kadath-initial-data`. Runs when CACTARIUM_TEST_PARFILE names one.
    #[test]
    fn a_real_parfile_has_no_false_positives() {
        let Some(path) = std::env::var_os("CACTARIUM_TEST_PARFILE") else { return };
        let Ok(par) = std::fs::read_to_string(path) else { return };
        let mut parsed = SimFile::from_toml(&sim(false, "x = 1")).unwrap();
        parsed.parfile.text = par;
        parsed.inputs.push(cactup_ecosystem_common::sim::Input {
            knob: "kadath-initial-data".into(),
            description: None,
            url: None,
            sha256: None,
            repo_file: None,
            unpack: false,
            path: None,
            fixups: vec![],
        });
        let c = check(parsed.to_toml().unwrap().as_bytes()).unwrap();
        let w = c.index.warnings.join("\n");
        assert!(!w.contains("/work") && !w.contains("KNOB") && !w.contains("refuse"), "{w}");
    }

    #[test]
    fn rejects_pins_that_do_not_match_the_thornlist() {
        let e = check(sim(true, "").as_bytes()).err().unwrap().to_string();
        assert!(e.contains("never checks out: Other"), "{e}");
        let unpinned = sim(false, "").replace(&format!("commit = \"{SHA}\"\n"), "");
        let e = check(unpinned.as_bytes()).err().unwrap().to_string();
        assert!(e.contains("fully specified"), "{e}");
    }
}
