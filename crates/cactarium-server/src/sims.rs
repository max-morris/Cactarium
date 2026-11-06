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
use crate::model::{self, Entry, number_sort_key};
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
    let text = std::str::from_utf8(bytes).map_err(|_| AppError::bad("the .sim file is not UTF-8 text"))?;
    let sim = SimFile::from_toml(text).map_err(AppError::bad)?;
    let problems = sim.unspecified();
    if !problems.is_empty() {
        let list: Vec<String> = problems.iter().map(|p| p.to_string()).collect();
        return Err(AppError::bad(format!(
            "only fully specified sims can be published: {}. Export with cactup sim export, which pins every repo",
            list.join("; ")
        )));
    }
    let list = crl::parse(&sim.thornlist.text).map_err(|e| AppError::bad(format!("the thornlist does not parse: {e:#}")))?;
    let crl_repos: BTreeSet<String> =
        list.components().iter().filter(|c| c.ty != ComponentType::Ignore).map(|c| c.repo.clone()).collect();
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
        return Err(AppError::bad(format!("[sim] root is '{}' but the thornlist's ROOT is '{}'", sim.sim.root, list.root())));
    }
    let mut warnings = Vec::new();
    let mut found: BTreeSet<String> = BTreeSet::new();
    for m in PRIVATE_PATH.find_iter(&sim.parfile.text) {
        found.insert(m.as_str().trim_end_matches('/').to_owned());
    }
    if !found.is_empty() {
        warnings.push(format!(
            "the parfile mentions machine-specific paths ({}); consider an @KNOB(...)@ input instead",
            found.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    let stuck = crate::stacks::thorns_on_checkout_lines(&sim.thornlist.text);
    if !stuck.is_empty() {
        warnings.push(format!(
            "these thorns sit on a !CHECKOUT line, where Cactus never builds them: {}",
            stuck.join(", ")
        ));
    }
    if sim.sim.license.is_none() {
        warnings.push("no license: others can view it but may not know whether they can reuse it".into());
    }
    for k in knob_tokens(&sim.parfile.text) {
        if !sim.inputs.iter().any(|i| i.knob == k) {
            warnings.push(format!("the parfile uses @KNOB({k})@ but declares no [[input]] for it"));
        }
    }
    let index = SimIndex {
        thorns: list.components().iter().filter(|c| c.checkout.contains('/')).map(|c| c.checkout.clone()).collect(),
        repos: crl_repos.into_iter().collect(),
        inputs: sim.inputs.iter().map(|i| i.knob.clone()).collect(),
        vars: sim.parfile.vars.clone(),
        warnings,
    };
    Ok(Checked { sim, index })
}

fn knob_tokens(par: &str) -> BTreeSet<String> {
    static KNOB: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"@KNOB\(([A-Za-z0-9_.-]+)\)@").expect("valid regex"));
    KNOB.captures_iter(par).map(|c| c[1].to_owned()).collect()
}

/// Publishes a checked sim as the next version of `user`'s `name` (creating the entry if new).
pub async fn publish(state: &AppState, user: &User, name: Option<&str>, checked: Checked) -> AppResult<(Entry, u32)> {
    let Checked { mut sim, index } = checked;
    let name = name.map(str::trim).filter(|n| !n.is_empty()).map(str::to_owned).unwrap_or_else(|| sim.sim.name.clone());
    name.parse::<Name>().map_err(AppError::bad)?;
    let entry = match model::find_entry(state, &user.username, &name).await? {
        Some(e) if e.kind != "sim" => return Err(AppError::Conflict(format!("{} is a {}, not a sim", e.slug(), e.kind))),
        Some(e) => e,
        None => {
            publish::create_entry(
                state,
                user,
                NewEntry {
                    kind: "sim",
                    owner: &user.username,
                    name: &name,
                    summary: sim.sim.summary.clone(),
                    description: sim.sim.description.clone(),
                    curated: false,
                },
            )
            .await?
        }
    };
    let next: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(version::bigint), 0) + 1 FROM versions WHERE entry_id = $1")
        .bind(entry.id)
        .fetch_one(&state.db)
        .await?;
    let n = u32::try_from(next).map_err(|_| AppError::bad("too many versions"))?;
    sim.sim.cactarium = Some(format!("{}@{n}", entry.slug()).parse().map_err(AppError::bad)?);
    let stored = sim.to_toml().map_err(AppError::bad)?;
    let sha = hex::encode(Sha256::digest(stored.as_bytes()));
    let mut tx = state.db.begin().await?;
    let vid: i64 = sqlx::query_scalar(
        "INSERT INTO versions (entry_id, track, version, sort_key, published_by) VALUES ($1, '', $2, $3, $4) RETURNING id",
    )
    .bind(entry.id)
    .bind(n.to_string())
    .bind(number_sort_key(n))
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO sim_files (version_id, sha256, content, index) VALUES ($1, $2, $3, $4)")
        .bind(vid)
        .bind(&sha)
        .bind(&stored)
        .bind(serde_json::to_value(&index).map_err(anyhow::Error::from)?)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE entries SET summary = COALESCE($2, summary), description = COALESCE($3, description), updated_at = now() WHERE id = $1")
        .bind(entry.id)
        .bind(&sim.sim.summary)
        .bind(&sim.sim.description)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracker::store_pins(state, vid, &sim.repos).await?;
    audit(state, Some(user.id), "sim.publish", Some(&entry.slug()), json!({ "version": n, "sha256": sha }), None).await?;
    Ok((entry, n))
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
!CHECKOUT = CarpetX/CarpetX CarpetX/Loop
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
            s.push_str(&format!("[[repo]]\nname = \"Other\"\nurl = \"https://x/o.git\"\ncommit = \"{SHA}\"\n"));
        }
        s
    }

    #[test]
    fn accepts_a_consistent_sim_and_warns_about_paths() {
        let c = check(sim(false, "x::f = \"/home/someone/id.info\"\ny = \"@KNOB(id)@\"").as_bytes()).unwrap();
        assert_eq!(c.index.repos, ["CarpetX"]);
        assert_eq!(c.index.thorns, ["CarpetX/CarpetX", "CarpetX/Loop"]);
        let w = c.index.warnings.join("\n");
        assert!(w.contains("/home/someone"), "{w}");
        assert!(w.contains("@KNOB(id)@"), "{w}");
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
