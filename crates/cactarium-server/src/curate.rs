//! Curated packages in bulk: `cactarium curate <admin> <curate.toml>`.
//!
//! A curated package keeps its manifest on the Cactarium for a repo whose maintainers haven't
//! committed a cactarium.toml yet: the stopgap until they do (then an admin hands it over, see
//! `tracker::hand_over`). The file lists one `[[package]]` per repo:
//!
//! ```toml
//! [[package]]
//! owner = "et"
//! url = "https://github.com/EinsteinToolkit/ExternalLibraries-HDF5"
//! manifest = "manifests/hdf5.toml"            # relative to this file; its tag-pattern and
//!                                             # since say which upstream tags are versions
//!
//! [[package.version]]                          # optional: versions by commit (untagged repos)
//! version = "2026.5.0"
//! commit = "…"
//! ```
//!
//! Running it again updates what changed and adds missing versions; a package that has been
//! handed over to its repo's manifest is left alone.

use std::path::Path;

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::auth::User;
use crate::model;
use crate::state::AppState;
use crate::tracker;
use cactup_ecosystem_common::manifest::{Manifest, PACKAGE_FILE};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CurateFile {
    #[serde(rename = "package")]
    packages: Vec<Item>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Item {
    owner: String,
    url: String,
    manifest: String,
    /// Accepted only to say where they belong now.
    tag_pattern: Option<String>,
    since: Option<String>,
    #[serde(default, rename = "version")]
    versions: Vec<Pinned>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pinned {
    version: String,
    commit: String,
}

pub async fn run(state: &AppState, admin: &User, file: &Path) -> anyhow::Result<()> {
    if !admin.is_admin() {
        bail!("{} is not an admin", admin.username);
    }
    let text =
        std::fs::read_to_string(file).with_context(|| format!("cannot read '{}'", file.display()))?;
    let list: CurateFile = toml::from_str(&text).with_context(|| format!("'{}'", file.display()))?;
    let dir = file.parent().unwrap_or(Path::new("."));
    let mut failed = 0;
    for item in &list.packages {
        match one(state, admin, dir, item).await {
            Ok(line) => println!("{line}"),
            Err(e) => {
                failed += 1;
                println!("FAILED {} ({}): {e:#}", item.manifest, item.url);
            }
        }
    }
    println!("{} packages, {failed} failed", list.packages.len());
    if failed > 0 {
        bail!("{failed} of {} packages failed", list.packages.len());
    }
    Ok(())
}

async fn one(state: &AppState, admin: &User, dir: &Path, item: &Item) -> anyhow::Result<String> {
    let err = |e: crate::error::AppError| anyhow::anyhow!("{e}");
    let path = dir.join(&item.manifest);
    let overlay =
        std::fs::read_to_string(&path).with_context(|| format!("cannot read '{}'", path.display()))?;
    let m = Manifest::from_repo_file(PACKAGE_FILE, &overlay).map_err(|e| anyhow::anyhow!("{e}"))?;
    let name = m.package.as_ref().context("the manifest has no [package]")?.name.to_string();
    if item.tag_pattern.is_some() || item.since.is_some() {
        bail!("tag-pattern and since belong in the manifest's [package] now, not in this file");
    }
    let (entry, what) = match model::find_entry(state, &item.owner, &name).await.map_err(err)? {
        None => {
            let e = tracker::register_curated(state, admin, &item.owner, &item.url, &overlay)
                .await
                .map_err(err)?;
            (e, "created")
        }
        Some(e) if e.curated => {
            tracker::update_curated(state, admin, &e, &item.url, &overlay)
                .await
                .map_err(err)?;
            (e, "updated")
        }
        Some(e) => return Ok(format!("{}: uses its repo's manifest now; left alone", e.slug())),
    };
    let mut added = 0;
    for p in &item.versions {
        if model::any_version_by_label(state, entry.id, &p.version)
            .await
            .map_err(err)?
            .is_none()
        {
            tracker::add_virtual_version(state, admin, &entry, &p.version, &p.commit)
                .await
                .map_err(err)?;
            added += 1;
        }
    }
    let versions = model::all_versions(state, entry.id).await.map_err(err)?;
    let labels: Vec<String> = versions.iter().map(|v| v.label()).collect();
    // Reading the repo's tags failed: say so, since the package then has no tagged versions.
    let poll_error: Option<String> =
        sqlx::query_scalar("SELECT poll_error FROM entry_repos WHERE entry_id = $1")
            .bind(entry.id)
            .fetch_optional(&state.db)
            .await?
            .flatten();
    Ok(format!(
        "{}: {what}{}; versions: {}{}",
        entry.slug(),
        if added > 0 { format!(", {added} added by commit") } else { String::new() },
        if labels.is_empty() { "none yet".to_owned() } else { labels.join(", ") },
        poll_error
            .map(|e| format!(" (reading its tags failed: {e})"))
            .unwrap_or_default()
    ))
}
