//! Manifests committed in a repo and read at every version tag.
//!
//! - [`PACKAGE_FILE`] (`cactarium.toml`) describes a **package** (`[package]`: the repo's thorns).
//! - [`STACK_FILE`] (`cactarium-stack.toml`) describes a **stack** (`[stack]`, see
//!   [`crate::stack`]). A repo holding one is a *manifest repo*; it may hold nothing else, or be a
//!   package repo that also carries a stack.
//!
//! A repo can carry either file or both; the registry looks for each at every tag. Claims
//! (`[[fork-of]]`, `[[depends-on]]`, `[[works-with]]`, `[[incompatible-with]]`) and `[[caveat]]`s
//! may appear in either file.
//!
//! Admins use the same schema for the overlay manifest of a curated package, i.e. one whose
//! upstream repo has no `cactarium.toml` of its own.

use std::str::FromStr;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::name::{Name, Owner};
use crate::slug::Slug;
use crate::stack::StackSection;
use crate::version::{DEFAULT_TRACK_KEYWORD, TrackName, TrackedReq};
use crate::{Error, MANIFEST_FORMAT, Result, generation};

/// The package manifest's file name, at the repo root.
pub const PACKAGE_FILE: &str = "cactarium.toml";
/// The stack manifest's file name, at the repo root.
pub const STACK_FILE: &str = "cactarium-stack.toml";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PackageSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<StackSection>,
    /// Descriptions of the repo's tracks (tag prefixes), keyed by track name.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub tracks: IndexMap<TrackName, TrackInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fork_of: Vec<ForkOf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<Claim>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub works_with: Vec<Claim>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incompatible_with: Vec<Claim>,
    #[serde(default, rename = "caveat", skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<Caveat>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PackageSection {
    pub name: Name,
    /// Cactarium users or orgs allowed to publish this repo. Only someone who can push to the repo
    /// can put their name here, so this is the proof of repo control.
    pub owners: Vec<Owner>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// An SPDX license expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// Path of the README to show, relative to the repo root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readme: Option<String>,
    /// The arrangement the thorns belong to, when they sit at the repo root (`Thorn/`). Repos laid
    /// out as `Arrangement/Thorn/` don't need it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arrangement: Option<String>,
    /// The thorns to publish, by directory name. Default: every directory with an interface.ccl.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thorns: Option<Vec<String>>,
    /// The track shown first on the package page: a track name, or "default" for unprefixed tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_track: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TrackInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ForkOf {
    /// The upstream package, `owner/name`.
    pub target: Slug,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A declared relation to another package or stack. Ranges are claims the registry displays and
/// checks for consistency; nothing resolves them into a build.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Claim {
    /// `owner/name` of a package or stack.
    pub target: Slug,
    /// Versions of the target the claim covers. Default: every version on the default track.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<TrackedReq>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A note attached to one thorn, e.g. a platform requirement.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Caveat {
    pub thorn: String,
    pub note: String,
}

fn bare_target(t: &Slug) -> Result<()> {
    if t.thorn.is_some() || t.at.is_some() {
        return Err(Error::invalid(format!("claim target '{t}' must be just owner/name (put versions in 'range')")));
    }
    Ok(())
}

impl Manifest {
    /// Reads a manifest found in a repo, checking that the file holds the kind its name promises
    /// and names the owners allowed to publish it.
    pub fn from_repo_file(filename: &str, text: &str) -> Result<Manifest> {
        let m = Manifest::from_toml(text)?;
        match filename {
            PACKAGE_FILE if m.package.is_none() => {
                Err(Error::invalid(format!("{PACKAGE_FILE} must hold a [package]; a stack goes in {STACK_FILE}")))
            }
            STACK_FILE if m.stack.is_none() => {
                Err(Error::invalid(format!("{STACK_FILE} must hold a [stack]; a package goes in {PACKAGE_FILE}")))
            }
            STACK_FILE if m.stack.as_ref().is_some_and(|s| s.owners.is_empty()) => {
                Err(Error::invalid(format!("[stack] in {STACK_FILE} needs owners")))
            }
            PACKAGE_FILE | STACK_FILE => Ok(m),
            other => Err(Error::invalid(format!("'{other}' is not a Cactarium manifest file name"))),
        }
    }

    pub fn from_toml(text: &str) -> Result<Manifest> {
        generation::check(text, "cactarium.toml", MANIFEST_FORMAT)?;
        let m: Manifest = toml::from_str(text).map_err(|source| Error::Toml { what: "cactarium.toml", source })?;
        m.validate()?;
        Ok(m)
    }

    pub fn to_toml(&self) -> Result<String> {
        self.validate()?;
        toml::to_string(self).map_err(|source| Error::Serialize { what: "cactarium.toml", source })
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != MANIFEST_FORMAT {
            return Err(Error::invalid(format!("format must be {MANIFEST_FORMAT}")));
        }
        match (&self.package, &self.stack) {
            (Some(_), Some(_)) => return Err(Error::invalid("cactarium.toml has both [package] and [stack]")),
            (None, None) => return Err(Error::invalid("cactarium.toml needs a [package] or a [stack] section")),
            (Some(p), None) => {
                if p.owners.is_empty() {
                    return Err(Error::invalid("[package] owners is empty"));
                }
                if let Some(d) = &p.default_track
                    && d != DEFAULT_TRACK_KEYWORD
                {
                    TrackName::from_str(d)?;
                }
            }
            (None, Some(s)) => s.validate()?,
        }
        for f in &self.fork_of {
            bare_target(&f.target)?;
        }
        for c in self.depends_on.iter().chain(&self.works_with).chain(&self.incompatible_with) {
            bare_target(&c.target)?;
        }
        Ok(())
    }
}
