//! Stacks: versioned thornlists.
//!
//! One format covers three shapes, and none is preferred over the others:
//! - **flat**: just a CRL thornlist (`thornlist = "carpetx.th"`, no `extends`). A standard
//!   CarpetX stack is typically this.
//! - **recipe**: `extends` other stacks (in priority order), then redirects repos with
//!   overrides and enables or disables thorns.
//! - **both**: bases plus extra CRL sections from `thornlist`.
//!
//! A definition names repos by branch (or tag), like any thornlist, and may pin some of them
//! (`[[stack.pin]]`, the same table a `.sim` uses). Pins in a definition are optional and may be
//! partial: a pinned repo stays at its commit, the rest follow their branches.
//!
//! Whatever the shape, every stack version is a **release**: a [`FrozenStack`] holding one
//! verbatim CRL plus a pin for every repo. Releases are addressed exactly like package versions,
//! with track-namespaced semver (`owner/stack@mixed-precision:1.2.0`). Consumers only ever see the
//! frozen form. The one exception is `owner/stack@head` (see [`crate::slug::HEAD`]): the
//! definition as written, unpinned repos at their branch tips, for developers and power users.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::name::{Name, Owner};
use crate::sim::{RepoPin, ThornlistText, validate_repos};
use crate::slug::Slug;
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct StackSection {
    pub name: Name,
    /// Cactarium users or orgs allowed to publish this stack from its repo: the proof of repo
    /// control, as for packages. Required in a repo's stack file; unused for uploaded stacks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owners: Vec<Owner>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Bases, highest priority first: where two bases disagree on a repo's source, the earlier one
    /// wins. Each is an exact release, `owner/stack@1.2.0` or `owner/stack@track:1.2.0`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extends: Vec<Slug>,
    /// A CRL file, relative to this manifest. For a flat stack this is the whole list; with
    /// `extends` its sections are added on top of the bases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thornlist: Option<String>,
    /// Repo redirections applied to the bases.
    #[serde(default, rename = "override", skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<Override>,
    /// Thorns to enable (added as checkouts, or un-`#DISABLED`), as `Arrangement/Thorn`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enable: Vec<String>,
    /// Thorns to disable (`#DISABLED`), as `Arrangement/Thorn`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disable: Vec<String>,
    /// Commits the author fixes in the definition itself. Optional and possibly partial; a release
    /// pins every repo regardless.
    #[serde(default, rename = "pin", skip_serializing_if = "Vec::is_empty")]
    pub pins: Vec<RepoPin>,
}

/// Points one repo of the bases somewhere else: a fork, another branch or tag, or a Cactarium
/// package version.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Override {
    /// The repo name as the base thornlist derives it.
    pub repo: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    /// A Cactarium package (`owner/pkg@track:range`) instead of url + ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<Slug>,
}

fn arr_thorn(s: &str) -> bool {
    let Some((a, t)) = s.split_once('/') else { return false };
    let ident = |x: &str| {
        x.starts_with(|c: char| c.is_ascii_alphabetic()) && x.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    ident(a) && ident(t)
}

impl StackSection {
    pub fn is_flat(&self) -> bool {
        self.extends.is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        let n = &self.name;
        if self.extends.is_empty() && self.thornlist.is_none() {
            return Err(Error::invalid(format!("stack '{n}' needs a thornlist, extends, or both")));
        }
        if self.extends.is_empty() && !self.overrides.is_empty() {
            return Err(Error::invalid(format!("stack '{n}' has overrides but extends nothing")));
        }
        for b in &self.extends {
            if b.thorn.is_some() || b.exact().is_err() {
                return Err(Error::invalid(format!("base '{b}' must be an exact release, owner/stack@1.2.3")));
            }
        }
        let mut repos = BTreeSet::new();
        for o in &self.overrides {
            if !repos.insert(o.repo.as_str()) {
                return Err(Error::invalid(format!("repo '{}' is overridden twice", o.repo)));
            }
            let git = o.url.is_some() || o.git_ref.is_some();
            if o.package.is_some() && git {
                return Err(Error::invalid(format!("override of '{}' gives both a package and url/ref", o.repo)));
            }
            if o.package.is_none() && !git {
                return Err(Error::invalid(format!("override of '{}' changes nothing", o.repo)));
            }
        }
        for t in self.enable.iter().chain(&self.disable) {
            if !arr_thorn(t) {
                return Err(Error::invalid(format!("'{t}' is not Arrangement/Thorn")));
            }
        }
        if let Some(t) = self.enable.iter().find(|t| self.disable.contains(t)) {
            return Err(Error::invalid(format!("'{t}' is both enabled and disabled")));
        }
        validate_repos(&self.pins)?;
        if let Some(p) = self.pins.iter().find(|p| p.dirty || (p.commit.is_none() && p.sha256.is_none())) {
            return Err(Error::invalid(format!("pin for '{}' needs a commit or sha256, and cannot be dirty", p.name)));
        }
        Ok(())
    }
}

/// A stack release: what `cactup install owner/stack@v` consumes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FrozenStack {
    pub format: u32,
    /// `owner/stack@[track:]X.Y.Z`.
    pub stack: Slug,
    pub root: String,
    pub thornlist: ThornlistText,
    #[serde(rename = "repo")]
    pub repos: Vec<RepoPin>,
    /// The recipe it was resolved from, verbatim, for display and diffing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipe: Option<String>,
}

impl FrozenStack {
    pub fn validate(&self) -> Result<()> {
        if self.stack.thorn.is_some() || self.stack.exact().is_err() {
            return Err(Error::invalid(format!("stack release '{}' needs an exact version", self.stack)));
        }
        validate_repos(&self.repos)?;
        if let Some(r) = self.repos.iter().find(|r| (r.commit.is_none() && r.sha256.is_none()) || r.dirty) {
            return Err(Error::invalid(format!("frozen stack repo '{}' is not pinned", r.name)));
        }
        Ok(())
    }
}
