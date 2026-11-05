//! `.sim` files: a parfile plus the configuration it ran on.
//!
//! The thornlist (CRL) and the parfile are stored **verbatim**: this module never interprets or
//! rewrites them, and a read/write round trip preserves them byte for byte. The structure around
//! them is the per-repo pin table, declared inputs, run hints and provenance.

use std::collections::BTreeSet;
use std::fmt;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::slug::Slug;
use crate::{Error, Result, SIM_FORMAT, generation};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SimFile {
    pub format: u32,
    pub sim: SimMeta,
    pub thornlist: ThornlistText,
    pub parfile: Parfile,
    #[serde(default, rename = "input", skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<Input>,
    #[serde(default, rename = "repo", skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<RepoPin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<RunHints>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SimMeta {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Markdown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<String>,
    /// An SPDX license expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Set by the registry when the file is published: `owner/name@N`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cactarium: Option<Slug>,
    /// The thornlist's `!DEFINE ROOT`, the source tree's directory under the install.
    pub root: String,
}

/// A CRL thornlist kept verbatim. Shared with frozen stacks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ThornlistText {
    pub filename: String,
    /// The CRL exactly as written, with any `!INCLUDE`s spliced in.
    pub text: String,
    /// Thorns in the build that no repo backs (no commit can pin them). Present only in files
    /// exported with an override; a fully specified file has none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub untracked: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParfileKind {
    /// A Cactus parameter file.
    Par,
    /// A Python script that prints a parameter file.
    Py,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Parfile {
    pub filename: String,
    pub kind: ParfileKind,
    /// The `@VAR@` tokens the parfile uses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vars: Vec<String>,
    /// The master copy, verbatim and un-substituted.
    pub text: String,
}

/// Something the parfile needs from outside the source tree, reached through a cactup knob
/// (`@KNOB(name)@`). On import, cactup asks for a value or fetches `url`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Input {
    pub knob: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// One source repo (not one CRL section: a section with `$1`/`$2` in its URL spans many repos).
/// Shared with frozen stacks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RepoPin {
    /// The repo's name as the thornlist derives it (`!NAME`, else the URL's basename).
    pub name: String,
    pub url: String,
    /// The branch or tag the thornlist names. A label only: the commit is what gets fetched.
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    /// The pinned commit (git). Absent means unpinned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// The pinned content hash (tarball components).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The Cactarium package version this commit belongs to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cactarium: Option<Slug>,
    /// The tree had local modifications at export (only with an explicit override).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dirty: bool,
}

/// Suggested run shape, used only as defaults by `cactup import`. Machine-shaped settings
/// (nodes, tasks per node, queue) are deliberately absent: they follow from the target machine.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RunHints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus_per_task: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpus_per_task: Option<u32>,
    /// Total wall time wanted, `HH:MM:SS`; cactup chains restarts against the queue's limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub walltime: Option<String>,
}

/// Where the file came from. Informational: import never requires any of it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Provenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exported_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exported_at: Option<toml::value::Datetime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// The machine flavor the config was built with. At most one of `flavor` and `optionlist`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flavor: Option<String>,
    /// The optionlist file's name, when the config was built from `--optionlist` instead of a flavor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optionlist: Option<String>,
    /// The build universe (e.g. a container image), when not the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub universe: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    /// Thorns the source machine's configuration turned off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub machine_disabled: Vec<String>,
    /// The stack the install was based on, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<Slug>,
    /// Anything else an exporter wants to record, as strings.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub extra: IndexMap<String, String>,
}

/// Why a `.sim` is not fully specified. Only fully specified files can be published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unspecified {
    Unpinned { repo: String },
    Dirty { repo: String },
    Untracked { thorn: String },
}

impl fmt::Display for Unspecified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unspecified::Unpinned { repo } => write!(f, "repo '{repo}' has no pinned commit or sha256"),
            Unspecified::Dirty { repo } => write!(f, "repo '{repo}' had local modifications at export"),
            Unspecified::Untracked { thorn } => write!(f, "thorn '{thorn}' is not backed by any repo"),
        }
    }
}

pub(crate) fn is_hex(s: &str, lens: &[usize]) -> bool {
    lens.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn validate_repos(repos: &[RepoPin]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for r in repos {
        if !seen.insert(r.name.as_str()) {
            return Err(Error::invalid(format!("repo '{}' is listed twice", r.name)));
        }
        if r.commit.is_some() && r.sha256.is_some() {
            return Err(Error::invalid(format!("repo '{}' has both a commit and a sha256", r.name)));
        }
        if let Some(c) = &r.commit
            && !is_hex(c, &[40, 64])
        {
            return Err(Error::invalid(format!("repo '{}': '{c}' is not a full lowercase commit id", r.name)));
        }
        if let Some(h) = &r.sha256
            && !is_hex(h, &[64])
        {
            return Err(Error::invalid(format!("repo '{}': '{h}' is not a sha256", r.name)));
        }
    }
    Ok(())
}

fn plain_filename(what: &str, f: &str) -> Result<()> {
    if f.is_empty() || f.contains('/') || f.contains('\\') || f == "." || f == ".." {
        return Err(Error::invalid(format!("{what} '{f}' must be a plain file name")));
    }
    Ok(())
}

impl SimFile {
    pub fn from_toml(text: &str) -> Result<SimFile> {
        generation::check(text, "the .sim file", SIM_FORMAT)?;
        let sim: SimFile = toml::from_str(text).map_err(|source| Error::Toml { what: "the .sim file", source })?;
        sim.validate()?;
        Ok(sim)
    }

    pub fn to_toml(&self) -> Result<String> {
        self.validate()?;
        toml::to_string(self).map_err(|source| Error::Serialize { what: "the .sim file", source })
    }

    /// Structural checks that hold for every `.sim`, pinned or not.
    pub fn validate(&self) -> Result<()> {
        if self.format != SIM_FORMAT {
            return Err(Error::invalid(format!("format must be {SIM_FORMAT}")));
        }
        if self.sim.name.trim().is_empty() {
            return Err(Error::invalid("[sim] name is empty"));
        }
        plain_filename("thornlist filename", &self.thornlist.filename)?;
        plain_filename("parfile filename", &self.parfile.filename)?;
        let ext = match self.parfile.kind {
            ParfileKind::Par => ".par",
            ParfileKind::Py => ".py",
        };
        if !self.parfile.filename.ends_with(ext) {
            return Err(Error::invalid(format!(
                "parfile '{}' must end in '{ext}' to match kind = \"{}\"",
                self.parfile.filename,
                &ext[1..]
            )));
        }
        let mut knobs = BTreeSet::new();
        for i in &self.inputs {
            if !knobs.insert(i.knob.as_str()) {
                return Err(Error::invalid(format!("input '{}' is declared twice", i.knob)));
            }
            if let Some(h) = &i.sha256
                && !is_hex(h, &[64])
            {
                return Err(Error::invalid(format!("input '{}': '{h}' is not a sha256", i.knob)));
            }
        }
        // `base` may be `owner/stack@head`: the [[repo]] pins, not the base, make a .sim reproducible.
        if let Some(p) = &self.provenance
            && p.flavor.is_some()
            && p.optionlist.is_some()
        {
            return Err(Error::invalid("[provenance] has both a flavor and an optionlist"));
        }
        validate_repos(&self.repos)
    }

    /// Every reason this file cannot be published. Empty means fully specified: every repo is
    /// pinned, nothing was dirty, and every thorn is backed by a repo.
    pub fn unspecified(&self) -> Vec<Unspecified> {
        let mut out = Vec::new();
        for r in &self.repos {
            if r.commit.is_none() && r.sha256.is_none() {
                out.push(Unspecified::Unpinned { repo: r.name.clone() });
            }
            if r.dirty {
                out.push(Unspecified::Dirty { repo: r.name.clone() });
            }
        }
        for t in &self.thornlist.untracked {
            out.push(Unspecified::Untracked { thorn: t.clone() });
        }
        out
    }

    pub fn is_fully_specified(&self) -> bool {
        self.unspecified().is_empty()
    }
}
