//! A conservative scanner for the dependency facts in a thorn's `interface.ccl` and
//! `configuration.ccl`.
//!
//! This is not a full CCL parser (that lives in the flesh's Perl). It extracts what the registry
//! indexes and what a thornlist trim needs:
//! - `interface.ccl`: `IMPLEMENTS`, `INHERITS`, `FRIEND(S)`, `REQUIRES/USES/PROVIDES FUNCTION`,
//!   `USES INCLUDE`.
//! - `configuration.ccl`: `REQUIRES` capabilities, `REQUIRES THORNS`, `OPTIONAL`, `PROVIDES`.
//!
//! Keywords are case-insensitive, `#` starts a comment, and the bodies of `{ ... }` blocks (a
//! `PROVIDES` block's `SCRIPT`/`LANG`, an `OPTIONAL` block's `DEFINE`) are skipped. Names keep the
//! case they were written in; Cactus compares implementation and capability names
//! case-insensitively, so callers should too.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// What one thorn declares about its dependencies.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ThornFacts {
    pub implements: Option<String>,
    pub inherits: Vec<String>,
    pub friends: Vec<String>,
    pub requires_functions: Vec<String>,
    pub uses_functions: Vec<String>,
    pub provides_functions: Vec<String>,
    pub uses_includes: Vec<String>,
    /// Capabilities from `REQUIRES` in configuration.ccl.
    pub requires: Vec<String>,
    /// Thorns from `REQUIRES THORNS:`.
    pub requires_thorns: Vec<String>,
    /// Capabilities from `OPTIONAL`.
    pub optional: Vec<String>,
    /// Capabilities from `PROVIDES`.
    pub provides: Vec<String>,
}

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or("").trim()
}

/// Splits a list written with spaces and/or commas.
fn words(s: &str) -> impl Iterator<Item = String> + '_ {
    s.split(|c: char| c.is_whitespace() || c == ',').filter(|w| !w.is_empty()).map(str::to_owned)
}

/// A capability name without a version constraint: `HDF5(>=1.10)` → `HDF5`.
fn bare_capability(w: &str) -> Option<String> {
    let name = w.split('(').next().unwrap_or("").trim();
    (!name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')).then(|| name.to_owned())
}

/// Splits `KEYWORD rest` case-insensitively; `rest` keeps its case.
fn after_keyword<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let head = line.get(..keyword.len())?;
    if !head.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = &line[keyword.len()..];
    // The keyword must end at a word boundary.
    match rest.chars().next() {
        None => Some(""),
        Some(c) if c.is_whitespace() || c == ':' || c == '{' || c == '(' => Some(rest),
        Some(_) => None,
    }
}

fn after_colon(rest: &str) -> &str {
    rest.trim_start().strip_prefix(':').unwrap_or(rest).trim()
}

/// Lines outside `{ ... }` blocks, comments stripped, with any text before an opening `{` kept.
fn top_level_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    for raw in text.lines() {
        let line = strip_comment(raw);
        let mut kept = String::new();
        for c in line.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                _ if depth == 0 => kept.push(c),
                _ => {}
            }
        }
        let kept = kept.trim();
        if !kept.is_empty() {
            out.push(kept.to_owned());
        }
    }
    out
}

impl ThornFacts {
    /// Reads `interface.ccl` and, if present, `configuration.ccl` text.
    pub fn scan(interface: &str, configuration: Option<&str>) -> ThornFacts {
        let mut f = ThornFacts::default();
        for line in interface.lines().map(strip_comment).filter(|l| !l.is_empty()) {
            if let Some(rest) = after_keyword(line, "IMPLEMENTS") {
                f.implements = words(after_colon(rest)).next();
            } else if let Some(rest) = after_keyword(line, "INHERITS") {
                f.inherits.extend(words(after_colon(rest)));
            } else if let Some(rest) = after_keyword(line, "FRIENDS").or_else(|| after_keyword(line, "FRIEND")) {
                f.friends.extend(words(after_colon(rest)));
            } else if let Some(rest) = after_keyword(line, "REQUIRES") {
                if let Some(name) = after_keyword(rest.trim_start(), "FUNCTION") {
                    f.requires_functions.extend(words(name).take(1));
                }
            } else if let Some(rest) = after_keyword(line, "PROVIDES") {
                if let Some(name) = after_keyword(rest.trim_start(), "FUNCTION") {
                    f.provides_functions.extend(words(name).take(1));
                }
            } else if let Some(rest) = after_keyword(line, "USES") {
                let rest = rest.trim_start();
                if let Some(name) = after_keyword(rest, "FUNCTION") {
                    f.uses_functions.extend(words(name).take(1));
                } else if let Some(inc) = after_keyword(rest, "INCLUDE") {
                    // USES INCLUDE [SOURCE|HEADER]: file.h ...
                    let inc = inc.trim_start();
                    let inc = after_keyword(inc, "SOURCE").or_else(|| after_keyword(inc, "HEADER")).unwrap_or(inc);
                    f.uses_includes.extend(words(after_colon(inc)));
                }
            }
        }
        if let Some(conf) = configuration {
            for line in top_level_lines(conf) {
                if let Some(rest) = after_keyword(&line, "REQUIRES") {
                    let rest = rest.trim_start();
                    if let Some(thorns) = after_keyword(rest, "THORNS") {
                        f.requires_thorns.extend(words(after_colon(thorns)));
                    } else {
                        f.requires.extend(words(rest).filter_map(|w| bare_capability(&w)));
                    }
                } else if let Some(rest) = after_keyword(&line, "OPTIONAL") {
                    f.optional.extend(words(rest).filter_map(|w| bare_capability(&w)));
                } else if let Some(rest) = after_keyword(&line, "PROVIDES") {
                    f.provides.extend(words(rest).filter_map(|w| bare_capability(&w)).take(1));
                }
            }
        }
        for v in [
            &mut f.inherits,
            &mut f.friends,
            &mut f.requires_functions,
            &mut f.uses_functions,
            &mut f.provides_functions,
            &mut f.uses_includes,
            &mut f.requires,
            &mut f.requires_thorns,
            &mut f.optional,
            &mut f.provides,
        ] {
            let mut seen = std::collections::BTreeSet::new();
            v.retain(|x| seen.insert(x.to_ascii_lowercase()));
        }
        f
    }
}

/// A thorn found in a source tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ScannedThorn {
    /// The thorn's directory relative to the scanned root (empty if the root is the thorn).
    pub dir: PathBuf,
    /// The directory's name; `None` when the root itself is the thorn.
    pub name: Option<String>,
    /// The parent directory's name, when the thorn sits at `Arrangement/Thorn`.
    pub arrangement: Option<String>,
    pub facts: ThornFacts,
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn scan_dir(root: &Path, rel: &Path, out: &mut Vec<ScannedThorn>) {
    let dir = root.join(rel);
    if let Some(iface) = read(&dir.join("interface.ccl")) {
        let conf = read(&dir.join("configuration.ccl"));
        let mut parts = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned());
        let (first, second) = (parts.next(), parts.next());
        let (arrangement, name) = match (first, second) {
            (Some(a), Some(t)) => (Some(a), Some(t)),
            (Some(t), None) => (None, Some(t)),
            _ => (None, None),
        };
        out.push(ScannedThorn {
            dir: rel.to_owned(),
            name,
            arrangement,
            facts: ThornFacts::scan(&iface, conf.as_deref()),
        });
    }
}

/// Finds thorns (directories with an `interface.ccl`) at the root, one level down
/// (`Thorn/`, when the root is an arrangement), and two levels down (`Arrangement/Thorn/`).
/// Hidden directories and symlinks are skipped. Sorted by directory.
pub fn scan_tree(root: &Path) -> Vec<ScannedThorn> {
    fn subdirs(dir: &Path) -> Vec<PathBuf> {
        let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
        let mut v: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .map(|e| PathBuf::from(e.file_name()))
            .collect();
        v.sort();
        v
    }
    let mut out = Vec::new();
    scan_dir(root, Path::new(""), &mut out);
    for a in subdirs(root) {
        scan_dir(root, &a, &mut out);
        for t in subdirs(&root.join(&a)) {
            scan_dir(root, &a.join(&t), &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_facts() {
        let iface = "\
# Interface definition for thorn CarpetX
IMPLEMENTS: CarpetX
INHERITS: grid, IO
friends: ADMBase
USES INCLUDE HEADER: loop_device.hxx
CCTK_INT FUNCTION GetCallFunctionCount()
REQUIRES FUNCTION GetCallFunctionCount  # comment
PROVIDES FUNCTION GetRefinementLevel WITH CarpetX_GetRefinementLevel LANGUAGE C
USES FUNCTION Boundary_SelectGroupForBC
";
        let f = ThornFacts::scan(iface, None);
        assert_eq!(f.implements.as_deref(), Some("CarpetX"));
        assert_eq!(f.inherits, ["grid", "IO"]);
        assert_eq!(f.friends, ["ADMBase"]);
        assert_eq!(f.uses_includes, ["loop_device.hxx"]);
        assert_eq!(f.requires_functions, ["GetCallFunctionCount"]);
        assert_eq!(f.provides_functions, ["GetRefinementLevel"]);
        assert_eq!(f.uses_functions, ["Boundary_SelectGroupForBC"]);
    }

    #[test]
    fn configuration_facts() {
        let conf = "\
# Configuration definitions for thorn CarpetX
REQUIRES AMReX MPI yaml_cpp zlib HDF5(>=1.10)
REQUIRES THORNS: Arith, CarpetXRegrid Loop
OPTIONAL ADIOS2 openPMD_api Silo
{
  DEFINE HAVE_IO
}
PROVIDES CarpetX
{
  SCRIPT configure.sh
  LANG bash
}
";
        let f = ThornFacts::scan("IMPLEMENTS: CarpetX", Some(conf));
        assert_eq!(f.requires, ["AMReX", "MPI", "yaml_cpp", "zlib", "HDF5"]);
        assert_eq!(f.requires_thorns, ["Arith", "CarpetXRegrid", "Loop"]);
        assert_eq!(f.optional, ["ADIOS2", "openPMD_api", "Silo"]);
        assert_eq!(f.provides, ["CarpetX"]);
    }

    #[test]
    fn keywords_need_word_boundaries() {
        let f = ThornFacts::scan("IMPLEMENTSX: nope\nIMPLEMENTS:Yes", None);
        assert_eq!(f.implements.as_deref(), Some("Yes"));
    }

    #[test]
    fn scans_both_tree_layouts() {
        let root = std::env::temp_dir().join(format!("cactarium-ccl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["CarpetX/Loop", "CarpetX/Arith", ".git/x", "doc"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("CarpetX/Loop/interface.ccl"), "IMPLEMENTS: Loop\n").unwrap();
        std::fs::write(root.join("CarpetX/Arith/interface.ccl"), "IMPLEMENTS: Arith\n").unwrap();
        std::fs::write(root.join(".git/x/interface.ccl"), "IMPLEMENTS: Hidden\n").unwrap();
        let found = scan_tree(&root);
        let names: Vec<_> = found.iter().map(|t| (t.arrangement.clone(), t.name.clone())).collect();
        assert_eq!(
            names,
            [
                (Some("CarpetX".into()), Some("Arith".into())),
                (Some("CarpetX".into()), Some("Loop".into()))
            ]
        );
        // Rooted at the arrangement, the same thorns have no arrangement.
        let found = scan_tree(&root.join("CarpetX"));
        assert!(found.iter().all(|t| t.arrangement.is_none() && t.name.is_some()));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
