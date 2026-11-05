//! The CRL 1.0 thornlist parser, shared by the Cactarium server and cactup.
//!
//! Copied from cactup's `src/thornlist.rs` (branch feature/cactarium, 2026-11-05, with the
//! `!REPO_COMMIT` pin extension), minus the parts that read an installed tree
//! (`parse_config_list` and its helpers stay in cactup). Parse semantics are a contract between
//! the registry and cactup: change them only together, and treat a change as a `.sim`/API format
//! question.
//!
//! Original notes: CRL 1.0 thornlist parser (spec §3.2) — a faithful port of the Perl
//! `GetComponents` parsing behavior. Parse-only; cactup never re-emits a
//! thornlist (source bytes are always copied verbatim).
//!
//! Implemented by the FETCH stream (design/_impl_fetch.md).
//!
//! Ported from `Cactus/bin/GetComponents` (`parse_list`, roughly lines
//! 319-793 of the reference checkout). Line numbers in comments below refer
//! to that file. Where the POD (spec, lines ~2790-2860) and the code
//! disagree, the code wins — see the notes on quoting and long-form
//! directive aliases below for the two places that actually matters.
//!
//! Deliberate divergences from GetComponents (called out again at each
//! site): !INCLUDE resolves *local* paths and errors on URLs (GetComponents
//! is the opposite: it only ever downloads a URL, via curl/wget); an
//! unresolvable `$VAR` is a hard error the first time it's seen rather than
//! a single die-on-first/blank-the-rest; a non-`ignore` component requires
//! `!URL` up front instead of silently producing an empty repo name; and an
//! unrecognized `!TYPE` value is rejected instead of silently accepted and
//! only failing much later when an actual checkout is attempted.

use anyhow::{anyhow, bail, Context};
use regex::{Captures, Regex};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

type Res<T> = anyhow::Result<T>;

/// A fully parsed CRL 1.0 thornlist.
#[derive(Debug, Clone)]
pub struct Thornlist {
    components: Vec<Component>,
    /// `#DISABLED <arrangement>/<Thorn>` lines (rule 6), collected before
    /// comment stripping. Not part of the CRL grammar proper — a cactup
    /// convention (see `src/build.rs::apply_thorn_toggles`) layered on top,
    /// needed by orphan detection later in the FETCH stream.
    disabled_thorns: Vec<String>,
    /// Warnings collected instead of printed (repeated `!DEFINE` under
    /// `_experimental`, sections with no `!CHECKOUT`).
    warnings: Vec<String>,
    crl_version: String,
    /// `!DEFINE ROOT`, or `.` if absent (GetComponents line ~431-432).
    root: String,
    /// Only for a list read by [`parse_config_list`] from a plain Cactus
    /// `ThornList`: the `Arrangement/Thorn`s that are not links into
    /// `repos/`, so no repo, and no source state, could be found for them —
    /// plus [`UNTRACKED_FLESH`] when the root `Makefile` is not one either.
    untracked: Vec<String>,
    /// Set only by [`parse_config_list`]'s plain-`ThornList` path. Not
    /// derived from an empty `crl_version`: a bare `!CRL_VERSION` header
    /// parses with one too.
    plain: bool,
}

/// The `!TYPE` a component is fetched with. `Ignore` components are parsed
/// and validated but dropped from [`Thornlist::components`] (rule 13), and
/// take no part in duplicate-checkout detection (see
/// [`detect_duplicates`]). The one exception is a list resolved from a plain
/// `ThornList` by [`parse_config_list`], which marks a thorn with no repo
/// behind it `Ignore`; such a list only ever reaches the §7.4 change
/// tracking, never the fetch planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentType {
    Cvs,
    Svn,
    Git,
    Darcs,
    Http,
    Https,
    Ftp,
    Hg,
    Ignore,
}

impl ComponentType {
    fn parse(s: &str) -> Option<ComponentType> {
        use ComponentType::*;
        Some(match s {
            "cvs" => Cvs,
            "svn" => Svn,
            "git" => Git,
            "darcs" => Darcs,
            "http" => Http,
            "https" => Https,
            "ftp" => Ftp,
            "hg" => Hg,
            "ignore" => Ignore,
            _ => return None,
        })
    }
}

/// One `!CHECKOUT` token's worth of a section: the section's directives
/// with `$1`/`$2` resolved against this particular checkout name (rule 11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub ty: ComponentType,
    pub target: String,
    pub checkout: String,
    pub name: Option<String>,
    /// Required for every non-`ignore` type (GetComponents itself never
    /// checks this — a deliberate strengthening, see the module doc).
    pub url: Option<String>,
    pub auth_url: Option<String>,
    pub anon_user: Option<String>,
    pub anon_pass: Option<String>,
    pub repo_path: Option<String>,
    /// `!REPO_BRANCH`: the branch to follow, or — with a `commit` — the
    /// branch or tag the pinned commit is fetched through (a label only).
    pub branch: Option<String>,
    /// `!REPO_COMMIT`: the commit a git repo is pinned to, as full lowercase
    /// hex. A cactup extension (GetComponents ignores the directive, so an
    /// older tool fetches the branch unpinned instead of failing). A pinned
    /// repo is checked out detached at exactly this commit and never
    /// fast-forwarded.
    pub commit: Option<String>,
    /// Derived repo directory name (rule 12): `!NAME` if present, else the
    /// URL basename with a trailing `.git`, `.hg`, or `_darcs` stripped.
    /// GetComponents only actually computes this for git/darcs/hg
    /// (`$rec{REPO}`, used to name a shared local mirror dir); we compute it
    /// uniformly for every type as a convenience for callers.
    pub repo: String,
}

/// Parse `src` as a CRL 1.0 thornlist. Equivalent to
/// `parse_with_base(src, None)` — a `!INCLUDE` of a local path will fail,
/// since there is no directory to resolve it against.
// Pinned foundation API: nothing in the crate calls into the thornlist
// parser yet (that's the FETCH stream, a later phase) — only the tests
// below exercise it.
pub fn parse(src: &str) -> Res<Thornlist> {
    parse_with_base(src, None)
}

/// Parse `src`, resolving local `!INCLUDE` paths against `include_base`
/// (rule 2). `!INCLUDE` of a URL always errors — cactup does not shell out
/// to curl/wget the way GetComponents does; this is a documented gap, not a
/// bug (the real Einstein Toolkit list uses no `!INCLUDE` at all).
pub fn parse_with_base(src: &str, include_base: Option<&Path>) -> Res<Thornlist> {
    // 1. CRLF normalization first.
    let normalized = normalize_crlf(src);
    // 2. !INCLUDE splicing, recursive.
    let spliced = splice_includes(&normalized, include_base)?;
    // 3. !CRL_VERSION must be first; everything before it is discarded.
    let (crl_version, experimental, body) = extract_header(&spliced)?;
    // 6. #DISABLED collection, BEFORE comment stripping.
    let disabled_thorns = collect_disabled(&body);
    // 4. !DEFINE extraction (single non-global $VAR resolution per value).
    let (defines, mut warnings) = collect_defines(&body, experimental)?;
    let root = defines.get("ROOT").cloned().unwrap_or_else(|| ".".to_owned());
    // 5. Comment stripping, in the exact three-step order.
    let stripped = strip_comments(&body);
    // 7. Long-form directive aliases.
    let aliased = apply_aliases(&stripped);
    // 8/9. $VAR substitution: defines first, then environment. $1/$2 stay
    // literal here (resolved per-checkout below).
    let substituted = substitute_vars(&aliased, &defines)?;

    // 10. Split into !TARGET sections.
    let target_re = Regex::new(r"(?m)^!TARGET\s*=\s*").unwrap();
    let mut pieces = target_re.split(&substituted);
    pieces.next(); // discard text before the first !TARGET (mirrors `shift @sections`)

    let mut all_components: Vec<Component> = Vec::new();
    // Which section each component came from, parallel to `all_components`.
    // Only used to phrase the duplicate-checkout error (a duplicate within
    // one `!CHECKOUT` list is a different mistake from two sections
    // fighting over a path); not worth a field on `Component`.
    let mut section_of: Vec<usize> = Vec::new();
    for (section_idx, section_body) in pieces.enumerate() {
        if section_body.is_empty() {
            // Only possible when two !TARGET markers are adjacent.
            continue;
        }
        let full_section = format!("!TARGET = {section_body}");
        let map = build_kv_map(&full_section);
        build_section(&map, &mut all_components, &mut warnings)?;
        section_of.resize(all_components.len(), section_idx);
    }

    // 14. Duplicate-checkout detection, lexical only, no filesystem access.
    detect_duplicates(&all_components, &section_of, &root)?;

    let components: Vec<Component> = all_components
        .into_iter()
        .filter(|c| c.ty != ComponentType::Ignore)
        .collect();

    Ok(Thornlist {
        components,
        disabled_thorns,
        warnings,
        crl_version,
        root,
        untracked: Vec::new(),
        plain: false,
    })
}

// Pinned foundation API (see the note on `parse` above): these accessors
// have no caller yet outside the test module.
impl Thornlist {
    pub fn components(&self) -> &[Component] {
        &self.components
    }

    pub fn disabled_thorns(&self) -> &[String] {
        &self.disabled_thorns
    }

    /// See the field: thorns of a plain `ThornList` with no repo behind them.
    pub fn untracked(&self) -> &[String] {
        &self.untracked
    }

    /// Whether this list came from a plain Cactus `ThornList` (see
    /// [`parse_config_list`]) rather than a CRL list.
    pub fn is_plain(&self) -> bool {
        self.plain
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The `!CRL_VERSION` header value, e.g. `"1.0"` or `"1.0_experimental"`.
    // Pinned parser API; only tests read it so far.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn crl_version(&self) -> &str {
        &self.crl_version
    }

    /// `!DEFINE ROOT`, or `"."` if the list never defined it.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Per-thorn provenance: thorn name -> providing directory relative to
    /// the checkout root, e.g. `"WeylScal4"` ->
    /// `"arrangements/EinsteinAnalysis/WeylScal4"`. This is the §7.4 build-
    /// invalidation input (see `build.rs::provider_delta`): Cactus keys
    /// per-thorn build state — `configs/<cfg>/build/<Thorn>/`,
    /// `libthorn_<Thorn>.a` — by thorn *name* only, so a name that changes
    /// provider across builds silently poisons that state (a stale `.d` file
    /// can reference a bindings header the reconfigure correctly deleted, and
    /// `ar` updates an existing archive in place, so stale members from the
    /// old provider can survive into the link). `#DISABLED` entries are
    /// comments to the parser and thus absent from `self.components` — which
    /// is exactly right here too, since only enabled thorns get built.
    pub fn thorn_providers(&self) -> BTreeMap<String, String> {
        self.components
            .iter()
            .filter_map(|c| {
                if !c.checkout.contains('/') {
                    // Flesh checkouts (`Makefile lib src`), simfactory, etc.
                    // — not thorns.
                    return None;
                }
                let (_, name) = split_checkout(&c.checkout);
                Some((name, canonical_checkout(&c.target, &c.checkout, &self.root)))
            })
            .collect()
    }
}

/// Step 1: `s/(\r\n|\r)/\n/gm`.
fn normalize_crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://")
}

/// Step 2: splice `!INCLUDE = <path>` lines in place, recursively. A line
/// only counts as an include if there is no `#` before `!INCLUDE` on it
/// (`^[^#]*!INCLUDE *= *(.*)$`), so a commented-out include is left alone.
fn splice_includes(text: &str, base: Option<&Path>) -> Res<String> {
    let include_re = Regex::new(r"^[^#]*!INCLUDE *= *(.*)$").unwrap();
    let mut out_lines: Vec<String> = Vec::new();
    for line in text.split('\n') {
        let Some(caps) = include_re.captures(line) else {
            out_lines.push(line.to_owned());
            continue;
        };
        let target = caps[1].trim();
        if is_url(target) {
            bail!("!INCLUDE of URL '{target}' is not yet supported; only local-path includes are");
        }
        let base_dir = base
            .ok_or_else(|| anyhow!("!INCLUDE '{target}' has no base directory to resolve against"))?;
        let include_path = base_dir.join(target);
        let include_src = std::fs::read_to_string(&include_path)
            .with_context(|| format!("Failed to read !INCLUDE file '{}'", include_path.display()))?;
        let normalized = normalize_crlf(&include_src);
        let nested_base = include_path.parent();
        let nested = splice_includes(&normalized, nested_base)?;
        out_lines.extend(nested.split('\n').map(|s| s.to_owned()));
    }
    Ok(out_lines.join("\n"))
}

/// Step 3: find `!CRL_VERSION`, discarding every comment/blank line before
/// it (GetComponents lines 325-348). Returns the version string, whether it
/// carries an `_experimental` suffix, and the remaining body text.
fn extract_header(text: &str) -> Res<(String, bool, String)> {
    let lines: Vec<&str> = text.split('\n').collect();
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("!CRL_VERSION") {
            let version = rest.trim().trim_start_matches('=').trim().to_owned();
            let experimental = line.starts_with("!CRL_VERSION ") && line.contains("_experimental");
            let body = lines[i + 1..].join("\n");
            return Ok((version, experimental, body));
        }
        if line.chars().any(|c| c.is_alphanumeric() || c == '_') {
            bail!("Thornlist has content before the !CRL_VERSION header: {line:?}");
        }
        // Neither blank/comment, version, nor word-bearing: GetComponents
        // silently falls through to the next line here too.
    }
    bail!("Thornlist is missing the required !CRL_VERSION header");
}

/// Step 6: collect `#DISABLED <arrangement>/<Thorn>` lines before any
/// comment stripping happens (they'd otherwise just vanish as comments).
fn collect_disabled(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| line.trim_start().strip_prefix("#DISABLED "))
        .map(|rest| rest.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Step 4: `!DEFINE k = v`, with single non-global `$VAR` resolution
/// (GetComponents line 377: `s/\$(\w+)/$DEFINITIONS{$1}/` — no `/g`, so
/// only the *first* `$VAR` in the value is resolved; a second reference in
/// the same value is left as a literal `$VAR` token). A repeated definition
/// with a different value is fatal unless the header was `_experimental`,
/// in which case it becomes a collected warning and the *original*
/// definition is kept (lines 380-393).
fn collect_defines(body: &str, experimental: bool) -> Res<(HashMap<String, String>, Vec<String>)> {
    let define_re = Regex::new(r"^!DEFINE\s*(\S+)\s*=\s*(.+)$").unwrap();
    let var_re = Regex::new(r"\$(\w+)").unwrap();
    let mut defines: HashMap<String, String> = HashMap::new();
    let mut warnings = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let Some(caps) = define_re.captures(line) else {
            continue;
        };
        let key = caps[1].to_owned();
        let raw_value = &caps[2];
        // Single, non-global substitution: only the first $VAR resolves.
        let value = if let Some(m) = var_re.captures(raw_value) {
            let name = &m[1];
            let repl = defines.get(name).cloned().unwrap_or_default();
            let whole = m.get(0).unwrap();
            format!("{}{}{}", &raw_value[..whole.start()], repl, &raw_value[whole.end()..])
        } else {
            raw_value.to_string()
        };
        if let Some(existing) = defines.get(&key) && existing != &value {
            if experimental {
                warnings.push(format!("Repeated definition of {key} on line {}, ignored", idx + 1));
                continue;
            } else {
                bail!("Repeated definition of {key} on line {}", idx + 1);
            }
        }
        defines.insert(key, value);
    }
    Ok((defines, warnings))
}

/// Step 5: the three comment-stripping substitutions, in this exact order.
fn strip_comments(body: &str) -> String {
    // (a) whole-line comments -> blank lines.
    let re_a = Regex::new(r"(?m)^\s*#.*$").unwrap();
    let step_a = re_a.replace_all(body, "").into_owned();
    // (b) collapse blank-line pairs. This is a SINGLE non-overlapping pass
    // (matching Perl's s/\n\n/\n/g), not a loop to a fixed point: four
    // newlines in a row collapse to two, not one. `str::replace` is exactly
    // this — a single left-to-right, non-overlapping scan.
    let step_b = step_a.replace("\n\n", "\n");
    // (c) trailing comments. Applied to every line, so any value containing
    // '#' gets truncated there.
    let re_c = Regex::new(r"(?m)#.*$").unwrap();
    re_c.replace_all(&step_b, "").into_owned()
}

/// Step 7: long-form directive aliases (GetComponents lines 407-413),
/// applied in the SAME order as the Perl source — which matters, because
/// it reproduces a real bug there: `!ANONYMOUS_PASS` is replaced with
/// `!ANON_PASS` *before* `!ANONYMOUS_PASSWORD` is replaced, so
/// `!ANONYMOUS_PASSWORD` never matches the second rule (its
/// `!ANONYMOUS_PASS` prefix is already gone) and it's left as the
/// unrecognized directive `!ANON_PASSWORD` instead of `!ANON_PASS`. We
/// replicate this faithfully rather than "fixing" it, per the porting
/// brief (behavior, not intent). `!REPOSITORY_PATH` -> `!REPO_PATH` is in
/// the Perl source (line 411) though absent from the porting brief's list;
/// included here since it's real, documented (POD item 10) behavior.
fn apply_aliases(text: &str) -> String {
    text.replace("!ANONYMOUS_USER", "!ANON_USER")
        .replace("!ANONYMOUS_PASS", "!ANON_PASS")
        .replace("!ANONYMOUS_PASSWORD", "!ANON_PASS")
        .replace("!LOCAL_PATH", "!LOC_PATH")
        .replace("!REPOSITORY_PATH", "!REPO_PATH")
        .replace("!REPOSITORY_BRANCH", "!REPO_BRANCH")
        .replace("!AUTHORIZATION_URL", "!AUTH_URL")
}

/// Steps 8/9: substitute `$VAR` from defines, then from the environment.
/// Each pass is a single global substitution over the whole text (not
/// recursive/looped) — so a define whose *own* resolved value still
/// contains a literal `$OTHER` (the rule-4 quirk) can leak an unresolved
/// `$OTHER` into the output text, which the environment pass then either
/// resolves or errors on. `\$VAR` (backslash-escaped) is left completely
/// untouched, backslash included — GetComponents never strips it either.
/// `$1`/`$2` are untouched by construction: the defines pass only replaces
/// names that exist in `defines` (a definition named "1" is exotic and
/// vanishingly unlikely, and behaves the same broken way in Perl), and the
/// environment pass's pattern requires a leading letter.
///
/// Divergence from GetComponents (rule 9, a deliberate improvement): the
/// Perl code validates only the *first* unresolved environment variable and
/// then blank-fills any later ones that happen to be missing. We error on
/// the first one found in left-to-right order and never silently blank
/// anything.
fn substitute_vars(text: &str, defines: &HashMap<String, String>) -> Res<String> {
    let define_re = Regex::new(r"\\\$(\w+)|\$(\w+)").unwrap();
    let phase1 = define_re.replace_all(text, |caps: &Captures| {
        if caps.get(1).is_some() {
            return caps.get(0).unwrap().as_str().to_owned();
        }
        let name = &caps[2];
        match defines.get(name) {
            Some(v) => v.clone(),
            None => caps.get(0).unwrap().as_str().to_owned(),
        }
    });

    let env_re = Regex::new(r"\\\$([A-Za-z]\w*)|\$([A-Za-z]\w*)").unwrap();
    for caps in env_re.captures_iter(&phase1) {
        if caps.get(1).is_some() {
            continue; // escaped, not a real reference
        }
        let name = &caps[2];
        if std::env::var(name).is_err() {
            bail!("No definition for {name} found in input file or environment");
        }
    }
    let phase2 = env_re.replace_all(&phase1, |caps: &Captures| {
        if caps.get(1).is_some() {
            return caps.get(0).unwrap().as_str().to_owned();
        }
        let name = &caps[2];
        std::env::var(name).unwrap_or_default()
    });
    Ok(phase2.into_owned())
}

/// Build the flat key -> value map for one `!TARGET = ...` section (rule
/// 10): find every `^!KEY = ` occurrence; a value runs from there to the
/// next such occurrence (or end of section), with only trailing whitespace
/// trimmed. This is what makes multi-line `!CHECKOUT` work, and later keys
/// win on repeat (mirrors Perl's `%rec = @pairs` hash-flatten).
fn build_kv_map(full_section: &str) -> HashMap<String, String> {
    let key_re = Regex::new(r"(?m)^\s*!([^\s=]+)\s*=\s*").unwrap();
    let matches: Vec<(String, usize, usize)> = key_re
        .captures_iter(full_section)
        .map(|caps| {
            let whole = caps.get(0).unwrap();
            (caps[1].to_owned(), whole.start(), whole.end())
        })
        .collect();
    let mut map = HashMap::new();
    for (i, (key, _start, value_start)) in matches.iter().enumerate() {
        let value_end = matches.get(i + 1).map(|m| m.1).unwrap_or(full_section.len());
        let value = full_section[*value_start..value_end].trim_end().to_owned();
        map.insert(key.clone(), value);
    }
    map
}

/// `$1`/`$2` from a checkout token (rule 11): `$1` is everything before the
/// LAST `/`, `$2` everything after it; with no `/`, `$1` is the whole token
/// and `$2` is empty (an undefined Perl var interpolates as "").
fn split_checkout(token: &str) -> (String, String) {
    match token.rfind('/') {
        Some(idx) => (token[..idx].to_owned(), token[idx + 1..].to_owned()),
        None => (token.to_owned(), String::new()),
    }
}

/// Literal, non-regex `$1`/`$2` replacement — matches Perl's `s!\$1!...!`,
/// which is not word-boundary-aware (a token like `$12` would have its
/// `$1` prefix replaced too). Not something the real Einstein Toolkit list
/// exercises; ported for fidelity, not because it's good design.
fn subst_12(s: &str, dir1: &str, dir2: &str) -> String {
    s.replace("$1", dir1).replace("$2", dir2)
}

/// Rule 12: `!NAME` if present, else the URL basename with a trailing
/// `.git`, `.hg`, or `_darcs` (and, for the `.hg` case, one trailing `/`)
/// stripped, else the raw checkout token as a last resort (only reachable
/// for `ignore` components, which may have neither `!NAME` nor `!URL`).
/// GetComponents only computes this (`$rec{REPO}`) for git/darcs/hg, to
/// name a shared local mirror directory; cvs/svn/http/https/ftp checkouts
/// use `!NAME` or the checkout name directly instead. We derive it
/// uniformly for every type as a general-purpose convenience.
fn derive_repo(name: Option<&str>, url: Option<&str>, checkout: &str) -> String {
    if let Some(n) = name {
        return n.to_owned();
    }
    if let Some(u) = url {
        return basename_strip(u);
    }
    checkout.to_owned()
}

fn basename_strip(url: &str) -> String {
    let stripped = if let Some(s) = url.strip_suffix(".git") {
        s
    } else if let Some(s) = url.strip_suffix("_darcs") {
        s
    } else if let Some(s) = url.strip_suffix(".hg") {
        s.strip_suffix('/').unwrap_or(s)
    } else {
        url
    };
    match stripped.rfind(['/', ':']) {
        Some(idx) => stripped[idx + 1..].to_owned(),
        None => stripped.to_owned(),
    }
}

/// Rules 10-13, 15: validate one section's flat directive map and expand
/// its `!CHECKOUT` list into components, appending them to `out`. Mirrors
/// GetComponents' exact validation order (lines 456-472): `ignore` sections
/// skip all further checks; then a missing `!CHECKOUT` is a warning (not
/// fatal) and the section is skipped; only then is a missing/unrecognized
/// `!TYPE` fatal.
fn build_section(
    map: &HashMap<String, String>,
    out: &mut Vec<Component>,
    warnings: &mut Vec<String>,
) -> Res<()> {
    let target = map.get("TARGET").cloned().unwrap_or_default();
    let type_str = map.get("TYPE").cloned();

    if type_str.as_deref() == Some("ignore") {
        if let Some(checkout_val) = map.get("CHECKOUT") {
            for token in checkout_val.split_whitespace() {
                let (dir1, dir2) = split_checkout(token);
                let name = map.get("NAME").map(|n| subst_12(n, &dir1, &dir2));
                let repo = derive_repo(name.as_deref(), None, token);
                out.push(Component {
                    ty: ComponentType::Ignore,
                    target: target.clone(),
                    checkout: token.to_owned(),
                    name,
                    url: None,
                    auth_url: None,
                    anon_user: map.get("ANON_USER").cloned(),
                    anon_pass: map.get("ANON_PASS").cloned(),
                    repo_path: map.get("REPO_PATH").cloned(),
                    branch: map.get("REPO_BRANCH").cloned(),
                    commit: None,
                    repo,
                });
            }
        }
        return Ok(());
    }

    let Some(checkout_val) = map.get("CHECKOUT") else {
        warnings.push(format!(
            "Nothing will be checked out from {} (target {target})",
            map.get("URL").cloned().unwrap_or_default()
        ));
        return Ok(());
    };

    let ty = match &type_str {
        None => bail!("Section for target '{target}' is missing the required !TYPE directive"),
        Some(t) => ComponentType::parse(t)
            .ok_or_else(|| anyhow!("Section for target '{target}' has unrecognized !TYPE '{t}'"))?,
    };

    let url_orig = map
        .get("URL")
        .cloned()
        .ok_or_else(|| anyhow!("Section for target '{target}' (type {type_str:?}) is missing the required !URL directive"))?;
    let auth_url_orig = map.get("AUTH_URL").cloned();
    let commit = map.get("REPO_COMMIT").map(|c| parse_commit(c, &target, ty)).transpose()?;

    for token in checkout_val.split_whitespace() {
        let (dir1, dir2) = split_checkout(token);
        let url = subst_12(&url_orig, &dir1, &dir2);
        let auth_url = auth_url_orig.as_deref().map(|a| subst_12(a, &dir1, &dir2));
        let name = map.get("NAME").map(|n| subst_12(n, &dir1, &dir2));
        let repo = derive_repo(name.as_deref(), Some(&url), token);
        out.push(Component {
            ty,
            target: target.clone(),
            checkout: token.to_owned(),
            name,
            url: Some(url),
            auth_url,
            anon_user: map.get("ANON_USER").cloned(),
            anon_pass: map.get("ANON_PASS").cloned(),
            repo_path: map.get("REPO_PATH").cloned(),
            branch: map.get("REPO_BRANCH").cloned(),
            commit: commit.clone(),
            repo,
        });
    }
    Ok(())
}

/// A `!REPO_COMMIT` value: a full commit id (40 hex digits, or 64 for a
/// SHA-256 repo), normalized to lowercase. Abbreviations are refused — a pin
/// must name exactly one commit on every remote, forever — and so is a pin on
/// anything but a git component, which nothing would honor.
fn parse_commit(value: &str, target: &str, ty: ComponentType) -> Res<String> {
    if ty != ComponentType::Git {
        bail!("Section for target '{target}' has !REPO_COMMIT, which only git components support");
    }
    let commit = value.trim().to_ascii_lowercase();
    if !matches!(commit.len(), 40 | 64) || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "Section for target '{target}' has !REPO_COMMIT '{}', which is not a full commit id \
             (40 or 64 hex digits)",
            value.trim()
        );
    }
    Ok(commit)
}

/// Rule 14: lexical-only path canonicalization (collapse `//`, drop `/./`,
/// resolve `a/../`). Never touches the filesystem.
fn lexical_canonicalize(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => match stack.last() {
                Some(&last) if last != ".." => {
                    stack.pop();
                }
                _ if !absolute => stack.push(".."),
                _ => {}
            },
            _ => stack.push(seg),
        }
    }
    let joined = stack.join("/");
    if absolute { format!("/{joined}") } else { joined }
}

/// Rule 14: `$TARGET/$CHECKOUT`, lexically canonicalized and stripped of the
/// `$ROOT/` prefix. Shared by `detect_duplicates` and
/// `Thornlist::thorn_providers`, which needs the identical path for the same
/// checkout token (its providing directory).
fn canonical_checkout(target: &str, checkout: &str, root: &str) -> String {
    let joined = format!("{target}/{checkout}");
    let canon = lexical_canonicalize(&joined);
    let root_prefix = format!("{root}/");
    canon.strip_prefix(&root_prefix).unwrap_or(&canon).to_owned()
}

/// Rule 14: duplicate detection over lexically-canonicalized
/// `$TARGET/$CHECKOUT` paths relative to `$ROOT` (GetComponents lines
/// 778-792). `ignore` components are excluded, exactly as in
/// GetComponents: `@all_components` (the list the check runs over) is only
/// ever appended to after two `next`s that skip `ignore` — one per section
/// (line 457), one per checkout token (line 733). So an `ignore` section
/// naming a path that some other section also checks out is legal, and a
/// common way to write a thornlist that overrides one thorn of a shared
/// repo. cactup still parses and validates those sections (rule 13); they
/// just don't collide here.
///
/// Beyond GetComponents: the error explains where each duplicate came
/// from, so it is fixable without hand-diffing the thornlist. The two
/// realistic mistakes read differently — one `!CHECKOUT` list naming a
/// thorn twice (usually from enabling a `#DISABLED` thorn by *both*
/// un-disabling its line and appending it to the `!CHECKOUT =` line), vs.
/// two sections claiming the same path from different repos.
///
/// `section_of` is parallel to `components` (see the caller).
fn detect_duplicates(components: &[Component], section_of: &[usize], root: &str) -> Res<()> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut dupes: Vec<(String, usize, usize)> = Vec::new();
    for (i, c) in components.iter().enumerate() {
        if c.ty == ComponentType::Ignore {
            continue;
        }
        let canon = canonical_checkout(&c.target, &c.checkout, root);
        match seen.get(&canon) {
            Some(&first) => dupes.push((canon, first, i)),
            None => {
                seen.insert(canon, i);
            }
        }
    }
    if !dupes.is_empty() {
        let paths: Vec<&str> = dupes.iter().map(|(p, _, _)| p.as_str()).collect();
        let detail: String = dupes
            .iter()
            .map(|&(ref p, first, second)| {
                let (a, b) = (&components[first], &components[second]);
                if section_of.get(first) == section_of.get(second) {
                    format!("\n  {p}: listed twice in one !CHECKOUT ({})", source_desc(a))
                } else {
                    format!("\n  {p}: from {} and from {}", source_desc(a), source_desc(b))
                }
            })
            .collect();
        bail!("Duplicate checkouts: {}{detail}", paths.join(" "));
    }
    Ok(())
}

/// Shortest thing that identifies which section a component came from, for
/// the duplicate-checkout error: its `!URL` (with `!REPO_BRANCH`, since two
/// sections can differ only by branch), else its `!TARGET`.
fn source_desc(c: &Component) -> String {
    match (&c.url, &c.branch) {
        (Some(url), Some(branch)) => format!("{url}, branch {branch}"),
        (Some(url), None) => url.clone(),
        (None, _) => format!("target {}", c.target),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn ok(src: &str) -> Thornlist {
        match parse(src) {
            Ok(t) => t,
            Err(e) => panic!("expected parse to succeed, got error: {e:#}"),
        }
    }

    fn err(src: &str) -> String {
        match parse(src) {
            Ok(t) => panic!("expected parse to fail, got: {t:#?}"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn defines_and_compound_defines() {
        let src = "\
!CRL_VERSION = 1.0
!DEFINE A = foo
!DEFINE B = $A/bar
!TARGET = t
!TYPE = git
!URL = https://example.com/$B.git
!CHECKOUT = x
";
        let t = ok(src);
        assert_eq!(t.components().len(), 1);
        assert_eq!(t.components()[0].url.as_deref(), Some("https://example.com/foo/bar.git"));
    }

    /// The single-non-global-substitution quirk (rule 4): a !DEFINE value
    /// referencing two earlier defines only resolves the FIRST one at
    /// define-time. The second reference survives as a literal token in
    /// the stored definition, and later leaks through the (also
    /// single-pass) whole-text defines substitution unresolved, where it's
    /// then treated as an unresolved environment variable and errors.
    #[test]
    fn compound_define_single_substitution_quirk() {
        let var = "CACTUP_THORNLIST_QUIRK_VAR_XYZ";
        assert!(std::env::var(var).is_err(), "test var must not be set");
        let src = format!(
            "\
!CRL_VERSION = 1.0
!DEFINE A = 1
!DEFINE C = $A${var}
!TARGET = t
!TYPE = git
!URL = https://example.com/repo.git
!REPO_BRANCH = $C
!CHECKOUT = x
"
        );
        let message = err(&src);
        assert!(message.contains(var), "error should name the leaked var: {message}");
    }

    #[test]
    fn dollar_1_dollar_2_multi_repo() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = arrangements
!TYPE = git
!URL = https://example.com/$1-$2
!CHECKOUT =
Foo/Alpha
Foo/Beta
Bar/Gamma
";
        let t = ok(src);
        assert_eq!(t.components().len(), 3);
        let urls: Vec<&str> = t.components().iter().map(|c| c.url.as_deref().unwrap()).collect();
        assert_eq!(
            urls,
            vec![
                "https://example.com/Foo-Alpha",
                "https://example.com/Foo-Beta",
                "https://example.com/Bar-Gamma",
            ]
        );
        let repos: Vec<&str> = t.components().iter().map(|c| c.repo.as_str()).collect();
        assert_eq!(repos, vec!["Foo-Alpha", "Foo-Beta", "Bar-Gamma"]);
        // All distinct repo names.
        assert_eq!(repos.iter().collect::<HashSet<_>>().len(), 3);
    }

    #[test]
    fn multiline_checkout() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = git
!URL = https://example.com/repo.git
!CHECKOUT =
alpha
beta
gamma
";
        let t = ok(src);
        let names: Vec<&str> = t.components().iter().map(|c| c.checkout.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn blank_line_collapse_with_mid_comment() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = git
!URL = https://example.com/repo.git
!CHECKOUT =
tokenA
# a comment about tokenB, sitting mid-value
tokenB
";
        let t = ok(src);
        let names: Vec<&str> = t.components().iter().map(|c| c.checkout.as_str()).collect();
        assert_eq!(names, vec!["tokenA", "tokenB"]);
    }

    #[test]
    fn quoted_values_are_substituted_anyway() {
        // The POD claims quoted values are taken literally; the code has no
        // quote handling at all, so substitution still runs over them.
        let src = "\
!CRL_VERSION = 1.0
!DEFINE HOST = example.com
!TARGET = t
!TYPE = git
!URL = \"http://$HOST/repo.git\"
!CHECKOUT = x
";
        let t = ok(src);
        // Quotes survive verbatim (never stripped); the $HOST inside them
        // still got resolved.
        assert_eq!(t.components()[0].url.as_deref(), Some("\"http://example.com/repo.git\""));
    }

    #[test]
    fn ignore_type_is_dropped() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = git
!URL = https://example.com/repo.git
!CHECKOUT = keep

!TARGET = t
!TYPE = ignore
!CHECKOUT = skip
";
        let t = ok(src);
        assert_eq!(t.components().len(), 1);
        assert_eq!(t.components()[0].checkout, "keep");
    }

    #[test]
    fn long_form_directive_aliases() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = cvs
!URL = https://example.com/repo
!ANONYMOUS_USER = anon
!ANONYMOUS_PASS = secret
!REPOSITORY_BRANCH = main
!AUTHORIZATION_URL = https://example.com/auth
!REPOSITORY_PATH = /path
!CHECKOUT = x
";
        let t = ok(src);
        let c = &t.components()[0];
        assert_eq!(c.anon_user.as_deref(), Some("anon"));
        assert_eq!(c.anon_pass.as_deref(), Some("secret"));
        assert_eq!(c.branch.as_deref(), Some("main"));
        assert_eq!(c.auth_url.as_deref(), Some("https://example.com/auth"));
        assert_eq!(c.repo_path.as_deref(), Some("/path"));
    }

    /// GetComponents applies its long-form aliases in a fixed order (lines
    /// 407-409) that has a real bug: !ANONYMOUS_PASS -> !ANON_PASS runs
    /// BEFORE !ANONYMOUS_PASSWORD -> !ANON_PASS, so by the time the second
    /// rule runs, every !ANONYMOUS_PASSWORD has already had its
    /// !ANONYMOUS_PASS prefix rewritten to !ANON_PASS, leaving
    /// !ANON_PASSWORD — an unrecognized directive. We replicate this
    /// faithfully: !ANONYMOUS_PASSWORD never actually populates anon_pass.
    #[test]
    fn anonymous_password_alias_bug_is_replicated() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = cvs
!URL = https://example.com/repo
!ANONYMOUS_PASSWORD = secret
!CHECKOUT = x
";
        let t = ok(src);
        assert_eq!(t.components()[0].anon_pass, None);
    }

    #[test]
    fn disabled_thorns_are_collected_and_invisible_to_components() {
        let src = "\
!CRL_VERSION = 1.0
#DISABLED McLachlan/ML_BSSN
!TARGET = t
!TYPE = git
!URL = https://example.com/repo.git
!CHECKOUT = x
";
        let t = ok(src);
        assert_eq!(t.disabled_thorns(), &["McLachlan/ML_BSSN".to_string()]);
        assert_eq!(t.components().len(), 1);
        assert_eq!(t.components()[0].checkout, "x");
    }

    #[test]
    fn duplicate_checkout_is_an_error() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = git
!URL = https://example.com/a.git
!CHECKOUT = x

!TARGET = t/
!TYPE = git
!URL = https://example.com/b.git
!CHECKOUT = x
";
        let message = err(src);
        assert!(message.contains("Duplicate checkouts"), "{message}");
        // The two colliding sections are named, not just the path.
        assert!(message.contains("https://example.com/a.git"), "{message}");
        assert!(message.contains("https://example.com/b.git"), "{message}");
    }

    /// The mistake real thornlists actually make: one `!CHECKOUT` list
    /// naming a thorn twice, once on the `!CHECKOUT =` line and once in the
    /// body. Naming the URL twice would read like a cactup bug, so this
    /// case gets its own phrasing.
    #[test]
    fn duplicate_within_one_section_says_so() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = arrangements
!TYPE = git
!URL = https://example.com/CarpetX.git
!REPO_BRANCH = mixed-precision
!REPO_PATH = $2
!CHECKOUT = CarpetX/Algo CarpetX/PDESolvers
CarpetX/ADMBaseX
CarpetX/Algo
CarpetX/Arith
";
        let message = err(src);
        assert!(message.contains("arrangements/CarpetX/Algo"), "{message}");
        assert!(message.contains("listed twice in one !CHECKOUT"), "{message}");
        assert!(message.contains("https://example.com/CarpetX.git"), "{message}");
        // Only the one repeat, not every thorn in the section.
        assert!(!message.contains("PDESolvers"), "{message}");
    }

    /// An `ignore` section may name a path that another section checks out
    /// — GetComponents never lets `ignore` entries reach the duplicate
    /// check (it `next`s out at lines 457 and 733), and real fork
    /// thornlists rely on that.
    #[test]
    fn ignore_section_may_shadow_a_real_checkout() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = arrangements
!TYPE = git
!URL = https://example.com/upstream.git
!REPO_PATH = $2
!CHECKOUT = CarpetX/Algo CarpetX/CarpetX

!TARGET = arrangements
!TYPE = ignore
!CHECKOUT = CarpetX/Algo
";
        let t = ok(src);
        let checkouts: Vec<&str> = t.components().iter().map(|c| c.checkout.as_str()).collect();
        assert_eq!(checkouts, vec!["CarpetX/Algo", "CarpetX/CarpetX"]);
    }

    /// Two `ignore` sections naming the same path don't collide either.
    #[test]
    fn duplicate_ignore_checkouts_are_not_an_error() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = arrangements
!TYPE = ignore
!CHECKOUT = CarpetX/Algo

!TARGET = arrangements
!TYPE = ignore
!CHECKOUT = CarpetX/Algo
";
        assert!(ok(src).components().is_empty());
    }

    /// Sections differing only by `!REPO_BRANCH` still collide, and the
    /// error says so (both sides would land in the same directory).
    #[test]
    fn duplicate_checkout_error_names_branches() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = arrangements
!TYPE = git
!URL = https://example.com/repo.git
!REPO_BRANCH = main
!CHECKOUT = CarpetX/Algo

!TARGET = arrangements
!TYPE = git
!URL = https://example.com/repo.git
!REPO_BRANCH = my-fork
!CHECKOUT = CarpetX/Algo
";
        let message = err(src);
        assert!(message.contains("branch main"), "{message}");
        assert!(message.contains("branch my-fork"), "{message}");
    }

    #[test]
    fn missing_crl_version_is_an_error() {
        let src = "\
!TARGET = t
!TYPE = git
!URL = https://example.com/repo.git
!CHECKOUT = x
";
        let message = err(src);
        assert!(message.contains("CRL_VERSION"), "{message}");
    }

    #[test]
    fn unresolvable_var_names_it() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = git
!URL = https://example.com/$CACTUP_THORNLIST_NOPE_VAR/repo.git
!CHECKOUT = x
";
        let message = err(src);
        assert!(message.contains("CACTUP_THORNLIST_NOPE_VAR"), "{message}");
    }

    #[test]
    fn repeated_define_is_fatal_without_experimental() {
        let src = "\
!CRL_VERSION = 1.0
!DEFINE A = one
!DEFINE A = two
!TARGET = t
!TYPE = git
!URL = https://example.com/repo.git
!CHECKOUT = x
";
        let message = err(src);
        assert!(message.contains("Repeated definition"), "{message}");
    }

    #[test]
    fn repeated_define_is_a_warning_under_experimental() {
        let src = "\
!CRL_VERSION = 1.0_experimental
!DEFINE A = one
!DEFINE A = two
!TARGET = t
!TYPE = git
!URL = https://example.com/$A.git
!CHECKOUT = x
";
        let t = ok(src);
        assert_eq!(t.warnings().len(), 1);
        assert!(t.warnings()[0].contains("Repeated definition"), "{:?}", t.warnings());
        // The original value is kept, not the repeat.
        assert_eq!(t.components()[0].url.as_deref(), Some("https://example.com/one.git"));
    }

    #[test]
    fn repo_name_derivation() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = git
!URL = https://github.com/org/Foo.git
!CHECKOUT = a

!TARGET = t
!TYPE = darcs
!URL = https://example.com/repos/bar_darcs
!CHECKOUT = b

!TARGET = t
!TYPE = hg
!URL = https://example.com/repos/baz.hg
!CHECKOUT = c

!TARGET = t
!TYPE = git
!URL = https://github.com/org/Ignored.git
!NAME = custom-name
!CHECKOUT = d
";
        let t = ok(src);
        let repos: Vec<&str> = t.components().iter().map(|c| c.repo.as_str()).collect();
        assert_eq!(repos, vec!["Foo", "bar", "baz", "custom-name"]);
    }

    #[test]
    fn env_var_substitution() {
        let var = "CACTUP_THORNLIST_TEST_ENV_VAR";
        // SAFETY: test-only, unique var name, single-threaded within this test.
        unsafe {
            std::env::set_var(var, "example.com");
        }
        let src = format!(
            "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = git
!URL = https://${var}/repo.git
!CHECKOUT = x
"
        );
        let t = ok(&src);
        assert_eq!(t.components()[0].url.as_deref(), Some("https://example.com/repo.git"));
        unsafe {
            std::env::remove_var(var);
        }
    }

    #[test]
    fn missing_checkout_warns_and_skips_section() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = git
!URL = https://example.com/repo.git

!TARGET = t
!TYPE = git
!URL = https://example.com/other.git
!CHECKOUT = x
";
        let t = ok(src);
        assert_eq!(t.components().len(), 1);
        assert_eq!(t.warnings().len(), 1);
        assert!(t.warnings()[0].contains("Nothing will be checked out"), "{:?}", t.warnings());
    }

    #[test]
    fn missing_type_is_an_error() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!URL = https://example.com/repo.git
!CHECKOUT = x
";
        let message = err(src);
        assert!(message.contains("TYPE"), "{message}");
    }

    /// `!REPO_COMMIT` (a cactup extension): a full commit id, lowercased,
    /// pinning every checkout of its section; `!REPO_BRANCH` stays the label
    /// (here a track-style tag) it was taken from.
    #[test]
    fn repo_commit_pins_the_section() {
        let pin = "3F2C9A0B1D4E5F60718293A4B5C6D7E8F9012345";
        let t = ok(&format!(
            "!CRL_VERSION = 1.0\n!TARGET = arrangements\n!TYPE = git\n\
             !URL = https://github.com/max-morris/CarpetX.git\n!REPO_PATH = $2\n\
             !REPO_BRANCH = mixed-precision/v1.4.0\n!REPO_COMMIT = {pin}\n\
             !CHECKOUT = CarpetX/CarpetX CarpetX/Loop\n"
        ));
        assert_eq!(t.components().len(), 2);
        for c in t.components() {
            assert_eq!(c.commit.as_deref(), Some(pin.to_ascii_lowercase().as_str()));
            assert_eq!(c.branch.as_deref(), Some("mixed-precision/v1.4.0"));
        }
        // Unpinned stays unpinned.
        let t = ok("!CRL_VERSION = 1.0\n!TARGET = a\n!TYPE = git\n!URL = https://x/r.git\n!CHECKOUT = A/B\n");
        assert_eq!(t.components()[0].commit, None);
    }

    #[test]
    fn repo_commit_must_be_a_full_id_on_a_git_component() {
        let section = |ty: &str, commit: &str| {
            format!("!CRL_VERSION = 1.0\n!TARGET = a\n!TYPE = {ty}\n!URL = https://x/r\n!REPO_COMMIT = {commit}\n!CHECKOUT = A/B\n")
        };
        let full = "0123456789abcdef0123456789abcdef01234567";
        assert!(err(&section("git", "0123abc")).contains("not a full commit id"));
        assert!(err(&section("git", &format!("{}g", &full[..39]))).contains("not a full commit id"));
        assert!(err(&section("svn", full)).contains("only git components"));
        // SHA-256 repositories have 64-digit ids.
        ok(&section("git", &format!("{full}{}", &full[..24])));
    }

    #[test]
    fn unknown_type_is_an_error() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = bzr
!URL = https://example.com/repo.git
!CHECKOUT = x
";
        let message = err(src);
        assert!(message.contains("bzr"), "{message}");
    }

    #[test]
    fn missing_url_is_an_error_for_non_ignore_type() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = git
!CHECKOUT = x
";
        let message = err(src);
        assert!(message.contains("URL"), "{message}");
    }

    #[test]
    fn ignore_section_needs_neither_url_nor_checkout() {
        let src = "\
!CRL_VERSION = 1.0
!TARGET = t
!TYPE = ignore
!CHECKOUT =
";
        let t = ok(src);
        assert_eq!(t.components().len(), 0);
        assert!(t.warnings().is_empty());
    }

    #[test]
    fn include_local_path_is_spliced() {
        let dir = std::env::temp_dir().join(format!(
            "cactup-thornlist-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let included = dir.join("included.th");
        std::fs::write(
            &included,
            "!TARGET = t\n!TYPE = git\n!URL = https://example.com/repo.git\n!CHECKOUT = x\n",
        )
        .unwrap();
        let src = "!CRL_VERSION = 1.0\n!INCLUDE = included.th\n";
        let t = match parse_with_base(src, Some(&dir)) {
            Ok(t) => t,
            Err(e) => panic!("expected include to resolve: {e:#}"),
        };
        assert_eq!(t.components().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn include_of_url_errors() {
        let src = "!CRL_VERSION = 1.0\n!INCLUDE = http://example.com/list.th\n";
        let message = err(src);
        assert!(message.contains("not yet supported"), "{message}");
    }

    #[test]
    fn include_without_base_errors() {
        let src = "!CRL_VERSION = 1.0\n!INCLUDE = some/local/list.th\n";
        let message = err(src);
        assert!(message.contains("base directory"), "{message}");
    }

    /// A miniature but structurally-complete Einstein-Toolkit-style list.
    #[test]
    fn et_style_miniature_list() {
        let src = "\
!CRL_VERSION = 1.0

!DEFINE ROOT = Cactus
!DEFINE ARR = $ROOT/arrangements
!DEFINE ET_RELEASE = ET_2026_05

#DISABLED McLachlan/ML_BSSN

!TARGET = $ARR
!TYPE = git
!URL = https://github.com/EinsteinToolkit/$2
!REPO_BRANCH = $ET_RELEASE
!CHECKOUT =
McLachlan/ML_BSSN
McLachlan/ML_ADMConstraints

!TARGET = $ARR
!TYPE = ignore
!CHECKOUT =
Numerical/PrivateThorn
";
        let t = ok(src);
        assert_eq!(t.crl_version(), "1.0");
        assert_eq!(t.root(), "Cactus");
        assert_eq!(t.components().len(), 2);
        for c in t.components() {
            assert_eq!(c.target, "Cactus/arrangements");
            assert_eq!(c.branch.as_deref(), Some("ET_2026_05"));
        }
        let repos: Vec<&str> = t.components().iter().map(|c| c.repo.as_str()).collect();
        assert_eq!(repos, vec!["ML_BSSN", "ML_ADMConstraints"]);
        assert_eq!(t.disabled_thorns(), &["McLachlan/ML_BSSN".to_string()]);
    }

    /// A prose header may *mention* `#DISABLED` mid-sentence. Only a line that
    /// starts with the directive counts — real-world trigger: a custom
    /// thornlist whose header documents "comment out X below (#DISABLED X)".
    /// The native fetcher copies `--thornlist` input verbatim, header and all,
    /// where GetComponents used to strip it, so this reaches the parser now.
    #[test]
    fn disabled_directive_must_start_the_line() {
        let src = "!CRL_VERSION = 1.0\n\
                   # comment out CarpetX/TestReal2 below (#DISABLED CarpetX/TestReal2). Nothing\n\
                   # else in this list needs it.\n\
                   !TARGET = Cactus/arrangements\n\
                   !TYPE = git\n\
                   !URL = https://e.invalid/carpetx.git\n\
                   !CHECKOUT = CarpetX/CarpetX\n\
                   #DISABLED ExternalLibraries/PETSc\n";
        let list = parse(src).unwrap();
        assert_eq!(
            list.disabled_thorns(),
            ["ExternalLibraries/PETSc"],
            "only the column-0 directive counts, not the prose mention"
        );
    }

    /// `thorn_providers()` keys on the bare thorn name, values the
    /// root-stripped canonical providing directory; a flesh-style section
    /// (slash-free checkout tokens) contributes nothing.
    #[test]
    fn thorn_providers_maps_names_to_providers() {
        let src = "\
!CRL_VERSION = 1.0
!DEFINE ROOT = Cactus

!TARGET = $ROOT/arrangements
!TYPE = git
!URL = https://example.com/foo.git
!CHECKOUT = Foo/Alpha

!TARGET = $ROOT
!TYPE = git
!URL = https://example.com/core.git
!CHECKOUT = Makefile lib src
";
        let t = ok(src);
        let providers = t.thorn_providers();
        assert_eq!(
            providers.keys().collect::<Vec<_>>(),
            vec!["Alpha"],
            "flesh checkout tokens (no '/') must be absent: {providers:?}"
        );
        assert_eq!(providers["Alpha"], "arrangements/Foo/Alpha");
    }

    /// The motivating incident: the same thorn *name* provided by two
    /// different arrangements across an old/new thornlist pair.
    /// `thorn_providers()` must report the actual providing directory for
    /// each, so `build.rs` can notice the swap and invalidate the stale
    /// per-thorn build state.
    #[test]
    fn thorn_providers_tracks_a_provider_swap() {
        let old = "\
!CRL_VERSION = 1.0
!DEFINE ROOT = Cactus

!TARGET = $ROOT/arrangements
!TYPE = git
!URL = https://example.com/einsteinanalysis.git
!CHECKOUT = EinsteinAnalysis/WeylScal4

!TARGET = $ROOT/arrangements
!TYPE = git
!URL = https://example.com/spacetimex.git
!CHECKOUT =
#DISABLED SpacetimeX/WeylScal4
";
        let new = "\
!CRL_VERSION = 1.0
!DEFINE ROOT = Cactus

!TARGET = $ROOT/arrangements
!TYPE = git
!URL = https://example.com/einsteinanalysis.git
!CHECKOUT =
#DISABLED EinsteinAnalysis/WeylScal4

!TARGET = $ROOT/arrangements
!TYPE = git
!URL = https://example.com/spacetimex.git
!CHECKOUT = SpacetimeX/WeylScal4
";
        let old_t = ok(old);
        let new_t = ok(new);
        assert_eq!(old_t.thorn_providers()["WeylScal4"], "arrangements/EinsteinAnalysis/WeylScal4");
        assert_eq!(new_t.thorn_providers()["WeylScal4"], "arrangements/SpacetimeX/WeylScal4");
    }

}

