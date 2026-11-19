//! The closure check every sim and stack release passes: the thorns its thornlist builds must
//! build together. Each hard CCL requirement of each built thorn (what it inherits or befriends,
//! the capabilities, thorns and functions it requires, the headers it includes outside any
//! conditional) must be met by a thorn the thornlist builds, by the crate's rule (`ccl::needs_of`,
//! `meets`, `counts`), shared with CactUp and with the package check in `deps.rs`.
//!
//! What a built thorn needs comes from the facts the Cactarium stored for the package version
//! that froze the commit its repo is pinned at. A header (`Need::Include`) counts only where some
//! published thorn provides it (`ccl::counts`): one nothing provides compiles empty, which is how
//! hooks work, so it never refuses anything. Nor does one whose provider is optional to the thorn
//! (`OPTIONAL`/`OPTIONAL_IFACTIVE`), nor one whose guard macro the thorn's sources test (the
//! scanner leaves those out of `needs_includes`).
//!
//! Some built thorns' facts can't be known: a download's (a tarball component), a repo no package
//! is registered for, a commit no version froze, a thorn the frozen version doesn't publish. The
//! check stays conservative about them, so that they never cause a refusal that may be false:
//! their own needs aren't checked (nothing says what they are), and they are taken to meet every
//! need they plausibly could. A thorn meets `Need::Thorn` by its name alone, so that is decided
//! by the name. Anything else is plausible when some thorn of the same name the Cactarium knows
//! (any version of any package; Cactus thorn names are global, so it is most likely the same
//! thorn) meets it, or when the Cactarium knows no thorn of that name at all: then nothing can be
//! said about it, and it may meet anything.

use std::collections::{BTreeMap, HashMap};

use cactup_ecosystem_common::ccl::{self, Need, ThornFacts};
use cactup_ecosystem_common::crl::{self, Component};
use cactup_ecosystem_common::sim::RepoPin;

use crate::error::AppResult;
use crate::state::AppState;

/// The SQL condition (on `thorns t`) that finds the thorns that might meet `need`, by index, and
/// the facts key it reads (`$2`; `$1` is the need's name). `ccl::meets` has the last word. Facts
/// stored before the scanner read `INCLUDE` lines have no `provides-includes` key and match no
/// header until they are rescanned (`cactarium rescan-facts`).
pub fn need_index(need: &Need) -> (&'static str, &'static str) {
    const IN_FACTS: &str = "EXISTS (SELECT 1 FROM jsonb_array_elements_text(t.facts -> $2) x WHERE lower(x) = lower($1))";
    match need {
        Need::Implementation(_) => ("lower(t.implements) = lower($1) AND $2 = ''", ""),
        Need::Thorn(_) => ("lower(t.name) = lower($1) AND $2 = ''", ""),
        Need::Capability(_) => (IN_FACTS, "provides"),
        Need::Function(_) => (IN_FACTS, "provides-functions"),
        Need::Include(_) => (IN_FACTS, "provides-includes"),
    }
}

/// Published thorns: of public packages, in approved, valid, unyanked versions. What a refusal
/// may name, and what makes a header count.
const PUBLISHED: &str = "e.kind = 'package' AND e.visibility = 'public' AND v.review = 'approved'
    AND v.state <> 'invalid' AND v.invalid_reason IS NULL AND NOT v.yanked";

/// The published thorns that meet `need`, as (`Arrangement/Thorn`, `owner/package`), each once,
/// by package, then thorn.
pub async fn providers(state: &AppState, need: &Need) -> AppResult<Vec<(String, String)>> {
    let (cond, key) = need_index(need);
    let rows: Vec<(String, String, String, serde_json::Value)> = sqlx::query_as(&format!(
        "SELECT e.owner || '/' || e.name, t.arrangement, t.name, t.facts
         FROM thorns t JOIN versions v ON v.id = t.version_id JOIN entries e ON e.id = v.entry_id
         WHERE {PUBLISHED} AND ({cond})
         ORDER BY 1, 2, 3"
    ))
    .bind(need.name())
    .bind(key)
    .fetch_all(&state.db)
    .await?;
    let mut out: Vec<(String, String)> = Vec::new();
    for (package, arrangement, thorn, facts) in rows {
        let facts: ThornFacts = serde_json::from_value(facts).unwrap_or_default();
        let found = (format!("{arrangement}/{thorn}"), package);
        if ccl::meets(&thorn, &facts, need) && !out.contains(&found) {
            out.push(found);
        }
    }
    Ok(out)
}

/// Whether an unmet `need` of the thorn with `needing` facts counts against a set, by the crate's
/// rule ([`ccl::counts`]), given the facts of the thorns the caller knows of (`local`) and every
/// published thorn: a header counts only where some thorn provides it, and none that does is
/// optional to the thorn (it `PROVIDES` or `IMPLEMENTS` something the thorn declares `OPTIONAL` or
/// `OPTIONAL_IFACTIVE`). Every other need counts. `cache` keeps the published providers of each
/// header for one check.
pub async fn counts(
    state: &AppState,
    needing: &ThornFacts,
    need: &Need,
    local: &[&ThornFacts],
    cache: &mut HashMap<String, Vec<ThornFacts>>,
) -> AppResult<bool> {
    let Need::Include(header) = need else { return Ok(true) };
    let key = header.to_ascii_lowercase();
    if !cache.contains_key(&key) {
        let (cond, facts_key) = need_index(need);
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(&format!(
            "SELECT DISTINCT t.facts FROM thorns t JOIN versions v ON v.id = t.version_id JOIN entries e ON e.id = v.entry_id
             WHERE {PUBLISHED} AND ({cond})"
        ))
        .bind(header)
        .bind(facts_key)
        .fetch_all(&state.db)
        .await?;
        cache.insert(key.clone(), rows.into_iter().map(|f| serde_json::from_value(f).unwrap_or_default()).collect());
    }
    Ok(ccl::counts(needing, need, local.iter().copied().chain(&cache[&key])))
}

/// A thorn a thornlist builds, with what the Cactarium knows of it.
#[derive(Clone, Debug)]
pub struct Built {
    /// `Arrangement/Thorn`, as the thornlist checks it out.
    pub checkout: String,
    /// Its facts, when a package version froze the commit its repo is pinned at and publishes it.
    pub facts: Option<ThornFacts>,
    /// For a thorn whose facts aren't known: the facts of every thorn of the same name the
    /// Cactarium knows, which say what it plausibly meets ([`Built::may_meet`]).
    pub like: Vec<ThornFacts>,
}

impl Built {
    fn name(&self) -> &str {
        self.checkout.rsplit('/').next().unwrap_or(&self.checkout)
    }

    /// Whether this thorn, whose facts aren't known, could meet `need` (see the module's doc): a
    /// thorn need by its name; anything else when a thorn of its name the Cactarium knows meets
    /// it, or when it knows no thorn of that name at all.
    fn may_meet(&self, need: &Need) -> bool {
        match need {
            Need::Thorn(t) => self.name().eq_ignore_ascii_case(t),
            _ => self.like.is_empty() || self.like.iter().any(|f| ccl::meets(self.name(), f, need)),
        }
    }
}

/// The needs of the built thorns whose facts are known that no built thorn meets, as (index in
/// `built`, need): unmet by every thorn whose facts are known, and by no thorn whose facts aren't
/// known plausibly met ([`Built::may_meet`]). Whether each counts is decided after
/// ([`counts`]).
pub fn unmet(built: &[Built]) -> Vec<(usize, Need)> {
    let known: Vec<(&str, &ThornFacts)> = built.iter().filter_map(|b| b.facts.as_ref().map(|f| (b.name(), f))).collect();
    let mut out = Vec::new();
    for (i, b) in built.iter().enumerate() {
        let Some(facts) = &b.facts else { continue };
        for need in ccl::unmet(facts, known.iter().copied()) {
            if !built.iter().any(|o| o.facts.is_none() && o.may_meet(&need)) {
                out.push((i, need));
            }
        }
    }
    out
}

/// The thorn a component builds, as (arrangement, thorn): a line of its own after `!CHECKOUT`
/// (one on the `!CHECKOUT` line is fetched, not built), naming `Arrangement/Thorn`, both CCL
/// names. Anything else a thornlist checks out (the flesh, simfactory, a library inside a thorn)
/// is no thorn Cactus builds.
fn built_thorn(c: &Component) -> Option<(&str, &str)> {
    if c.fetch_only {
        return None;
    }
    let (arrangement, thorn) = c.checkout.split_once('/')?;
    (ccl::is_ccl_name(arrangement) && ccl::is_ccl_name(thorn)).then_some((arrangement, thorn))
}

/// One problem, as a refusal says it: the thorn, its need, and the published thorns that would
/// meet it (`providers`, as (`Arrangement/Thorn`, `owner/package`)), else what to do. `what` is
/// what builds the thornlist: "the sim", "the release".
pub fn said(checkout: &str, need: &Need, what: &str, providers: &[(String, String)]) -> String {
    let missing = match need {
        Need::Thorn(_) => format!("which {what} doesn't build"),
        Need::Implementation(_) => format!("which nothing {what} builds implements"),
        _ => format!("which nothing {what} builds provides"),
    };
    let named: Vec<String> = providers.iter().take(3).map(|(t, p)| format!("{t} ({p})")).collect();
    let more = providers.len().saturating_sub(named.len());
    let fix = match (named.as_slice(), more) {
        ([], _) => format!("no package on the Cactarium provides it either: add a thorn that does, or drop {checkout}"),
        ([one], _) => format!("{one} does: add it to the thornlist"),
        (some, 0) => format!("{} and {} do: add one of them to the thornlist", some[..some.len() - 1].join(", "), some[some.len() - 1]),
        (some, n) => format!("{}, and {n} more, do: add one of them to the thornlist", some.join(", ")),
    };
    format!("{checkout} {need}, {missing}; {fix}")
}

/// What is wrong with the thorns `thornlist` builds, its repos pinned by `pins` (a sim's
/// `[[repo]]`, a stack release's frozen pins), with `what` naming what builds it ("the sim",
/// "the release"): every counting need of a built thorn no built thorn meets ([`unmet`],
/// [`counts`]), with the published thorns that would meet it. Empty when it builds, or when the
/// thornlist doesn't parse (its own check says so).
pub async fn problems(state: &AppState, what: &str, thornlist: &str, pins: &[RepoPin]) -> AppResult<Vec<String>> {
    let Ok(list) = crl::parse(thornlist) else { return Ok(Vec::new()) };
    let thorns: Vec<(&Component, &str)> =
        list.components().iter().filter_map(|c| built_thorn(c).map(|(_, t)| (c, t))).collect();
    if thorns.is_empty() {
        return Ok(Vec::new());
    }
    // Package entries by repo, public first (as `sims::pin_problems` matches them).
    let packages: Vec<(i64, String)> = sqlx::query_as(
        "SELECT e.id, r.url FROM entries e JOIN entry_repos r ON r.entry_id = e.id
         WHERE e.kind = 'package' ORDER BY e.visibility = 'public' DESC, e.created_at",
    )
    .fetch_all(&state.db)
    .await?;
    // The thorns of the version that froze each pinned commit, by repo name (lower-cased thorn
    // name → facts); none for a download, a repo no package has, or a commit no version froze.
    let mut frozen: BTreeMap<&str, Option<HashMap<String, ThornFacts>>> = BTreeMap::new();
    for (c, _) in &thorns {
        if frozen.contains_key(c.repo.as_str()) {
            continue;
        }
        let pin = pins.iter().find(|p| p.name == c.repo);
        let package = pin.and_then(|p| crate::model::find_repo(&p.url, &packages, |(_, u)| u).map(|(id, _)| *id));
        let version: Option<i64> = match (package, pin.and_then(|p| p.commit.as_deref())) {
            (Some(id), Some(commit)) => sqlx::query_scalar(
                "SELECT id FROM versions WHERE entry_id = $1 AND commit = $2 AND state <> 'invalid' AND invalid_reason IS NULL
                 ORDER BY (track = '') DESC, sort_key DESC LIMIT 1",
            )
            .bind(id)
            .bind(commit)
            .fetch_optional(&state.db)
            .await?,
            _ => None,
        };
        let facts = match version {
            Some(vid) => {
                let rows: Vec<(String, serde_json::Value)> =
                    sqlx::query_as("SELECT name, facts FROM thorns WHERE version_id = $1").bind(vid).fetch_all(&state.db).await?;
                Some(rows.into_iter().map(|(n, f)| (n.to_ascii_lowercase(), serde_json::from_value(f).unwrap_or_default())).collect())
            }
            None => None,
        };
        frozen.insert(c.repo.as_str(), facts);
    }
    let mut built: Vec<Built> = thorns
        .iter()
        .map(|(c, thorn)| Built {
            checkout: c.checkout.clone(),
            facts: frozen.get(c.repo.as_str()).and_then(|f| f.as_ref()?.get(&thorn.to_ascii_lowercase()).cloned()),
            like: Vec::new(),
        })
        .collect();
    // What the thorns whose facts aren't known plausibly meet: every thorn of their name the
    // Cactarium knows, in any version of any package.
    let unknown: Vec<String> = built.iter().filter(|b| b.facts.is_none()).map(|b| b.name().to_ascii_lowercase()).collect();
    if !unknown.is_empty() {
        let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
            "SELECT lower(t.name), t.facts FROM thorns t JOIN versions v ON v.id = t.version_id JOIN entries e ON e.id = v.entry_id
             WHERE e.kind = 'package' AND v.state <> 'invalid' AND lower(t.name) = ANY($1)",
        )
        .bind(&unknown)
        .fetch_all(&state.db)
        .await?;
        let mut like: HashMap<String, Vec<ThornFacts>> = HashMap::new();
        for (name, facts) in rows {
            like.entry(name).or_default().push(serde_json::from_value(facts).unwrap_or_default());
        }
        for b in built.iter_mut().filter(|b| b.facts.is_none()) {
            b.like = like.get(&b.name().to_ascii_lowercase()).cloned().unwrap_or_default();
        }
    }
    let local: Vec<&ThornFacts> = built.iter().filter_map(|b| b.facts.as_ref()).collect();
    let mut cache = HashMap::new();
    let mut out: Vec<String> = Vec::new();
    for (i, need) in unmet(&built) {
        let needing = built[i].facts.as_ref().expect("unmet only reads thorns with facts");
        if !counts(state, needing, &need, &local, &mut cache).await? {
            continue;
        }
        let line = said(&built[i].checkout, &need, what, &providers(state, &need).await?);
        if !out.contains(&line) {
            out.push(line);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(interface: &str, configuration: Option<&str>) -> ThornFacts {
        ThornFacts::scan(interface, configuration)
    }

    /// TwoPuncturesX as the scanner reads it with its sources: it includes TP_Guts.h outside any
    /// conditional.
    fn tpx() -> ThornFacts {
        ThornFacts {
            needs_includes: vec!["TP_Guts.h".into()],
            ..facts("IMPLEMENTS: TwoPuncturesX\nINHERITS: ADMBase\nUSES INCLUDE: TP_Guts.h\n", None)
        }
    }

    fn known(checkout: &str, f: ThornFacts) -> Built {
        Built { checkout: checkout.into(), facts: Some(f), like: vec![] }
    }

    fn unknown(checkout: &str, like: Vec<ThornFacts>) -> Built {
        Built { checkout: checkout.into(), facts: None, like }
    }

    fn needs(built: &[Built]) -> Vec<(String, String)> {
        unmet(built).into_iter().map(|(i, n)| (built[i].checkout.clone(), n.to_string())).collect()
    }

    /// The case that motivated the check: TwoPuncturesX without TwoPunctures.
    #[test]
    fn a_header_only_another_thorn_provides_is_unmet_without_it() {
        let admbase = facts("IMPLEMENTS: ADMBase\n", None);
        let tp = facts("IMPLEMENTS: TwoPunctures\nINCLUDE HEADER: TP_Guts.h in TP_Guts.h\n", None);
        let without = [known("EinsteinBase/ADMBase", admbase.clone()), known("EinsteinInitialData/TwoPuncturesX", tpx())];
        assert_eq!(needs(&without), [("EinsteinInitialData/TwoPuncturesX".to_owned(), "includes the header TP_Guts.h".to_owned())]);
        let with = [
            known("EinsteinBase/ADMBase", admbase),
            known("EinsteinInitialData/TwoPuncturesX", tpx()),
            known("EinsteinInitialData/TwoPunctures", tp),
        ];
        assert!(unmet(&with).is_empty());
    }

    /// A thorn whose facts aren't known: its own needs aren't checked, it meets a thorn need by its
    /// name, and anything else when a known thorn of its name does or none of its name is known.
    #[test]
    fn unknown_thorns_never_refuse_what_they_may_meet() {
        let tp = facts("IMPLEMENTS: TwoPunctures\nINCLUDE HEADER: TP_Guts.h in TP_Guts.h\n", None);
        let admbase = known("EinsteinBase/ADMBase", facts("IMPLEMENTS: ADMBase\n", None));
        // A download named like TwoPunctures, which a published version provides the header in.
        let built = [admbase.clone(), known("EinsteinInitialData/TwoPuncturesX", tpx()), unknown("Downloads/TwoPunctures", vec![tp])];
        assert!(unmet(&built).is_empty());
        // One the Cactarium knows nothing of may be anything.
        let built = [admbase.clone(), known("EinsteinInitialData/TwoPuncturesX", tpx()), unknown("Mine/Secret", vec![])];
        assert!(unmet(&built).is_empty());
        // One known by name that doesn't provide the header doesn't stand in for it.
        let other = facts("IMPLEMENTS: Other\n", None);
        let built = [admbase.clone(), known("EinsteinInitialData/TwoPuncturesX", tpx()), unknown("Mine/Other", vec![other])];
        assert_eq!(needs(&built).len(), 1);
        // A required thorn is met by name, never by an unknown thorn of another name.
        let needy = known("A/Needy", facts("IMPLEMENTS: Needy\n", Some("REQUIRES THORNS: Helper\n")));
        assert!(unmet(&[needy.clone(), unknown("B/Helper", vec![])]).is_empty());
        assert_eq!(needs(&[needy, unknown("B/Stranger", vec![])]), [("A/Needy".to_owned(), "requires the thorn Helper".to_owned())]);
        // An unknown thorn's own needs aren't checked: nothing says what they are.
        assert!(unmet(&[unknown("A/Alone", vec![tpx()])]).is_empty());
    }

    /// Headers a thorn builds without are never needs that count, by the crate's rules: one whose
    /// provider it declares OPTIONAL (Slab's loopcontrol.h, PUGH's vectors.h, McLachlan's
    /// loopcontrol.h) or OPTIONAL_IFACTIVE (GRHydro's and NoExcision's carpet.hh), and one whose
    /// guard macro its sources test (Formaline's http_Content.h, used only under
    /// `#ifdef __HTTP_CONTENT_H__`), which the scanner leaves out of its needs.
    #[test]
    fn headers_a_thorn_builds_without_do_not_count() {
        let header = |h: &str| Need::Include(h.into());
        let needing = |interface: &str, configuration: &str, needs: &[&str]| ThornFacts {
            needs_includes: needs.iter().map(|s| s.to_string()).collect(),
            ..facts(interface, Some(configuration))
        };
        let loopcontrol = facts("IMPLEMENTS: LoopControl\nINCLUDES HEADER: loopcontrol.h IN loopcontrol.h\n", Some("PROVIDES LoopControl\n{\n}\n"));
        let vectors = facts("IMPLEMENTS: Vectors\nINCLUDE HEADER: vectors.h IN vectors.h\n", Some("PROVIDES Vectors\n{\n}\n"));
        let carpet = facts("IMPLEMENTS: Driver\nINCLUDE HEADER: carpet.hh IN carpet.hh\n", Some("PROVIDES Carpet\n{\n}\n"));
        let providers = [&loopcontrol, &vectors, &carpet];
        let slab = needing("IMPLEMENTS: Slab\nUSES INCLUDE HEADER: loopcontrol.h\n", "PROVIDES Slab\n{\n}\nOPTIONAL LoopControl MPI\n{\n}\n", &["loopcontrol.h"]);
        let pugh = needing("IMPLEMENTS: Driver\nUSES INCLUDE: vectors.h\n", "OPTIONAL MPI\n{\n}\nOPTIONAL Vectors\n{\n}\n", &["vectors.h"]);
        let ml = needing("IMPLEMENTS: ML_ADMConstraints\nUSES INCLUDE: loopcontrol.h\n", "REQUIRES GenericFD\nOPTIONAL LoopControl\n{\n}\n", &["loopcontrol.h"]);
        let grhydro = needing("IMPLEMENTS: GRHydro\nUSES INCLUDE: carpet.hh\n", "OPTIONAL_IFACTIVE Carpet\n{\n}\n", &["carpet.hh"]);
        let noexcision = needing("IMPLEMENTS: NoExcision\nUSES INCLUDE: carpet.hh\n", "OPTIONAL_IFACTIVE Carpet\n{\n}\n", &["carpet.hh"]);
        for (what, f, h) in [("Slab", &slab, "loopcontrol.h"), ("PUGH", &pugh, "vectors.h"), ("McLachlan", &ml, "loopcontrol.h"), ("GRHydro", &grhydro, "carpet.hh"), ("NoExcision", &noexcision, "carpet.hh")] {
            assert_eq!(ccl::needs_of(f).last(), Some(&header(h)), "{what} still includes {h}");
            assert!(!ccl::counts(f, &header(h), providers), "{what} builds without {h}");
        }
        // TwoPuncturesX's header is no optional provider's: it counts.
        let tp = facts("IMPLEMENTS: TwoPunctures\nINCLUDE HEADER: TP_Guts.h in TP_Guts.h\n", None);
        assert!(ccl::counts(&tpx(), &header("TP_Guts.h"), [&tp, &loopcontrol]));
        // Formaline: the sources test the header's guard, so the scanner reads no need at all.
        let dir = std::env::temp_dir().join(format!("closure-formaline-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/announce.cc"),
            "#include \"http_Content.h\"\nvoid f() {\n#ifdef __HTTP_CONTENT_H__\n  HTTP_Port();\n#endif\n}\n",
        )
        .unwrap();
        let mut formaline = facts("IMPLEMENTS: Formaline\nUSES INCLUDE HEADER: http_Content.h\n", Some("OPTIONAL MPI\n{\n}\n"));
        formaline.scan_sources(&dir);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(formaline.needs_includes.is_empty(), "{:?}", formaline.needs_includes);
        // And so a thornlist of them without the providers builds.
        let built = [known("CactusNumerical/Slab", slab), known("CactusPUGH/PUGH", pugh), known("CactusUtils/Formaline", formaline)];
        let flagged: Vec<_> = unmet(&built).into_iter().filter(|(i, n)| ccl::counts(built[*i].facts.as_ref().unwrap(), n, providers)).collect();
        assert!(flagged.is_empty(), "{flagged:?}");
    }

    /// Only lines of their own naming Arrangement/Thorn are built thorns.
    #[test]
    fn only_thorn_lines_are_built() {
        let list = crl::parse(
            "!CRL_VERSION = 1.0\n!DEFINE ROOT = Cactus\n\
             !TARGET = $ROOT\n!TYPE = git\n!URL = https://x/flesh.git\n!NAME = .\n!CHECKOUT = ./simfactory\n\
             !TARGET = $ROOT/arrangements\n!TYPE = git\n!URL = https://x/r.git\n!REPO_PATH = $2\n!CHECKOUT = CactusElliptic/EllPETSc\n\
             CactusBase/IOUtil\nEinsteinInitialData/TwoPuncturesX\n",
        )
        .unwrap();
        let built: Vec<(&str, &str)> = list.components().iter().filter_map(built_thorn).collect();
        assert_eq!(built, [("CactusBase", "IOUtil"), ("EinsteinInitialData", "TwoPuncturesX")]);
    }

    /// Thornlists that really build, checked against the facts scanned from a Cactus tree that
    /// built them (every thorn in it standing for the registry's): nothing is flagged. Runs when
    /// CACTARIUM_TEST_CACTUS names the tree and CACTARIUM_TEST_THORNLISTS the lists (separated by
    /// `:`); with CACTARIUM_TEST_DROP=Arr/Thorn, that thorn is dropped from each list first, and
    /// what it alone met must then be flagged.
    #[test]
    fn real_thornlists_have_no_false_positives() {
        let (Some(tree), Some(lists)) = (std::env::var_os("CACTARIUM_TEST_CACTUS"), std::env::var("CACTARIUM_TEST_THORNLISTS").ok()) else {
            return;
        };
        let drop = std::env::var("CACTARIUM_TEST_DROP").ok();
        // CactUp's trees link each thorn into arrangements/ from its repo: scanned where it is.
        let arrangements = std::path::Path::new(&tree).join("arrangements");
        let mut all: HashMap<String, ThornFacts> = HashMap::new();
        for a in std::fs::read_dir(&arrangements).unwrap().flatten() {
            for t in std::fs::read_dir(a.path()).into_iter().flatten().flatten() {
                let Ok(dir) = t.path().canonicalize() else { continue };
                if let Some(found) = ccl::scan_tree(&dir).into_iter().find(|s| s.dir.as_os_str().is_empty()) {
                    all.insert(format!("{}/{}", a.file_name().to_string_lossy(), t.file_name().to_string_lossy()), found.facts);
                }
            }
        }
        let registry: Vec<&ThornFacts> = all.values().collect();
        for path in lists.split(':') {
            let text = std::fs::read_to_string(path).unwrap();
            let list = crl::parse(&text).unwrap();
            let built: Vec<Built> = list
                .components()
                .iter()
                .filter_map(built_thorn)
                .map(|(a, t)| format!("{a}/{t}"))
                .filter(|c| drop.as_deref() != Some(c.as_str()))
                .map(|c| Built { facts: all.get(&c).cloned(), checkout: c, like: vec![] })
                .collect();
            let flagged: Vec<String> = unmet(&built)
                .into_iter()
                .filter(|(i, n)| ccl::counts(built[*i].facts.as_ref().unwrap(), n, registry.iter().copied()))
                .map(|(i, n)| format!("{} {n}", built[i].checkout))
                .collect();
            let unknown = built.iter().filter(|b| b.facts.is_none()).count();
            eprintln!("{path}: {} built ({unknown} not in the tree), flagged: {flagged:?}", built.len());
            match &drop {
                None => assert!(flagged.is_empty(), "{path}: {flagged:?}"),
                Some(d) => assert!(!flagged.is_empty(), "{path} without {d}: nothing flagged"),
            }
        }
    }

    /// A refusal names the thorn, the need and who would meet it.
    #[test]
    fn problems_say_what_would_fix_them() {
        let header = Need::Include("TP_Guts.h".into());
        let tp = ("EinsteinInitialData/TwoPunctures".to_owned(), "et/einsteininitialdata".to_owned());
        assert_eq!(
            said("EinsteinInitialData/TwoPuncturesX", &header, "the sim", std::slice::from_ref(&tp)),
            "EinsteinInitialData/TwoPuncturesX includes the header TP_Guts.h, which nothing the sim builds provides; \
             EinsteinInitialData/TwoPunctures (et/einsteininitialdata) does: add it to the thornlist"
        );
        let drivers: Vec<(String, String)> =
            ["Carpet", "CarpetX", "PUGH", "Other"].iter().map(|d| (format!("{d}/{d}"), format!("et/{}", d.to_lowercase()))).collect();
        let s = said("A/B", &Need::Implementation("driver".into()), "the release", &drivers[..2]);
        assert!(s.contains("which nothing the release builds implements; Carpet/Carpet (et/carpet) and CarpetX/CarpetX (et/carpetx) do: add one of them"), "{s}");
        let s = said("A/B", &Need::Implementation("driver".into()), "the release", &drivers);
        assert!(s.contains("PUGH/PUGH (et/pugh), and 1 more, do"), "{s}");
        let s = said("A/B", &Need::Thorn("Helper".into()), "the sim", &[]);
        assert_eq!(s, "A/B requires the thorn Helper, which the sim doesn't build; no package on the Cactarium provides it either: add a thorn that does, or drop A/B");
    }
}
