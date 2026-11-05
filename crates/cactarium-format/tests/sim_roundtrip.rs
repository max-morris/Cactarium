use cactarium_format::Error;
use cactarium_format::sim::{ParfileKind, Parfile, RepoPin, SimFile, SimMeta, ThornlistText, Unspecified};

const SHA: &str = "3f2c9e1a00112233445566778899aabbccddeeff";

fn sample(thornlist: &str, par: &str) -> SimFile {
    SimFile {
        format: 1,
        sim: SimMeta {
            name: "bhns-gw230529-dense".into(),
            summary: Some("BHNS merger with dense 2D output".into()),
            description: None,
            authors: vec!["Max Morris".into()],
            license: None,
            cactarium: None,
            root: "Cactus".into(),
        },
        thornlist: ThornlistText { filename: "bhns.th".into(), text: thornlist.into(), untracked: vec![] },
        parfile: Parfile {
            filename: "bhns.par".into(),
            kind: ParfileKind::Par,
            vars: vec![],
            text: par.into(),
        },
        inputs: vec![],
        repos: vec![RepoPin {
            name: "carpetx".into(),
            url: "https://github.com/max-morris/CarpetX.git".into(),
            git_ref: Some("mixed-precision".into()),
            commit: Some(SHA.into()),
            sha256: None,
            cactarium: Some("max-morris/carpetx@mixed-precision:1.4.0".parse().unwrap()),
            dirty: false,
        }],
        run: None,
        provenance: None,
    }
}

/// Text that stresses TOML string encoding: literal-string delimiters, basic-string delimiters,
/// backslashes, CRLF, lone CR, tabs, trailing spaces, non-ASCII, control chars, no final newline.
const NASTY: &[&str] = &[
    "ActiveThorns = \"CarpetX\"\n",
    "a = '''x'''\nb = \"\"\"y\"\"\"\n",
    "path = \"C:\\\\x\\n\" # \\ backslash\n",
    "line1\r\nline2\r\n",
    "lone\rcr\n",
    "\ttabbed  \ntrailing   \n",
    "Ψ₄ extracted at r = 500 M — “quotes”\n",
    "bell\u{7}and\u{1b}esc\n",
    "no final newline",
    "",
    "\n\n\nleading newlines",
];

#[test]
fn verbatim_text_round_trips_byte_for_byte() {
    for (i, t) in NASTY.iter().enumerate() {
        let sim = sample(t, t);
        let out = sim.to_toml().unwrap();
        let back = SimFile::from_toml(&out).unwrap_or_else(|e| panic!("case {i}: {e}\n{out}"));
        assert_eq!(back.thornlist.text.as_bytes(), t.as_bytes(), "thornlist case {i}");
        assert_eq!(back.parfile.text.as_bytes(), t.as_bytes(), "parfile case {i}");
        assert_eq!(back, sim, "case {i}");
    }
}

#[test]
fn hand_written_file_parses() {
    let text = format!(
        r#"
format = 1

[sim]
name = "qc0-bbh"
root = "Cactus"

[thornlist]
filename = "qc0.th"
text = '''
!CRL_VERSION = 1.0
!DEFINE ROOT = Cactus
'''

[parfile]
filename = "qc0.par"
kind = "par"
vars = ["WALLTIME_HOURS"]
text = '''
ActiveThorns = "Carpet"
'''

[[input]]
knob = "kadath-initial-data"
description = "FUKA initial data"

[[repo]]
name = "flesh"
url = "https://bitbucket.org/cactuscode/cactus.git"
ref = "ET_2026_05"
commit = "{SHA}"

[run]
tasks = 256
cpus-per-task = 8
walltime = "48:00:00"

[provenance]
machine = "qbd"
exported-at = 2026-11-05T22:00:00Z
"#
    );
    let sim = SimFile::from_toml(&text).unwrap();
    assert!(sim.is_fully_specified());
    assert_eq!(sim.inputs[0].knob, "kadath-initial-data");
    assert_eq!(sim.run.unwrap().cpus_per_task, Some(8));
}

#[test]
fn unknown_keys_are_rejected() {
    let mut out = sample("x\n", "y\n").to_toml().unwrap();
    out = out.replacen("[sim]\n", "[sim]\nflavour = \"intel\"\n", 1);
    assert!(matches!(SimFile::from_toml(&out), Err(Error::Toml { .. })));
}

#[test]
fn newer_format_asks_for_an_upgrade() {
    let out = sample("x\n", "y\n").to_toml().unwrap().replacen("format = 1", "format = 2", 1);
    let err = SimFile::from_toml(&out).unwrap_err();
    assert!(matches!(err, Error::NewerFormat { found: 2, supported: 1, .. }), "{err}");
    assert!(err.to_string().contains("upgrade"));
}

#[test]
fn missing_format_is_reported() {
    let out = sample("x\n", "y\n").to_toml().unwrap().replacen("format = 1\n", "", 1);
    assert!(matches!(SimFile::from_toml(&out), Err(Error::MissingFormat { .. })));
}

#[test]
fn fully_specified_rules() {
    let mut sim = sample("x\n", "y\n");
    assert!(sim.is_fully_specified());

    sim.repos[0].commit = None;
    sim.repos[0].dirty = true;
    sim.thornlist.untracked.push("LocalThorns/Boost".into());
    let problems = sim.unspecified();
    assert_eq!(
        problems,
        vec![
            Unspecified::Unpinned { repo: "carpetx".into() },
            Unspecified::Dirty { repo: "carpetx".into() },
            Unspecified::Untracked { thorn: "LocalThorns/Boost".into() },
        ]
    );
    // Unpinned files are still valid .sim files; they just can't be published.
    SimFile::from_toml(&sim.to_toml().unwrap()).unwrap();
}

#[test]
fn structural_errors() {
    let mut sim = sample("x\n", "y\n");
    sim.repos[0].commit = Some("3f2c9e1".into());
    assert!(sim.to_toml().is_err(), "abbreviated commit");

    let mut sim = sample("x\n", "y\n");
    sim.repos.push(sim.repos[0].clone());
    assert!(sim.to_toml().is_err(), "duplicate repo");

    let mut sim = sample("x\n", "y\n");
    sim.parfile.kind = ParfileKind::Py;
    assert!(sim.to_toml().is_err(), "kind/extension mismatch");

    let mut sim = sample("x\n", "y\n");
    sim.thornlist.filename = "../etc/passwd".into();
    assert!(sim.to_toml().is_err(), "path in filename");
}

/// Round-trips Max's real pretty-bhns thornlist and parfile when they are present.
#[test]
fn real_pretty_bhns_files_round_trip() {
    let Some(home) = std::env::var_os("HOME") else { return };
    let dir = std::path::Path::new(&home).join("src/pretty-bhns/parfiles");
    let (Ok(th), Ok(par)) = (
        std::fs::read_to_string(dir.join("bhns.th")),
        std::fs::read_to_string(dir.join("bhns_gw230529_dense_output.par")),
    ) else {
        eprintln!("skipping: pretty-bhns not found");
        return;
    };
    let sim = sample(&th, &par);
    let back = SimFile::from_toml(&sim.to_toml().unwrap()).unwrap();
    assert_eq!(back.thornlist.text, th);
    assert_eq!(back.parfile.text, par);
}
