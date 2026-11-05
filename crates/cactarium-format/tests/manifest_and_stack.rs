use cactarium_format::manifest::Manifest;
use cactarium_format::stack::FrozenStack;
use cactarium_format::Error;

const PACKAGE: &str = r#"
format = 1

[package]
name = "carpetx"
owners = ["max-morris"]
description = "CarpetX with mixed-precision grid functions"
license = "LGPL-2.1-or-later"
default-track = "mixed-precision"

[tracks.mixed-precision]
description = "CCTK_REAL4/REAL2 storage; needs a mixed-precision flesh"

[[fork-of]]
target = "einsteintoolkit/carpetx"

[[depends-on]]
target = "max-morris/cactus"
range = "mixed-precision:^1"

[[works-with]]
target = "max-morris/carpetx-mp"
range = "^1"

[[incompatible-with]]
target = "einsteintoolkit/et"
range = "*"
note = "needs the mixed-precision flesh"

[[caveat]]
thorn = "TestReal2"
note = "needs _Float16 (GCC >= 12)"
"#;

#[test]
fn package_manifest_parses_and_round_trips() {
    let m = Manifest::from_toml(PACKAGE).unwrap();
    let p = m.package.as_ref().unwrap();
    assert_eq!(p.owners[0].as_str(), "max-morris");
    let dep = &m.depends_on[0];
    assert!(dep.range.as_ref().unwrap().matches(&"mixed-precision:1.3.0".parse().unwrap()));
    assert_eq!(Manifest::from_toml(&m.to_toml().unwrap()).unwrap(), m);
}

/// The carpetx-mp-forks case: ET with nine repos redirected to forks, two thorns added.
const RECIPE: &str = r#"
format = 1

[stack]
name = "carpetx-mp-forks"
extends = ["einsteintoolkit/et@2026.5.0"]
enable = ["CarpetX/TestReal4", "CarpetX/TestReal2"]

[[stack.override]]
repo = "flesh"
url = "https://github.com/max-morris/Cactus.git"
ref = "mixed-precision"

[[stack.override]]
repo = "CarpetX"
package = "max-morris/carpetx@mixed-precision:^1"

[[stack.override]]
repo = "ExternalLibraries-AMReX"
url = "https://github.com/max-morris/ExternalLibraries-AMReX.git"
ref = "mpi-cmake-hints"

[[incompatible-with]]
target = "einsteintoolkit/et"
note = "the mixed-precision flesh changes generated bindings"
"#;

/// A standard CarpetX stack: just a thornlist, no recipe.
const FLAT: &str = r#"
format = 1

[stack]
name = "carpetx"
description = "CarpetX driver, AsterX, Z4c and their external libraries"
thornlist = "carpetx.th"
"#;

/// Both: the cottonmouth union, with extra sections from a thornlist on top of two bases.
const BOTH: &str = r#"
format = 1

[stack]
name = "carpetx-mp-cottonmouth"
extends = ["max-morris/carpetx-mp-forks@1.0.0", "rhaas/cottonmouth@2.1.0"]
thornlist = "asterx-additions.th"
enable = ["ExternalLibraries/PAPI"]
"#;

#[test]
fn every_stack_shape_parses() {
    let recipe = Manifest::from_toml(RECIPE).unwrap().stack.unwrap();
    assert!(!recipe.is_flat());
    assert_eq!(recipe.overrides.len(), 3);
    let flat = Manifest::from_toml(FLAT).unwrap().stack.unwrap();
    assert!(flat.is_flat());
    let both = Manifest::from_toml(BOTH).unwrap().stack.unwrap();
    assert_eq!(both.extends.len(), 2);
    assert!(both.thornlist.is_some());
}

fn invalid(text: &str) -> String {
    match Manifest::from_toml(text) {
        Err(Error::Invalid(msg)) => msg,
        other => panic!("expected a validation error, got {other:?}"),
    }
}

#[test]
fn stack_validation() {
    let empty = "format = 1\n[stack]\nname = \"x\"\n";
    assert!(invalid(empty).contains("needs a thornlist, extends, or both"));

    let unversioned_base = "format = 1\n[stack]\nname = \"x\"\nextends = [\"a/b\"]\n";
    assert!(invalid(unversioned_base).contains("exact release"));
    let ranged_base = "format = 1\n[stack]\nname = \"x\"\nextends = [\"a/b@^1\"]\n";
    assert!(invalid(ranged_base).contains("exact release"));

    let overrides_flat = "format = 1\n[stack]\nname = \"x\"\nthornlist = \"x.th\"\n\
                          [[stack.override]]\nrepo = \"r\"\nref = \"b\"\n";
    assert!(invalid(overrides_flat).contains("extends nothing"));

    let both_ways = "format = 1\n[stack]\nname = \"x\"\nextends = [\"a/b@1.0.0\"]\n\
                     [[stack.override]]\nrepo = \"r\"\nref = \"b\"\npackage = \"a/c@^1\"\n";
    assert!(invalid(both_ways).contains("both a package and url/ref"));

    let clash = "format = 1\n[stack]\nname = \"x\"\nthornlist = \"x.th\"\n\
                 enable = [\"A/B\"]\ndisable = [\"A/B\"]\n";
    assert!(invalid(clash).contains("both enabled and disabled"));
}

#[test]
fn manifest_validation() {
    let neither = "format = 1\n";
    assert!(invalid(neither).contains("[package] or a [stack]"));

    let versioned_target = PACKAGE.replace("target = \"max-morris/carpetx-mp\"", "target = \"max-morris/carpetx-mp@1.0.0\"");
    assert!(invalid(&versioned_target).contains("just owner/name"));

    let no_owners = "format = 1\n[package]\nname = \"x\"\nowners = []\n";
    assert!(invalid(no_owners).contains("owners is empty"));
}

#[test]
fn frozen_stack_requires_every_pin() {
    let text = r#"
format = 1
stack = "max-morris/carpetx-mp-forks@1.0.0"
root = "Cactus"

[thornlist]
filename = "carpetx-mp-forks.th"
text = "!CRL_VERSION = 1.0\n"

[[repo]]
name = "flesh"
url = "https://github.com/max-morris/Cactus.git"
ref = "mixed-precision"
commit = "3f2c9e1a00112233445566778899aabbccddeeff"

[[repo]]
name = "CarpetX"
url = "https://github.com/max-morris/CarpetX.git"
"#;
    let frozen: FrozenStack = toml::from_str(text).unwrap();
    assert!(frozen.validate().unwrap_err().to_string().contains("'CarpetX' is not pinned"));
}

/// A flat stack whose definition pins some repos and lets the rest follow their branches.
#[test]
fn flat_stack_with_partial_pins() {
    let text = r#"
format = 1

[stack]
name = "carpetx"
thornlist = "carpetx.th"

[[stack.pin]]
name = "AsterX"
url = "https://github.com/jaykalinani/AsterX.git"
ref = "main"
commit = "3f2c9e1a00112233445566778899aabbccddeeff"
"#;
    let s = Manifest::from_toml(text).unwrap().stack.unwrap();
    assert!(s.is_flat());
    assert_eq!(s.pins.len(), 1);

    let unpinned = text.replace("commit = \"3f2c9e1a00112233445566778899aabbccddeeff\"\n", "");
    assert!(invalid(&unpinned).contains("needs a commit or sha256"));
}

#[test]
fn head_is_never_a_base() {
    let text = "format = 1\n[stack]\nname = \"x\"\nextends = [\"a/b@head\"]\n";
    assert!(invalid(text).contains("exact release"));
}

#[test]
fn manifest_repo_file_names_fix_the_kind() {
    use cactarium_format::manifest::{PACKAGE_FILE, STACK_FILE};
    // A manifest repo holding only the curated CarpetX stack.
    let stack = "format = 1\n[stack]\nname = \"carpetx\"\nowners = [\"cactarium\"]\nthornlist = \"carpetx.th\"\n";
    Manifest::from_repo_file(STACK_FILE, stack).unwrap();
    assert!(Manifest::from_repo_file(PACKAGE_FILE, stack).is_err());
    assert!(Manifest::from_repo_file(STACK_FILE, PACKAGE).is_err());
    Manifest::from_repo_file(PACKAGE_FILE, PACKAGE).unwrap();

    let ownerless = stack.replace("owners = [\"cactarium\"]\n", "");
    let err = Manifest::from_repo_file(STACK_FILE, &ownerless).unwrap_err();
    assert!(err.to_string().contains("needs owners"));
    assert!(Manifest::from_repo_file("stack.toml", stack).is_err());
}
