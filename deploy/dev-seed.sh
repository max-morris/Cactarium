#!/usr/bin/env bash
# Builds demo git repos under deploy/demo/repos (mounted in the dev container at /repos) and
# registers them, so the local site shows every kind of entry. Safe to rerun after `just dev-reset`.
set -euo pipefail
cd "$(dirname "$0")"
DEMO=$PWD/demo
REPOS=$DEMO/repos
U=file://$REPOS   # the same path inside the container (see compose.dev.yaml)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$REPOS" "$DEMO/files"
cli() { docker compose --project-directory . -f compose.yaml -f compose.dev.yaml exec -T app cactarium "$@"; }

export GIT_AUTHOR_NAME="Demo" GIT_AUTHOR_EMAIL="demo@example.invalid"
export GIT_COMMITTER_NAME="Demo" GIT_COMMITTER_EMAIL="demo@example.invalid"
# A repo by name (under $WORK) or by path.
at() { case "$1" in /*) echo "$1" ;; *) echo "$WORK/$1" ;; esac; }
g() { git -C "$(at "$1")" "${@:2}" >/dev/null; }

# new_repo NAME: a working tree in $WORK/NAME on branch master
new_repo() { rm -rf "$WORK/$1" "$REPOS/$1.git"; mkdir -p "$WORK/$1"; git -C "$WORK/$1" init -q -b master; }
# publish NAME: push every branch and tag to the bare repo the container reads
publish() { git clone -q --bare "$(at "$1")" "$REPOS/$(basename "$1").git"; }
commit() { g "$1" add -A; g "$1" commit -m "$2"; }

thorn() { # thorn DIR IMPLEMENTS [configuration.ccl text]
  # Demo thorns require only what the demo packages provide, so every published version passes
  # the dependency check (each hard CCL requirement is met by its package or a dependency's needs).
  mkdir -p "$1"
  printf '# Interface definition for thorn %s\nIMPLEMENTS: %s\n' "$(basename "$1")" "$2" > "$1/interface.ccl"
  printf '# Parameter definitions\n' > "$1/param.ccl"
  printf '# Schedule definitions\n' > "$1/schedule.ccl"
  [ -n "${3:-}" ] && printf '%s\n' "$3" > "$1/configuration.ccl"
  return 0
}

echo "Building demo repos in $REPOS"

# The flesh, published as a flesh package (et/cactus): a sim's every pin must be a registered
# package's, the flesh included.
new_repo cactus
mkdir -p "$WORK/cactus/src/main" "$WORK/cactus/lib/sbin"
echo 'all:' > "$WORK/cactus/Makefile"; echo 'int main(void) { return 0; }' > "$WORK/cactus/src/main/flesh.cc"; echo '# CST' > "$WORK/cactus/lib/sbin/CST"
printf 'format = 1\n\n[package]\nname = "cactus"\nowners = ["et"]\ndescription = "The Cactus flesh (a demo stand-in)"\nflesh = true\n' > "$WORK/cactus/cactarium.toml"
commit cactus "The flesh"; g cactus tag v1.0.0; publish cactus

# CactusBase: another unregistered source.
new_repo cactusbase
thorn "$WORK/cactusbase/IOUtil" IO
thorn "$WORK/cactusbase/Boundary" boundary
commit cactusbase "CactusBase"; publish cactusbase

# CarpetX: a package with a default track and a mixed-precision track.
new_repo carpetx
R=$WORK/carpetx
thorn "$R/CarpetX" driver $'REQUIRES THORNS: Arith Loop\nOPTIONAL AMReX MPI yaml_cpp zlib ADIOS2 Silo\n{\n}'
thorn "$R/Loop" Loop 'REQUIRES THORNS: Arith'
thorn "$R/Arith" Arith 'OPTIONAL NSIMD yaml_cpp'
cat > "$R/README.md" <<'EOF'
# CarpetX

CarpetX is a Cactus driver built on [AMReX](https://amrex-codes.github.io/). This demo package
mirrors its layout: the thorns sit at the repo root, as in the Einstein Toolkit's CarpetX repo.

- `CarpetX`: the driver
- `Loop`: loop macros over grid points
- `Arith`: SIMD-friendly arithmetic
EOF
cat > "$R/cactarium.toml" <<'EOF'
format = 1

[package]
name = "carpetx"
owners = ["max"]
description = "CarpetX, the AMReX-based driver, with mixed-precision grid functions on its own track"
license = "LGPL-2.1-or-later"
arrangement = "CarpetX"

[[fork-of]]
target = "et/carpetx"
EOF
commit "$R" "CarpetX 1.0.0"; g "$R" tag v1.0.0
echo "Faster regridding." >> "$R/README.md"; commit "$R" "CarpetX 1.1.0"; g "$R" tag v1.1.0
g "$R" checkout -b mixed-precision
thorn "$R/TestReal4" TestReal4 'REQUIRES THORNS: CarpetX'
cat > "$R/cactarium.toml" <<'EOF'
format = 1

[package]
name = "carpetx"
owners = ["max"]
description = "CarpetX, the AMReX-based driver, with mixed-precision grid functions on its own track"
license = "LGPL-2.1-or-later"
arrangement = "CarpetX"
default-track = "mixed-precision"

[tracks.mixed-precision]
description = "CCTK_REAL4 and CCTK_REAL2 grid functions; needs a mixed-precision flesh"

[[fork-of]]
target = "et/carpetx"

[[works-with]]
target = "et/et-stack@^2026"
note = "the flesh and CactusBase from this stack"

[[incompatible-with]]
target = "et/et-stack@<2026"

[[caveat]]
thorn = "TestReal4"
note = "needs a compiler with _Float16 for the REAL2 half (GCC 12 or newer)"
EOF
commit "$R" "Mixed precision"; g "$R" tag mixed-precision/v1.0.0
g "$R" checkout master
publish carpetx

# Upstream CarpetX, published by an admin in the et namespace (its own authors haven't).
new_repo carpetx-et
R=$WORK/carpetx-et
thorn "$R/CarpetX" driver $'REQUIRES THORNS: Arith Loop\nOPTIONAL AMReX MPI yaml_cpp zlib\n{\n}'
thorn "$R/Loop" Loop 'REQUIRES THORNS: Arith'
thorn "$R/Arith" Arith ''
printf '# CarpetX\n\nThe Einstein Toolkit AMReX-based driver (a demo stand-in).\n' > "$R/README.md"
cat > "$R/cactarium.toml" <<'EOF'
format = 1

[package]
name = "carpetx"
owners = ["et"]
description = "The Einstein Toolkit's AMReX-based driver"
license = "LGPL-2.1-or-later"
arrangement = "CarpetX"
contact = "https://bitbucket.org/einsteintoolkit/tickets/issues"
EOF
commit "$R" "CarpetX 1.0.0"; g "$R" tag v1.0.0; publish carpetx-et

# The ET stack: a flat stack in a manifest repo, published by an admin in the et namespace.
new_repo et-stack
R=$WORK/et-stack
cat > "$R/et.th" <<EOF
# A tiny stand-in for the Einstein Toolkit's component list.
!CRL_VERSION = 1.0

!DEFINE ROOT = Cactus
!DEFINE ARR  = \$ROOT/arrangements

# Cactus Flesh
!TARGET   = \$ROOT
!TYPE     = git
!URL      = $U/cactus.git
!NAME     = flesh
!CHECKOUT = Makefile lib src

# CactusBase thorns
!TARGET   = \$ARR
!TYPE     = git
!URL      = $U/cactusbase.git
!REPO_PATH= \$2
!CHECKOUT =
CactusBase/Boundary
CactusBase/IOUtil

# CarpetX thorns
!TARGET   = \$ARR
!TYPE     = git
!URL      = $U/carpetx.git
!REPO_PATH= \$2
!CHECKOUT =
CarpetX/Arith
CarpetX/CarpetX
CarpetX/Loop
#DISABLED CarpetX/TestReal4
EOF
cat > "$R/cactarium-stack.toml" <<'EOF'
format = 1

[stack]
name = "et-stack"
owners = ["et"]
description = "The Einstein Toolkit's component list (a demo stand-in), one stack among many"
contact = "https://bitbucket.org/einsteintoolkit/tickets/issues"
thornlist = "et.th"
EOF
commit "$R" "ET 2026.5"; g "$R" tag v2026.5.0; publish et-stack

# CarpetX mixed precision: a recipe stack on top of the ET stack, by "max".
new_repo carpetx-mp
R=$WORK/carpetx-mp
cat > "$R/cactarium-stack.toml" <<'EOF'
format = 1

[stack]
name = "carpetx-mp"
owners = ["max"]
description = "The ET stack with CarpetX switched to its mixed-precision track"
extends = ["et/et-stack@2026.5.0"]
enable = ["CarpetX/TestReal4"]

[[stack.override]]
repo = "carpetx"
package = "max/carpetx@mixed-precision:^1"

[[incompatible-with]]
target = "et/et-stack"
note = "use one or the other"
EOF
commit "$R" "carpetx-mp 1.0.0"; g "$R" tag v1.0.0; publish carpetx-mp

# A package from a new user, left pending for review.
new_repo spacetimex
R=$WORK/spacetimex
thorn "$R/Z4c" Z4c 'REQUIRES THORNS: Loop'
thorn "$R/NewRadX" NewRadX ''
printf '# SpacetimeX\n\nZ4c evolution on CarpetX.\n' > "$R/README.md"
printf 'format = 1\n\n[package]\nname = "spacetimex"\nowners = ["alice"]\ndescription = "Spacetime evolution thorns for CarpetX"\narrangement = "SpacetimeX"\n\n[[dependency]]\ntarget = "et/carpetx"\nneeds = ["Loop"]\nneeded-by = ["Z4c"]\n' > "$R/cactarium.toml"
commit "$R" "SpacetimeX"; g "$R" tag v0.1.0; publish spacetimex

echo "Registering on the local site"
cli migrate >/dev/null
for u in max alice bob; do cli dev-user "$u"; done
# The Einstein Toolkit's organization; its members publish under et/ and manage its entries.
cli org create et max --display-name "Einstein Toolkit" 2>/dev/null || echo "Organization et exists"
cli register max $U/carpetx-et.git --owner et
cli register max $U/et-stack.git --owner et
cli register max $U/carpetx.git
cli register max $U/carpetx-mp.git
cli register alice $U/spacetimex.git

# A fully specified sim, pinned to today's demo commits.
c() { git --git-dir="$REPOS/$1.git" rev-parse "$2"; }
cat > "$DEMO/files/qc0.sim" <<EOF
format = 1

[sim]
name = "qc0-demo"
summary = "A demo binary black hole run on the ET stack"
description = "Built by the dev seed: every repo is pinned, and the initial data comes through an input."
authors = ["Demo"]
license = "CC-BY-4.0"
root = "Cactus"

[thornlist]
filename = "qc0.th"
text = '''
$(cat "$WORK/et-stack/et.th")
'''

[parfile]
filename = "qc0.par"
kind = "par"
vars = ["WALLTIME_HOURS"]
text = '''
# QC-0, low resolution (demo)
ActiveThorns = "CarpetX Loop Arith IOUtil Boundary"
Cactus::cctk_final_time = 100
IO::out_dir = \$parfile
TerminationTrigger::max_walltime = @WALLTIME_HOURS@
TwoPunctures::filename = "@KNOB(initial-data)@"
'''

[[input]]
knob = "initial-data"
description = "Initial data for the black holes"

[[repo]]
name = "flesh"
url = "$U/cactus.git"
ref = "master"
commit = "$(c cactus master)"

[[repo]]
name = "cactusbase"
url = "$U/cactusbase.git"
ref = "master"
commit = "$(c cactusbase master)"

[[repo]]
name = "carpetx"
url = "$U/carpetx.git"
ref = "master"
commit = "$(c carpetx master)"

[run]
tasks = 32
cpus-per-task = 8
walltime = "24:00:00"

[provenance]
exported-by = "dev-seed"
machine = "qbd"
flavor = "cpu"
base = "et/et-stack@2026.5.0"
EOF
# The sim pins the flesh, CactusBase and CarpetX: each must be a registered package's repo.
cli register max $U/cactus.git --owner et
mkdir -p "$DEMO/files/curate/manifests"
printf '[[package]]\nowner = "et"\nurl = "%s"\nmanifest = "manifests/cactusbase.toml"\n' "$U/cactusbase.git" > "$DEMO/files/curate/curate.toml"
printf 'format = 1\n\n[package]\nname = "cactusbase"\nowners = ["et"]\ndescription = "CactusBase (a demo stand-in)"\narrangement = "CactusBase"\n' > "$DEMO/files/curate/manifests/cactusbase.toml"
cli curate max /demo/curate/curate.toml
cli publish-sim max /demo/qc0.sim

# A repo carrying a package and a multi-sim entry (Cottonmouth's shape): the package releases with
# vX.Y.Z tags; its example sims, listed in [sim.files], with their own sim-vX.Y.Z tags (a
# tag-pattern, never sim/v..., which reads as a track). The sims manifest lives on a branch, not on
# master, so it is registered from its tag: `register --tag`, which adds only the missing entry.
new_repo bbh-demo
R=$WORK/bbh-demo
thorn "$R/BBHDemo" BBHDemo ''
printf 'format = 1\n\n[package]\nname = "bbh-demo"\nowners = ["max"]\ndescription = "A demo package that ships its own example sims"\narrangement = "BBHDemoArr"\n' > "$R/cactarium.toml"
commit "$R" "bbh-demo 1.0.0"; g "$R" tag v1.0.0
PKG=$(git -C "$R" rev-parse HEAD)
g "$R" checkout -b sims
mkdir -p "$R/examples/sims"
demo_sim() { # demo_sim NAME SUMMARY: a fully specified .sim building the package's thorn
  local q="'''"
  printf '%s\n' "format = 1" "" "[sim]" "name = \"$1\"" "summary = \"$2\"" "license = \"CC0-1.0\"" "root = \"Cactus\"" "" \
    "[thornlist]" "filename = \"$1.th\"" "text = $q" "!CRL_VERSION = 1.0" "!DEFINE ROOT = Cactus" \
    "!TARGET = \$ROOT/arrangements" "!TYPE = git" "!URL = $U/bbh-demo.git" "!REPO_PATH = \$2" "!CHECKOUT =" \
    "BBHDemoArr/BBHDemo" "$q" "" "[parfile]" "filename = \"$1.par\"" "kind = \"par\"" "text = $q" \
    "ActiveThorns = \"BBHDemo\"" "$q" "" "[[repo]]" "name = \"bbh-demo\"" "url = \"$U/bbh-demo.git\"" "commit = \"$PKG\""
}
demo_sim qc0 "Head-on QC-0, low resolution" > "$R/examples/sims/qc0.sim"
demo_sim tov "A single TOV star" > "$R/examples/sims/tov.sim"
cat > "$R/cactarium-sim.toml" <<'TOML'
format = 2

[sim]
name = "bbh-demo-sims"
owners = ["max"]
description = "bbh-demo's example simulations, released together with sim-vX.Y.Z tags."
tag-pattern = "sim-v{major}.{minor}.{patch}"

[sim.files]
qc0 = "examples/sims/qc0.sim"
tov = "examples/sims/tov.sim"
TOML
commit "$R" "Example sims"; g "$R" tag sim-v1.0.0
g "$R" checkout master
publish bbh-demo
cli register max $U/bbh-demo.git
cli register max $U/bbh-demo.git --tag sim-v1.0.0

# Move a frozen tag upstream: the site keeps serving the frozen commit and raises an alert.
R=$WORK/carpetx
g "$R" checkout master
echo "rewritten history" >> "$R/README.md"; commit "$R" "Rewrite"
g "$R" tag -f v1.0.0
git -C "$R" push -q --force "$REPOS/carpetx.git" refs/tags/v1.0.0
cli sync max/carpetx

echo
echo "Done. Sign in at http://localhost:8000/auth/login as max (superadmin, owner of et), alice or bob."
