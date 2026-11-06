#!/usr/bin/env bash
# Builds demo git repos under deploy/demo/repos (mounted in the dev container at /repos) and
# registers them, so the local site shows every kind of entry. Safe to rerun after `just dev-reset`.
set -euo pipefail
cd "$(dirname "$0")"
DEMO=$PWD/demo
REPOS=$DEMO/repos
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
  mkdir -p "$1"
  printf '# Interface definition for thorn %s\nIMPLEMENTS: %s\nINHERITS: grid\n' "$(basename "$1")" "$2" > "$1/interface.ccl"
  printf '# Parameter definitions\n' > "$1/param.ccl"
  printf '# Schedule definitions\n' > "$1/schedule.ccl"
  [ -n "${3:-}" ] && printf '%s\n' "$3" > "$1/configuration.ccl"
  return 0
}

echo "Building demo repos in $REPOS"

# The flesh: an unregistered source every stack uses.
new_repo cactus
mkdir -p "$WORK/cactus/src" "$WORK/cactus/lib"
echo 'all:' > "$WORK/cactus/Makefile"; echo 'int main(void) { return 0; }' > "$WORK/cactus/src/main.c"; echo '# flesh libs' > "$WORK/cactus/lib/README"
commit cactus "The flesh"; publish cactus

# CactusBase: another unregistered source.
new_repo cactusbase
thorn "$WORK/cactusbase/IOUtil" IO
thorn "$WORK/cactusbase/Boundary" boundary
commit cactusbase "CactusBase"; publish cactusbase

# CarpetX: a package with a default track and a mixed-precision track.
new_repo carpetx
R=$WORK/carpetx
thorn "$R/CarpetX" driver $'REQUIRES AMReX MPI yaml_cpp zlib\nREQUIRES THORNS: Arith Loop\nOPTIONAL ADIOS2 Silo\n{\n}'
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
target = "einsteintoolkit/carpetx"
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
target = "einsteintoolkit/carpetx"

[[depends-on]]
target = "et/et"
range = "^2026"
note = "the flesh and CactusBase from this stack"

[[incompatible-with]]
target = "et/et"
range = "<2026"

[[caveat]]
thorn = "TestReal4"
note = "needs a compiler with _Float16 for the REAL2 half (GCC 12 or newer)"
EOF
commit "$R" "Mixed precision"; g "$R" tag mixed-precision/v1.0.0
g "$R" checkout master
publish carpetx

# The ET stack: a flat stack in a manifest repo, by user "et".
new_repo et-stack
R=$WORK/et-stack
cat > "$R/et.th" <<'EOF'
# A tiny stand-in for the Einstein Toolkit's component list.
!CRL_VERSION = 1.0

!DEFINE ROOT = Cactus
!DEFINE ARR  = $ROOT/arrangements

# Cactus Flesh
!TARGET   = $ROOT
!TYPE     = git
!URL      = file:///repos/cactus.git
!NAME     = flesh
!CHECKOUT = Makefile lib src

# CactusBase thorns
!TARGET   = $ARR
!TYPE     = git
!URL      = file:///repos/cactusbase.git
!REPO_PATH= $2
!CHECKOUT =
CactusBase/Boundary
CactusBase/IOUtil

# CarpetX thorns
!TARGET   = $ARR
!TYPE     = git
!URL      = file:///repos/carpetx.git
!REPO_PATH= $2
!CHECKOUT =
CarpetX/Arith
CarpetX/CarpetX
CarpetX/Loop
#DISABLED CarpetX/TestReal4
EOF
cat > "$R/cactarium-stack.toml" <<'EOF'
format = 1

[stack]
name = "et"
owners = ["et"]
description = "The Einstein Toolkit's component list (a demo stand-in), one stack among many"
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
extends = ["et/et@2026.5.0"]
enable = ["CarpetX/TestReal4"]

[[stack.override]]
repo = "carpetx"
package = "max/carpetx@mixed-precision:^1"

[[incompatible-with]]
target = "et/et"
note = "use one or the other"
EOF
commit "$R" "carpetx-mp 1.0.0"; g "$R" tag v1.0.0; publish carpetx-mp

# A package from a new user, left pending for review.
new_repo spacetimex
R=$WORK/spacetimex
thorn "$R/Z4c" Z4c 'REQUIRES THORNS: Loop'
thorn "$R/NewRadX" NewRadX ''
printf '# SpacetimeX\n\nZ4c evolution on CarpetX.\n' > "$R/README.md"
printf 'format = 1\n\n[package]\nname = "spacetimex"\nowners = ["alice"]\ndescription = "Spacetime evolution thorns for CarpetX"\narrangement = "SpacetimeX"\n' > "$R/cactarium.toml"
commit "$R" "SpacetimeX"; g "$R" tag v0.1.0; publish spacetimex

echo "Registering on the local site"
cli migrate >/dev/null
for u in max et alice; do cli dev-user "$u"; done
cli admin trust et
cli register et file:///repos/et-stack.git
cli register max file:///repos/carpetx.git
cli register max file:///repos/carpetx-mp.git
cli register alice file:///repos/spacetimex.git

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
url = "file:///repos/cactus.git"
ref = "master"
commit = "$(c cactus master)"

[[repo]]
name = "cactusbase"
url = "file:///repos/cactusbase.git"
ref = "master"
commit = "$(c cactusbase master)"

[[repo]]
name = "carpetx"
url = "file:///repos/carpetx.git"
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
base = "et/et@2026.5.0"
EOF
cli publish-sim max /demo/qc0.sim

# Move a frozen tag upstream: the site keeps serving the frozen commit and raises an alert.
R=$WORK/carpetx
g "$R" checkout master
echo "rewritten history" >> "$R/README.md"; commit "$R" "Rewrite"
g "$R" tag -f v1.0.0
git -C "$R" push -q --force "$REPOS/carpetx.git" refs/tags/v1.0.0
cli sync max/carpetx

echo
echo "Done. Sign in at http://localhost:8000/auth/login as max (superadmin), et (trusted) or alice."
