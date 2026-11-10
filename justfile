# The Cactarium. `just` lists the recipes.
set shell := ["bash", "-euo", "pipefail", "-c"]

compose := "docker compose --project-directory deploy -f deploy/compose.yaml"
devc := compose + " -f deploy/compose.dev.yaml"

default:
    @just --list

# Local development: build and start at http://localhost:8000 with dev sign-in
dev:
    test -f deploy/.env || just _dev-env
    grep -q '^DEMO_REPOS=' deploy/.env || echo "DEMO_REPOS=$PWD/deploy/demo/repos" >> deploy/.env
    mkdir -p deploy/demo/repos deploy/demo/files
    {{devc}} up -d --build
    @echo "The Cactarium is at http://localhost:$(grep -E '^PORT=' deploy/.env | cut -d= -f2 || echo 8000)"

# Fill the local site with demo repos, stacks, a sim, a pending review and a moved tag
dev-seed:
    deploy/dev-seed.sh

# Stop the local site and delete its database and demo repos
dev-reset:
    {{devc}} down --volumes
    rm -rf deploy/demo

# Follow the app's log
logs:
    {{compose}} logs -f app

# Show the containers
status:
    {{compose}} ps

# Stop everything (data is kept)
down:
    {{compose}} down

# Production, once per VM: deploy/.env, docker group, Apache proxy, nightly backups
setup:
    sh deploy/setup.sh

# Production: build and (re)start, applying migrations
up:
    test -f deploy/.env || { echo "deploy/.env is missing: run just setup"; exit 1; }
    {{compose}} build app
    {{compose}} up -d db
    {{compose}} run --rm app migrate
    {{compose}} up -d
    {{compose}} ps

# Production, once per VM, over SSH through the bastion: ufw allowing only 80, 443 and SSH from it
firewall:
    sh deploy/setup.sh firewall

# Production: back up, pull, rebuild, migrate, restart (data kept; seconds of downtime)
update:
    just backup
    git pull --ff-only
    {{compose}} build app
    {{compose}} run --rm app migrate
    {{compose}} up -d
    {{compose}} ps

# Run the server's command line inside the app container, e.g. `just cli admin list`
cli *args:
    {{compose}} exec app cactarium {{args}}

# Make a user an admin (only the superadmin can do this on the site)
admin-grant user:
    {{compose}} exec app cactarium admin grant {{user}}

# Dump the database to deploy/backups/
backup:
    mkdir -p deploy/backups
    {{compose}} exec -T db pg_dump -U cactarium -d cactarium --format=custom > deploy/backups/cactarium-$(date +%Y%m%d-%H%M%S).dump
    @ls -lh deploy/backups | tail -1

# Unit tests
test:
    cargo test

# End to end: reset the local site, seed it, and exercise every page and action
smoke:
    just dev-reset
    just dev
    just dev-seed
    deploy/smoke.py

_dev-env:
    printf 'POSTGRES_PASSWORD=%s\nCACTARIUM_BASE_URL=http://localhost:8000\nCACTARIUM_SUPERADMIN=dev:max\nBIND=127.0.0.1\nPORT=8000\n' "$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')" > deploy/.env
    @echo "Wrote deploy/.env for local development"
