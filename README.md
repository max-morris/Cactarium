# The Cactarium

A registry for the Cactup ecosystem: **packages** of Cactus thorns (published from the authors'
own git repos, versioned by tags), **stacks** (versioned thornlists whose releases pin every repo),
and **sim files** (a parfile plus the exact configuration it ran on). The `cactup` CLI is its
client: `cactup add`, `cactup install owner/stack`, `cactup import owner/sim`.

The file formats, the CRL thornlist parser and the CCL scanner live in
[cactup-ecosystem-common](https://github.com/max-morris/cactup-ecosystem-common), shared with
cactup.

## Running it locally

Needs Docker (rootless is fine) and [just](https://github.com/casey/just).

```bash
just dev        # build and start at http://localhost:8000, with development sign-in
just dev-seed   # demo repos, packages, stacks, a sim, a pending review, a moved tag
just smoke      # reset, seed, and exercise every page and action end to end
just logs       # follow the server's log
just dev-reset  # stop and delete the local database and demo repos
```

After seeding, sign in at http://localhost:8000/auth/login as `max` (superadmin, owner of the `et`
organization), `alice` or `bob`. The development sign-in and `file://` repos are refused unless the site is served from
localhost.

## Layout

- `crates/cactarium-server`: the server (axum, sqlx/Postgres, askama templates)
  - `src/tracker.rs`: following repos, freezing tags, noticing moved tags
  - `src/stacks.rs`: resolving stack definitions into releases
  - `src/sims.rs`: checking and publishing `.sim` files
  - `src/web/`: the site, the admin panel, the JSON API and the webhooks
  - `templates/`, `static/app.css`: the look; every color and size is a token in `app.css`
  - `migrations/`: the database schema
- `deploy/`: Dockerfile, Compose files, the demo seed and the smoke test

## Deploying

The production setup mirrors the CactUp tutorial server: the host's Apache terminates TLS and
proxies to the app, which Docker Compose publishes on loopback only. Copy `deploy/.env.example` to
`deploy/.env`, fill it in, then `just up`. `just update` snapshots the database, pulls, rebuilds,
migrates and restarts.

Server-side commands run in the app container with `just cli ...`:
`admin grant|revoke|trust|untrust|list`, `org create <name> <owner>`, `org add <name> <user>
[--owner]`, `org list`, `register [--owner <ns>] [--tag <tag>] [--only <name>]...`, `check <url> [--tag <tag>
[--commit <ref>]]`, `publish-sim`, `sync`, `reread <admin> <owner/name> <version>` (or `--tag <tag>`), `move-repo`, `reapply`, `token`. Create the `et`
organization with `just cli org create et <your-username> --display-name "Einstein Toolkit"`.

- `register` finds each manifest file's newest release among the repo's tags (the newest tag its
  own manifest reads as a version, with siblings' claims applied; the default branch decides
  nothing), or reads exactly `--tag`; a manifest with no release tag yet is skipped with a note. It
  reads each new entry at its tag before writing anything, creates the entries in one transaction
  (only those named by `--only`, if given, by manifest name), and prints one line per entry
  registered; on a repo that already has entries it adds only the missing ones. An entry is named
  by its manifest's `name`, under `--owner` (default: the registering user), which the manifest's
  `owners` must list. `check` prints the same preview as a dry run (nothing written), also for tags
  that don't exist yet (`--commit` names the commit or branch they would name). The website's
  Register a repo is the same, in two steps: the preview, then confirming the entries checked.
- Each tag is read by the entry's manifest in the tag's commit (`tag-pattern`, else
  `[track/]vX.Y.Z`, and its `since`): a manifest change applies to the tags carrying it, with no
  admin step. `reread` reads an invalid version of a non-curated repo entry again (valid if it
  reads cleanly now, or from another tag naming that version; removed if the tag isn't a version
  of the entry at all); with `--tag`, it examines a tag recorded as not a version again under the
  current rules.
- New tags are examined per sync up to `CACTARIUM_EXAMINE_PER_SYNC` (default 300; the dev site
  uses 25): after deploying, the first polls examine the existing tags of big repos over a few
  checks; a version is frozen once no unexamined or waiting tag could also be it. Each tag's
  outcome is stored as it is examined, so a background sync stopped by its 15-minute limit keeps
  its progress. Tags whose manifest needs a checkout (a symbolic link, or a host that refuses
  files by id) are read up to `CACTARIUM_CHECKOUTS_PER_SYNC` per sync (default 40; the dev site
  uses 1).
- Upgrading from master to this release, by design but worth knowing:
  - a newer manifest's `since` no longer excludes older tags: each tag is read by the manifest in
    its commit, so an old tag whose manifest had no `since` becomes a version on the first sync if
    it wasn't one;
  - invalid versions whose tags moved before the deploy are read again on the first sync, at the
    tags' new commits;
  - invalid versions whose tags were deleted upstream before the deploy are deleted on the first
    sync (each deletion is in the audit log, `version.invalid-tag-deleted`); the version's other
    tags, if any, are examined again;
  - invalid versions frozen by master keep their labels (an admin can re-read them, also from
    another tag of the same version);
  - the stored tag pattern is now only a display hint for repo entries; after a rollback to the
    retry-not-freeze release it would be taken as the real rule again.
- `move-repo` moves every entry on the repo together.
- A database that ran an early build of the multi-sim branch (with `0012_multi_sim.sql`, or
  `0013_multi_sim.sql` before it was renumbered to 0014) refuses to start: "migration 12 (or 13) was
  previously applied but has been modified". Production on master or the retry-not-freeze release
  never ran those builds and is unaffected. For a dev or smoke database, reset it: `just dev-reset`
  (`just smoke` does). To keep such a database instead, undo what that build's migration did and
  forget it, so the renumbered migrations reapply it (with
  `docker compose --project-directory deploy -f deploy/compose.yaml exec -T db psql -U cactarium -d
  cactarium`, since `just cli` won't start): `DROP TABLE foreign_tags; ALTER TABLE entry_repos DROP
  COLUMN IF EXISTS sim_form; ALTER TABLE sim_files DROP CONSTRAINT sim_files_pkey; ALTER TABLE
  sim_files DROP COLUMN name; ALTER TABLE sim_files ADD PRIMARY KEY (version_id); ALTER TABLE
  source_pins DROP CONSTRAINT source_pins_pkey; ALTER TABLE source_pins DROP COLUMN sim; ALTER TABLE
  source_pins ADD PRIMARY KEY (version_id, repo); DELETE FROM _sqlx_migrations WHERE description
  = 'multi sim';`. That works only before any multi-sim version was stored (several rows per
  version can't go back to one); otherwise reset.
- Rollback: a binary from the retry-not-freeze release on starts on a database a later release
  migrated; leaves unread (never freezes) the tags it can't read: format-2 manifests, format-4
  sims, a tag without an entry's manifest on a repo with several entries; skips the tags this
  release recorded as not an entry's (`foreign_tags`); and serves a sim download's file and
  sha256 from one row. Under it, a multi-sim entry's pages fail to render (its stored sims are
  format 4), so hide those entries (Admin, Entries, Hide) for the duration. Before rolling back
  further than that release, hiding every multi-sim entry is required: hidden entries aren't
  synced.

### First deploy

The whole sequence, rehearsed end to end against the real repos (curating takes about a minute):

1. On the VM, clone this repo and run `just setup`: it writes `deploy/.env` (with a generated database
   password) and points the Apache virtual host at the app. The recipes run Docker through `sudo`
   unless you can already reach the daemon; nothing changes your groups. Then edit
   `deploy/.env`: `CACTARIUM_BASE_URL`, `CACTARIUM_SUPERADMIN`, the GitHub OAuth app (callback
   `<base>/auth/github/callback`) and optionally ORCID's, and `SSH_FROM`. Never set
   `CACTARIUM_DEV_LOGIN` there.
2. `just up`, then `just firewall` from an SSH session that comes through the bastion. It allows SSH
   from the bastion on the ports sshd listens on now; if sshd is moving to another port, list both in
   `SSH_PORTS` (e.g. `22 2525`) and run it again with only the new one once that works.
3. Sign in on the site with GitHub. The account named in `CACTARIUM_SUPERADMIN` is the superadmin;
   signing in creates your user.
4. The `et` organization, trusted so its releases skip review:
   `just cli org create et <you> --display-name "Einstein Toolkit"`, then `just cli admin trust et`.
5. The curated packages: clone [cactarium-curate](https://github.com/max-morris/cactarium-curate) and
   run `just curate <you> <path>/cactarium-curate/curate.toml`.
6. The official stacks, carpetx-stack before cottonmouth-stack (which extends it):
   `just cli register --owner et <you> https://github.com/max-morris/<stack>` for `et-stack`,
   `carpet-stack`, `carpetx-stack` and `cottonmouth-stack`.
   Then the packages that carry their own `cactarium.toml` rather than a curated one:
   `just cli register --owner et <you> https://github.com/EinsteinToolkit/Cottonmouth`.
   Cottonmouth's example sims (`cactarium-sim.toml` with `[sim.files]` and
   `tag-pattern = "sim-v{major}.{minor}.{patch}"`, not on its `main`; each `sim-vX.Y.Z` sits on top
   of the package's `vX.Y.Z` and pins it): the plain `register` finds them at their newest
   `sim-v` tag too. To check a sims release before tagging it:
   `just cli check https://github.com/EinsteinToolkit/Cottonmouth --tag sim-v2026.6.0 --commit <commit>`
   (the commit's pins must all be public packages, and `et/cottonmouth`'s stored URL must match the
   pins'). Production registered `et/cottonmouth-sims` with
   `just cli register --owner et --tag sim-v2026.5.1 <you> https://github.com/EinsteinToolkit/Cottonmouth`,
   which adds only the entries that read that tag.
7. The starter sim: create a token on the site's Settings page, `cactup login --token <token>`, then,
   in cactarium-curate, `cactup sim publish sims/wavetoy.sim et/wavetoy`. CactUp talks to
   `https://cactarium.cct.lsu.edu` unless `CACTARIUM_URL` or the `cactarium-url` knob says otherwise.
8. Check it from a CactUp: `cactup install et/carpet-stack@2026.5.0` and `cactup import et/wavetoy --run`.
