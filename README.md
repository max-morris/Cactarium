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

## The API

CactUp talks to the server under `/api/v1`; the shapes are the crate's `api.rs`, and its
`docs/api.md` is the reference (the site's `/docs/api` describes each route). Reads are anonymous;
writes take a bearer token from the site's Settings page (or `just cli token <user>`).

| Request | Response |
|---|---|
| `GET /resolve?req=owner/name[/sim]@[track:]range` | `Resolved` |
| `GET /entries/{owner}/{name}` | `EntryInfo` |
| `GET /packages/{owner}/{name}/versions` | `PackageVersions` |
| `GET /packages/{owner}/{name}/versions/{commit\|head\|master}` | `PackageVersion` |
| `GET /stacks/{owner}/{name}/releases` | `StackReleases` |
| `GET /stacks/{owner}/{name}/releases/{version\|head\|master}` | `FrozenStack` |
| `GET /sims/{owner}/{name}/{X.Y.Z}/download[?sim=<sim>]` | the `.sim` bytes, with `x-sha256` |
| `POST /lookup` | `LookedUp`: which package and version each pinned commit is, each download's review |
| `GET /providers?implements=…` (or `capability=`, `function=`, `thorn=`, `include=`) | `Providers` |
| `POST /sims/{owner}/{name}` (bearer, `.sim` body) | `Published` |
| `POST /stacks/{owner}/{name}/releases` (bearer, `ReleaseRequest`) | `Published` |
| `POST /packages/{owner}/{name}/refresh` (bearer) | `Refreshed` |
| `POST /repos` (bearer, `RegisterRequest`) | `Registered`: the site's registration, preview (`dry-run`) and confirm (`expect`) |
| `GET /whoami` (bearer) | `WhoAmI` |
| `POST /downloads` (bearer, `DownloadSubmission`) | `DownloadReview`; 409 `DownloadConflict` when submitted before |

Every read honors `x-cactarium-include-unreviewed: true` (CactUp's
`--risky-allow-untrusted-artifacts`): an admin's token also gets what awaits review, anyone gets
releases awaiting review of public entries when the site serves unreviewed code, and such answers
say `x-cactarium-unreviewed: true`.

- `POST /lookup`: a pin's `flesh` and `fork-of` are exact for a commit a version froze. For any
  other commit the server doesn't read the manifest there: `flesh` is the package's newest
  version's value, a hint, and `fork-of` is empty.
- Repo URLs are matched with the crate's `url::normalize_repo_url` (stored as
  `source_pins.url_norm`), and on GitHub, GitLab and Bitbucket also by `url::same_repo_lenient`.
- A sim stored from now on labels each pin `cactarium = "owner/pkg@X.Y.Z"` when a published version
  froze its commit (never `owner/pkg#sha`); stack releases get the labels when served. Stored sims
  are served byte for byte.
- A sim that pins a download (a tarball component by sha256, or an `[[input]]` with url and
  sha256) is published only once that URL and content are approved: `cactup download submit <url>`
  submits it, a background job fetches it once to check the sha256 (keeping no copy; rows left
  fetching by a restart are fetched again at startup), and an admin decides it under Admin,
  Downloads once verified. A rejected download can be reopened or approved there; a tag that froze
  invalid over it is read again with `reread`.
- A package version (or stack release) whose dependency resolves to a version awaiting review, or
  to a package that isn't public, waits (left unread, retried) until it is reviewed; stack
  releases' dependencies are checked like packages', but for the CCL.

## Deploying

The production setup mirrors the CactUp tutorial server: the host's Apache terminates TLS and
proxies to the app, which Docker Compose publishes on loopback only. Copy `deploy/.env.example` to
`deploy/.env`, fill it in, then `just up`. `just update` snapshots the database, pulls, rebuilds,
migrates and restarts.

Server-side commands run in the app container with `just cli ...`:
`admin grant|revoke|trust|untrust|list`, `org create <name> <owner>`, `org add <name> <user>
[--owner]`, `org list`, `register [--owner <ns>] [--tag <tag>] [--only <name>]...`, `check <url> [--tag <tag>
[--commit <ref>]]`, `publish-sim`, `sync`, `reread <admin> <owner/name> <version>` (or `--tag <tag>`, or `<version> --moved`), `rescan-facts <admin> [<owner/name>] [--all]`, `move-repo`, `reapply`, `token`. Create the `et`
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
  current rules. With `--moved`, `reread` reads a version of a sim or stack whose tag moved (marked
  `tag-moved`, the frozen commit still served) at the tag's current commit: if the tag there is still
  that version and passes every check a new tag passes, the version takes the new commit and
  everything stored from the old one is replaced (a stack's frozen thornlist and pins, every stored
  `.sim` of a sim entry, the thorn and pin indexes; the next release's diff), the mark goes, the
  tag's alerts are acknowledged, and it is reviewed as a pushed tag is (`version.reread-moved` in the
  audit log); otherwise nothing changes and the reasons are printed. Admin, Entries has the same as
  *Re-read moved tag*. Package versions are refused: sims and stacks pin their commits.
- A package version, a sim (upload or tag) and a stack release (tag or upload) are checked against
  what their thorns need: a package's against its own thorns and its dependencies' `needs`, a sim's
  and a release's against the thorns their thornlist builds (each thorn's facts are those of the
  package version that froze its pinned commit). Besides the CCL requirements, a thorn needs every
  `USES INCLUDE` header its sources include outside any `#if`/`#ifdef`, where a published thorn
  provides it (`INCLUDE ... IN`) and the thorn doesn't declare such a provider `OPTIONAL` or
  `OPTIONAL_IFACTIVE`, and the sources don't test the header's own guard macro. A built thorn
  the Cactarium has no facts for (a download, a commit no version froze) is not checked and is
  taken to meet whatever a known thorn of its name meets, or anything when none is known. `rescan-facts` reads the stored facts of package versions again at their frozen
  commits: facts stored before the scanner read headers say a thorn needs and provides none.
- New tags are examined per sync up to `CACTARIUM_EXAMINE_PER_SYNC` (default 300; the dev site
  uses 25): after deploying, the first polls examine the existing tags of big repos over a few
  checks; a version is frozen once no unexamined or waiting tag could also be it. Each tag's
  outcome is stored as it is examined, so a background sync stopped by its 15-minute limit keeps
  its progress. Tags whose manifest needs a checkout (a symbolic link, or a host that refuses
  files by id) are read up to `CACTARIUM_CHECKOUTS_PER_SYNC` per sync (default 40; the dev site
  uses 1).
- A registration preview (and a registration's discovery) reads at most `CACTARIUM_PREVIEW_TAGS`
  tags (default 100; the dev site uses 40), at most `CACTARIUM_PREVIEW_CHECKOUTS` of them from a
  checkout (default 5); when not every tag could be read, each manifest needs a tag named. A
  preview of a repo with no entries uses a temporary mirror, deleted afterward, cloned on a slot of
  its own (never one of syncing's three), given up (its git killed) once the request goes away,
  and stopped past 1 GB; leftovers of a process that died are swept at startup and hourly. Kept
  mirrors have no size limit. Previews and confirms together are limited to
  `CACTARIUM_PREVIEWS_PER_HOUR` per user (default 20); previews also to 60 a minute per address,
  confirms to 10.
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
- Upgrading to the include-closure release (migration 0019 adds `thorns.scanned_by`, which scanner
  read a thorn's facts; older binaries ignore it): every stored thorn's facts predate the header
  fields, so until they are rescanned no header is needed or provided anywhere. After `just
  update`, run `just cli rescan-facts <admin>` once (it fetches each package version's commit; one
  line per version; run it again to retry what failed, it skips what is done). From then on new
  package versions, sims and stack releases are refused when a thorn includes a header only a thorn
  they don't build provides. Versions already frozen stay as they are. Tags read after the deploy
  (or `reapply`) of curated packages whose manifests leave such a header to a dependency without
  naming its thorn in `needs` are refused with the line that fixes it; so are tip reads of them.
- Upgrading to the dependency-plan release (migrations 0017 and 0018): the first `migrate` (which
  `just update` runs) recomputes every stored repo key (`source_pins.url_norm`) with the crate's
  `url::normalize_repo_url`, once, in Rust (queued in the new `data_migrations` table; `serve` runs
  it too if `migrate` didn't). https:// keys stay as they were; scp-like, ssh://, ported and local
  (`file://`) keys change. 0018 adds the `downloads` table. Behavior that changes for existing
  data: a new tag whose dependency is a version awaiting review waits until it is reviewed (frozen
  versions are never re-read); a new stack tag whose `[[dependency]]` names no usable package
  version is now invalid (or waits); registering a repo whose new entry's first version would wait
  registers it instead of refusing; a sim pinning an approved download is accepted where every
  tarball pin was refused, and a new sim (upload or tag) whose `[[input]]` downloads a url+sha256
  needs that download approved too (stored sims, such as
  max-morris/bhns-gw230529-dense@1.0.0, keep their versions). `serve` also recomputes repo keys at
  every start, for pins the old server stored between `migrate` and the restart.
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
