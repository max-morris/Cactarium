-- The Cactarium schema.

CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    -- The user's namespace: lowercase, valid as an owner name.
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT,
    role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'superadmin')),
    -- Trusted users' submissions skip the review queue.
    trusted       BOOLEAN NOT NULL DEFAULT FALSE,
    banned        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One login method of a user: a GitHub account, an ORCID iD, or (local development only) a dev name.
CREATE TABLE identities (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL CHECK (provider IN ('github', 'orcid', 'dev')),
    subject    TEXT NOT NULL,
    login      TEXT,
    email      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);

CREATE TABLE sessions (
    -- sha256 of the cookie's token; the token itself is never stored.
    token_hash  BYTEA PRIMARY KEY,
    user_id     BIGINT REFERENCES users(id) ON DELETE CASCADE,
    csrf        TEXT NOT NULL,
    -- Short-lived state during an OAuth round trip, or a pending signup.
    data        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expiry ON sessions (expires_at);

-- A package, stack or sim: owner/name.
CREATE TABLE entries (
    id          BIGSERIAL PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('package', 'stack', 'sim')),
    owner       TEXT NOT NULL,
    name        TEXT NOT NULL,
    summary     TEXT,
    description TEXT,
    visibility  TEXT NOT NULL DEFAULT 'pending' CHECK (visibility IN ('pending', 'public', 'hidden')),
    verified    BOOLEAN NOT NULL DEFAULT FALSE,
    -- Created by an admin for a repo nobody on the Cactarium controls.
    curated     BOOLEAN NOT NULL DEFAULT FALSE,
    created_by  BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (owner, name)
);
CREATE INDEX entries_kind ON entries (kind, visibility);

-- Where a package or a repo-backed stack comes from.
CREATE TABLE entry_repos (
    entry_id        BIGINT PRIMARY KEY REFERENCES entries(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    -- Which manifest the repo provides for this entry: cactarium.toml or cactarium-stack.toml.
    manifest_file   TEXT NOT NULL,
    webhook_secret  TEXT NOT NULL,
    -- For curated packages: the admin-maintained manifest used instead of the repo's.
    overlay_manifest TEXT,
    last_polled_at  TIMESTAMPTZ,
    poll_error      TEXT
);

-- A version of an entry. Packages and stacks: track + semver. Sims: a number.
CREATE TABLE versions (
    id           BIGSERIAL PRIMARY KEY,
    entry_id     BIGINT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    -- '' is the default track.
    track        TEXT NOT NULL DEFAULT '',
    version      TEXT NOT NULL,
    -- Sort key within a track (semver precedence, or the sim number), maintained by the app.
    sort_key     TEXT NOT NULL,
    -- Repo-backed: the git tag, frozen commit and tree. Virtual: an admin-entered curated version.
    tag          TEXT,
    commit       TEXT,
    tree         TEXT,
    is_virtual   BOOLEAN NOT NULL DEFAULT FALSE,
    state        TEXT NOT NULL DEFAULT 'ok' CHECK (state IN ('ok', 'invalid', 'tag-moved', 'upstream-missing')),
    invalid_reason TEXT,
    yanked       BOOLEAN NOT NULL DEFAULT FALSE,
    yank_reason  TEXT,
    -- Parsed manifest (packages, stacks) as JSON.
    manifest     JSONB,
    readme_html  TEXT,
    published_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (entry_id, track, version)
);
CREATE INDEX versions_entry ON versions (entry_id, track, sort_key);

-- The thorns a package version contains, with CCL-derived facts.
CREATE TABLE thorns (
    id           BIGSERIAL PRIMARY KEY,
    version_id   BIGINT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    arrangement  TEXT NOT NULL,
    name         TEXT NOT NULL,
    dir          TEXT NOT NULL,
    implements   TEXT,
    facts        JSONB NOT NULL
);
CREATE INDEX thorns_name ON thorns (lower(name));
CREATE INDEX thorns_implements ON thorns (lower(implements));

-- Declared relations: depends-on, works-with, incompatible-with, fork-of.
CREATE TABLE claims (
    id           BIGSERIAL PRIMARY KEY,
    version_id   BIGINT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('depends-on', 'works-with', 'incompatible-with', 'fork-of')),
    target_owner TEXT NOT NULL,
    target_name  TEXT NOT NULL,
    range        TEXT,
    note         TEXT
);
CREATE INDEX claims_target ON claims (target_owner, target_name);

-- A stack release: the frozen CRL and every repo's pin, as a FrozenStack TOML.
CREATE TABLE stack_releases (
    version_id   BIGINT PRIMARY KEY REFERENCES versions(id) ON DELETE CASCADE,
    how          TEXT NOT NULL CHECK (how IN ('tag', 'snapshot', 'upload')),
    frozen       TEXT NOT NULL,
    -- The definition (cactarium-stack.toml) and its own thornlist, kept to resolve `@head` and `@master`.
    recipe       TEXT,
    own_thornlist TEXT,
    -- Repos that moved since the previous release on the same track: [{repo, from, to}].
    diff         JSONB NOT NULL DEFAULT '[]'::jsonb
);

-- A sim version: the .sim file itself plus a search index.
CREATE TABLE sim_files (
    version_id   BIGINT PRIMARY KEY REFERENCES versions(id) ON DELETE CASCADE,
    sha256       TEXT NOT NULL,
    content      TEXT NOT NULL,
    index        JSONB NOT NULL
);

-- Every repo URL pinned by a stack release or a sim, for "used by" and unregistered sources.
CREATE TABLE source_pins (
    version_id   BIGINT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    repo         TEXT NOT NULL,
    url          TEXT NOT NULL,
    url_norm     TEXT NOT NULL,
    git_ref      TEXT,
    commit       TEXT,
    PRIMARY KEY (version_id, repo)
);
CREATE INDEX source_pins_url ON source_pins (url_norm);

CREATE TABLE submissions (
    id           BIGSERIAL PRIMARY KEY,
    entry_id     BIGINT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    version_id   BIGINT REFERENCES versions(id) ON DELETE CASCADE,
    submitter    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    status       TEXT NOT NULL DEFAULT 'open'
                 CHECK (status IN ('open', 'changes-requested', 'approved', 'rejected', 'auto-approved')),
    reviewer     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    note         TEXT,
    checklist    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at   TIMESTAMPTZ
);
CREATE INDEX submissions_status ON submissions (status, created_at);

CREATE TABLE api_tokens (
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   BYTEA NOT NULL UNIQUE,
    -- The first characters of the token, shown so the owner can tell tokens apart.
    prefix       TEXT NOT NULL,
    scopes       TEXT[] NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked      BOOLEAN NOT NULL DEFAULT FALSE
);

-- A frozen tag that later moved to another commit, or disappeared upstream.
CREATE TABLE tag_events (
    id              BIGSERIAL PRIMARY KEY,
    entry_id        BIGINT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    version_id      BIGINT REFERENCES versions(id) ON DELETE CASCADE,
    tag             TEXT NOT NULL,
    frozen_commit   TEXT NOT NULL,
    -- NULL when the tag was deleted.
    new_commit      TEXT,
    seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at TIMESTAMPTZ
);

CREATE TABLE audit_log (
    id       BIGSERIAL PRIMARY KEY,
    actor    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    action   TEXT NOT NULL,
    target   TEXT,
    details  JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip       TEXT,
    at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_at ON audit_log (at DESC);

-- Owner names nobody may register (admins can still create curated entries under them).
CREATE TABLE reserved_names (
    name     TEXT PRIMARY KEY,
    reason   TEXT
);
INSERT INTO reserved_names (name, reason) VALUES
    ('admin', 'site'), ('api', 'site'), ('static', 'site'), ('auth', 'site'), ('search', 'site'),
    ('docs', 'site'), ('new', 'site'), ('settings', 'site'), ('dashboard', 'site'), ('hooks', 'site'),
    ('thorns', 'site'), ('implementations', 'site'), ('sources', 'site'), ('packages', 'site'),
    ('stacks', 'site'), ('sims', 'site'), ('cactarium', 'curation'), ('cactup', 'project'),
    ('einsteintoolkit', 'curation');
