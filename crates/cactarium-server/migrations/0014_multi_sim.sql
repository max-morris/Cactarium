-- Sim entries holding several sims per version ([sim.files] in cactarium-sim.toml, manifest
-- format 2), and tags recorded as not an entry's own.
--
-- A version of a multi-sim entry stores one row per sim, keyed by the sim's name. Existing rows
-- keep '' as their name: the entry's only sim. Readers ask for a sim by name ('' for a one-sim
-- entry), so a version's file and its sha256 always come from the same row. A binary from before
-- this migration still inserts (the name defaults to '') and reads one-sim entries as before.
ALTER TABLE sim_files ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE sim_files DROP CONSTRAINT sim_files_pkey;
ALTER TABLE sim_files ADD PRIMARY KEY (version_id, name);

-- The repos each sim pins: the sims of one version may pin one repo at different commits.
ALTER TABLE source_pins ADD COLUMN sim TEXT NOT NULL DEFAULT '';
ALTER TABLE source_pins DROP CONSTRAINT source_pins_pkey;
ALTER TABLE source_pins ADD PRIMARY KEY (version_id, sim, repo);

-- release_thorns keeps one row per (version, thorn): a multi-sim version's thorns are the union of
-- its sims' (inserted with ON CONFLICT DO NOTHING), so it needs no change.

-- Tags examined for an entry and found not to be versions of it (each is read by the entry's
-- manifest at its own commit): kept so they aren't examined again, and judged again when the tag
-- moves (commit differs).
CREATE TABLE foreign_tags (
    entry_id   BIGINT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    tag        TEXT NOT NULL,
    commit     TEXT NOT NULL,
    reason     TEXT NOT NULL,
    -- Why, as a kind: absent (no manifest for this entry at the commit), rule (the manifest there
    -- doesn't read the tag as a version), identity (it names another entry, or not the owner), form
    -- (the other sim form), claim (a sibling's manifest there reads it with its own tag-pattern),
    -- unreadable (unreadable, and no rule reads the tag), duplicate (its version is another tag's),
    -- large (too large to read, with siblings).
    kind       TEXT NOT NULL DEFAULT 'rule'
               CHECK (kind IN ('absent', 'rule', 'identity', 'form', 'claim', 'unreadable', 'duplicate', 'large')),
    seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (entry_id, tag)
);

-- A sim entry's form, fixed when it is registered: 'file' (one sim, addressed owner/name) or
-- 'files' ([sim.files], each sim addressed owner/name/sim). A tag whose manifest uses the other form
-- is not the entry's. Every repo-backed sim entry before this migration is a 'file' one.
ALTER TABLE entry_repos ADD COLUMN sim_form TEXT CHECK (sim_form IN ('file', 'files'));
UPDATE entry_repos r SET sim_form = 'file' FROM entries e WHERE e.id = r.entry_id AND e.kind = 'sim';

-- Each tag is read by the entry's manifest at its commit. Tags examined and read as versions wait
-- here until every tag of the entry has been examined; then one tag per version is frozen (the best
-- spelling, then the first by name), so the outcome doesn't depend on how the examining was paged.
-- error: the manifest there is unreadable; that version is frozen invalid with it.
CREATE TABLE tag_reads (
    entry_id   BIGINT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    tag        TEXT NOT NULL,
    commit     TEXT NOT NULL,
    label      TEXT NOT NULL,
    rank       INTEGER NOT NULL,
    error      TEXT,
    seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (entry_id, tag)
);
