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

-- Tags an entry's rule picks that turn out not to be its own: the manifest inside reads the tag
-- under another rule (another kind's tag-pattern), or, on a repo carrying several entries, the
-- tag has no manifest for this entry at all. Recorded instead of frozen as invalid versions, and
-- judged again when the tag moves (commit differs) or the entry's tag rule is re-read.
CREATE TABLE foreign_tags (
    entry_id   BIGINT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    tag        TEXT NOT NULL,
    commit     TEXT NOT NULL,
    reason     TEXT NOT NULL,
    seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (entry_id, tag)
);

-- A sim entry's form, fixed when it is registered: 'file' (one sim, addressed owner/name) or
-- 'files' ([sim.files], each sim addressed owner/name/sim). A tag whose manifest uses the other form
-- is not the entry's. Every repo-backed sim entry before this migration is a 'file' one.
ALTER TABLE entry_repos ADD COLUMN sim_form TEXT CHECK (sim_form IN ('file', 'files'));
UPDATE entry_repos r SET sim_form = 'file' FROM entries e WHERE e.id = r.entry_id AND e.kind = 'sim';
