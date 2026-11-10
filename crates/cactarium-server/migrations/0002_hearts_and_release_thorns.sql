-- Hearts: a user saves an entry for later; the count is public.
CREATE TABLE hearts (
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entry_id   BIGINT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, entry_id)
);
CREATE INDEX hearts_entry ON hearts (entry_id);

-- The thorns a stack release or a sim builds (Arrangement/Thorn), so they can be found by thorn:
-- "a stack that builds CarpetX".
CREATE TABLE release_thorns (
    version_id BIGINT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    checkout   TEXT NOT NULL,
    PRIMARY KEY (version_id, checkout)
);
CREATE INDEX release_thorns_name ON release_thorns (lower(checkout));

-- `et` is the Einstein Toolkit's namespace, kept for entries admins publish there.
INSERT INTO reserved_names (name, reason) VALUES ('et', 'Einstein Toolkit namespace'), ('compare', 'site') ON CONFLICT DO NOTHING;
