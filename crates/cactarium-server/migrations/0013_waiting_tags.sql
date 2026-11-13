-- Tags left unread because what they need isn't there yet (a host that didn't answer, a pinned
-- package not public yet, a newer format...). The poller tries each again with backoff (5 minutes,
-- doubling, at most 6 hours apart), after the new tags; the count starts over when the tag moves.
CREATE TABLE waiting_tags (
    entry_id    BIGINT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    tag         TEXT NOT NULL,
    commit      TEXT NOT NULL,
    tries       INTEGER NOT NULL DEFAULT 1,
    reason      TEXT NOT NULL,
    next_try_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (entry_id, tag)
);
