-- Downloads (a .sim input's file, a tarball component pinned by sha256) submitted for review, so
-- pins to them can be trusted: one row per URL and content. A background job fetches the URL once
-- and checks the sha256 (fetch_state: fetching, then ok or failed, with the reason); only a
-- verified row can be decided, and the server keeps no copy of the file. A sim whose download isn't approved is
-- refused (an upload) or waits (a tag); a rejected one makes a tag invalid. An admin can reopen a
-- rejected download (back to pending, or approved at once).
CREATE TABLE downloads (
    id           BIGSERIAL PRIMARY KEY,
    url          TEXT NOT NULL,
    sha256       TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    fetch_state  TEXT NOT NULL DEFAULT 'fetching' CHECK (fetch_state IN ('fetching', 'ok', 'failed')),
    -- Why the fetch failed, for the submitter and the admins.
    fetch_error  TEXT,
    -- What the fetch read, in bytes, once it succeeded.
    size         BIGINT,
    fetched_at   TIMESTAMPTZ,
    -- The submitter's word for the reviewer: what it is and why it can be trusted.
    note         TEXT,
    review       TEXT NOT NULL DEFAULT 'pending' CHECK (review IN ('pending', 'approved', 'rejected')),
    -- Submitted by a trusted user or an admin: approved as soon as the fetch verifies it.
    auto_approve BOOLEAN NOT NULL DEFAULT FALSE,
    submitter    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    reviewer     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    review_note  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at   TIMESTAMPTZ,
    UNIQUE (url, sha256),
    CHECK (review = 'pending' OR fetch_state = 'ok')
);
CREATE INDEX downloads_review ON downloads (review, created_at);
CREATE INDEX downloads_fetching ON downloads (submitter) WHERE fetch_state = 'fetching';
