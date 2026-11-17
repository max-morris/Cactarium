-- Downloads (a .sim input's file, a tarball component pinned by sha256) submitted for review, so
-- pins to them can be trusted: one row per URL and content. The server fetched the URL once and
-- checked the sha256 before storing the row; it keeps no copy of the file. A sim whose download
-- isn't approved is refused (an upload) or waits (a tag).
CREATE TABLE downloads (
    id          BIGSERIAL PRIMARY KEY,
    url         TEXT NOT NULL,
    sha256      TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    -- What the fetch read, in bytes.
    size        BIGINT NOT NULL,
    -- The submitter's word for the reviewer: what it is and why it can be trusted.
    note        TEXT,
    review      TEXT NOT NULL DEFAULT 'pending' CHECK (review IN ('pending', 'approved', 'rejected')),
    submitter   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    reviewer    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    review_note TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at  TIMESTAMPTZ,
    UNIQUE (url, sha256)
);
CREATE INDEX downloads_review ON downloads (review, created_at);
