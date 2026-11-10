-- Trust beyond users: an organization or an entry can be trusted too. A new release of a public
-- entry publishes without review when the entry, its owner (user or organization), or the user
-- publishing it is trusted; otherwise it waits in the review queue like a new submission.
ALTER TABLE orgs ADD COLUMN trusted BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE entries ADD COLUMN trusted BOOLEAN NOT NULL DEFAULT FALSE;

-- Whether a version may be served: 'pending' and 'rejected' versions are seen only by the entry's
-- managers and admins. Every version that exists already was published, so it is 'approved'.
ALTER TABLE versions ADD COLUMN review TEXT NOT NULL DEFAULT 'approved'
    CHECK (review IN ('approved', 'pending', 'rejected'));

CREATE INDEX submissions_version ON submissions (version_id) WHERE version_id IS NOT NULL;
