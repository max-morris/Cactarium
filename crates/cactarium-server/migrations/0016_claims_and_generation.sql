-- A tag taken as a sibling's because the sibling's manifest at that commit couldn't be read: which
-- sibling, so the record is examined again once that sibling's rule no longer reads the tag.
ALTER TABLE foreign_tags ADD COLUMN claimed_by BIGINT;

-- Bumped for every entry on a repo when registering another entry on it clears their records: a
-- sync that started before stores nothing more (its reads were judged without the new sibling).
ALTER TABLE entry_repos ADD COLUMN generation BIGINT NOT NULL DEFAULT 0;
