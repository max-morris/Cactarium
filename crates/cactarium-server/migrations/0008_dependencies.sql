-- [[depends-on]] became [[dependency]]: a target at a range or a commit, and optionally the
-- target's thorns it needs (needs) and this package's thorns it is for (needed_by; empty means
-- every thorn).
ALTER TABLE claims DROP CONSTRAINT claims_kind_check;
UPDATE claims SET kind = 'dependency' WHERE kind = 'depends-on';
ALTER TABLE claims ADD CONSTRAINT claims_kind_check
    CHECK (kind IN ('dependency', 'works-with', 'incompatible-with', 'fork-of'));
ALTER TABLE claims
    ADD COLUMN sha       TEXT,
    ADD COLUMN needs     TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN needed_by TEXT[] NOT NULL DEFAULT '{}';
