-- Organizations: namespaces shared by their members, such as `et`. They share the owner namespace
-- with users: no org may have a user's name, and the reverse.
CREATE TABLE orgs (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    display_name TEXT,
    created_by   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Members publish under the org and manage its entries; owners also manage its members.
CREATE TABLE org_members (
    org_id   BIGINT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id  BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role     TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX org_members_user ON org_members (user_id);

-- Settings only the superadmin changes.
CREATE TABLE site_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Who may mark users trusted: 'superadmin' or 'admins'.
INSERT INTO site_settings (key, value) VALUES ('trust-granted-by', 'superadmin');

INSERT INTO reserved_names (name, reason) VALUES ('orgs', 'site') ON CONFLICT DO NOTHING;
