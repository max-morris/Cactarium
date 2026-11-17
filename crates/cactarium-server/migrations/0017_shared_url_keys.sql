-- Repo URL keys (source_pins.url_norm) now come from cactup-ecosystem-common's
-- url::normalize_repo_url, the key CactUp compares with too. Ordinary https:// URLs keep their
-- keys; scp-like (git@host:x/y), ssh://, credentialed, ported and local (file://, /path) ones
-- change. The new keys can't be computed in SQL: the server recomputes every stored key from its
-- url in Rust, once, at the first `cactarium migrate` (or `serve`) of this release, and marks it
-- done here. Steps of this kind are listed here by name; a binary runs those it knows that aren't
-- done yet.
CREATE TABLE data_migrations (
    name    TEXT PRIMARY KEY,
    done_at TIMESTAMPTZ
);
INSERT INTO data_migrations (name) VALUES ('shared-url-keys');
