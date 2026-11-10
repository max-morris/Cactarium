-- Upstream release tags that aren't vX.Y.Z: a pattern maps them to versions, e.g.
-- `ET_{major}_{minor}_v{patch}` turns the Einstein Toolkit's ET_2026_05_v0 into 2026.5.0. With a
-- pattern, only tags it matches become versions. `min_version` ignores tags below it. Set by admins
-- for curated packages (a stopgap until the repo carries its own cactarium.toml), and kept when one
-- is handed over to its repo's manifest.
ALTER TABLE entry_repos ADD COLUMN tag_pattern TEXT;
ALTER TABLE entry_repos ADD COLUMN min_version TEXT;
