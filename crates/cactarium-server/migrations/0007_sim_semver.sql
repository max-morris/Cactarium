-- Sim versions are semver now, like packages and stacks: an upload that was version N becomes
-- N.0.0, so `owner/sim@N` (the range N.x.x) still finds it. The stored files' stamps follow.
UPDATE versions v SET
    version  = v.version || '.0.0',
    sort_key = lpad(v.version, 10, '0') || '.0000000000.0000000000~'
FROM entries e
WHERE e.id = v.entry_id AND e.kind = 'sim' AND v.version ~ '^[0-9]+$';

UPDATE sim_files SET content = regexp_replace(content, '^(cactarium = "[^"@]+@)([0-9]+)"', '\1\2.0.0"', 'n')
WHERE content ~ '(?n)^cactarium = "[^"@]+@[0-9]+"';
UPDATE sim_files SET sha256 = encode(sha256(convert_to(content, 'UTF8')), 'hex');
