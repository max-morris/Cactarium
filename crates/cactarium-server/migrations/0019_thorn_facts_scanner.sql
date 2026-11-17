-- Which scanner read a thorn's stored facts (`tracker::FACTS_SCANNER`); NULL for facts stored before
-- this was recorded. `cactarium rescan-facts` reads again the versions with a thorn whose facts an
-- older scanner read. Older binaries don't write it, so their facts read as NULL: rescanned again.
ALTER TABLE thorns ADD COLUMN scanned_by TEXT;
