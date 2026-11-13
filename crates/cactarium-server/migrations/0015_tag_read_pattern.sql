-- The tag-pattern of the manifest a pending tag read came from (NULL: none, or unreadable), so a
-- version is held while a tag that this pattern could read is still unexamined.
ALTER TABLE tag_reads ADD COLUMN pattern TEXT;
