-- A tag whose commit couldn't be fetched used to become an invalid version, never read again, even
-- when the cause was passing (DNS, the host being down). Now such a tag is left unread and tried
-- at the next sync. Versions already stored that way are removed, so their tags are read afresh;
-- invalid versions are never served, so nothing that depended on them is lost. A commit refused for
-- its size stays invalid: that is a fact about the content.
DELETE FROM versions
 WHERE state = 'invalid'
   AND invalid_reason LIKE 'cannot fetch the tagged commit:%'
   AND invalid_reason NOT LIKE '%too large to index%'
   AND invalid_reason NOT LIKE '%the download passed%';
