-- An invalid version whose tag later moved was marked tag-moved, which counted as usable and was
-- served with no manifest. An invalid version stays invalid whatever its tag does (the sync no
-- longer marks it); rows already marked are put back.
UPDATE versions SET state = 'invalid' WHERE invalid_reason IS NOT NULL AND state = 'tag-moved';
