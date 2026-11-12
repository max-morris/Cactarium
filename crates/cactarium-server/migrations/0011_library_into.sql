-- A dependency on a library (a package with library = true, which has no thorns): where its
-- checkout goes, relative to the dependent package's repo root. NULL for every other claim.
ALTER TABLE claims ADD COLUMN into_path TEXT;
