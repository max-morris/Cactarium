-- An any-of dependency's alternatives (owner, name, range, sha, needs each), in the author's order;
-- the row's own target columns repeat the first. NULL for every other claim.
ALTER TABLE claims ADD COLUMN alternatives JSONB;

-- What the Cactarium noticed about a version that reviewers should look at (includes that reach
-- another thorn's sources by path, a generic driver inherit next to one driver's headers, needs
-- the CCL doesn't explain, ...). Shown on the review page; never blocks anything.
ALTER TABLE versions ADD COLUMN smells TEXT[] NOT NULL DEFAULT '{}';
