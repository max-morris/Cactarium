-- Whether the unpinned forms (`@head`, `@master`) of a stack that isn't trusted (neither the entry
-- nor its owner) are served: 'refuse' (not at all) or 'allow' (with a header that makes cactup warn
-- and ask). Their branch tips never pass review, so the default is to refuse.
INSERT INTO site_settings (key, value) VALUES ('untrusted-tips', 'refuse') ON CONFLICT DO NOTHING;
