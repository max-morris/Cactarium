#!/usr/bin/env python3
"""End-to-end smoke test of a local dev Cactarium (after `just dev && just dev-seed`).

Signs in through the dev login, visits every page as each kind of visitor, and exercises the main
actions: review, tokens, API publishing, yanking, stack releases, the security checks. Standard
library only. Exits non-zero on the first failure.

    deploy/smoke.py [http://localhost:8000]
"""

import http.cookiejar
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")
ENV = dict(l.strip().split("=", 1) for l in open(__file__.rsplit("/", 1)[0] + "/.env") if "=" in l and not l.startswith("#"))
REPOS = "file://" + ENV["DEMO_REPOS"]
FAILED = []


class Visitor:
    def __init__(self, name=None):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())
        self.csrf = ""
        self.name = name
        if name:
            self.login(name)

    def req(self, method, path, data=None, headers=None, raw=None):
        h = {"Origin": BASE, "Sec-Fetch-Site": "same-origin"} if method == "POST" else {}
        h.update(headers or {})
        body = raw
        if data is not None:
            body = urllib.parse.urlencode(data).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        r = urllib.request.Request(BASE + path, data=body, method=method, headers=h)
        try:
            with self.opener.open(r) as resp:
                text = resp.read().decode("utf-8", "replace")
                status, hdrs = resp.status, dict(resp.headers)
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            status, hdrs = e.code, dict(e.headers)
        m = re.search(r'name="_csrf" value="([^"]+)"', text)
        if m:
            self.csrf = m.group(1)
        return status, text, hdrs

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    def post(self, path, data=None, **kw):
        data = dict(data or {})
        data.setdefault("_csrf", self.csrf)
        return self.req("POST", path, data=data, **kw)

    def login(self, name):
        self.get("/auth/login")
        status, _, hdrs = self.post("/auth/dev", {"username": name, "next": "/dashboard"})
        check(f"dev login as {name}", status == 303, status)
        self.get("/dashboard")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def check(what, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + what + ("" if ok else f"  ({detail})"))
    if not ok:
        FAILED.append(what)


def page(v, path, expect=200, contains=None):
    status, text, _ = v.get(path)
    ok = status == expect and "Something went wrong" not in text
    if contains and contains not in text:
        ok = False
    check(f"{v.name or 'anonymous'} GET {path} -> {expect}", ok, f"{status} {text[:200]!r}")
    return text


anon = Visitor()
for p in ["/", "/search", "/search?kind=package", "/search?kind=stack", "/search?kind=sim", "/search?kind=thorn",
          "/search?q=carpetx", "/search?q=driver", "/docs", "/thorns/CarpetX/Loop", "/thorns/Loop",
          "/implementations/driver", "/sources?url=" + REPOS + "/cactus.git", "/max", "/et",
          "/max/carpetx", "/max/carpetx?tab=thorns", "/max/carpetx?tab=versions", "/max/carpetx?tab=usedby",
          "/max/carpetx?track=default", "/max/carpetx/mixed-precision:1.0.0", "/max/carpetx/1.0.0",
          "/et/et-stack", "/et/et-stack/2026.5.0", "/max/carpetx-mp", "/max/qc0-demo", "/max/qc0-demo/1.0.0?tab=pins",
          "/max/qc0-demo/1.0.0?tab=thornlist", "/max/qc0-demo/1.0.0?tab=inputs", "/max/qc0-demo/1.0.0?tab=run",
          "/max/carpetx-mp/1.0.0/download.th", "/max/qc0-demo/1.0.0/download.sim", "/auth/login"]:
    page(anon, p)
page(anon, "/max/carpetx", contains="mixed-precision")
# Forks and the compare page.
page(anon, "/et/carpetx", contains="max/carpetx")
page(anon, "/compare?a=et/carpetx&b=max/carpetx", contains="CarpetX/TestReal4")
# Stacks found by the thorn they build.
page(anon, "/search?q=TestReal4&kind=stack", contains="max/carpetx-mp")
page(anon, "/thorns/CarpetX/TestReal4", contains="max/carpetx-mp")
# Contacts: declared, or the repo.
page(anon, "/et/et-stack", contains="bitbucket.org/einsteintoolkit/tickets/issues")
s, body, _ = anon.get("/api/v1/entries/max/carpetx")
check("the API gives a contact (the repo, when none is declared)", s == 200 and json.loads(body)["contact"].endswith("/carpetx"), body[:200])
page(anon, "/max/carpetx/1.0.0", contains="tag moved upstream")
page(anon, "/alice/spacetimex", expect=404)
page(anon, "/nobody", expect=404)
page(anon, "/dashboard", expect=401)
page(anon, "/admin", expect=401)

# Cross-site and token-less writes are refused.
s, _, _ = anon.req("POST", "/auth/logout", data={"_csrf": "x"}, headers={"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
check("cross-site POST is forbidden", s == 403, s)
s, _, _ = anon.req("POST", "/api/v1/sims/max/x", raw=b"x")
check("API write without a token is 401", s == 401, s)

alice = Visitor("alice")
page(alice, "/alice/spacetimex", contains="pending review")
page(alice, "/admin", expect=403)
s, t, _ = alice.post("/max/carpetx/refresh", {})
check("alice cannot manage max's package", s == 403, s)
s, t, _ = alice.post("/new/repo", {"_csrf": "wrong", "url": "file:///repos/x.git"})
check("a wrong CSRF token is refused", s == 400, s)

# Only admins publish under a namespace that is not theirs.
alice.get("/new/repo")
s, t, _ = alice.post("/new/repo", {"url": REPOS + "/spacetimex.git", "owner": "et"})
check("a non-member cannot publish under et", s == 200 and "organization you belong to" in t, s)

maxv = Visitor("max")
for p in ["/dashboard", "/settings", "/new/repo", "/new/sim", "/new/stack", "/new/stack?name=max/carpetx-mp",
          "/admin", "/admin/entries", "/admin/curated", "/admin/tags", "/admin/users", "/admin/audit"]:
    page(maxv, p)
page(maxv, "/admin/tags", contains="v1.0.0")
page(maxv, "/dashboard", contains="Publish a new version instead of moving tags")

def seen_of(sid):
    """The newest version the review page for `sid` shows, as its form submits it."""
    _, text, _ = maxv.get(f"/admin?s={sid}")
    m = re.search(r'name="seen" value="(\d+)"', text)
    return m.group(1) if m else "0"


# Review: request changes, alice resubmits, then approve.
text = page(maxv, "/admin", contains="alice/spacetimex")
sub = re.search(r'action="/admin/review/(\d+)"', text)
check("the queue shows a review form", sub is not None)
if sub:
    sid = sub.group(1)
    s, _, _ = maxv.post(f"/admin/review/{sid}", {"decision": "changes", "note": "Add a license."})
    check("request changes", s == 303, s)
    page(alice, "/alice/spacetimex", contains="Add a license.")
    alice.get("/alice/spacetimex")
    s, _, _ = alice.post("/alice/spacetimex/resubmit", {})
    check("alice resubmits", s == 303, s)
    s, _, _ = maxv.post(f"/admin/review/{sid}", {"decision": "approve", "check_license": "on", "seen": seen_of(sid)})
    check("approve", s == 303, s)
    page(anon, "/alice/spacetimex", contains="spacetimex")

# Security regressions (from the review).
# A stack can't extend someone else's pending stack, and can't tell that it exists.
alice.get("/new/stack")
pend = 'format = 1\n\n[stack]\nname = "alice-private"\nextends = ["et/et-stack@2026.5.0"]\n'
s, _, _ = alice.post("/new/stack", {"definition": pend, "thornlist": "", "version": "1.0.0"})
check("alice cuts a (pending) stack release", s == 303, s)
page(anon, "/alice/alice-private", expect=404)
maxv.get("/new/stack")
peek = 'format = 1\n\n[stack]\nname = "peek"\nextends = ["alice/alice-private@1.0.0"]\n'
s, text, _ = maxv.post("/new/stack", {"definition": peek, "thornlist": "", "version": "0.1.0"})
check("a pending stack is not available as a base", s == 200 and "is not available" in text, s)
# The post-login destination stays on the site.
v = Visitor()
v.get("/auth/login")
s, _, hdrs = v.post("/auth/dev", {"username": "alice", "next": "/\t/evil.example"})
check("a tab-smuggled next stays on the site", s == 303 and hdrs.get("location") == "/dashboard", hdrs.get("location"))
# A name that owns entries cannot be claimed by signing up with it.
maxv.get("/admin/curated")
overlay = 'format = 1\n\n[package]\nname = "cb"\nowners = ["orgx"]\narrangement = "CactusBase"\n'
s, _, _ = maxv.post("/admin/curated", {"owner": "orgx", "url": REPOS + "/cactusbase.git", "manifest": overlay})
check("an admin creates a curated package under a new owner", s == 303, s)
v = Visitor()
v.get("/auth/login")
s, _, hdrs = v.post("/auth/dev", {"username": "orgx", "next": "/dashboard"})
check("signing in as that owner must choose another name", hdrs.get("location") == "/auth/choose-name", hdrs.get("location"))
# Untrusted stacks' branch tips: refused by default, served marked untrusted when the site allows.
s, body, _ = anon.get("/api/v1/stacks/et/et-stack/releases/head")
check("an untrusted stack's @head is refused by default", s == 403 and "isn't trusted" in body, f"{s} {body[:200]}")
s, _, _ = anon.get("/api/v1/stacks/et/et-stack/releases/master")
check("and so is its @master", s == 403, s)
page(anon, "/et/et-stack", contains="doesn't serve its")
maxv.get("/admin/site")
s, _, _ = maxv.post("/admin/site", {"untrusted_tips": "allow"})
check("the superadmin allows untrusted tips", s == 303, s)
s, _, hdrs = anon.get("/api/v1/stacks/et/et-stack/releases/head")
check("then it is served, marked untrusted", s == 200 and hdrs.get("x-cactarium-untrusted") == "true", f"{s} {hdrs}")
page(anon, "/et/et-stack", contains="cactup warns and asks")
maxv.get("/admin/site")
maxv.post("/admin/site", {"untrusted_tips": "refuse"})
s, _, hdrs = anon.get("/api/v1/stacks/max/carpetx-mp/releases/head")
check("a trusted owner's @head is served, not marked", s == 200 and hdrs.get("x-cactarium-untrusted") == "false", f"{s} {hdrs}")
# The unpinned forms are rate-limited.
codes = [anon.get("/api/v1/stacks/max/carpetx-mp/releases/head")[0] for _ in range(14)]
check("@head requests are rate-limited", codes[0] == 200 and codes[-1] == 429, codes)

# Hearts: save, count, un-save.
maxv.get("/max/qc0-demo")
s, _, _ = maxv.post("/max/qc0-demo/heart", {})
check("save an entry", s == 303, s)
page(maxv, "/max/qc0-demo", contains="Saved")
page(maxv, "/dashboard", contains="max/qc0-demo")
s, body, _ = anon.get("/api/v1/entries/max/qc0-demo")
check("the public count goes up", json.loads(body)["hearts"] == 1, body[:200])
maxv.get("/max/qc0-demo")
maxv.post("/max/qc0-demo/heart", {})
s, body, _ = anon.get("/api/v1/entries/max/qc0-demo")
check("saving again un-saves", json.loads(body)["hearts"] == 0, body[:200])
s, _, _ = anon.req("POST", "/max/qc0-demo/heart", data={"_csrf": "x"})
check("saving needs an account", s == 401, s)

# Users: trust alice.
text = page(maxv, "/admin/users")
uid = re.search(r'<a class="mono strong" href="/alice">alice</a>.*?action="/admin/users/(\d+)"', text, re.S)
if uid:
    s, _, _ = maxv.post(f"/admin/users/{uid.group(1)}", {"action": "trust"})
    check("trust alice", s == 303, s)

# Tokens and publishing through the API.
s, text, _ = maxv.post("/settings/tokens", {"name": "smoke", "days": "30"})
tok = re.search(r"(cactarium_[A-Za-z0-9_-]+)", text)
check("create an API token", s == 200 and tok is not None, s)
if tok:
    _, sim, _ = anon.get("/api/v1/sims/max/qc0-demo/1.0.0/download")
    s, body, hdrs = anon.req("POST", "/api/v1/sims/max/qc0-demo", raw=sim.encode(), headers={"Authorization": f"Bearer {tok.group(1)}"})
    check("publish a sim version through the API: the next major by default", s == 200 and '"max/qc0-demo@2.0.0"' in body, f"{s} {body[:200]}")
    s, body, _ = anon.req("POST", "/api/v1/sims/max/qc0-demo?version=2.0.1", raw=sim.encode(), headers={"Authorization": f"Bearer {tok.group(1)}"})
    check("or the version the uploader names", s == 200 and '"max/qc0-demo@2.0.1"' in body, f"{s} {body[:200]}")
    s, body, _ = anon.req("POST", "/api/v1/sims/max/qc0-demo?version=2.0.1", raw=sim.encode(), headers={"Authorization": f"Bearer {tok.group(1)}"})
    check("a sim version never changes", s == 409, f"{s} {body[:200]}")
    s, body, _ = anon.get("/api/v1/resolve?req=max/qc0-demo@2")
    check("@2 means the newest 2.x.x", s == 200 and json.loads(body)["slug"] == "max/qc0-demo@2.0.1", body[:200])
    s, body, _ = anon.get("/api/v1/resolve?req=max/qc0-demo@1")
    check("and @1 the newest 1.x.x", s == 200 and json.loads(body)["slug"] == "max/qc0-demo@1.0.0", body[:200])
    check("API responses carry api-generation", hdrs.get("api-generation") == "1", hdrs.get("api-generation"))
    s, body, _ = anon.req("POST", "/api/v1/sims/alice/qc0-demo", raw=sim.encode(), headers={"Authorization": f"Bearer {tok.group(1)}"})
    check("a token cannot publish under another owner", s == 403, s)
    # Every pin must be a registered package's repo, at a commit it has: not fully specified otherwise.
    import re as _re
    last_commit = _re.findall(r'commit = "([0-9a-f]{40})"', sim)[-1]
    fake = sim.replace(f'commit = "{last_commit}"', 'commit = "' + "0" * 40 + '"')
    s, body, _ = anon.req("POST", "/api/v1/sims/max/qc0-demo", raw=fake.encode(), headers={"Authorization": f"Bearer {tok.group(1)}"})
    check("a sim pinning a commit its package's repo doesn't have is refused", s == 400 and "ot fully specified" in body and "isn't in" in body, f"{s} {body[:240]}")
    bad = sim.replace('commit = "', 'commit = "zz', 1)
    s, body, _ = anon.req("POST", "/api/v1/sims/max/qc0-demo", raw=bad.encode(), headers={"Authorization": f"Bearer {tok.group(1)}"})
    check("an invalid .sim is refused with a message", s == 400 and '"code":"bad-request"' in body, f"{s} {body[:200]}")
    # An input that downloads an archive, unpacks it and fixes a path inside (sim format 2).
    import hashlib, io, tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"eosfile = /path/to/gam2.polytrope\n"
        info = tarfile.TarInfo("id/run.info")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(buf.getvalue()).hexdigest()
    archive_input = ('\n[[input]]\nknob = "archive-data"\ndescription = "archive data"\n'
                     'url = "https://example.org/id.tar.gz"\nsha256 = "' + digest + '"\nunpack = true\n'
                     'path = "id/run.info"\n\n[[input.fixup]]\nfile = "id/run.info"\n'
                     'replace = "/path/to/gam2.polytrope"\nwith = "{dir}/id/gam2.polytrope"\n')
    v2 = sim.replace("format = 1", "format = 2", 1) + archive_input
    auth = {"Authorization": f"Bearer {tok.group(1)}"}
    s, body, _ = anon.req("POST", "/api/v1/sims/max/qc0-demo", raw=v2.encode(), headers=auth)
    check("a sim with an unpacking input publishes", s == 200, f"{s} {body[:300]}")
    n = json.loads(body)["slug"].rsplit("@", 1)[1] if s == 200 else "0"
    text = page(anon, f"/max/qc0-demo/{n}?tab=inputs", contains="Downloads and unpacks")
    check("the sim page shows what an import fetches and edits", "id/run.info" in text and digest in text and "/path/to/gam2.polytrope" in text)
    for what, bad in [("unpack without a sha256", v2.replace('sha256 = "' + digest + '"\n', "")),
                      ("a member path with ..", v2.replace('path = "id/run.info"', 'path = "../run.info"')),
                      ("an unpacking input in a format-1 file", sim + archive_input)]:
        s, body, _ = anon.req("POST", "/api/v1/sims/max/qc0-demo", raw=bad.encode(), headers=auth)
        check(f"refused: {what}", s == 400, f"{s} {body[:200]}")

# Bare versions read npm-style: a full version is exact, 1.2 is ~1.2, 1 is ^1.
for req, want in [("1.0.0", "1.0.0"), ("=1.0.0", "1.0.0"), ("1.0", "1.0.0"), ("1", "1.1.0"), ("^1.0.0", "1.1.0"), ("~1.0.0", "1.0.0")]:
    s, body, _ = anon.get("/api/v1/resolve?req=" + urllib.parse.quote(f"max/carpetx@{req}"))
    check(f"max/carpetx@{req} resolves to {want}", s == 200 and json.loads(body)["slug"] == f"max/carpetx@{want}", body[:200])
s, body, _ = anon.get("/api/v1/resolve?req=max/carpetx@1.0.9")
check("an exact version that doesn't exist matches nothing", s == 400, f"{s} {body[:200]}")

# Yank and unyank.
text = page(maxv, "/max/carpetx?tab=versions")
vid = re.search(r'name="version_id" value="(\d+)"', text)
if vid:
    s, _, _ = maxv.post("/max/carpetx/yank", {"version_id": vid.group(1), "yank": "1", "reason": "smoke"})
    check("yank", s == 303, s)
    s, body, _ = anon.get("/api/v1/resolve?req=max/carpetx@^1")
    check("resolve skips the yanked version", s == 200 and json.loads(body)["slug"] != "max/carpetx@1.1.0", body[:200])
    s, body, _ = anon.get("/api/v1/resolve?req=max/carpetx@1.1.0")
    check("an exact request still reaches it, marked yanked",
          s == 200 and json.loads(body)["slug"] == "max/carpetx@1.1.0" and '"yanked":true' in body, body[:300])
    maxv.get("/max/carpetx?tab=versions")
    s, _, _ = maxv.post("/max/carpetx/yank", {"version_id": vid.group(1), "yank": "0"})
    check("unyank", s == 303, s)
    # The same from the command line, by someone who manages the entry.
    run = subprocess.run(["just", "cli", "yank", "max", "max/carpetx", "1.1.0", "--reason", "from the cli"], capture_output=True, text=True)
    check("just cli yank", run.returncode == 0 and "Yanked max/carpetx@1.1.0" in run.stdout, run.stdout + run.stderr[-300:])
    s, body, _ = anon.get("/api/v1/resolve?req=max/carpetx@%3D1.1.0")
    check("the cli yank shows, with its reason", '"yanked":true' in body and "from the cli" in body, body[:300])
    run = subprocess.run(["just", "cli", "yank", "alice", "max/carpetx", "1.1.0"], capture_output=True, text=True)
    check("only someone who manages the entry can yank it", run.returncode != 0 and "doesn't manage" in run.stdout + run.stderr, run.stdout + run.stderr[-300:])
    run = subprocess.run(["just", "cli", "unyank", "max", "max/carpetx", "1.1.0"], capture_output=True, text=True)
    check("just cli unyank", run.returncode == 0 and "Unyanked max/carpetx@1.1.0" in run.stdout, run.stdout + run.stderr[-300:])

# A snapshot release of a stack defined on the site.
maxv.get("/new/stack")
definition = 'format = 1\n\n[stack]\nname = "smoke-stack"\nextends = ["et/et-stack@2026.5.0"]\ndisable = ["CarpetX/Loop"]\n'
s, text, hdrs = maxv.post("/new/stack", {"definition": definition, "thornlist": "", "version": "0.1.0"})
check("cut a snapshot release", s == 303, f"{s} {text[:300]}")
s, body, _ = anon.get("/api/v1/stacks/max/smoke-stack/releases/0.1.0")
check("the release disables CarpetX/Loop", s == 200 and "#DISABLED CarpetX/Loop" in json.loads(body)["thornlist"]["text"], body[:200])
s, text, _ = maxv.post("/new/stack", {"definition": definition, "thornlist": "", "version": "0.1.0"})
check("a release never changes", s == 200 and "already exists" in text, s)

# Collisions are refused.
maxv.get("/new/stack")
clash = ("!CRL_VERSION = 1.0\n!DEFINE ROOT = Cactus\n!TARGET = $ROOT/arrangements\n!TYPE = git\n"
         "!URL = " + REPOS + "/cactusbase.git\n"
         "!REPO_PATH = $2\n!CHECKOUT =\nOther/Boundary\n")
s, text, _ = maxv.post("/new/stack", {"definition": definition.replace("smoke-stack", "clash"), "thornlist": clash, "version": "0.1.0"})
check("thorn-name collisions are refused", s == 200 and "collide" in text, text[text.find("alert"):][:300])
page(anon, "/max/clash", expect=404)  # a failed release leaves no entry behind
maxv.get("/new/stack")
s, text, _ = maxv.post("/new/stack", {"definition": definition.replace("smoke-stack", "squeezed"), "thornlist": clash.replace("!CHECKOUT =\nOther/Boundary", "!CHECKOUT = Other/Boundary"), "version": "0.1.0"})
check("a checkout-only thorn (on the !CHECKOUT line) is accepted, not treated as a collision", s == 303, f"{s} {text[text.find('alert'):][:200]}")
s, body, _ = anon.get("/api/v1/stacks/max/squeezed/releases/0.1.0")
check("the release keeps it checkout-only", s == 200 and "= Other/Boundary" in json.loads(body)["thornlist"]["text"], body[:300])
text = page(anon, "/max/carpetx")
check("the newest manifest's default track is shown first", 'pill mono selected" href="/max/carpetx?track=mixed-precision"' in text)

# Organizations.
text = page(anon, "/et", contains="Organization")
check("the et page lists its members", 'href="/max">max</a> <span class="muted">(owner)' in text)
alice = Visitor("alice")
bob = Visitor("bob")
page(alice, "/orgs/et", expect=403)
alice.get("/orgs/new")
s, text, _ = alice.post("/orgs/new", {"name": "et", "display_name": ""})
check("an organization cannot take a taken name", s == 200 and "taken" in text, s)
s, text, _ = alice.post("/orgs/new", {"name": "max", "display_name": ""})
check("an organization cannot take a user's name", s == 200 and "taken" in text, s)
s, _, hdrs = alice.post("/orgs/new", {"name": "alice-lab", "display_name": "Alice's Lab"})
check("anyone can create an organization", s == 303 and hdrs.get("location") == "/orgs/alice-lab", f"{s} {hdrs.get('location')}")
page(alice, "/orgs/alice-lab", contains="Add member")
page(anon, "/alice", contains="alice-lab")
alice.get("/new/stack")
s, text, _ = alice.post("/new/stack", {"owner": "et", "definition": definition.replace("smoke-stack", "alice-et"), "thornlist": "", "version": "0.1.0"})
check("a non-member cannot publish under an organization", s == 200 and "organization you belong to" in text, text[text.find("alert"):][:200])
maxv.get("/orgs/et")
s, _, _ = maxv.post("/orgs/et/members", {"username": "alice", "role": "member"})
check("an owner adds a member", s == 303, s)
alice = Visitor("alice")  # memberships load with the session's user
alice.get("/new/stack")
s, text, _ = alice.post("/new/stack", {"owner": "et", "definition": definition.replace("smoke-stack", "alice-et"), "thornlist": "", "version": "0.1.0"})
check("a member publishes under the organization", s == 303, f"{s} {text[text.find('alert'):][:200]}")
page(alice, "/et/carpetx", contains="Check for new tags now")

_, text, _ = bob.get("/et/carpetx")
check("a non-member cannot manage the organization's entries", "Check for new tags now" not in text)
s, _, _ = alice.post("/orgs/et/members", {"username": "bob", "role": "member"})
check("a plain member cannot add members", s == 403, s)
text = page(maxv, "/orgs/et")
mid = re.search(r'action="/orgs/et/members/(\d+)"', text)  # max, the only owner, is listed first
s, _, _ = maxv.post(f"/orgs/et/members/{mid.group(1)}", {"action": "member"})
check("the last owner cannot step down", s == 400, s)
text = page(alice, "/dashboard", contains="/orgs/et")
check("the dashboard shows the organization's entries", "et/alice-et" in text)

# Release review: a new release of a public entry is reviewed unless the entry, its owner (user or
# organization) or the publisher is trusted.
def queue_id(needle):
    """The review queue's submission for `needle` (owner/name or owner/name@version)."""
    _, text, _ = maxv.get("/admin")
    for sid, body in re.findall(r'href="/admin\?s=(\d+)">(.*?)</a>', text, re.S):
        if f">{needle}<" in body:
            return sid
    return None


def decide(needle, decision, note=""):
    sid = queue_id(needle)
    check(f"the queue lists {needle}", sid is not None)
    if sid is None:
        return 0
    s, _, _ = maxv.post(f"/admin/review/{sid}", {"decision": decision, "note": note, "seen": seen_of(sid)})
    return s


def cut(v, name, version, owner=""):
    v.get("/new/stack")
    d = f'format = 1\n\n[stack]\nname = "{name}"\nextends = ["et/et-stack@2026.5.0"]\n'
    s, text, _ = v.post("/new/stack", {"owner": owner, "definition": d, "thornlist": "", "version": version})
    check(f"{v.name} cuts {owner or v.name}/{name}@{version}", s == 303, f"{s} {text[text.find('alert'):][:200]}")


# alice was made trusted above; untrust her for this part, and wait out the per-minute limit on
# stack releases that the checks above used up.
text = page(maxv, "/admin/users")
alice_id = re.search(r'href="/alice">alice</a>.*?action="/admin/users/(\d+)"', text, re.S).group(1)
s, _, _ = maxv.post(f"/admin/users/{alice_id}", {"action": "untrust"})
check("untrust alice", s == 303, s)
time.sleep(61)

# Pins by tag: pin-tag pins every repo that has the tag, a repo's own [[stack.pin]] wins over it,
# and a repo without the tag follows its branch.
def git(repo, *args):
    return subprocess.run(["git", "-C", ENV["DEMO_REPOS"] + f"/{repo}.git", *args], check=True,
                          capture_output=True, text=True).stdout.strip()


git("cactusbase", "tag", "v1.1.0", "master")
moved = git("cactusbase", "commit-tree", "master^{tree}", "-p", "master", "-m", "After the tag")
git("cactusbase", "update-ref", "refs/heads/master", moved)  # the branch head is no longer the tag
want = {"carpetx": git("carpetx", "rev-parse", "v1.0.0^{commit}"),
        "cactusbase": git("cactusbase", "rev-parse", "v1.1.0^{commit}"),
        "spacetimex": git("spacetimex", "rev-parse", "master")}
tagged_th = "!CRL_VERSION = 1.0\n!DEFINE ROOT = Cactus\n" + "".join(
    f"\n!TARGET = $ROOT/arrangements\n!TYPE = git\n!URL = {REPOS}/{r}.git\n!REPO_PATH = $2\n!CHECKOUT =\n{t}\n"
    for r, t in [("carpetx", "CarpetX/Arith"), ("cactusbase", "CactusBase/IOUtil"), ("spacetimex", "SpacetimeX/NewRadX")])
tagged = ('format = 1\n\n[stack]\nname = "tagged"\nthornlist = "tagged.th"\npin-tag = "v1.1.0"\n\n'
          '[[stack.pin]]\nname = "carpetx"\ntag = "v1.0.0"\n')
maxv.get("/new/stack")
s, text, _ = maxv.post("/new/stack", {"definition": tagged, "thornlist": tagged_th, "version": "0.1.0"})
check("publish a release pinned by tags", s == 303, f"{s} {text[text.find('alert'):][:300]}")
s, body, _ = anon.get("/api/v1/stacks/max/tagged/releases/0.1.0")
got = {p["name"]: p.get("commit") for p in json.loads(body)["repo"]} if s == 200 else {}
check("a repo's own tag pin wins over pin-tag", got.get("carpetx") == want["carpetx"], got)
check("pin-tag pins a repo that has the tag", got.get("cactusbase") == want["cactusbase"], got)
check("a repo without the tag follows its branch", got.get("spacetimex") == want["spacetimex"], got)
maxv.get("/new/stack")
s, text, _ = maxv.post("/new/stack", {"definition": tagged.replace('tag = "v1.0.0"', 'tag = "v9.9.9"').replace('"tagged"', '"tagged2"'), "thornlist": tagged_th, "version": "0.1.0"})
check("a tag a [[stack.pin]] names must exist", s == 200 and "has no tag &#39;v9.9.9&#39;" in text, text[text.find("alert"):][:300])
cut(alice, "alice-rel", "1.0.0")
check("approve alice's new stack", decide("alice/alice-rel", "approve") == 303)
page(anon, "/alice/alice-rel/1.0.0")
cut(alice, "alice-rel", "1.1.0")
page(anon, "/alice/alice-rel/1.1.0", expect=404)
s, _, _ = anon.get("/api/v1/stacks/alice/alice-rel/releases/1.1.0")
check("an unreviewed release is not served by the API", s == 404, s)
s, body, _ = anon.get("/api/v1/stacks/alice/alice-rel/releases")
check("nor listed by it", s == 200 and "1.1.0" not in body and "1.0.0" in body, body[:200])
page(alice, "/alice/alice-rel?tab=versions", contains="awaiting review")
page(alice, "/dashboard", contains="alice/alice-rel@1.1.0")
check("a release cannot get 'changes requested'", decide("alice/alice-rel@1.1.0", "changes", "x") == 400)
check("approve the release", decide("alice/alice-rel@1.1.0", "approve") == 303)
page(anon, "/alice/alice-rel/1.1.0")
cut(alice, "alice-rel", "1.2.0")
check("reject a release", decide("alice/alice-rel@1.2.0", "reject", "Pin CarpetX.") == 303)
page(anon, "/alice/alice-rel/1.2.0", expect=404)
page(alice, "/dashboard", contains="Pin CarpetX.")

# A pushed tag is reviewed too.
subprocess.run(["git", "-C", ENV["DEMO_REPOS"] + "/spacetimex.git", "tag", "v0.2.0", "HEAD"], check=True)
s, body, _ = anon.req("POST", "/api/v1/packages/alice/spacetimex/refresh", headers={"Authorization": f"Bearer {tok.group(1)}"})
r = json.loads(body) if s == 200 else {}
check("an API refresh counts the tag as new and awaiting review",
      r.get("new-versions") == 1 and r.get("awaiting-review") == 1, f"{s} {body[:200]}")
page(anon, "/alice/spacetimex/0.2.0", expect=404)
page(maxv, "/admin", contains="alice (pushed a tag)")
check("approve the pushed tag", decide("alice/spacetimex@0.2.0", "approve") == 303)
page(anon, "/alice/spacetimex/0.2.0")

# A trusted entry's releases publish at once.
text = page(maxv, "/admin/entries?q=alice-rel")
eid = re.search(r'action="/admin/entries/(\d+)"', text).group(1)
s, _, _ = maxv.post(f"/admin/entries/{eid}", {"action": "trust"})
check("the superadmin trusts an entry", s == 303, s)
page(maxv, "/admin/entries?q=alice-rel", contains="trusted")
cut(alice, "alice-rel", "1.3.0")
page(anon, "/alice/alice-rel/1.3.0")

# So do a trusted organization's, and new entries under it.
page(anon, "/et/alice-et")  # created above while alice was trusted, so already public
cut(alice, "alice-et", "0.2.0", owner="et")
page(anon, "/et/alice-et/0.2.0", expect=404)
bob.get("/dashboard")
s, _, _ = bob.post("/orgs/et/trust", {"trusted": "true"})
check("only the superadmin trusts organizations by default", s == 403, s)
maxv.get("/orgs/et")
s, _, _ = maxv.post("/orgs/et/trust", {"trusted": "true"})
check("the superadmin trusts et", s == 303, s)
page(maxv, "/orgs/et", contains="Untrust organization")
page(maxv, "/admin/site", contains="trusted")
cut(alice, "alice-et", "0.3.0", owner="et")
page(anon, "/et/alice-et/0.3.0")
cut(alice, "alice-et2", "0.1.0", owner="et")
page(anon, "/et/alice-et2/0.1.0")
page(anon, "/et/alice-et/0.2.0", expect=404)  # trusting the owner later doesn't approve what waits
maxv.get("/orgs/et")
maxv.post("/orgs/et/trust", {"trusted": "false"})
maxv.get("/admin/users")
maxv.post(f"/admin/users/{alice_id}", {"action": "trust"})

# Trust: only the superadmin by default; the Site panel lets admins do it too.
text = page(maxv, "/admin/users")
bid = re.search(r'href="/bob">bob</a>.*?action="/admin/users/(\d+)"', text, re.S).group(1)
aid = re.search(r'href="/alice">alice</a>.*?action="/admin/users/(\d+)"', text, re.S).group(1)
s, _, _ = maxv.post(f"/admin/users/{aid}", {"action": "grant-admin"})
check("make alice an admin", s == 303, s)
alice = Visitor("alice")
text = page(alice, "/admin/users")
check("an admin sees no trust buttons by default", 'value="trust"' not in text)
s, _, _ = alice.post(f"/admin/users/{bid}", {"action": "trust"})
check("an admin cannot trust users by default", s == 400, s)
page(alice, "/admin/site", expect=403)
page(maxv, "/admin/site", contains="Who can mark users, organizations and entries trusted")
s, _, _ = maxv.post("/admin/site", {"trust_granted_by": "admins"})
check("the superadmin lets admins grant trust", s == 303, s)
alice.get("/admin/users")
s, _, _ = alice.post(f"/admin/users/{bid}", {"action": "trust"})
check("then an admin can trust users", s == 303, s)
maxv.get("/admin/site")
maxv.post("/admin/site", {"trust_granted_by": "superadmin"})
maxv.get("/admin/users")
maxv.post(f"/admin/users/{aid}", {"action": "revoke-admin"})

# Curated packages in bulk: a repo that is one thorn, versions from a tag pattern, a version by
# commit, then a hand-over once the repo carries its own cactarium.toml.
import os, tempfile
work = tempfile.mkdtemp()
lib = os.path.join(work, "fakelib")
os.makedirs(lib)
def sh(*args, cwd=lib):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()
sh("git", "init", "-q", "-b", "master")
for f, t in [("interface.ccl", "IMPLEMENTS: FakeLib\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n"), ("configuration.ccl", "PROVIDES FakeLib\n{\n}\n")]:
    open(os.path.join(lib, f), "w").write(t)
ident = ["-c", "user.name=smoke", "-c", "user.email=smoke@example.invalid"]
sh("git", "add", "-A"); sh("git", *ident, "commit", "-q", "-m", "FakeLib"); sh("git", "tag", "XT_2025_11_v0")
open(os.path.join(lib, "README.md"), "w").write("FakeLib\n")
sh("git", "add", "-A"); sh("git", *ident, "commit", "-q", "-m", "2026.05"); sh("git", "tag", "XT_2026_05_v0"); sh("git", "tag", "v9.9.9")
bare = ENV["DEMO_REPOS"] + "/fakelib.git"
subprocess.run(["rm", "-rf", bare], check=True)
sh("git", "clone", "-q", "--bare", lib, bare, cwd=work)
cdir = os.path.join(work, "curated")
os.makedirs(os.path.join(cdir, "manifests"))
open(os.path.join(cdir, "manifests", "fakelib.toml"), "w").write(
    'format = 1\n\n[package]\nname = "fakelib"\nowners = ["et"]\ndescription = "A one-thorn library repo"\n'
    'arrangement = "ExternalLibraries"\nthorns = ["FakeLib"]\ntag-pattern = "XT_{major}_{minor}_v{patch}"\nsince = "2026.5.0"\n')
open(os.path.join(cdir, "manifests", "cbase.toml"), "w").write(
    'format = 1\n\n[package]\nname = "cbase"\nowners = ["et"]\ndescription = "CactusBase, by commit"\narrangement = "CactusBase"\n')
cb_head = git("cactusbase", "rev-parse", "master")
open(os.path.join(cdir, "curate.toml"), "w").write(
    f'[[package]]\nowner = "et"\nurl = "{REPOS}/fakelib.git"\nmanifest = "manifests/fakelib.toml"\n\n'
    f'[[package]]\nowner = "et"\nurl = "{REPOS}/cactusbase.git"\nmanifest = "manifests/cbase.toml"\n\n'
    f'[[package.version]]\nversion = "1.0.0"\ncommit = "{cb_head}"\n')
run = subprocess.run(["just", "curate", "max", os.path.join(cdir, "curate.toml")], capture_output=True, text=True)
check("just curate creates the packages", run.returncode == 0 and "et/fakelib: created; versions: 2026.5.0" in run.stdout
      and "et/cbase: created, 1 added by commit" in run.stdout, run.stdout[-600:] + run.stderr[-300:])
# (et/cbase also takes cactusbase's v1.1.0 tag from the tag-pin checks above: no pattern means vX.Y.Z tags.)
run = subprocess.run(["just", "curate", "max", os.path.join(cdir, "curate.toml")], capture_output=True, text=True)
check("running it again only updates", run.returncode == 0 and "et/fakelib: updated; versions: 2026.5.0" in run.stdout
      and "added by commit" not in run.stdout, run.stdout[-600:])
s, body, _ = anon.get("/api/v1/packages/et/fakelib/versions")
d = json.loads(body) if s == 200 else {"versions": []}
check("only tags matching the pattern, from since on, become versions",
      [v["version"] for v in d["versions"]] == ["2026.5.0"], body[:300])
check("a one-thorn repo publishes its thorn, reached as the ET does (../$1-$2)", '"thorn":"FakeLib"' in body and '"arrangement":"ExternalLibraries"' in body and '"repo-path":"../$1-$2"' in body, body[:400])
s, body, _ = anon.get("/api/v1/packages/max/carpetx/versions")
check("a thorn at the repo root is reached as $2", '"thorn":"Arith","repo-path":"$2"' in body.replace('"arrangement":"CarpetX",', ''), body[:400])
page(maxv, "/admin/curated", contains="versions from tags matching XT_{major}_{minor}_v{patch}, from 2026.5.0 on")
text = page(maxv, "/admin/curated")
fid = re.search(r'href="/et/fakelib">et/fakelib</a>.*?action="/admin/curated/(\d+)/hand-over"', text, re.S).group(1)
s, text, _ = maxv.post(f"/admin/curated/{fid}/hand-over", {})
check("no hand-over before the repo has a cactarium.toml", s == 200 and "has no cactarium.toml yet" in text, text[text.find("alert"):][:300])
open(os.path.join(lib, "cactarium.toml"), "w").write(
    'format = 1\n\n[package]\nname = "fakelib"\nowners = ["et"]\ndescription = "FakeLib, from its own manifest"\n'
    'arrangement = "ExternalLibraries"\nthorns = ["FakeLib"]\ntag-pattern = "XT_{major}_{minor}_v{patch}"\n')
sh("git", "add", "-A"); sh("git", *ident, "commit", "-q", "-m", "cactarium.toml"); sh("git", "tag", "XT_2026_11_v0")
sh("git", "push", "-q", bare, "master", "--tags")
maxv.get("/admin/curated")
s, _, _ = maxv.post(f"/admin/curated/{fid}/hand-over", {})
check("hand over to the repo's manifest", s == 303, s)
text = page(maxv, "/admin/curated")
check("it is no longer curated", 'href="/et/fakelib"' not in text)
s, body, _ = anon.get("/api/v1/packages/et/fakelib/versions")
check("its versions stay", s == 200 and '"version":"2026.5.0"' in body, body[:300])
text = page(maxv, "/et/fakelib?tab=versions")
check("its next tag follows the repo manifest's own tag-pattern (et isn't trusted, so it waits for review)",
      "2026.11.0" in text and "awaiting review" in text, text[text.find("<table"):][:500])

# A repo whose cactarium.toml gives a tag-pattern registers like any other, though it has no vX.Y.Z tag.
plib = os.path.join(work, "patlib")
os.makedirs(os.path.join(plib, "PatThorn"))
for f, t in [("interface.ccl", "IMPLEMENTS: PatThorn\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n")]:
    open(os.path.join(plib, "PatThorn", f), "w").write(t)
open(os.path.join(plib, "cactarium.toml"), "w").write(
    'format = 1\n\n[package]\nname = "patlib"\nowners = ["et"]\ndescription = "Released with ET-style tags"\n'
    'arrangement = "PatArr"\ntag-pattern = "XT_{major}_{minor}_v{patch}"\n')
sh("git", "init", "-q", "-b", "master", cwd=plib)
sh("git", "add", "-A", cwd=plib); sh("git", *ident, "commit", "-q", "-m", "patlib", cwd=plib); sh("git", "tag", "XT_2026_05_v1", cwd=plib)
pbare = ENV["DEMO_REPOS"] + "/patlib.git"
subprocess.run(["rm", "-rf", pbare], check=True)
sh("git", "clone", "-q", "--bare", plib, pbare, cwd=work)
maxv.get("/new/repo")
s, text, _ = maxv.post("/new/repo", {"url": REPOS + "/patlib.git", "owner": "et"})
check("a repo with only pattern tags registers", s == 303, f"{s} {text[text.find('alert'):][:300]}")
s, body, _ = anon.get("/api/v1/packages/et/patlib/versions")
check("its pattern tag is its version", s == 200 and '"version":"2026.5.1"' in body and '"tag":"XT_2026_05_v1"' in body, body[:300])

# Moving a registered repo to a new URL: only one that holds the same tags at the same commits.
moved = ENV["DEMO_REPOS"] + "/fakelib-moved.git"
subprocess.run(["rm", "-rf", moved], check=True)
sh("git", "clone", "-q", "--bare", bare, moved, cwd=work)
text = page(maxv, "/admin/entries?q=fakelib")
feid = re.search(r'action="/admin/entries/(\d+)"', text).group(1)
s, text, _ = maxv.post(f"/admin/entries/{feid}", {"action": "move-repo", "new_url": REPOS + "/patlib.git"})
check("a repo with other history is refused", s == 200 and "doesn&#39;t hold" in text, text[text.find("alert"):][:300])
maxv.get("/admin/entries?q=fakelib")
s, _, _ = maxv.post(f"/admin/entries/{feid}", {"action": "move-repo", "new_url": REPOS + "/fakelib-moved.git"})
check("the same repo at a new URL is accepted", s == 303, s)
s, body, _ = anon.get("/api/v1/packages/et/fakelib/versions")
check("versions now name the new URL", s == 200 and "fakelib-moved.git" in body, body[:300])

# A sim published from its repo: cactarium-sim.toml names the .sim; each version tag is a version.
_, qc0, _ = anon.get("/api/v1/sims/max/qc0-demo/1.0.0/download")
srepo = os.path.join(work, "simrepo")
os.makedirs(os.path.join(srepo, "runs"))
# Its .sim reads one input from the repo itself (repo-file, sim format 3).
repo_input = '\n[[input]]\nknob = "repo-data"\ndescription = "a file kept beside the sim"\nrepo-file = "data/blob.txt"\n'
open(os.path.join(srepo, "runs", "qc0.sim"), "w").write(qc0.replace("format = 1", "format = 3", 1) + repo_input)
os.makedirs(os.path.join(srepo, "data"))
open(os.path.join(srepo, "data", "blob.txt"), "w").write("data\n")
open(os.path.join(srepo, "cactarium-sim.toml"), "w").write(
    'format = 1\n\n[sim]\nname = "repo-sim"\nowners = ["max"]\nfile = "runs/qc0.sim"\n'
    'description = "A sim kept in its repo"\ncontact = "https://example.org/sim-help"\n')
sh("git", "init", "-q", "-b", "master", cwd=srepo)
sh("git", "add", "-A", cwd=srepo); sh("git", *ident, "commit", "-q", "-m", "sim", cwd=srepo); sh("git", "tag", "v1.0.0", cwd=srepo)
stag = sh("git", "rev-parse", "HEAD", cwd=srepo)
sbare = ENV["DEMO_REPOS"] + "/simrepo.git"
subprocess.run(["rm", "-rf", sbare], check=True)
sh("git", "clone", "-q", "--bare", srepo, sbare, cwd=work)
maxv.get("/new/repo")
s, text, _ = maxv.post("/new/repo", {"url": REPOS + "/simrepo.git", "owner": "max"})
check("register a repo that carries cactarium-sim.toml", s == 303, f"{s} {text[text.find('alert'):][:300]}")
s, body, _ = anon.get("/api/v1/resolve?req=max/repo-sim@1")
check("its tag is a sim version, with the repo and commit to fetch from",
      s == 200 and '"slug":"max/repo-sim@1.0.0"' in body and "simrepo.git" in body and stag in body, body[:300])
s, body, _ = anon.get("/api/v1/sims/max/repo-sim/1.0.0/download")
check("the stored file is stamped with its version", s == 200 and 'cactarium = "max/repo-sim@1.0.0"' in body, body[:200])
page(anon, "/max/repo-sim", contains="A sim kept in its repo")
s, body, _ = anon.get("/api/v1/resolve?req=max/repo-sim@1")
check("cactarium-sim.toml's contact wins over the file's", '"contact":"https://example.org/sim-help"' in body, body[:300])
text = page(maxv, "/max/repo-sim")
check("its managers get the repo controls, with each forge's webhook URL",
      "Check for new tags now" in text and "/hooks/gitlab/" in text and "/hooks/bitbucket/" in text and "Upload a new version" not in text)
for d in ["/docs/publishing", "/docs/packages", "/docs/stacks", "/docs/sims", "/docs/versions", "/docs/review",
          "/docs/organizations", "/docs/curated", "/docs/finding", "/docs/api"]:
    page(anon, d)
page(anon, "/docs/nonsense", expect=404)
s, body, _ = anon.req("POST", "/api/v1/sims/max/repo-sim", raw=qc0.encode(), headers={"Authorization": f"Bearer {tok.group(1)}"})
check("a sim released from its repo takes no uploads", s == 400 and "released from its repo" in body, f"{s} {body[:200]}")
page(anon, "/max/repo-sim/1.0.0?tab=inputs", contains="from the sim's repo")
s, body, _ = anon.req("POST", "/api/v1/sims/max/qc0-demo", raw=(qc0.replace("format = 1", "format = 3", 1) + repo_input).encode(),
                      headers={"Authorization": f"Bearer {tok.group(1)}"})
check("an uploaded sim can't read files from a repo", s == 400 and "repo-file" in body, f"{s} {body[:200]}")
# A tag whose repo-file is missing becomes an invalid version, with the reason.
os.remove(os.path.join(srepo, "data", "blob.txt"))
sh("git", "add", "-A", cwd=srepo); sh("git", *ident, "commit", "-q", "-m", "drop the data", cwd=srepo); sh("git", "tag", "v1.1.0", cwd=srepo)
sh("git", "push", "-q", sbare, "master", "--tags", cwd=srepo)
maxv.get("/max/repo-sim")
maxv.post("/max/repo-sim/refresh", {})
text = page(maxv, "/max/repo-sim?tab=versions")
check("a tag whose repo-file is missing is invalid, with the reason", "1.1.0" in text and "not a file in the repo" in text, text[text.find("<table"):][:600])

# A package's @head and @master: its default branch's tip, read now; unpinned, and refused for an
# untrusted package unless the site allows untrusted tips.
head = git("carpetx", "rev-parse", "master")
s, body, hdrs = anon.get("/api/v1/packages/max/carpetx/versions/head")
check("a package's @head is its default branch's tip, with its thorns",
      s == 200 and f'"commit":"{head}"' in body and '"version":"head"' in body and '"thorn":"Arith"' in body
      and hdrs.get("x-cactarium-unpinned") == "true" and hdrs.get("x-cactarium-untrusted") == "false", f"{s} {body[:300]} {hdrs}")
s, body, _ = anon.get("/api/v1/resolve?req=max/carpetx@master")
check("resolve takes a package's @master", s == 200 and '"slug":"max/carpetx@master"' in body and head in body, body[:300])
s, body, _ = anon.get("/api/v1/packages/et/fakelib/versions/head")
check("an untrusted package's @head is refused by default", s == 403 and "isn't trusted" in body, f"{s} {body[:200]}")
s, _, _ = anon.get("/api/v1/packages/max/carpetx/versions/tip")
check("only head and master are tips", s == 404, s)

# A package at one full commit id: a commit a version froze is that version; any other commit is
# the package as it is there, which an untrusted package serves only if the site allows it.
v110 = git("carpetx", "rev-parse", "v1.1.0^{commit}")
s, body, _ = anon.get(f"/api/v1/resolve?req=max/carpetx@{v110}")
check("a commit a version froze resolves as that version", s == 200 and json.loads(body)["slug"] == "max/carpetx@1.1.0", body[:200])
# A commit no version froze, on a branch of its own.
unrel = git("carpetx", "commit-tree", "master^{tree}", "-p", "master", "-m", "Unreleased")
git("carpetx", "update-ref", "refs/heads/unreleased", unrel)
s, body, hdrs = anon.get(f"/api/v1/resolve?req=max/carpetx@{unrel}")
check("another commit of a trusted package is the package at that commit (named with #)",
      s == 200 and json.loads(body)["slug"] == f"max/carpetx#{unrel}" and f'"commit":"{unrel}"' in body
      and hdrs.get("x-cactarium-untrusted") == "false" and "x-cactarium-unpinned" not in hdrs, f"{s} {body[:200]} {hdrs}")
s, body, _ = anon.get(f"/api/v1/packages/max/carpetx/versions/{unrel}")
check("versions/<commit> gives its thorns", s == 200 and '"thorn":"Arith"' in body and f'"version":"{unrel}"' in body, f"{s} {body[:200]}")
fv = git("fakelib-moved", "rev-parse", "XT_2026_05_v0^{commit}")
fold = git("fakelib-moved", "rev-parse", "XT_2025_11_v0^{commit}")
s, body, _ = anon.get(f"/api/v1/resolve?req=et/fakelib@{fv}")
check("an untrusted package's version commit is still served, as the version", s == 200 and json.loads(body)["slug"] == "et/fakelib@2026.5.0", body[:200])
s, body, _ = anon.get(f"/api/v1/packages/et/fakelib/versions/{fv}")
check("versions/<that commit> is the version", s == 200 and '"version":"2026.5.0"' in body, f"{s} {body[:200]}")
s, body, _ = anon.get(f"/api/v1/resolve?req=et/fakelib@{fold}")
check("an untrusted package at a commit no version froze is refused by default", s == 403 and "no published version is at that commit" in body, f"{s} {body[:200]}")
# Abbreviated ids (7+ hex digits), resolved against the repo's history; '#' names only commits,
# '@' tries a commit only after every other reading.
s, body, _ = anon.get(f"/api/v1/resolve?req=" + urllib.parse.quote(f"max/carpetx#{unrel[:7]}"))
check("#<abbreviated> resolves to the full commit", s == 200 and json.loads(body)["slug"] == f"max/carpetx#{unrel}", body[:200])
s, body, _ = anon.get(f"/api/v1/resolve?req=max/carpetx@{unrel[:9]}")
check("@<abbreviated> falls back to the commit when it names no version", s == 200 and json.loads(body)["slug"] == f"max/carpetx#{unrel}", body[:200])
s, body, _ = anon.get(f"/api/v1/packages/max/carpetx/versions/{unrel[:8]}")
check("versions/<abbreviated> reads the package there", s == 200 and f'"version":"{unrel}"' in body, f"{s} {body[:200]}")
s, body, _ = anon.get(f"/api/v1/packages/max/carpetx/versions/{v110[:7]}")
check("an abbreviated version commit is the version", s == 200 and '"version":"1.1.0"' in body, f"{s} {body[:200]}")
s, body, _ = anon.get("/api/v1/resolve?req=" + urllib.parse.quote("max/carpetx#0000000"))
check("a prefix no commit has is refused", s == 400 and "has no commit 0000000" in body, f"{s} {body[:200]}")
s, body, _ = anon.get("/api/v1/resolve?req=" + urllib.parse.quote("max/carpetx#beef12"))
check("'#' needs at least 7 hex digits", s == 400, f"{s} {body[:200]}")
s, body, _ = anon.get("/api/v1/resolve?req=max/carpetx@1.0.0")
check("@ prefers a version over everything else", s == 200 and json.loads(body)["slug"] == "max/carpetx@1.0.0", body[:200])

print()
if FAILED:
    print(f"{len(FAILED)} failed")
    sys.exit(1)
print("all passed")
