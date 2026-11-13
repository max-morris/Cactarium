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
ENV_DIR = __file__.rsplit("/", 1)[0] or "."
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
# An admin reviewing can fetch what awaits review (CactUp's --risky-allow-untrusted-artifacts sends
# the header); nobody else can, header or not.
REV = {"x-cactarium-include-unreviewed": "true"}
pending_req = "/api/v1/resolve?req=alice/spacetimex@0.2.0"
s, _, _ = anon.get(pending_req)
check("a release awaiting review isn't served", s in (400, 404), s)
s, _, _ = anon.get(pending_req, headers=REV)
check("asking for unreviewed versions without a token changes nothing", s in (400, 404), s)
alice.get("/settings")
_, atext, _ = alice.post("/settings/tokens", {"name": "smoke-alice", "days": "30"})
atok = re.search(r"(cactarium_[A-Za-z0-9_-]+)", atext)
if atok:
    s, _, _ = anon.get(pending_req, headers={**REV, "Authorization": f"Bearer {atok.group(1)}"})
    check("nor with a token that isn't an admin's", s in (400, 404), s)
if tok:
    s, body, hdrs = anon.get(pending_req, headers={**REV, "Authorization": f"Bearer {tok.group(1)}"})
    check("an admin who asks gets it, marked unreviewed",
          s == 200 and json.loads(body)["slug"] == "alice/spacetimex@0.2.0" and hdrs.get("x-cactarium-unreviewed") == "true",
          f"{s} {body[:160]} {hdrs.get('x-cactarium-unreviewed')}")
    s, body, hdrs = anon.get("/api/v1/packages/alice/spacetimex/versions", headers={**REV, "Authorization": f"Bearer {tok.group(1)}"})
    check("and in the version list", s == 200 and '"version":"0.2.0"' in body and hdrs.get("x-cactarium-unreviewed") == "true", f"{s} {body[:160]}")
page(maxv, f"/admin?s={queue_id('alice/spacetimex@0.2.0')}", contains="cactup add alice/spacetimex@0.2.0 --risky-allow-untrusted-artifacts")
# When the site serves unreviewed code, anyone who asks gets a release awaiting review, marked.
maxv.get("/admin/site")
maxv.post("/admin/site", {"untrusted_tips": "allow"})
s, body, hdrs = anon.get(pending_req, headers=REV)
check("with untrusted-tips allowed, anyone who asks gets a release awaiting review, marked",
      s == 200 and hdrs.get("x-cactarium-unreviewed") == "true", f"{s} {body[:160]}")
s, _, _ = anon.get(pending_req)
check("but still not without asking", s in (400, 404), s)
maxv.get("/admin/site")
maxv.post("/admin/site", {"untrusted_tips": "refuse"})
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

# A library package (FUKA's shape): no thorns; the package that builds against it says where it goes.
dlib = os.path.join(work, "demolib")
os.makedirs(os.path.join(dlib, "src"))
open(os.path.join(dlib, "CMakeLists.txt"), "w").write("project(demolib)\n")
open(os.path.join(dlib, "src", "lib.cc"), "w").write("int demolib() { return 0; }\n")
open(os.path.join(dlib, "cactarium.toml"), "w").write(
    'format = 1\n\n[package]\nname = "demolib"\nowners = ["et"]\ndescription = "A library thorns build against"\nlibrary = true\n')
sh("git", "init", "-q", "-b", "master", cwd=dlib)
sh("git", "add", "-A", cwd=dlib); sh("git", *ident, "commit", "-q", "-m", "demolib", cwd=dlib); sh("git", "tag", "v1.0.0", cwd=dlib)
dbare = ENV["DEMO_REPOS"] + "/demolib.git"
subprocess.run(["rm", "-rf", dbare], check=True)
sh("git", "clone", "-q", "--bare", dlib, dbare, cwd=work)
maxv.get("/new/repo")
s, text, _ = maxv.post("/new/repo", {"url": REPOS + "/demolib.git", "owner": "et"})
check("a library package registers, though it has no thorns", s == 303, f"{s} {text[text.find('alert'):][:300]}")
s, body, _ = anon.get("/api/v1/packages/et/demolib/versions")
check("it is served as a library with no thorns", s == 200 and '"library":true' in body and '"thorns":[]' in body, body[:300])
kdem = os.path.join(work, "kadathdemo")
os.makedirs(os.path.join(kdem, "KadathDemo", "src"))
for f, t in [("interface.ccl", "IMPLEMENTS: KadathDemo\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n")]:
    open(os.path.join(kdem, "KadathDemo", f), "w").write(t)
open(os.path.join(kdem, "KadathDemo", "src", "make.code.defn"), "w").write("SRCS =\n")
def kmanifest(dep):
    open(os.path.join(kdem, "cactarium.toml"), "w").write(
        'format = 1\n\n[package]\nname = "kadathdemo"\nowners = ["max"]\ndescription = "Builds demolib from src/demolib"\n'
        'arrangement = "Fuka"\n\n[[dependency]]\ntarget = "et/demolib"\nneeded-by = ["KadathDemo"]\n' + dep)
def ktag(msg, tag):
    sh("git", "add", "-A", cwd=kdem); sh("git", *ident, "commit", "-q", "-m", msg, cwd=kdem); sh("git", "tag", tag, cwd=kdem)
sh("git", "init", "-q", "-b", "master", cwd=kdem)
kmanifest('into = "KadathDemo/src/demolib"\n'); ktag("kadathdemo", "v1.0.0")
kbare = ENV["DEMO_REPOS"] + "/kadathdemo.git"
subprocess.run(["rm", "-rf", kbare], check=True)
sh("git", "clone", "-q", "--bare", kdem, kbare, cwd=work)
maxv.get("/new/repo")
s, text, _ = maxv.post("/new/repo", {"url": REPOS + "/kadathdemo.git", "owner": "max"})
check("a package depending on a library registers", s == 303, f"{s} {text[text.find('alert'):][:300]}")
# Later tags with mistakes (registration reads the newest tag first and would refuse them).
kmanifest(''); ktag("forget into", "v1.1.0")
kmanifest('into = "KadathDemo/src"\n'); ktag("into a folder in use", "v1.2.0")
sh("git", "push", "-q", kbare, "master", "--tags", cwd=kdem)
subprocess.run(["just", "cli", "sync", "max/kadathdemo"], capture_output=True, text=True)
s, body, _ = anon.get("/api/v1/packages/max/kadathdemo/versions")
check("its dependency carries into, and no needs", s == 200 and '"into":"KadathDemo/src/demolib"' in body
      and '"target":"et/demolib"' in body and '"needs"' not in body, body[:500])
page(anon, "/max/kadathdemo", contains="checked out into")
text = page(maxv, "/max/kadathdemo?tab=versions")
check("a dependency on a library without into is refused, saying how to fix it",
      "1.1.0" in text and "is a library: say where its checkout goes with into" in text, text[text.find("<table"):][:900])
check("into a folder the repo already has is refused",
      "1.2.0" in text and "which this commit already has" in text, text[text.find("<table"):][:900])

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

# Only facts about the commit make a version invalid. A file from a newer format than this server
# reads, a pinned package that isn't public yet, or a repo history that can't be read right now
# leaves the tag unread: it is read again at the next sync, never frozen.
def cli_sync(slug):
    """`just cli sync`: (ok, output). Not rate-limited, unlike the refresh button and API."""
    run = subprocess.run(["just", "cli", "sync", slug], capture_output=True, text=True)
    return run.returncode == 0, run.stdout + run.stderr
def has_version(v, slug, label):
    """Whether the entry's version list links `label` (a multi-sim entry's links carry ?sim=)."""
    return re.search(rf'href="/{re.escape(slug)}/{re.escape(label)}["?]', v.get(f"/{slug}?tab=versions")[1]) is not None
def retag(cwd, bare, tag):
    """Commit what changed and (re)point `tag` at it, upstream too."""
    sh("git", "add", "-A", cwd=cwd); sh("git", *ident, "commit", "-q", "--allow-empty", "-m", tag, cwd=cwd)
    sh("git", "tag", "-f", tag, cwd=cwd)
    sh("git", "push", "-q", "--force", bare, "master", f"refs/tags/{tag}", cwd=cwd)
open(os.path.join(srepo, "data", "blob.txt"), "w").write("data\n")
good_sim = open(os.path.join(srepo, "runs", "qc0.sim")).read()
open(os.path.join(srepo, "runs", "qc0.sim"), "w").write(good_sim.replace("format = 3", "format = 99", 1))
retag(srepo, sbare, "v1.2.0")
ok, out = cli_sync("max/repo-sim")
check("a .sim from a newer format leaves its tag unread, to be read again",
      not ok and "format 99" in out and "tried again" in out, out[-400:])
check("and stores no version for it", not has_version(maxv, "max/repo-sim", "1.2.0"))
open(os.path.join(srepo, "runs", "qc0.sim"), "w").write(good_sim)
retag(srepo, sbare, "v1.2.0")
ok, out = cli_sync("max/repo-sim")
check("once the tag holds a file this server reads, it becomes a version", ok and "1 new versions" in out, out[-400:])
manifest_text = open(os.path.join(srepo, "cactarium-sim.toml")).read()
open(os.path.join(srepo, "cactarium-sim.toml"), "w").write(manifest_text.replace("format = 1", "format = 99", 1))
retag(srepo, sbare, "v1.3.0")
ok, out = cli_sync("max/repo-sim")
check("a manifest from a newer format leaves its tag unread too", not ok and "format 99" in out, out[-400:])
open(os.path.join(srepo, "cactarium-sim.toml"), "w").write(manifest_text)
retag(srepo, sbare, "v1.3.0")
ok, out = cli_sync("max/repo-sim")
check("and is read once fixed", ok and "1 new versions" in out, out[-400:])
def tiny_package(name, owner, arr):
    """A one-thorn package repo with tag v1.0.0 and one untagged commit after it: (dir, bare, tagged, untagged)."""
    d = os.path.join(work, name)
    os.makedirs(os.path.join(d, arr + "Thorn"))
    for f, t in [("interface.ccl", f"IMPLEMENTS: {arr}Thorn\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n")]:
        open(os.path.join(d, arr + "Thorn", f), "w").write(t)
    open(os.path.join(d, "cactarium.toml"), "w").write(
        f'format = 1\n\n[package]\nname = "{name}"\nowners = ["{owner}"]\ndescription = "A package sims pin"\narrangement = "{arr}"\n')
    sh("git", "init", "-q", "-b", "master", cwd=d)
    sh("git", "add", "-A", cwd=d); sh("git", *ident, "commit", "-q", "-m", name, cwd=d); sh("git", "tag", "v1.0.0", cwd=d)
    tagged = sh("git", "rev-parse", "HEAD", cwd=d)
    open(os.path.join(d, "README.md"), "w").write("later\n")
    sh("git", "add", "-A", cwd=d); sh("git", *ident, "commit", "-q", "-m", "after the tag", cwd=d)
    untagged = sh("git", "rev-parse", "HEAD", cwd=d)
    b = ENV["DEMO_REPOS"] + f"/{name}.git"
    subprocess.run(["rm", "-rf", b], check=True)
    sh("git", "clone", "-q", "--bare", d, b, cwd=work)
    return d, b, tagged, untagged

def pin_sim(name, pins):
    """A fully specified .sim checking out one thorn from each (repo, arrangement, url, commit)."""
    th = "!CRL_VERSION = 1.0\n!DEFINE ROOT = Cactus\n" + "".join(
        f"\n!TARGET = $ROOT/arrangements\n!TYPE = git\n!URL = {url}\n!REPO_PATH = $2\n!CHECKOUT =\n{arr}/{arr}Thorn\n"
        for _, arr, url, _ in pins)
    repos = "".join(f'\n[[repo]]\nname = "{r}"\nurl = "{url}"\ncommit = "{c}"\n' for r, _, url, c in pins)
    q = "'" * 3
    return (f'format = 1\n\n[sim]\nname = "{name}"\nsummary = "The {name} run"\nlicense = "CC0-1.0"\nroot = "Cactus"\n\n'
            f'[thornlist]\nfilename = "{name}.th"\ntext = {q}\n{th}{q}\n\n'
            f'[parfile]\nfilename = "{name}.par"\nkind = "par"\ntext = {q}\nActiveThorns = "{name}"\n{q}\n{repos}')

pdir, pbare_pkg, ptagged, puntagged = tiny_package("pinpkg", "max", "PinArr")
maxv.get("/new/repo")
s, text, _ = maxv.post("/new/repo", {"url": REPOS + "/pinpkg.git", "owner": "max"})
check("register a package that sims pin", s == 303, f"{s} {text[text.find('alert'):][:300]}")
psim = os.path.join(work, "pinsim")
os.makedirs(psim)
psbare = ENV["DEMO_REPOS"] + "/pinsim.git"
open(os.path.join(psim, "cactarium-sim.toml"), "w").write('format = 1\n\n[sim]\nname = "pinsim"\nowners = ["max"]\nfile = "pin.sim"\n')
open(os.path.join(psim, "pin.sim"), "w").write(pin_sim("pinsim", [("pinpkg", "PinArr", REPOS + "/pinpkg.git", ptagged)]))
sh("git", "init", "-q", "-b", "master", cwd=psim)
sh("git", "add", "-A", cwd=psim); sh("git", *ident, "commit", "-q", "-m", "pinsim", cwd=psim); sh("git", "tag", "v1.0.0", cwd=psim)
subprocess.run(["rm", "-rf", psbare], check=True)
sh("git", "clone", "-q", "--bare", psim, psbare, cwd=work)
maxv.get("/new/repo")
s, text, _ = maxv.post("/new/repo", {"url": REPOS + "/pinsim.git", "owner": "max"})
check("register a sim repo pinning a version's commit", s == 303, f"{s} {text[text.find('alert'):][:300]}")
page(anon, "/max/pinsim/1.0.0")
# The pinned package's repo goes away for a while, as a host that doesn't answer would.
open(os.path.join(psim, "pin.sim"), "w").write(pin_sim("pinsim", [("pinpkg", "PinArr", REPOS + "/pinpkg.git", puntagged)]))
os.rename(pbare_pkg, pbare_pkg + ".away")
retag(psim, psbare, "v1.1.0")
ok, out = cli_sync("max/pinsim")
check("a pin whose repo history can't be read right now leaves the tag unread",
      not ok and "be checked yet" in out and "max/pinpkg" in out and "tried again" in out, out[-400:])
check("with no version stored for it", not has_version(maxv, "max/pinsim", "1.1.0"))
os.rename(pbare_pkg + ".away", pbare_pkg)
back = time.time()  # a failed history read is remembered for a minute
# A pinned package that is registered but not public yet: the tag waits for it.
text = page(maxv, "/admin/users")
bid = re.search(r'href="/bob">bob</a>.*?action="/admin/users/(\d+)"', text, re.S).group(1)
maxv.post(f"/admin/users/{bid}", {"action": "untrust"})
_, qbare, qtagged, _ = tiny_package("pendpkg", "bob", "PendArr")
bob = Visitor("bob")
bob.get("/new/repo")
s, text, _ = bob.post("/new/repo", {"url": REPOS + "/pendpkg.git", "owner": ""})
check("bob registers a package that waits for review", s == 303, f"{s} {text[text.find('alert'):][:300]}")
open(os.path.join(psim, "pin.sim"), "w").write(pin_sim("pinsim", [("pinpkg", "PinArr", REPOS + "/pinpkg.git", ptagged),
                                                                   ("pendpkg", "PendArr", REPOS + "/pendpkg.git", qtagged)]))
retag(psim, psbare, "v1.2.0")
ok, out = cli_sync("max/pinsim")
check("a pin to a package awaiting review leaves the tag unread", not ok and "public yet" in out, out[-400:])
check("approve bob's package", decide("bob/pendpkg", "approve") == 303)
time.sleep(max(0, 62 - (time.time() - back)))
ok, out = cli_sync("max/pinsim")
# (The dev site's poller may have read one of them first.)
check("once the repo answers and the package is public, both tags are read",
      ok and has_version(anon, "max/pinsim", "1.1.0") and has_version(anon, "max/pinsim", "1.2.0"), out[-400:])
page(anon, "/max/pinsim/1.1.0?tab=pins", contains="max/pinpkg")
page(anon, "/max/pinsim/1.2.0?tab=pins", contains="bob/pendpkg@1.0.0")
# A pin to a repo no package is registered for yet waits too: registering it makes the commit valid.
_, _, ntagged, _ = tiny_package("nobody", "max", "NoArr")
open(os.path.join(psim, "pin.sim"), "w").write(pin_sim("pinsim", [("pinpkg", "PinArr", REPOS + "/pinpkg.git", ptagged),
                                                                   ("nobody", "NoArr", REPOS + "/nobody.git", ntagged)]))
retag(psim, psbare, "v1.3.0")
ok, out = cli_sync("max/pinsim")
text = page(maxv, "/max/pinsim?tab=versions")
check("a pin to a repo no package is registered for yet leaves the tag unread",
      not ok and "the repo of any package" in out and 'href="/max/pinsim/1.3.0"' not in text, out[-300:] + text[text.find('<table'):][:600])

# On a repo carrying several entries, a tag without one entry's manifest is most likely another
# entry's release: left unread for that entry, never frozen as an invalid version of it.
sib = os.path.join(work, "sibrepo")
os.makedirs(os.path.join(sib, "SibArrThorn"))
for f, t in [("interface.ccl", "IMPLEMENTS: SibArrThorn\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n")]:
    open(os.path.join(sib, "SibArrThorn", f), "w").write(t)
open(os.path.join(sib, "cactarium.toml"), "w").write(
    'format = 1\n\n[package]\nname = "sibrepo"\nowners = ["max"]\ndescription = "A package with a sim beside it"\narrangement = "SibArr"\n')
sh("git", "init", "-q", "-b", "master", cwd=sib)
sh("git", "add", "-A", cwd=sib); sh("git", *ident, "commit", "-q", "-m", "package", cwd=sib)
sib_c = sh("git", "rev-parse", "HEAD", cwd=sib)
open(os.path.join(sib, "run.sim"), "w").write(pin_sim("sibrun", [("sibrepo", "SibArr", REPOS + "/sibrepo.git", sib_c)]))
open(os.path.join(sib, "cactarium-sim.toml"), "w").write('format = 1\n\n[sim]\nname = "sibrepo-sim"\nowners = ["max"]\nfile = "run.sim"\n')
sh("git", "add", "-A", cwd=sib); sh("git", *ident, "commit", "-q", "-m", "and a sim", cwd=sib); sh("git", "tag", "v1.0.0", cwd=sib)
sibbare = ENV["DEMO_REPOS"] + "/sibrepo.git"
subprocess.run(["rm", "-rf", sibbare], check=True)
sh("git", "clone", "-q", "--bare", sib, sibbare, cwd=work)
run = subprocess.run(["just", "cli", "register", "max", REPOS + "/sibrepo.git"], capture_output=True, text=True)
check("a repo with a package and a sim registers both", run.returncode == 0 and run.stdout.count("Registered") == 2, run.stdout + run.stderr[-300:])
os.remove(os.path.join(sib, "run.sim")); os.remove(os.path.join(sib, "cactarium-sim.toml"))
retag(sib, sibbare, "v1.1.0")
ok, out = cli_sync("max/sibrepo-sim")
check("a tag without the sim's manifest, on a repo with other entries, is recorded as not the sim's, never frozen",
      ok and not has_version(maxv, "max/sibrepo-sim", "1.1.0") and '<span class="mono">v1.1.0</span>: it has no cactarium-sim.toml' in maxv.get("/max/sibrepo-sim")[1], out[-400:])
ok, out = cli_sync("max/sibrepo")
check("and is the package's release", ok and has_version(maxv, "max/sibrepo", "1.1.0"), out[-400:])
# ---------------------------------------------------------------------------------------------
# Several entries on one repo, multi-sim entries, and how tags become versions per entry. All on
# scratch repos built here.
def cli(*args):
    """`just cli ...`: (ok, output)."""
    run = subprocess.run(["just", "cli", *args], capture_output=True, text=True)
    return run.returncode == 0, run.stdout + run.stderr

def resolve(req):
    s, body, hdrs = anon.get("/api/v1/resolve?req=" + urllib.parse.quote(req))
    try:
        return s, json.loads(body), hdrs
    except ValueError:
        return s, {"raw": body}, hdrs

def new_tree(name):
    d = os.path.join(work, name)
    subprocess.run(["rm", "-rf", d], check=True)
    os.makedirs(d)
    sh("git", "init", "-q", "-b", "master", cwd=d)
    return d

def write(d, rel, text):
    path = os.path.join(d, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").write(text)

def thorn_at(d, arr):
    for f, t in [("interface.ccl", f"IMPLEMENTS: {arr}Thorn\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n")]:
        write(d, f"{arr}Thorn/{f}", t)

def commit_tag(d, msg, *tags):
    sh("git", "add", "-A", cwd=d); sh("git", *ident, "commit", "-q", "--allow-empty", "-m", msg, cwd=d)
    for t in tags:
        sh("git", "tag", "-f", t, cwd=d)
    return sh("git", "rev-parse", "HEAD", cwd=d)

def publish_tree(d, name):
    b = ENV["DEMO_REPOS"] + f"/{name}.git"
    subprocess.run(["rm", "-rf", b], check=True)
    sh("git", "clone", "-q", "--bare", d, b, cwd=work)
    return b

def push_all(d, bare):
    sh("git", "push", "-q", "--force", bare, "--all", cwd=d)
    sh("git", "push", "-q", "--force", bare, "--tags", cwd=d)

def package_toml(name, arr, extra=""):
    return f'format = 1\n\n[package]\nname = "{name}"\nowners = ["max"]\ndescription = "{name}, a scratch package"\narrangement = "{arr}"\n{extra}'

def sims_toml(name, files, pattern="sim-v{major}.{minor}.{patch}"):
    pat = f'tag-pattern = "{pattern}"\n' if pattern else ""
    listed = "".join(f'{k} = "{v}"\n' for k, v in files.items())
    return (f'format = 2\n\n[sim]\nname = "{name}"\nowners = ["max"]\ndescription = "Example sims of {name}"\n{pat}'
            f'\n[sim.files]\n{listed}')

def versions_of(slug):
    return page(maxv, f"/{slug}?tab=versions")

# --- A package and a two-sim entry on one repo, the sims released with their own sim-vX.Y.Z tags,
# from a branch (the default branch has no sims manifest, as Cottonmouth's main has none).
M = new_tree("msrepo")
MURL = REPOS + "/msrepo.git"
write(M, "README.md", "before the manifest\n")
commit_tag(M, "before the manifest", "v0.9.0")
thorn_at(M, "MsArr")
write(M, "cactarium.toml", package_toml("msrepo", "MsArr"))
pkg_c = commit_tag(M, "msrepo 1.0.0", "v1.0.0")
mbare = publish_tree(M, "msrepo")
ok, out = cli("register", "max", MURL)
check("register the package (the default branch has only cactarium.toml)", ok and "Registered max/msrepo (package" in out, out[-400:])
text = versions_of("max/msrepo")
check("its tag from before the manifest is invalid (no siblings yet)", 'href="/max/msrepo/0.9.0"' in text and "no cactarium.toml" in text, text[text.find("<table"):][:500])
sh("git", "checkout", "-q", "-b", "sims", cwd=M)
def ms_sim(name):
    return pin_sim(name, [("msrepo", "MsArr", MURL, pkg_c)])
write(M, "examples/sims/alpha.sim", ms_sim("alpha"))
write(M, "examples/sims/beta.sim", ms_sim("beta"))
write(M, "cactarium-sim.toml", sims_toml("msrepo-sims", {"alpha": "examples/sims/alpha.sim", "beta": "examples/sims/beta.sim"}))
# sim/v1.0.0 is the form never to use: the default rule reads it as track "sim".
commit_tag(M, "example sims", "sim-v1.0.0", "sim/v1.0.0")
push_all(M, mbare)
ok, out = cli("register", "max", MURL)
check("registering again from the default branch finds nothing to add", not ok and "nothing to add" in out, out[-400:])
ok, out = cli("check", MURL, "--tag", "sim-v1.0.0")
check("cactarium check: the dry run reads the new entry at the tag, and what the package makes of it",
      ok and "new sim max/msrepo-sims" in out and "max/msrepo-sims@1.0.0: reads cleanly (sims: alpha, beta)" in out
      and "max/msrepo: sim-v1.0.0 isn't one of its tags" in out, out[-800:])
page(anon, "/max/msrepo-sims", expect=404)  # the dry run wrote nothing
ok, out = cli("register", "max", MURL, "--tag", "sim-v1.0.0")
check("register --tag adds only the missing entry", ok and "Registered max/msrepo-sims (sim" in out and "max/msrepo (" not in out, out[-400:])
ok, out = cli("sync", "max/msrepo")
check("no cross-ingest: sim-v1.0.0 is not a package version", "sim-v1.0.0" not in versions_of("max/msrepo"))
check("but sim/v1.0.0 is, on a track named sim: why sims never use sim/v...", has_version(maxv, "max/msrepo", "sim:1.0.0"))
check("and the sims take only their own tag", has_version(maxv, "max/msrepo-sims", "1.0.0") and not has_version(maxv, "max/msrepo-sims", "sim:1.0.0"))
# Three-part resolution and per-sim downloads, each with its own sha256.
shas = {}
for sim in ["alpha", "beta"]:
    s, r, _ = resolve(f"max/msrepo-sims/{sim}@1")
    check(f"max/msrepo-sims/{sim}@1 resolves to that sim of 1.0.0",
          s == 200 and r.get("slug") == f"max/msrepo-sims/{sim}@1.0.0" and r.get("sim") == sim and r.get("tag") == "sim-v1.0.0"
          and "newer-without-sim" not in r, r)
    s, body, hdrs = anon.get(f"/api/v1/sims/max/msrepo-sims/1.0.0/download?sim={sim}")
    import hashlib as _h
    sha = _h.sha256(body.encode()).hexdigest()
    shas[sim] = sha
    check(f"download ?sim={sim}: the stamped file, with its own sha256",
          s == 200 and hdrs.get("x-sha256") == sha and f'cactarium = "max/msrepo-sims/{sim}@1.0.0"' in body
          and body.startswith("format = 4"), f"{s} {hdrs.get('x-sha256')} {sha} {body[:200]}")
check("each sim has its own file and sha", shas.get("alpha") != shas.get("beta"))
s, r, _ = resolve("max/msrepo-sims@1")
check("owner/name of a multi-sim entry is refused, listing its sims",
      s == 400 and "max/msrepo-sims/alpha" in str(r) and "max/msrepo-sims/beta" in str(r), r)
s, body, _ = anon.get("/api/v1/sims/max/msrepo-sims/1.0.0/download")
check("its download without ?sim= is refused, naming the sims", s == 400 and "alpha" in body and "beta" in body, f"{s} {body[:200]}")
s, r, _ = resolve("max/repo-sim/alpha@1")
check("a one-sim entry has no sims to name", s == 400 and "is one sim" in str(r), r)
s, body, _ = anon.get("/api/v1/sims/max/repo-sim/1.0.0/download?sim=alpha")
check("nor does its download take ?sim=", s == 400, f"{s} {body[:200]}")
s, body, _ = anon.get("/api/v1/entries/max/msrepo-sims")
check("the entry lists its sims", s == 200 and json.loads(body).get("sims") == ["alpha", "beta"], body[:300])
page(anon, "/max/msrepo-sims", contains="Sims in this version")
text = page(anon, "/max/msrepo-sims/1.0.0?sim=beta&tab=pins", contains="max/msrepo@1.0.0")
check("the sim page names the sim in its import command and links", "cactup import max/msrepo-sims/beta@1.0.0" in text
      and "download.sim?sim=beta" in text and re.search(r"sim=beta&(amp|#38);tab=thornlist", text) is not None, text[:0])
s, body, _ = anon.get("/max/msrepo-sims/1.0.0/download.sim?sim=alpha")
check("the web download takes ?sim= too", s == 200 and "max/msrepo-sims/alpha@1.0.0" in body, f"{s} {body[:200]}")
# A vX.Y.Z tag that also carries cactarium-sim.toml is the package's, never the sims'.
commit_tag(M, "package 2.0.0 on the sims branch", "v2.0.0")
push_all(M, mbare)
cli("sync", "max/msrepo"); cli("sync", "max/msrepo-sims")
check("a v tag carrying cactarium-sim.toml is the package's", has_version(maxv, "max/msrepo", "2.0.0"))
check("and not the sims'", not has_version(maxv, "max/msrepo-sims", "2.0.0"))
# One bad sim refuses the whole version, with the reason.
write(M, "examples/sims/beta.sim", ms_sim("beta").replace(f'commit = "{pkg_c}"', 'dirty = true'))
commit_tag(M, "a broken beta", "sim-v1.1.0")
push_all(M, mbare)
ok, out = cli("sync", "max/msrepo-sims")
text = versions_of("max/msrepo-sims")
check("one bad sim makes the version invalid, naming the sim", 'href="/max/msrepo-sims/1.1.0' in text and "sim beta" in text, text[text.find("<table"):][:700])
ok, out = cli("reread", "max", "max/msrepo-sims", "1.1.0")
check("re-reading an invalid version that still fails leaves it, with the reason", not ok and "sim beta" in out, out[-300:])
# A dropped sim resolves to its last version, flagged. Checked first with a dry run of the branch.
write(M, "cactarium-sim.toml", sims_toml("msrepo-sims", {"alpha": "examples/sims/alpha.sim"}))
sh("git", "add", "-A", cwd=M); sh("git", *ident, "commit", "-q", "-m", "drop beta", cwd=M)
push_all(M, mbare)
ok, out = cli("check", MURL, "--tag", "sim-v1.2.0", "--commit", "sims")
check("cactarium check reads a tag that doesn't exist yet, at a branch", ok and "max/msrepo-sims@1.2.0: reads cleanly (sims: alpha)" in out, out[-500:])
commit_tag(M, "sims 1.2.0", "sim-v1.2.0")
push_all(M, mbare)
cli("sync", "max/msrepo-sims")
s, r, _ = resolve("max/msrepo-sims/alpha@1")
check("alpha@1 is the newest 1.x holding it", s == 200 and r.get("slug") == "max/msrepo-sims/alpha@1.2.0" and "newer-without-sim" not in r, r)
s, r, _ = resolve("max/msrepo-sims/beta@1")
check("a dropped sim resolves to its last version, flagged",
      s == 200 and r.get("slug") == "max/msrepo-sims/beta@1.0.0" and r.get("newer-without-sim") == "1.2.0", r)
s, r, _ = resolve("max/msrepo-sims/gamma@1")
check("a sim no version holds is refused, naming the newest's sims", s == 400 and "gamma" in str(r) and "max/msrepo-sims/alpha" in str(r), r)
page(anon, "/max/msrepo-sims/1.2.0?sim=beta", contains="has no sim")
# A later sims manifest without tag-pattern doesn't flip the rule onto the package's v tags.
write(M, "cactarium-sim.toml", sims_toml("msrepo-sims", {"alpha": "examples/sims/alpha.sim"}, pattern=None))
commit_tag(M, "manifest without a pattern", "sim-v1.3.0", "v1.3.0")
push_all(M, mbare)
cli("sync", "max/msrepo-sims"); cli("sync", "max/msrepo")
text = page(maxv, "/max/msrepo-sims")
check("a sim-v tag whose manifest dropped the pattern is not the sims' (recorded, not frozen)",
      not has_version(maxv, "max/msrepo-sims", "1.3.0") and '<span class="mono">sim-v1.3.0</span>' in text and "this entry's" in text, text[text.find("Manage"):][:900])
check("the rule doesn't flip: the sims still follow sim-v tags", "tags matching sim-v{major}.{minor}.{patch}" in text)
check("and v1.3.0 is the package's", has_version(maxv, "max/msrepo", "1.3.0"))
check("the manage panel lists the other entry on the repo", "Also on this repo" in text and 'href="/max/msrepo">max/msrepo</a>' in text)
# A verified webhook on one entry syncs every entry on the repo.
commit_tag(M, "package 1.4.0", "v1.4.0")
push_all(M, mbare)
hook_id = re.search(r"/hooks/github/(\d+)", text).group(1)
secret = re.search(r'Secret: <code class="mono">([^<]+)</code>', text).group(1)
import hmac as _hmac
payload = b'{"ref":"refs/tags/v1.4.0"}'
sig = "sha256=" + _hmac.new(secret.encode(), payload, "sha256").hexdigest()
s, _, _ = anon.req("POST", f"/hooks/github/{hook_id}", raw=payload, headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "push", "Content-Type": "application/json"})
check("the sims entry's webhook is accepted", s == 202, s)
for _ in range(30):
    if has_version(anon, "max/msrepo", "1.4.0"):
        break
    time.sleep(1)
check("and it synced the package, its sibling", has_version(anon, "max/msrepo", "1.4.0"))
# Switching schemes is explicit: re-read the tag rule (here at a tag whose manifest has no pattern).
ok, out = cli("reread-rule", "max", "max/msrepo-sims")
check("re-reading the rule from a default branch without the manifest is refused", not ok and "no cactarium-sim.toml" in out, out[-300:])
ok, out = cli("reread-rule", "max", "max/msrepo-sims", "--tag", "v1.3.0")
check("re-read tag rule switches the sims to vX.Y.Z tags", ok and "now follows version tags" in out, out[-300:])
check("tags judged not its own before are read again under the new rule: v1.3.0 is a sims version now",
      has_version(maxv, "max/msrepo-sims", "1.3.0") and has_version(maxv, "max/msrepo-sims", "1.4.0"))
check("tags without its manifest, or whose manifest follows sim-v, stay not its own",
      not has_version(maxv, "max/msrepo-sims", "2.0.0") and not has_version(maxv, "max/msrepo-sims", "0.9.0"))
# A new version sorting below one taken from another tag form gets a reviewer's warning.
commit_tag(M, "a low number", "v1.1.5")
push_all(M, mbare)
cli("sync", "max/msrepo-sims")
page(maxv, "/max/msrepo-sims/1.1.5?sim=alpha", contains="sorts below 1.2.0")
# An invalid version frozen before the repo had siblings: re-read, it turns out not to be the entry's.
ok, out = cli("reread", "max", "max/msrepo", "0.9.0")
check("re-read invalid version: a tag that isn't the entry's (no manifest, siblings now) is removed",
      ok and "isn't max/msrepo's tag" in out and not has_version(maxv, "max/msrepo", "0.9.0"), out[-300:])
# Moving the repo moves every entry on it, together.
mmoved = ENV["DEMO_REPOS"] + "/msrepo-moved.git"
subprocess.run(["rm", "-rf", mmoved], check=True)
sh("git", "clone", "-q", "--bare", mbare, mmoved, cwd=work)
text = page(maxv, "/admin/entries?q=msrepo")
mid = re.search(r'href="/max/msrepo">max/msrepo</a>.*?action="/admin/entries/(\d+)"', text, re.S).group(1)
s, text, _ = maxv.post(f"/admin/entries/{mid}", {"action": "move-repo", "new_url": REPOS + "/msrepo-moved.git"})
check("move-repo with siblings is accepted", s == 303, text[text.find("alert"):][:300])
for slug in ["max/msrepo", "max/msrepo-sims"]:
    s, body, _ = anon.get(f"/api/v1/entries/{slug}")
    check(f"{slug} now reads the new URL", s == 200 and json.loads(body)["repo"].endswith("msrepo-moved.git"), body[:300])

# --- A register that fails partway writes nothing.
F = new_tree("fpkg")
thorn_at(F, "FArr")
write(F, "cactarium.toml", package_toml("fpkg", "FArr"))
f_c = commit_tag(F, "fpkg")
write(F, "run.sim", pin_sim("frun", [("fpkg", "FArr", REPOS + "/fpkg.git", f_c)]).replace(f'commit = "{f_c}"', ""))
write(F, "cactarium-sim.toml", 'format = 1\n\n[sim]\nname = "fpkg-sims"\nowners = ["max"]\nfile = "run.sim"\n')
commit_tag(F, "a broken sim", "v1.0.0")
publish_tree(F, "fpkg")
ok, out = cli("register", "max", REPOS + "/fpkg.git")
check("a register whose sims fail at their newest tag is refused, naming them", not ok and "max/fpkg-sims@1.0.0" in out, out[-400:])
page(anon, "/max/fpkg", expect=404)  # the package, though fine, wasn't registered either
G = new_tree("gclash")
thorn_at(G, "GArr")
write(G, "cactarium.toml", package_toml("gclash", "GArr"))
g_c = commit_tag(G, "gclash")
write(G, "run.sim", pin_sim("grun", [("gclash", "GArr", REPOS + "/gclash.git", g_c)]))
write(G, "cactarium-sim.toml", 'format = 1\n\n[sim]\nname = "gclash"\nowners = ["max"]\nfile = "run.sim"\n')
commit_tag(G, "a sim named like the package", "v1.0.0")
publish_tree(G, "gclash")
ok, out = cli("register", "max", REPOS + "/gclash.git")
check("two manifests naming one entry are refused, saying so", not ok and "both name 'gclash'" in out, out[-300:])
s, _, _ = anon.get("/api/v1/entries/max/gclash")
check("and writes nothing: the first entry is gone too", s == 404, s)

# --- No tag-pattern anywhere: package, stack and sims share one vX.Y.Z tag.
S = new_tree("sharedrel")
SURL = REPOS + "/sharedrel.git"
thorn_at(S, "ShArr")
write(S, "cactarium.toml", package_toml("sharedrel", "ShArr"))
s_c = commit_tag(S, "the package")
write(S, "s.th", f"!CRL_VERSION = 1.0\n!DEFINE ROOT = Cactus\n!TARGET = $ROOT/arrangements\n!TYPE = git\n!URL = {SURL}\n!REPO_PATH = $2\n!CHECKOUT =\nShArr/ShArrThorn\n")
write(S, "cactarium-stack.toml", 'format = 1\n\n[stack]\nname = "sharedrel-stack"\nowners = ["max"]\ndescription = "A stack beside its package"\nthornlist = "s.th"\n')
write(S, "run.sim", pin_sim("sharedrel-sim", [("sharedrel", "ShArr", SURL, s_c)]))
write(S, "cactarium-sim.toml", 'format = 1\n\n[sim]\nname = "sharedrel-sim"\nowners = ["max"]\nfile = "run.sim"\n')
commit_tag(S, "one release of all three", "v1.0.0")
publish_tree(S, "sharedrel")
ok, out = cli("register", "max", SURL)
check("a repo with a package, a stack and a sim registers all three", ok and out.count("Registered") == 3, out[-500:])
for slug in ["max/sharedrel", "max/sharedrel-stack", "max/sharedrel-sim"]:
    s, r, _ = resolve(f"{slug}@1.0.0")
    check(f"without patterns, one v tag released {slug} too", s == 200 and r.get("tag") == "v1.0.0", r)

# --- One kind on vX.Y.Z; two kinds with the same tag-pattern, which share their tags.
T = new_tree("patrel")
TURL = REPOS + "/patrel.git"
thorn_at(T, "PtArr")
write(T, "cactarium.toml", package_toml("patrel", "PtArr"))
t_c = commit_tag(T, "the package")
write(T, "s.th", f"!CRL_VERSION = 1.0\n!DEFINE ROOT = Cactus\n!TARGET = $ROOT/arrangements\n!TYPE = git\n!URL = {TURL}\n!REPO_PATH = $2\n!CHECKOUT =\nPtArr/PtArrThorn\n")
write(T, "cactarium-stack.toml", 'format = 1\n\n[stack]\nname = "patrel-stack"\nowners = ["max"]\nthornlist = "s.th"\ntag-pattern = "rel-{major}.{minor}.{patch}"\n')
write(T, "run.sim", pin_sim("patrel-sim", [("patrel", "PtArr", TURL, t_c)]))
write(T, "cactarium-sim.toml", 'format = 1\n\n[sim]\nname = "patrel-sim"\nowners = ["max"]\nfile = "run.sim"\ntag-pattern = "rel-{major}.{minor}.{patch}"\n')
commit_tag(T, "first releases", "v1.0.0", "rel-1.0.0")
tbare = publish_tree(T, "patrel")
ok, out = cli("register", "max", TURL)
check("a repo whose stack and sims share a tag-pattern registers", ok and out.count("Registered") == 3, out[-500:])
s, r, _ = resolve("max/patrel@1.0.0")
check("the package follows v tags", s == 200 and r.get("tag") == "v1.0.0", r)
for slug in ["max/patrel-stack", "max/patrel-sim"]:
    s, r, _ = resolve(f"{slug}@1.0.0")
    check(f"{slug} follows only its pattern", s == 200 and r.get("tag") == "rel-1.0.0", r)
commit_tag(T, "package only", "v1.1.0")
commit_tag(T, "stack and sims only", "rel-2.0.0")
push_all(T, tbare)
for slug in ["max/patrel", "max/patrel-stack", "max/patrel-sim"]:
    cli("sync", slug)
check("a v tag releases only the package", has_version(anon, "max/patrel", "1.1.0")
      and not has_version(anon, "max/patrel-stack", "1.1.0") and not has_version(anon, "max/patrel-sim", "1.1.0"))
check("kinds with the same pattern share its tags", has_version(anon, "max/patrel-stack", "2.0.0")
      and has_version(anon, "max/patrel-sim", "2.0.0") and not has_version(anon, "max/patrel", "2.0.0"))

# --- A tag waiting for a pinned repo to be registered is read once it is.
ok, out = cli("register", "max", REPOS + "/nobody.git")
check("register the repo the waiting pin names", ok, out[-300:])
ok, out = cli("sync", "max/pinsim")
check("the waiting tag is read, valid", ok and has_version(anon, "max/pinsim", "1.3.0"), out[-300:])
page(anon, "/max/pinsim/1.3.0?tab=pins", contains="max/nobody")
# --- A dependency on a package not registered yet waits; a dependency whose version lacks a thorn
# its needs names is a fact (invalid), which an admin can re-read once a version has it.
L = new_tree("needer")
thorn_at(L, "NdArr")
write(L, "cactarium.toml", package_toml("needer", "NdArr"))
commit_tag(L, "needer 1.0", "v1.0.0")
lbare = publish_tree(L, "needer")
ok, out = cli("register", "max", REPOS + "/needer.git")
check("register a package with no dependency yet", ok, out[-300:])
write(L, "cactarium.toml", package_toml("needer", "NdArr", '\n[[dependency]]\ntarget = "max/latepkg"\nneeds = ["LtArrThorn"]\n'))
commit_tag(L, "depends on a package not registered yet", "v1.1.0")
push_all(L, lbare)
ok, out = cli("sync", "max/needer")
check("a dependency on a package nobody registered yet waits", not ok and "max/latepkg" in out and not has_version(maxv, "max/needer", "1.1.0"), out[-300:])
LT = new_tree("latepkg")
thorn_at(LT, "LtArr")
write(LT, "cactarium.toml", package_toml("latepkg", "LtArr"))
commit_tag(LT, "latepkg", "v1.0.0")
ltbare = publish_tree(LT, "latepkg")
ok, out = cli("register", "max", REPOS + "/latepkg.git")
check("register the package it depends on", ok, out[-300:])
ok, out = cli("sync", "max/needer")
check("then the waiting tag is read, valid", ok and has_version(anon, "max/needer", "1.1.0"), out[-300:])
write(L, "cactarium.toml", package_toml("needer", "NdArr", '\n[[dependency]]\ntarget = "max/latepkg"\nneeds = ["LtArrThorn", "LtExtra"]\n'))
commit_tag(L, "needs a thorn latepkg doesn't have", "v1.2.0")
push_all(L, lbare)
cli("sync", "max/needer")
check("a dependency whose version lacks a needed thorn makes the version invalid",
      "doesn&#39;t have" in versions_of("max/needer") and 'href="/max/needer/1.2.0' in versions_of("max/needer"))
for f, t in [("interface.ccl", "IMPLEMENTS: LtExtra\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n")]:
    write(LT, f"LtExtra/{f}", t)
commit_tag(LT, "latepkg 1.1 with LtExtra", "v1.1.0")
push_all(LT, ltbare)
cli("sync", "max/latepkg")
ok, out = cli("reread", "max", "max/needer", "1.2.0")
check("re-read invalid version: it reads cleanly now", ok and "reads cleanly now" in out, out[-300:])
s, r, _ = resolve("max/needer@1.2.0")
check("and is served", s == 200 and r.get("slug") == "max/needer@1.2.0", r)

# --- A tag whose manifest file can't be read (not UTF-8) doesn't stop the entry's sync.
U8 = new_tree("badutf")
thorn_at(U8, "BuArr")
write(U8, "cactarium.toml", package_toml("badutf", "BuArr"))
commit_tag(U8, "1.0", "v1.0.0")
u8bare = publish_tree(U8, "badutf")
cli("register", "max", REPOS + "/badutf.git")
good_u8 = open(os.path.join(U8, "cactarium.toml")).read()
open(os.path.join(U8, "cactarium.toml"), "wb").write(b"format = 1\n# \xff\xfe broken\n")
commit_tag(U8, "1.1 unreadable", "v1.1.0")
write(U8, "cactarium.toml", good_u8)
commit_tag(U8, "1.2", "v1.2.0")
push_all(U8, u8bare)
ok, out = cli("sync", "max/badutf")
text = versions_of("max/badutf")
check("an unreadable manifest is an invalid version, and the sync goes on to the next tag",
      ok and 'href="/max/badutf/1.1.0' in text and "UTF-8" in text and has_version(anon, "max/badutf", "1.2.0"), out[-300:] + text[text.find("<table"):][:500])

# --- The sims' form is the entry's, fixed when it is registered: an older tag in the other form is
# not its release (not an invalid version), and `check` agrees with the sync.
D = new_tree("formsims")
DURL = REPOS + "/formsims.git"
write(D, "a.sim", pin_sim("alpha", [("pinpkg", "PinArr", REPOS + "/pinpkg.git", ptagged)]))
write(D, "cactarium-sim.toml", 'format = 1\n\n[sim]\nname = "formsims"\nowners = ["max"]\nfile = "a.sim"\n')
commit_tag(D, "one sim", "v1.0.0")
write(D, "b.sim", pin_sim("beta", [("pinpkg", "PinArr", REPOS + "/pinpkg.git", ptagged)]))
write(D, "cactarium-sim.toml", 'format = 2\n\n[sim]\nname = "formsims"\nowners = ["max"]\n\n[sim.files]\nalpha = "a.sim"\nbeta = "b.sim"\n')
commit_tag(D, "two sims", "v2.0.0")
publish_tree(D, "formsims")
ok, out = cli("check", DURL, "--tag", "v2.0.0", "--owner", "max")
check("check reads the newest tag cleanly", ok and "max/formsims@2.0.0: reads cleanly (sims: alpha, beta)" in out, out[-400:])
ok, out = cli("register", "max", DURL)
text = versions_of("max/formsims")
check("registered from [sim.files], the entry keeps that form: 2.0.0 is a valid version",
      ok and has_version(anon, "max/formsims", "2.0.0") and "invalid" not in text, out[-300:] + text[text.find("<table"):][:500])
check("and the older one-file tag is recorded as not its release, not frozen invalid",
      not has_version(maxv, "max/formsims", "1.0.0") and "one sim (file)" in page(maxv, "/max/formsims"))

# --- A kind with a tag-pattern the standard form also reads (bare X.Y.Z): its tags are its own; the
# kind without a pattern doesn't take them.
E = new_tree("bareform")
EURL = REPOS + "/bareform.git"
thorn_at(E, "BfArr")
write(E, "cactarium.toml", package_toml("bareform", "BfArr", 'tag-pattern = "{major}.{minor}.{patch}"\n'))
write(E, "a.sim", pin_sim("alpha", [("pinpkg", "PinArr", REPOS + "/pinpkg.git", ptagged)]))
write(E, "cactarium-sim.toml", 'format = 1\n\n[sim]\nname = "bareform-sims"\nowners = ["max"]\nfile = "a.sim"\n')
commit_tag(E, "sims 1.0", "v1.0.0")
commit_tag(E, "package 2.0", "2.0.0")
commit_tag(E, "package 3.0", "3.0.0")
ebare = publish_tree(E, "bareform")
ok, out = cli("register", "max", EURL)
check("a package on bare X.Y.Z tags and sims on the standard form register", ok and out.count("Registered") == 2, out[-400:])
check("the package takes its bare tags", has_version(anon, "max/bareform", "2.0.0") and has_version(anon, "max/bareform", "3.0.0"))
check("the sims take only v1.0.0, never the package's bare tags",
      has_version(anon, "max/bareform-sims", "1.0.0") and not has_version(maxv, "max/bareform-sims", "2.0.0")
      and not has_version(maxv, "max/bareform-sims", "3.0.0"))
check("which they list as another entry's", "its tag-pattern {major}.{minor}.{patch} reads 3.0.0" in page(maxv, "/max/bareform-sims"))

# --- register --tag registers only the manifests that read that tag; the others are added by
# registering again without it.
TP = new_tree("tagpart")
TPURL = REPOS + "/tagpart.git"
thorn_at(TP, "TpArr")
write(TP, "cactarium.toml", package_toml("tagpart", "TpArr"))
tp_c = commit_tag(TP, "package", "v1.0.0")
write(TP, "a.sim", pin_sim("alpha", [("tagpart", "TpArr", TPURL, tp_c)]))
write(TP, "cactarium-sim.toml", sims_toml("tagpart-sims", {"alpha": "a.sim"}))
commit_tag(TP, "sims", "sim-v1.0.0")
publish_tree(TP, "tagpart")
ok, out = cli("check", TPURL, "--tag", "sim-v1.0.0", "--owner", "max")
check("check says which manifests read the tag, and that the others need a register without --tag",
      ok and "cactarium.toml at sim-v1.0.0 follows version tags" in out and "register again without --tag" in out
      and "new sim max/tagpart-sims from cactarium-sim.toml at sim-v1.0.0" in out and "new package" not in out, out[-600:])
ok, out = cli("register", "max", TPURL, "--tag", "sim-v1.0.0")
check("register --tag registers only what reads the tag", ok and "Registered max/tagpart-sims" in out and "Registered max/tagpart " not in out
      and "register again without --tag" in out, out[-500:])
check("its tag waits for the package it pins", not has_version(maxv, "max/tagpart-sims", "1.0.0"))
ok, out = cli("register", "max", TPURL)
check("registering again without --tag adds the package", ok and "Registered max/tagpart (package" in out, out[-400:])
cli("sync", "max/tagpart-sims")
check("and the sims' tag is read", has_version(anon, "max/tagpart", "1.0.0") and has_version(anon, "max/tagpart-sims", "1.0.0"))

# --- A sibling declaring the standard form explicitly (v{major}.{minor}.{patch}) shares the v tags
# with a package that declares no pattern; it never claims them.
V = new_tree("stdform")
VURL = REPOS + "/stdform.git"
thorn_at(V, "SfArr")
write(V, "cactarium.toml", package_toml("stdform", "SfArr"))
commit_tag(V, "package 1.0", "v1.0.0")
vbare = publish_tree(V, "stdform")
cli("register", "max", VURL)
write(V, "a.sim", pin_sim("alpha", [("pinpkg", "PinArr", REPOS + "/pinpkg.git", ptagged)]))
write(V, "cactarium-sim.toml", 'format = 1\n\n[sim]\nname = "stdform-sims"\nowners = ["max"]\nfile = "a.sim"\ntag-pattern = "v{major}.{minor}.{patch}"\n')
commit_tag(V, "sims, released with the package", "v1.1.0")
push_all(V, vbare)
ok, out = cli("register", "max", VURL)
check("register sims declaring the standard form beside a package", ok and "Registered max/stdform-sims" in out, out[-300:])
commit_tag(V, "package and sims 1.2", "v1.2.0")
push_all(V, vbare)
cli("sync", "max/stdform"); cli("sync", "max/stdform-sims")
check("an explicit v{major}.{minor}.{patch} shares the v tags: both take v1.1.0 and v1.2.0",
      has_version(anon, "max/stdform", "1.1.0") and has_version(anon, "max/stdform", "1.2.0")
      and has_version(anon, "max/stdform-sims", "1.1.0") and has_version(anon, "max/stdform-sims", "1.2.0"))

# --- A sibling's claim goes when its rule is re-read: the sims claim bare tags, then drop the pattern.
W2 = new_tree("claimgone")
W2URL = REPOS + "/claimgone.git"
thorn_at(W2, "CgArr")
write(W2, "cactarium.toml", package_toml("claimgone", "CgArr"))
write(W2, "a.sim", pin_sim("alpha", [("pinpkg", "PinArr", REPOS + "/pinpkg.git", ptagged)]))
write(W2, "cactarium-sim.toml", 'format = 1\n\n[sim]\nname = "claimgone-sims"\nowners = ["max"]\nfile = "a.sim"\ntag-pattern = "{major}.{minor}.{patch}"\n')
commit_tag(W2, "both", "v1.0.0", "1.0.0")
w2bare = publish_tree(W2, "claimgone")
ok, out = cli("register", "max", W2URL)
check("register a package and sims claiming bare tags", ok and out.count("Registered") == 2, out[-400:])
commit_tag(W2, "a bare tag", "2.0.0")
push_all(W2, w2bare)
cli("sync", "max/claimgone"); cli("sync", "max/claimgone-sims")
check("the bare tag is the sims', not the package's", has_version(anon, "max/claimgone-sims", "2.0.0") and not has_version(maxv, "max/claimgone", "2.0.0"))
write(W2, "cactarium-sim.toml", 'format = 1\n\n[sim]\nname = "claimgone-sims"\nowners = ["max"]\nfile = "a.sim"\n')
commit_tag(W2, "sims drop the pattern", "v1.1.0")
push_all(W2, w2bare)
ok, out = cli("reread-rule", "max", "max/claimgone-sims", "--tag", "v1.1.0")
check("the sims re-read their rule", ok, out[-300:])
cli("sync", "max/claimgone")
check("the package's tag claimed by the sims' old pattern is judged again, and is the package's now", has_version(anon, "max/claimgone", "2.0.0"))

# --- A sim entry without a stored form (registered by an older release after a rollback) publishes
# one file: a tag whose manifest lists [sim.files] isn't its release.
subprocess.run(["docker", "compose", "--project-directory", ENV_DIR, "-f", ENV_DIR + "/compose.yaml", "-f", ENV_DIR + "/compose.dev.yaml",
                "exec", "-T", "db", "psql", "-U", "cactarium", "-d", "cactarium", "-c",
                "UPDATE entry_repos SET sim_form = NULL WHERE entry_id = (SELECT id FROM entries WHERE owner = 'max' AND name = 'repo-sim')"],
               check=True, capture_output=True)
write(srepo, "cactarium-sim.toml", 'format = 2\n\n[sim]\nname = "repo-sim"\nowners = ["max"]\n\n[sim.files]\nqc0 = "runs/qc0.sim"\n')
commit_tag(srepo, "now several sims", "v1.4.0")
push_all(srepo, sbare)
cli("sync", "max/repo-sim")
check("a sim entry with no stored form is a one-file entry: a [sim.files] tag isn't its release",
      not has_version(maxv, "max/repo-sim", "1.4.0") and "one sim (file)" in page(maxv, "/max/repo-sim"))

# --- A re-read of one entry's rule keeps a sibling's judgments that don't depend on it (no manifest
# for the sibling at that tag).
ok, out = cli("reread-rule", "max", "max/sibrepo")
check("re-read the package's rule beside a sim with a tag it has no manifest at", ok, out[-300:])
check("the sim's 'no manifest' record stays", '<span class="mono">v1.1.0</span>: it has no cactarium-sim.toml' in page(maxv, "/max/sibrepo-sim"))

# --- An invalid version frozen from one tag is re-read from another tag naming exactly that version.
RB = new_tree("rebare")
thorn_at(RB, "RbArr")
write(RB, "cactarium.toml", package_toml("rebare", "RbArr"))
commit_tag(RB, "0.5", "v0.5.0")
rbbare = publish_tree(RB, "rebare")
cli("register", "max", REPOS + "/rebare.git")
os.remove(os.path.join(RB, "cactarium.toml"))
commit_tag(RB, "an upstream release without the manifest", "1.0.0")
push_all(RB, rbbare)
cli("sync", "max/rebare")
check("a bare 1.0.0 without the manifest is an invalid 1.0.0", "no cactarium.toml" in versions_of("max/rebare"))
write(RB, "cactarium.toml", package_toml("rebare", "RbArr"))
commit_tag(RB, "the real release", "v1.0.0")
push_all(RB, rbbare)
cli("sync", "max/rebare")
ok, out = cli("reread", "max", "max/rebare", "1.0.0")
check("re-read invalid version reads it from the other tag naming 1.0.0", ok and "from v1.0.0" in out, out[-300:])
s, r, _ = resolve("max/rebare@1.0.0")
check("and 1.0.0 is now the real release", s == 200 and r.get("tag") == "v1.0.0", r)

# --- Under a pattern, the spelling it writes wins even without a manifest there; the release in
# another spelling of that version is reached by re-reading the invalid version.
RP = new_tree("relpat")
write(RP, "README", "old\n")
commit_tag(RP, "old", "rel-1.0")
thorn_at(RP, "RpArr")
write(RP, "cactarium.toml", package_toml("relpat", "RpArr", 'tag-pattern = "rel-{major}.{minor}"\n'))
commit_tag(RP, "release", "rel-1.00", "rel-1.1")
publish_tree(RP, "relpat")
cli("register", "max", REPOS + "/relpat.git")
check("rel-1.0, the pattern's own spelling, is read for 1.0.0 (invalid: no manifest there)", "no cactarium.toml" in versions_of("max/relpat"))
ok, out = cli("reread", "max", "max/relpat", "1.0.0")
check("re-read invalid version reads 1.0.0 from rel-1.00", ok and "from rel-1.00" in out, out[-300:])

# --- The seeded multi-sim entry, registered with --tag beside its package.
page(anon, "/max/bbh-demo-sims", contains="Sims in this version")
page(anon, "/max/bbh-demo-sims/1.0.0?sim=tov&tab=thornlist", contains="BBHDemoArr/BBHDemo")
s, r, _ = resolve("max/bbh-demo-sims/qc0")
check("the seeded sims resolve by name", s == 200 and r.get("slug") == "max/bbh-demo-sims/qc0@1.0.0", r)

# --- An old CactUp against this server: it knows neither sims nor the new fields.
s, r, _ = resolve("max/repo-sim@1")
check("old CactUp: a one-sim entry resolves exactly as before (no new fields)",
      s == 200 and r.get("slug", "").startswith("max/repo-sim@1.") and "sim" not in r and "newer-without-sim" not in r, r)
s, body, hdrs = anon.get("/api/v1/sims/max/repo-sim/1.0.0/download")
check("old CactUp: its download is unchanged (no ?sim=, a two-part stamp, its old format)",
      s == 200 and 'cactarium = "max/repo-sim@1.0.0"' in body and body.startswith("format = 3") and hdrs.get("x-sha256"), body[:120])
s, r, _ = resolve("max/msrepo-sims@1")
check("old CactUp: owner/name on a multi-sim entry is an error it shows, never a wrong file", s == 400 and r.get("error", {}).get("code") == "bad-request", r)
s, _, _ = anon.get("/api/v1/sims/max/msrepo-sims/1.2.0/download")
check("old CactUp: a download without ?sim= is refused, so it can't fetch a sim it didn't name", s == 400, s)

def versions_page(v, slug):
    return v.get(f"/{slug}?tab=versions")[1]
def resolve_q(req):
    s, body, hdrs = anon.get("/api/v1/resolve?req=" + urllib.parse.quote(req))
    try:
        return s, json.loads(body), hdrs
    except ValueError:
        return s, {"raw": body}, hdrs
# A stack tag read while one of its source repos can't be reached waits; it isn't frozen invalid.
dep = os.path.join(work, "depsrc")
os.makedirs(os.path.join(dep, "DepArr", "DepThorn"))
for f, t in [("interface.ccl", "IMPLEMENTS: DepThorn\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n")]:
    open(os.path.join(dep, "DepArr", "DepThorn", f), "w").write(t)
sh("git", "init", "-q", "-b", "master", cwd=dep)
sh("git", "add", "-A", cwd=dep); sh("git", *ident, "commit", "-q", "-m", "dep", cwd=dep)
depbare = ENV["DEMO_REPOS"] + "/depsrc.git"
subprocess.run(["rm", "-rf", depbare], check=True)
sh("git", "clone", "-q", "--bare", dep, depbare, cwd=work)
stk = os.path.join(work, "flakystack")
os.makedirs(stk)
open(os.path.join(stk, "s.th"), "w").write(
    f"!CRL_VERSION = 1.0\n!DEFINE ROOT = Cactus\n!TARGET = $ROOT/arrangements\n!TYPE = git\n!URL = {REPOS}/depsrc.git\n!REPO_PATH = $1/$2\n!CHECKOUT =\nDepArr/DepThorn\n")
open(os.path.join(stk, "cactarium-stack.toml"), "w").write('format = 1\n\n[stack]\nname = "flakystack"\nowners = ["max"]\nthornlist = "s.th"\n')
sh("git", "init", "-q", "-b", "master", cwd=stk)
sh("git", "add", "-A", cwd=stk); sh("git", *ident, "commit", "-q", "-m", "1.0", cwd=stk); sh("git", "tag", "v1.0.0", cwd=stk)
stkbare = ENV["DEMO_REPOS"] + "/flakystack.git"
subprocess.run(["rm", "-rf", stkbare], check=True)
sh("git", "clone", "-q", "--bare", stk, stkbare, cwd=work)
run = subprocess.run(["just", "cli", "register", "max", REPOS + "/flakystack.git"], capture_output=True, text=True)
check("register a stack built from another repo", run.returncode == 0 and has_version(anon, "max/flakystack", "1.0.0"), run.stdout + run.stderr[-300:])
os.rename(depbare, depbare + ".away")
retag(stk, stkbare, "v1.1.0")
ok, out = cli_sync("max/flakystack")
check("a stack tag whose source repo can't be reached is left unread, not frozen invalid",
      not ok and "tried again" in out and not has_version(maxv, "max/flakystack", "1.1.0"), out[-400:])
os.rename(depbare + ".away", depbare)
ok, out = cli_sync("max/flakystack")
check("once the source answers, the stack tag becomes a valid release",
      ok and has_version(anon, "max/flakystack", "1.1.0") and "invalid" not in versions_page(maxv, "max/flakystack"), out[-400:])

# Waiting tags back off and are tried a few at a time: a dozen tags waiting on the same source.
os.rename(depbare, depbare + ".away")
for i in range(1, 13):
    retag(stk, stkbare, f"v1.2.{i}")
ok, out = cli_sync("max/flakystack")
check("new tags that can't be read wait, each with its next automatic try, at most ten per sync",
      not ok and "next automatic try after" in out and "2 more new tag(s) not tried this time" in out
      and not has_version(maxv, "max/flakystack", "1.2.1"), out[-300:])
cli_sync("max/flakystack")  # the ten waiting are tried again, the two new ones now too
ok, out = cli_sync("max/flakystack")
check("waiting tags are tried again at most ten per sync", not ok and "2 more waiting tag(s) not tried this time" in out, out[-300:])
os.rename(depbare + ".away", depbare)
cli_sync("max/flakystack")
cli_sync("max/flakystack")
check("once the source answers they are all read, ten at a time",
      has_version(anon, "max/flakystack", "1.2.1") and has_version(anon, "max/flakystack", "1.2.12"))

# A stack pinning a tag of a source repo that is pushed a moment after the stack's own tag waits.
sh("git", "tag", "d-1", cwd=dep); sh("git", "push", "-q", depbare, "--tags", cwd=dep)
pst = os.path.join(work, "pinstack")
os.makedirs(pst)
open(os.path.join(pst, "s.th"), "w").write(open(os.path.join(stk, "s.th")).read())
pst_toml = lambda t: f'format = 1\n\n[stack]\nname = "pinstack"\nowners = ["max"]\nthornlist = "s.th"\n\n[[stack.pin]]\nname = "depsrc"\ntag = "{t}"\n'
open(os.path.join(pst, "cactarium-stack.toml"), "w").write(pst_toml("d-1"))
sh("git", "init", "-q", "-b", "master", cwd=pst)
sh("git", "add", "-A", cwd=pst); sh("git", *ident, "commit", "-q", "-m", "1.0", cwd=pst); sh("git", "tag", "v1.0.0", cwd=pst)
pstbare = ENV["DEMO_REPOS"] + "/pinstack.git"
subprocess.run(["rm", "-rf", pstbare], check=True)
sh("git", "clone", "-q", "--bare", pst, pstbare, cwd=work)
subprocess.run(["just", "cli", "register", "max", REPOS + "/pinstack.git"], capture_output=True, text=True)
open(os.path.join(pst, "cactarium-stack.toml"), "w").write(pst_toml("d-2"))
retag(pst, pstbare, "v1.1.0")
ok, out = cli_sync("max/pinstack")
check("a stack pinning a source tag that isn't pushed yet waits", not ok and "d-2" in out and not has_version(maxv, "max/pinstack", "1.1.0"), out[-300:])
open(os.path.join(dep, "README"), "w").write("2\n")
sh("git", "add", "-A", cwd=dep); sh("git", *ident, "commit", "-q", "-m", "d-2", cwd=dep); sh("git", "tag", "d-2", cwd=dep)
sh("git", "push", "-q", depbare, "master", "--tags", cwd=dep)
ok, out = cli_sync("max/pinstack")
check("and is read once the tag is there", ok and has_version(anon, "max/pinstack", "1.1.0"), out[-300:])
# A tag that has waited a very long time (its backoff long capped) doesn't break the sync: other
# waiting tags are still tried and read.
def psql(sql):
    here = os.path.dirname(os.path.abspath(__file__))
    return subprocess.run(["docker", "compose", "--project-directory", here, "-f", here + "/compose.yaml", "-f", here + "/compose.dev.yaml",
                           "exec", "-T", "db", "psql", "-U", "cactarium", "-d", "cactarium", "-tAc", sql],
                          check=True, capture_output=True, text=True).stdout.strip()
open(os.path.join(pst, "cactarium-stack.toml"), "w").write(pst_toml("never"))
retag(pst, pstbare, "v1.2.0")
open(os.path.join(pst, "cactarium-stack.toml"), "w").write(pst_toml("d-3"))
retag(pst, pstbare, "v1.3.0")
ok, out = cli_sync("max/pinstack")
check("two stack tags wait for source tags", not ok and not has_version(maxv, "max/pinstack", "1.3.0"), out[-300:])
psql("UPDATE waiting_tags SET tries = 34, next_try_at = now() - interval '1 minute' WHERE tag = 'v1.2.0' AND entry_id = (SELECT id FROM entries WHERE name = 'pinstack')")
open(os.path.join(dep, "README"), "w").write("3\n")
sh("git", "add", "-A", cwd=dep); sh("git", *ident, "commit", "-q", "-m", "d-3", cwd=dep); sh("git", "tag", "d-3", cwd=dep)
sh("git", "push", "-q", depbare, "master", "--tags", cwd=dep)
ok, out = cli_sync("max/pinstack")
check("a tag that waited about a week doesn't break the sync: a later waiting tag is read",
      "out of range" not in out and has_version(anon, "max/pinstack", "1.3.0"), out[-300:])
open(os.path.join(pst, "cactarium-stack.toml"), "w").write(pst_toml("d-4"))
retag(pst, pstbare, "v1.4.0")
cli_sync("max/pinstack")
sh("git", "tag", "d-4", cwd=dep); sh("git", "push", "-q", depbare, "--tags", cwd=dep)
psql("UPDATE waiting_tags SET next_try_at = now() - interval '1 minute'")
ok, out = cli_sync("max/pinstack")
check("and the syncs after it keep working", "out of range" not in out and has_version(anon, "max/pinstack", "1.4.0")
      and int(psql("SELECT tries FROM waiting_tags WHERE tag = 'v1.2.0' AND entry_id = (SELECT id FROM entries WHERE name = 'pinstack')") or 0) >= 35, out[-300:])

# An old bare tag (no manifest) naming the same version as the real v release doesn't take it.
yb = os.path.join(work, "baretag")
os.makedirs(yb)
open(os.path.join(yb, "README"), "w").write("old\n")
sh("git", "init", "-q", "-b", "master", cwd=yb)
sh("git", "add", "-A", cwd=yb); sh("git", *ident, "commit", "-q", "-m", "old upstream release", cwd=yb); sh("git", "tag", "1.0.0", cwd=yb)
os.makedirs(os.path.join(yb, "YbArr", "YbThorn"))
for f, t in [("interface.ccl", "IMPLEMENTS: YbThorn\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n")]:
    open(os.path.join(yb, "YbArr", "YbThorn", f), "w").write(t)
open(os.path.join(yb, "cactarium.toml"), "w").write('format = 1\n\n[package]\nname = "baretag"\nowners = ["max"]\ndescription = "x"\n')
sh("git", "add", "-A", cwd=yb); sh("git", *ident, "commit", "-q", "-m", "release", cwd=yb); sh("git", "tag", "v1.0.0", cwd=yb); sh("git", "tag", "v1.1.0", cwd=yb)
ybbare = ENV["DEMO_REPOS"] + "/baretag.git"
subprocess.run(["rm", "-rf", ybbare], check=True)
sh("git", "clone", "-q", "--bare", yb, ybbare, cwd=work)
subprocess.run(["just", "cli", "register", "max", REPOS + "/baretag.git"], capture_output=True, text=True)
s, r, _ = resolve_q("max/baretag@1.0.0")
check("v1.0.0, not an old bare 1.0.0, is version 1.0.0", s == 200 and r.get("tag") == "v1.0.0", r)

# A dependency released together with this package: its needed thorn comes in a version tagged but
# not read yet, so this version waits instead of freezing.
def tiny(name, thorns, deps=""):
    d = os.path.join(work, name)
    for t in thorns:
        os.makedirs(os.path.join(d, "CoArr", t), exist_ok=True)
        for f, txt in [("interface.ccl", f"IMPLEMENTS: {t}\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n")]:
            open(os.path.join(d, "CoArr", t, f), "w").write(txt)
    open(os.path.join(d, "cactarium.toml"), "w").write(f'format = 1\n\n[package]\nname = "{name}"\nowners = ["max"]\ndescription = "x"\n{deps}')
    return d
cob = tiny("cob", ["CbThorn"])
sh("git", "init", "-q", "-b", "master", cwd=cob)
sh("git", "add", "-A", cwd=cob); sh("git", *ident, "commit", "-q", "-m", "cob 2.0", cwd=cob); sh("git", "tag", "v2.0.0", cwd=cob)
cobbare = ENV["DEMO_REPOS"] + "/cob.git"
subprocess.run(["rm", "-rf", cobbare], check=True)
sh("git", "clone", "-q", "--bare", cob, cobbare, cwd=work)
subprocess.run(["just", "cli", "register", "max", REPOS + "/cob.git"], capture_output=True, text=True)
coa = tiny("coa", ["CaThorn"])
sh("git", "init", "-q", "-b", "master", cwd=coa)
sh("git", "add", "-A", cwd=coa); sh("git", *ident, "commit", "-q", "-m", "coa 1.0", cwd=coa); sh("git", "tag", "v1.0.0", cwd=coa)
coabare = ENV["DEMO_REPOS"] + "/coa.git"
subprocess.run(["rm", "-rf", coabare], check=True)
sh("git", "clone", "-q", "--bare", coa, coabare, cwd=work)
subprocess.run(["just", "cli", "register", "max", REPOS + "/coa.git"], capture_output=True, text=True)
tiny("coa", ["CaThorn"], '\n[[dependency]]\ntarget = "max/cob@^2"\nneeds = ["CbThorn", "CbExtra"]\n')
retag(coa, coabare, "v2.0.0")       # coa 2.0 needs CbExtra, which cob gets in 2.1
tiny("cob", ["CbThorn", "CbExtra"])
retag(cob, cobbare, "v2.1.0")       # tagged, not read yet
ok, out = cli_sync("max/coa")
check("a dependency whose needed thorn comes in a version not read yet makes the version wait",
      not ok and "isn't read yet" in out and not has_version(maxv, "max/coa", "2.0.0"), out[-300:])
cli_sync("max/cob")
ok, out = cli_sync("max/coa")
check("once that version is read, it is valid", ok and has_version(anon, "max/coa", "2.0.0") and "invalid" not in versions_page(maxv, "max/coa"), out[-300:])

# When the dependency's repo can't be listed, the wait says so.
tiny("coa", ["CaThorn"], '\n[[dependency]]\ntarget = "max/cob@^2"\nneeds = ["CbThorn", "CbMore"]\n')
retag(coa, coabare, "v3.0.0")
os.rename(cobbare, cobbare + ".away")
ok, out = cli_sync("max/coa")
os.rename(cobbare + ".away", cobbare)
check("a dependency whose repo can't be listed waits, saying so",
      not ok and "can't be listed right now" in out and not has_version(maxv, "max/coa", "3.0.0"), out[-300:])
ok, out = cli_sync("max/coa")
check("once it can be, a needed thorn no version in range has is a fact", "doesn&#39;t have" in versions_page(maxv, "max/coa")
      and 'href="/max/coa/3.0.0' in versions_page(maxv, "max/coa"), out[-300:])

# With a declared pattern, the spelling the pattern writes wins over another spelling of one version.
rs = os.path.join(work, "relspell")
os.makedirs(rs)
open(os.path.join(rs, "README"), "w").write("old\n")
sh("git", "init", "-q", "-b", "master", cwd=rs)
sh("git", "add", "-A", cwd=rs); sh("git", *ident, "commit", "-q", "-m", "old", cwd=rs); sh("git", "tag", "rel-01.0", cwd=rs)
os.makedirs(os.path.join(rs, "RsArr", "RsThorn"))
for f, t in [("interface.ccl", "IMPLEMENTS: RsThorn\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n")]:
    open(os.path.join(rs, "RsArr", "RsThorn", f), "w").write(t)
open(os.path.join(rs, "cactarium.toml"), "w").write('format = 1\n\n[package]\nname = "relspell"\nowners = ["max"]\ndescription = "x"\ntag-pattern = "rel-{major}.{minor}"\n')
sh("git", "add", "-A", cwd=rs); sh("git", *ident, "commit", "-q", "-m", "release", cwd=rs); sh("git", "tag", "rel-1.0", cwd=rs); sh("git", "tag", "rel-1.1", cwd=rs)
rsbare = ENV["DEMO_REPOS"] + "/relspell.git"
subprocess.run(["rm", "-rf", rsbare], check=True)
sh("git", "clone", "-q", "--bare", rs, rsbare, cwd=work)
subprocess.run(["just", "cli", "register", "max", REPOS + "/relspell.git"], capture_output=True, text=True)
s, r, _ = resolve_q("max/relspell@1.0.0")
check("rel-1.0, the spelling its pattern writes, is 1.0.0, not an old rel-01.0", s == 200 and r.get("tag") == "rel-1.0", r)



# A stack override naming a package registered a moment after the stack's tag waits.
ovp = os.path.join(work, "ovpkg")
os.makedirs(os.path.join(ovp, "OvArr", "OvThorn"))
for f, t in [("interface.ccl", "IMPLEMENTS: OvThorn\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n")]:
    open(os.path.join(ovp, "OvArr", "OvThorn", f), "w").write(t)
open(os.path.join(ovp, "cactarium.toml"), "w").write('format = 1\n\n[package]\nname = "ovpkg"\nowners = ["max"]\ndescription = "x"\n')
sh("git", "init", "-q", "-b", "master", cwd=ovp)
sh("git", "add", "-A", cwd=ovp); sh("git", *ident, "commit", "-q", "-m", "ovpkg", cwd=ovp); sh("git", "tag", "v1.0.0", cwd=ovp)
ovbare = ENV["DEMO_REPOS"] + "/ovpkg.git"
subprocess.run(["rm", "-rf", ovbare], check=True)
sh("git", "clone", "-q", "--bare", ovp, ovbare, cwd=work)
ovs = os.path.join(work, "ovstack")
os.makedirs(ovs)
open(os.path.join(ovs, "s.th"), "w").write(
    f"!CRL_VERSION = 1.0\n!DEFINE ROOT = Cactus\n!TARGET = $ROOT/arrangements\n!TYPE = git\n!URL = {REPOS}/ovpkg.git\n!REPO_PATH = $1/$2\n!CHECKOUT =\nOvArr/OvThorn\n")
ovs_toml = 'format = 1\n\n[stack]\nname = "ovstack"\nowners = ["max"]\nthornlist = "s.th"\n'
open(os.path.join(ovs, "cactarium-stack.toml"), "w").write(ovs_toml)
sh("git", "init", "-q", "-b", "master", cwd=ovs)
sh("git", "add", "-A", cwd=ovs); sh("git", *ident, "commit", "-q", "-m", "1.0", cwd=ovs); sh("git", "tag", "v1.0.0", cwd=ovs)
ovsbare = ENV["DEMO_REPOS"] + "/ovstack.git"
subprocess.run(["rm", "-rf", ovsbare], check=True)
sh("git", "clone", "-q", "--bare", ovs, ovsbare, cwd=work)
subprocess.run(["just", "cli", "register", "max", REPOS + "/ovstack.git"], capture_output=True, text=True)
ovt = os.path.join(work, "ovtop")
os.makedirs(ovt)
ovt_toml = 'format = 1\n\n[stack]\nname = "ovtop"\nowners = ["max"]\nextends = ["max/ovstack@1.0.0"]\n'
open(os.path.join(ovt, "cactarium-stack.toml"), "w").write(ovt_toml)
sh("git", "init", "-q", "-b", "master", cwd=ovt)
sh("git", "add", "-A", cwd=ovt); sh("git", *ident, "commit", "-q", "-m", "1.0", cwd=ovt); sh("git", "tag", "v1.0.0", cwd=ovt)
ovtbare = ENV["DEMO_REPOS"] + "/ovtop.git"
subprocess.run(["rm", "-rf", ovtbare], check=True)
sh("git", "clone", "-q", "--bare", ovt, ovtbare, cwd=work)
run = subprocess.run(["just", "cli", "register", "max", REPOS + "/ovtop.git"], capture_output=True, text=True)
check("register a stack extending another", run.returncode == 0 and has_version(anon, "max/ovtop", "1.0.0"), run.stdout + run.stderr[-300:])
open(os.path.join(ovt, "cactarium-stack.toml"), "w").write(ovt_toml + '\n[[stack.override]]\nrepo = "ovpkg"\npackage = "max/ovpkg@1"\n')
retag(ovt, ovtbare, "v1.1.0")
ok, out = cli_sync("max/ovtop")
check("a stack override naming a package not registered yet waits", not ok and "max/ovpkg" in out and not has_version(maxv, "max/ovtop", "1.1.0"), out[-300:])
subprocess.run(["just", "cli", "register", "max", REPOS + "/ovpkg.git"], capture_output=True, text=True)
ok, out = cli_sync("max/ovtop")
check("and is read once the package is", ok and has_version(anon, "max/ovtop", "1.1.0") and "invalid" not in versions_page(maxv, "max/ovtop"), out[-300:])

# An invalid version whose tag moves stays invalid, and is never served.
ib = os.path.join(work, "invmove")
os.makedirs(os.path.join(ib, "InvArr", "InvThorn"))
for f, t in [("interface.ccl", "IMPLEMENTS: InvThorn\n"), ("param.ccl", "\n"), ("schedule.ccl", "\n")]:
    open(os.path.join(ib, "InvArr", "InvThorn", f), "w").write(t)
inv_toml = lambda name: f'format = 1\n\n[package]\nname = "{name}"\nowners = ["max"]\ndescription = "x"\n'
open(os.path.join(ib, "cactarium.toml"), "w").write(inv_toml("invmove"))
sh("git", "init", "-q", "-b", "master", cwd=ib)
sh("git", "add", "-A", cwd=ib); sh("git", *ident, "commit", "-q", "-m", "1.0", cwd=ib); sh("git", "tag", "v1.0.0", cwd=ib)
ibare = ENV["DEMO_REPOS"] + "/invmove.git"
subprocess.run(["rm", "-rf", ibare], check=True)
sh("git", "clone", "-q", "--bare", ib, ibare, cwd=work)
subprocess.run(["just", "cli", "register", "max", REPOS + "/invmove.git"], capture_output=True, text=True)
open(os.path.join(ib, "cactarium.toml"), "w").write(inv_toml("wrongname"))
retag(ib, ibare, "v1.1.0")
cli_sync("max/invmove")
check("a tag naming another entry is an invalid version", "the manifest names" in versions_page(maxv, "max/invmove"))
open(os.path.join(ib, "cactarium.toml"), "w").write(inv_toml("invmove"))
retag(ib, ibare, "v1.1.0")  # the tag moves onto a fixed commit
cli_sync("max/invmove")
text = versions_page(maxv, "max/invmove")
check("an invalid version whose tag moves stays invalid (not tag-moved)", "the manifest names" in text and "tag moved upstream" not in text, text[text.find("<table"):][:600])
s, r, _ = resolve_q("max/invmove@1.1.0")
check("and is never served, even asked for exactly", s == 400, r)
s, r, _ = resolve_q("max/invmove@^1")
check("ranges skip it", s == 200 and r.get("slug") == "max/invmove@1.0.0", r)
# A second tag naming a version the entry already has (bare 1.0.0 beside v1.0.0) is skipped; it
# doesn't stop the sync with a collision.
open(os.path.join(ib, "README"), "w").write("dup\n")
retag(ib, ibare, "1.0.0")
retag(ib, ibare, "v1.2.0")
ok, out = cli_sync("max/invmove")
check("a tag naming a version the entry has is skipped, and later tags are still read",
      ok and has_version(anon, "max/invmove", "1.2.0"), out[-300:])


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
