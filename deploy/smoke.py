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
          "/et/et-stack", "/et/et-stack/2026.5.0", "/max/carpetx-mp", "/max/qc0-demo", "/max/qc0-demo/1?tab=pins",
          "/max/qc0-demo/1?tab=thornlist", "/max/qc0-demo/1?tab=inputs", "/max/qc0-demo/1?tab=run",
          "/max/carpetx-mp/1.0.0/download.th", "/max/qc0-demo/1/download.sim", "/auth/login"]:
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
    s, _, _ = maxv.post(f"/admin/review/{sid}", {"decision": "approve", "check_license": "on"})
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
    _, sim, _ = anon.get("/api/v1/sims/max/qc0-demo/1/download")
    s, body, hdrs = anon.req("POST", "/api/v1/sims/max/qc0-demo", raw=sim.encode(), headers={"Authorization": f"Bearer {tok.group(1)}"})
    check("publish a sim version through the API", s == 200 and '"max/qc0-demo@2"' in body, f"{s} {body[:200]}")
    check("API responses carry api-generation", hdrs.get("api-generation") == "1", hdrs.get("api-generation"))
    s, body, _ = anon.req("POST", "/api/v1/sims/alice/qc0-demo", raw=sim.encode(), headers={"Authorization": f"Bearer {tok.group(1)}"})
    check("a token cannot publish under another owner", s == 403, s)
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

# Yank and unyank.
text = page(maxv, "/max/carpetx?tab=versions")
vid = re.search(r'name="version_id" value="(\d+)"', text)
if vid:
    s, _, _ = maxv.post("/max/carpetx/yank", {"version_id": vid.group(1), "yank": "1", "reason": "smoke"})
    check("yank", s == 303, s)
    s, body, _ = anon.get("/api/v1/resolve?req=max/carpetx@^1")
    check("resolve skips the yanked version", s == 200 and json.loads(body)["slug"] != "max/carpetx@1.1.0", body[:200])
    maxv.get("/max/carpetx?tab=versions")
    s, _, _ = maxv.post("/max/carpetx/yank", {"version_id": vid.group(1), "yank": "0"})
    check("unyank", s == 303, s)

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
    maxv.get(f"/admin?s={sid}")
    s, _, _ = maxv.post(f"/admin/review/{sid}", {"decision": decision, "note": note})
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
check("cut a release pinned by tags", s == 303, f"{s} {text[text.find('alert'):][:300]}")
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

print()
if FAILED:
    print(f"{len(FAILED)} failed")
    sys.exit(1)
print("all passed")
