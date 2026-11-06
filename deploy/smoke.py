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
import sys
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
          "/et/et", "/et/et/2026.5.0", "/max/carpetx-mp", "/max/qc0-demo", "/max/qc0-demo/1?tab=pins",
          "/max/qc0-demo/1?tab=thornlist", "/max/qc0-demo/1?tab=inputs", "/max/qc0-demo/1?tab=run",
          "/max/carpetx-mp/1.0.0/download.th", "/max/qc0-demo/1/download.sim", "/auth/login"]:
    page(anon, p)
page(anon, "/max/carpetx", contains="mixed-precision")
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
definition = 'format = 1\n\n[stack]\nname = "smoke-stack"\nextends = ["et/et@2026.5.0"]\ndisable = ["CarpetX/Loop"]\n'
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
         "!REPO_PATH = $2\n!CHECKOUT = Other/Boundary\n")
s, text, _ = maxv.post("/new/stack", {"definition": definition.replace("smoke-stack", "clash"), "thornlist": clash, "version": "0.1.0"})
check("thorn-name collisions are refused", s == 200 and "collide" in text, text[text.find("alert"):][:300])
page(anon, "/max/clash", expect=404)  # a failed release leaves no entry behind
text = page(anon, "/max/carpetx")
check("the newest manifest's default track is shown first", 'pill mono selected" href="/max/carpetx?track=mixed-precision"' in text)

print()
if FAILED:
    print(f"{len(FAILED)} failed")
    sys.exit(1)
print("all passed")
