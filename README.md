# wp2shell lab & detector

A small, self-contained lab plus a **non-destructive detector** for **wp2shell** — the
pre-authentication vulnerability chain in WordPress core:

| CVE | Component | Class | CVSS |
|-----|-----------|-------|------|
| **CVE-2026-60137** | `WP_Query::author__not_in` | SQL injection (CWE-89) | 9.1 |
| **CVE-2026-63030** | REST `/batch/v1` route confusion | interpretation conflict (CWE-436) → chains to RCE | 7.5 |

**Affected:** WordPress core **6.9.0–6.9.4** and **7.0.0–7.0.1** (the SQLi sink alone also affects
6.8.0–6.8.5). **Fixed in 6.8.6 / 6.9.5 / 7.0.2.** Reported by Adam Kues (Assetnote / Searchlight
Cyber); SQLi also credited to TF1T, dtro, haongo.

> **Update first.** WordPress shipped forced auto-updates for this. This repo exists to help you
> *verify* your own estate is patched and to understand the bug — not to attack anyone. See
> [SECURITY.md](SECURITY.md).

---

## What it actually is (read this before calling it "RCE")

The **always-true** primitive is an **unauthenticated, no-plugin, stock-core SQL injection** giving
full **database read** (admin password hashes, everything in `wp_options`/`wp_users`). That alone
earns the 9.1 and immediate patching.

The **"RCE" is real but conditional.** The only core-only escalation shown publicly is
SQLi → `INTO OUTFILE` webshell, which additionally needs **all** of:
1. the WordPress DB user holding the global **FILE** privilege — *not* the default
   (`GRANT ALL ON wordpressdb.*`, as cPanel/managed hosts issue, has no FILE; FILE shows up mainly
   on self-managed VPS `GRANT ALL ON *.*` and dev boxes),
2. a **web-served `secure_file_priv`** directory, and
3. the dropped file being **readable by the web user** (MySQL writes `OUTFILE` as `0640 mysql:mysql`).

On a normal/managed host none of that holds, so wp2shell is a **read-only SQL injection**, not RCE.
This lab is configured like a normal host (no FILE privilege) and this detector deliberately stops
at proving the SQLi — it never attempts code execution.

## How the chain works

`serve_batch_request_v1()` (in `wp-includes/rest-api/class-wp-rest-server.php`) builds two parallel
arrays while iterating sub-requests: a sub-request whose path fails `wp_parse_url()` (e.g. `http://`)
is appended to `$validation` but **not** to `$matches`. The dispatch loop then indexes both by the
same offset, so every sub-request *after* an injected parse error is executed under the **next**
sub-request's handler. Nested twice, this (a) self-calls the batch handler to bypass the method
allow-list, then (b) runs `POST /wp/v2/categories?author_exclude=<sqli>` under posts `get_items` —
and because `categories` never registers `author_exclude`, the value skips sanitization and reaches
`WP_Query::author__not_in`, interpolated into `NOT IN (...)`. Directly hitting
`?rest_route=/wp/v2/posts&author_exclude=<sqli>` returns HTTP 400 (sanitized); the confusion is
required.

---

## Quick start

Requirements: Docker + Docker Compose v2, Python 3.8+ (stdlib only), `make`, `curl`.

```bash
make up          # WordPress 6.9.4 (vulnerable) + MySQL 8.0, auto-installed on :8093
make check       # -> [VULNERABLE] http://localhost:8093 (WordPress 6.9.4 ...)
make proof       # -> also reads @@version and current_user() as read-only evidence
make patched     # rebuild on the fixed image and re-check -> [not vulnerable]
make down        # tear down (removes volumes)
```

Change the port with `WP_PORT=8100 make up`.

> **Note on the patched image:** the official Docker `wordpress` images lag WordPress core security
> releases by a day or two. If `make patched` reports that `wordpress:7.0.2` isn't on Docker Hub yet,
> retry later or point it at whichever fixed tag has published:
> `make patched WP_PATCHED_TAG=6.9.5` (or `7.0.2` / `6.8.6`). Any WordPress ≥ 6.9.5 / 7.0.2 / 6.8.6
> returns `not vulnerable`.

### Expected output

```
$ make check
[VULNERABLE] http://localhost:8093  (WordPress 6.9.4, affected-range)  [fast=0.02s slow=4.03s delta=4.01s]

$ make patched
[not vulnerable] http://localhost:8093  (WordPress 7.0.2, outside-affected-range)  [fast=0.02s slow=0.03s delta=0.01s]
```

---

## The detector (`wp2shell_check.py`)

Standard library only. **Non-destructive:** a time-based differential (fast vs. injected `SLEEP`)
confirms the injection without reading data or changing state. `--proof` reads only `@@version` and
`current_user()` via a bounded blind read, as hard evidence for a ticket. It **does not** attempt
code execution or extract sensitive data.

```bash
# your own single asset (remote targets require an authorization assertion)
python3 wp2shell_check.py https://your-site.example --authorized

# a list of assets you own, JSON out
python3 wp2shell_check.py -f assets.txt --authorized --json

# through Burp
python3 wp2shell_check.py http://127.0.0.1:8093 --proxy http://127.0.0.1:8080
```

Options: `--sleep N` (injected delay, default 4), `--rounds N` (median over N probes),
`--route auto|rest-route|wp-json`, `--timeout N`, `--proof`, `--json`, `--authorized`.
Exit codes: `0` vulnerable, `1` not vulnerable, `2` inconclusive/error.

---

## Remediation

- **Patch** to WordPress **6.9.5 / 7.0.2** (or **6.8.6** on the 6.8 branch).
- If you can't patch immediately, block **both** `/wp-json/batch/v1` **and** `?rest_route=/batch/v1`
  at the edge — a rule on only the pretty path leaves the query-string route open — or require auth
  on the batch route via a `rest_pre_dispatch` filter.
- Defense in depth: ensure the WordPress DB user has **no global FILE privilege**.

## References

- Searchlight Cyber / Assetnote — https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/
- WordPress 7.0.2 release — https://wordpress.org/news/2026/07/wordpress-7-0-2-release/
- Advisories: GHSA-ff9f-jf42-662q, GHSA-fpp7-x2x2-2mjf

## License

MIT — see [LICENSE](LICENSE).
