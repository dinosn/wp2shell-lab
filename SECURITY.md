# Responsible use

This repository is for **defensive verification and education**: confirming your own WordPress
estate is patched against wp2shell (CVE-2026-63030 / CVE-2026-60137) and understanding the bug. The
vulnerability is public and fixed in WordPress 6.8.6 / 6.9.5 / 7.0.2.

- **Only run the detector against systems you own or are explicitly authorized to test.** Remote
  (non-loopback) targets require the `--authorized` flag as an affirmative assertion of that.
- The detector is **non-destructive**: it confirms the SQL injection via a timing differential and,
  with `--proof`, reads only `@@version` and `current_user()`. It does **not** attempt code
  execution, dump sensitive data, or modify anything.
- The Docker lab runs entirely locally and is configured like a normal host (DB user has no `FILE`
  privilege). No exploit that achieves code execution is included.

Testing systems you do not own or lack permission to test may be illegal. You are responsible for
staying within scope and the law.

## Reporting

Found an issue in this repo (not in WordPress)? Open an issue or PR. For WordPress core itself, use
the official channel: https://hackerone.com/wordpress.
