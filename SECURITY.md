# Responsible use

This repository is for **defensive verification, education, and authorized security testing**:
confirming your own WordPress estate is patched against wp2shell (CVE-2026-63030 / CVE-2026-60137)
and understanding the bug. The vulnerability is public and fixed in WordPress 6.8.6 / 6.9.5 / 7.0.2.

- **Only run the tool against systems you own or are explicitly authorized to test.** Remote
  (non-loopback) targets require the `--authorized` flag as an affirmative assertion of that.
- **Detection mode (default)** is non-destructive: it confirms the SQL injection via a timing
  differential and, with `--proof`, reads only `@@version` and `current_user()`. It does not
  extract sensitive data or modify anything.
- **RCE mode (`-c COMMAND`)** performs the full pre-auth exploitation chain. It creates a
  temporary administrator account, uploads a self-cleaning webshell plugin (deactivates and deletes
  itself after one use), and executes the specified command. Use only in controlled lab environments
  or with explicit written authorization.
- The Docker lab runs entirely locally. No exploit is sent to any external service.

Testing systems you do not own or lack permission to test may be illegal. You are responsible for
staying within scope and the law.

## Credits

- Route confusion + SQLi: Adam Kues (Assetnote / Searchlight Cyber)
- Stock-default RCE chain: Mustafa Can İPEKÇİ (nukedx)
- SQLi: also TF1T, dtro, haongo

## Reporting

Found an issue in this repo (not in WordPress)? Open an issue or PR. For WordPress core itself, use
the official channel: https://hackerone.com/wordpress.
