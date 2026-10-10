# wp-guard

[![CI](https://github.com/balzatech/wp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/balzatech/wp-guard/actions/workflows/ci.yml) [![License: GPL v3](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

**Find and safely fix malware on a WordPress site — from the command line, in minutes.**

wp-guard is a free (GPL-3.0) security scanner and cleaner for WordPress, written in plain Bash. It was born from cleaning a real, compromised site on shared hosting, so it is built for the situation of people who manage WordPress sites over SSH: freelancers, agencies and technical site owners — no root, no extra services.

*Español: [README.es.md](README.es.md)*

## Is it for you?

**wp-guard needs SSH (command-line) access to your hosting.** It is not a WordPress plugin and has no web interface.

| You have... | Then... |
|---|---|
| SSH access on Linux hosting (most VPS, Hostinger, SiteGround, Cloudways, cPanel plans with Terminal/SSH) | **wp-guard is for you.** Install [wp-cli](https://wp-cli.org) too for the database and checksum checks. |
| Only a hosting panel, but you can create **Cron Jobs** | Partly: schedule `wp-guard watch` and get alerts by email or chat. You cannot fix from there. Look in your panel for "SSH Access" first: it is often a switch you have not enabled. |
| No SSH and no cron | wp-guard will not work for you. Use a WordPress security plugin instead (for example Wordfence or Sucuri), or ask your host to enable SSH. |

You also need: Linux, bash 4+, and GNU `find`/`grep`/`awk`/`sed` (macOS, BSD and Windows are not supported). Check your access with `ssh user@your-server` (details are in your host's panel).

```
$ wp-guard scan
 VERDICT: ALERT - 3 alerts, 14 warnings, 6 info
 ...
$ wp-guard fix
 QUARANTINE   [1] ./wp-content/uploads/shell.php   [executable inside uploads]
 QUARANTINE   [2] ./wp-content/uploads/pic.gif     [image with PHP code inside (polyglot)]
 Apply these changes? [y]es / [N]o / [s]elect items to leave out:
```

## Why wp-guard

- **Detects what plugins often miss:** webshells, PHP hidden in images, injected JavaScript, cloaked redirects that only Google visitors see, rogue admins, rogue cron jobs and SSH keys, tampered core/plugin files.
- **Fixes conservatively.** It only acts on high-confidence findings, **never deletes** (everything goes to a quarantine you can undo), asks before acting, and refuses to act at all when too many things look wrong at once (that usually means a false positive or a bigger compromise that needs a human).
- **Easy.** `init` detects your site and administrators for you. Three commands from install to first fix.
- **Tells you.** Alerts to Slack, Discord, ntfy, Telegram or email — and it proves the channel works with a real test message before you rely on it.
- **Transparent.** Plain shell scripts, signatures are one-line text rules you can read and edit, nothing is sent anywhere except the alerts you configure.

## Quick start

```bash
# 1. install (no root needed)
git clone https://github.com/balzatech/wp-guard.git && cd wp-guard && bash install.sh

# 2. one-time guided setup, run from your WordPress folder
wp-guard init

# 3. look, then fix
wp-guard scan        # read-only
wp-guard fix         # preview: changes nothing
wp-guard fix --apply # asks first; nothing is deleted
```

> **Before you fix anything on a real site, make a backup** (your hosting panel, or `wp db export` plus a copy of the files). wp-guard is careful, but it is a heuristic tool.

If you run `wp-guard` with no arguments in a terminal you get a small menu instead.

## Commands

| Command | What it does | Changes the site? |
|---|---|---|
| `wp-guard init` | Guided setup: finds WordPress, reads the URL and administrators, offers to set up alerts | No (writes `~/.wp_auditor/config.sh`) |
| `wp-guard scan [quick]` | Full audit and report. `quick` = files and server only | No (read-only) |
| `wp-guard fix [--apply]` | Preview, or apply, the safe fixes | Only with `--apply` |
| `wp-guard undo DIR` | Put quarantined files back | Yes (restores files) |
| `wp-guard baseline` | Save the current state as "clean" so later changes stand out | No |
| `wp-guard watch` | For cron: alerts only when the set of alerts changes | No |
| `wp-guard notify [setup\|status]` | Set up and test alert channels | No |
| `wp-guard cron` | Print recommended crontab lines | No |
| `wp-guard --version` / `--help` | | No |

Common options: `--path DIR` (site folder), `--site URL`, `-w N` (parallel workers), `--only a,b` / `--skip a,b` (check groups), `--format text|json`, `-y/--yes` (do not ask).
Exit codes of `scan`/`watch`: `0` clean, `1` warnings, `2` alerts.

### JSON output

`wp-guard scan --format json` prints the result as JSON (and nothing else) on stdout, so you can feed it to scripts, CI, dashboards or `jq`. The exit code is unchanged, and every scan also saves a copy as `~/.wp_auditor/reports/report_*.json`.

```bash
wp-guard scan --format json | jq '.counts'
wp-guard scan --format json | jq -r '.findings[] | select(.level=="ALERT") | "\(.category): \(.title)"'
```

```json
{
  "tool": "wp-guard", "version": "0.9.0", "generated": "2026-10-09T02:10:00Z",
  "site": "https://example.com", "path": "/home/user/public_html", "mode": "full",
  "duration_seconds": 51, "verdict": "alert",
  "counts": {"alert": 3, "warning": 14, "info": 28},
  "findings": [
    {"level": "ALERT", "category": "Uploads",
     "title": "Executable files inside uploads (there should be none)", "count": 2,
     "items": ["./wp-content/uploads/shell.php", "./wp-content/uploads/cache/x.php"]}
  ]
}
```

`verdict` is `alert`, `review` or `clean`. `count` is the total number of matches (`items` is capped, usually at 25 entries) or `null` when the finding is a single message.

## What `scan` checks

| Group | Looks for |
|---|---|
| `php`, `js` | Malware signatures and obfuscation heuristics ([rules](docs/rules.md)) in code not verified by official checksums |
| `ioc` | Known attacker markers in files and paths |
| `uploads` | Executable files, hidden files and server config inside `uploads/` |
| `structure` | Foreign files in the web root, hidden files, recently changed code, bad permissions |
| `htaccess`, `wpconfig` | Suspicious rewrite/redirect rules, risky `wp-config.php` settings |
| `plugins`, `integrity` | Official checksums of core and plugins, unverified/nulled/inactive plugins, changes since your baseline |
| `persist` | Cron jobs, authorized SSH keys, long-running processes, scripts outside the web root |
| `othersites` | Infection in other sites of the same hosting account |
| `db` | Unknown administrators, injected scripts in posts/options, suspicious options, database size |
| `http` | Fetches your public pages as different visitors (desktop, mobile, Googlebot, arriving from Google/Bing) to catch cloaked injections |
| `probes` | Exposed files, missing security headers, `xmlrpc.php`, hijacked `robots.txt`/sitemap |
| `logs` | Attack traces in access logs, when the host lets you read them |

Core and plugin files that pass WordPress.org checksum verification are trusted and not scanned, which keeps false positives low and the scan fast.

## Light on your server

Shared hosting limits the CPU of the whole account, so a scanner that runs flat out can get you throttled or suspended. wp-guard limits itself: by default everything it launches (`grep`, `find`, wp-cli, `curl`...) together uses **at most half a core**, enforced by pausing and resuming its own processes (the technique of the `cpulimit` tool, in plain Bash), on top of the lowest CPU and disk priority.

```bash
wp-guard scan              # default: up to 50% of one core (slower, gentle)
wp-guard scan --cpu 25     # even gentler, for very small plans
wp-guard scan --fast       # no limit: finishes sooner, uses more than one core
```

**It also avoids repeating work (incremental scanning).** After a scan, wp-guard remembers which files were clean and which core/plugin folders passed the official checksum check. The next scan only reads files that are new or changed, and only restarts wp-cli for plugins that changed (each wp-cli start costs about 2 s of CPU). On a real site with about 22,000 files and 22 plugins this halved the CPU of a scan (66 s to 29 s) with identical findings.

This is designed so it cannot hide malware:

- Only files that matched **nothing** are skipped; any file that ever produced a finding is read again on every scan.
- "Unchanged" means same size, mtime **and ctime** (ctime cannot be forged with `touch`), so swapping a file for a malicious one with the same size and a copied timestamp is still detected. A file added to a cached plugin invalidates that plugin.
- The cache is dropped when the rules, your matching settings, the allow list or the wp-guard version change, after `FULL_SCAN_DAYS` days (default 7), and with `--full`. A scan limited with `--only`/`--skip` never reads or writes it.
- Only successful verifications are cached. Failures and unverifiable plugins are checked again every time.

```bash
wp-guard scan --full       # re-read everything, ignore the cache
```

Measured on a real site on shared hosting (full scan, first run): unlimited = 41 s at about 160% CPU; the default limit = 130 s at about 51%; `--cpu 30` = 206 s at about 35%. Later scans use the cache and take about 55 s at the default limit. Set `CPU_LIMIT` in the config to make your choice permanent.

## What `fix` does (and does not)

With high confidence only, and always after a preview:

- Moves to quarantine: executable files inside `uploads/`, images with PHP inside, PHP in folders that should have none, foreign PHP in the web root, files carrying known attacker markers, extra files inside the core or official plugins, fake plugin folders.
- Restores modified WordPress core files and reinstalls modified official plugins (same version) from wordpress.org.
- Removes world-write permissions, blocks PHP execution in `uploads/`, demotes unauthorized administrators.

It does **not** delete anything, touch files younger than `MIN_AGE_MIN` (30 min, so it does not fight an update in progress), clean infected database rows automatically, or "repair" third-party themes and premium plugins. What it cannot fix is listed in the report for manual review.

Safety net: **quarantine with a manifest** (original path, sha256, reason) in `~/.wp_auditor/quarantine/`, `wp-guard undo` restores byte-for-byte, a `MAX_HEAL` limit (25) stops it when too many things look wrong, and `wp-guard fix` without `--apply` never writes.

## Alerts

```bash
wp-guard notify setup     # pick Slack / Discord / ntfy / Telegram / email, sends a real test message
wp-guard notify status
```

`watch` alerts only when the set of alerts *changes* (no daily noise); `fix --apply` reports what it did, with the undo command. If no channel is configured, wp-guard says so out loud instead of staying silent.

## Run it automatically

`wp-guard cron` prints the lines. Typical setup: a daily `watch` (read-only) and, once you trust it after a week or two of previews, a periodic `fix --apply`. On hosts without `crontab` over SSH (e.g. Hostinger) paste them in the control panel's Cron Jobs page.

## Configuration

`wp-guard init` writes `~/.wp_auditor/config.sh` (permissions 600). Everything is optional; useful keys:

| Key | Meaning |
|---|---|
| `WP_PATH`, `SITE` | Site folder and public URL (auto-detected) |
| `ALLOWED_ADMINS` | Administrator logins you trust; anyone else is reported |
| `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL`, `NTFY_URL` (+`NTFY_TOKEN`), `TELEGRAM_BOT_TOKEN`+`TELEGRAM_CHAT_ID`, `NOTIFY_EMAIL` | Alert channels |
| `ORIGIN_IP` | Hosting IP, to bypass Cloudflare in the HTTP checks |
| `KNOWN_HOSTS` | External domains you consider normal |
| `IOC_LIST` | Extra attacker markers to look for |
| `MIN_AGE_MIN`, `MAX_HEAL` | Safety limits for `fix` |
| `CPU_LIMIT` | Max CPU as % of one core (default 50; 0 = unlimited) |
| `INCREMENTAL`, `FULL_SCAN_DAYS` | Incremental scanning on/off (default 1) and how often everything is re-read (default 7 days) |
| `WORKERS` | Parallel jobs (default 3; use 1 on very small hosts) |

**False positives:** add a path or text fragment, one per line, to `~/.wp_auditor/allow.txt`; matching lines are dropped from findings.

## Requirements

- Linux with **bash 4+** and GNU `find`, `stat`, `xargs`, `grep`, `awk`, `sed` (macOS/BSD are not supported yet).
- **wp-cli** recommended: without it, database checks and official checksum verification are skipped.
- `curl` for the HTTP checks and Slack/Discord/ntfy/Telegram alerts.
- Tested on shared hosting (Hostinger, SSH without root, no `proc_open`, no `/dev/fd`). Other environments should work but have had less testing — please report what you find.

## How it works

Each command is a small script in `bin/`; `lib/` holds single-purpose modules; every check is one file in `checks/` that only reads. Adding a check = one file in `checks/` plus one `spawn` line in `lib/audit.sh`. Adding a signature = one line in `rules/*.rules` ([guide](docs/rules.md)). Run the tests with `bash tests/run.sh`.

## Limitations — please read

- wp-guard is a **detection and cleanup aid, not a firewall or a guarantee**. Signature and heuristic scanning has false positives and can be evaded by a determined attacker.
- Cleaning files does not close the hole that let the attacker in. After an incident: update everything, remove unused plugins/themes, change all passwords and the keys/salts in `wp-config.php`, review users, and restore from a known-good backup when in doubt.
- Always keep **backups**, and review `wp-guard fix` previews before applying.
- Antivirus software may flag the rule files or test samples because they describe malware; they contain patterns, not working malware.

## Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability in wp-guard itself, see [SECURITY.md](SECURITY.md).

## License

[GPL-3.0-or-later](LICENSE). No warranty; use at your own risk.
