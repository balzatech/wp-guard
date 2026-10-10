# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.9.0] - 2026-10-08

First public pre-release, extracted from a private tool used on a real, previously compromised site.

### Added
- `wp-guard init`: guided setup that auto-detects the WordPress folder, the site URL and the administrators.
- Single entry point `wp-guard` with `scan`, `fix`, `undo`, `watch`, `baseline`, `notify`, `cron`, plus an interactive menu.
- `fix --apply` asks for confirmation in a terminal, numbers the quarantine items so some can be left out, and prints a summary with the exact undo command. `--yes` skips the question (cron keeps working unchanged).
- Alert channels: Slack, Discord, ntfy, Telegram and email; `wp-guard notify setup` sends a real test message; a missing or failing channel is reported instead of being silent.
- Test suite (`tests/run.sh`) with a fake WordPress site and a simulated wp-cli, and a GitHub Actions workflow.
- CPU governor: everything wp-guard launches is kept under `CPU_LIMIT` (default 50% of one core) by pausing and resuming its process tree. `--cpu N` changes it, `--fast` removes it. Default workers lowered from 4 to 3.
- Incremental scanning: later scans only read files that are new or changed (size, mtime and ctime) and only re-verify core/plugins whose files changed, which halves the CPU of a scan. Only files that matched nothing and only successful verifications are cached; the cache is dropped when rules or settings change, after `FULL_SCAN_DAYS` (7) days, and with `--full`. Config: `INCREMENTAL`, `FULL_SCAN_DAYS`.
- `wp-guard scan --format json`: machine-readable report on stdout (valid JSON only; hostile file names are escaped). A `report_*.json` copy is saved with every scan.
- Developer tooling: `Makefile` (`make test`, `make lint`, `make check`), CI on Ubuntu 22.04 and 24.04 with ShellCheck at warning level, issue and pull request templates, `.editorconfig`, Dependabot for GitHub Actions.
- `install.sh`, `VERSION`, GPL-3.0 license.
- Documentation: English README, Spanish README, rules guide, CONTRIBUTING and SECURITY policy.

### Changed
- No site-specific defaults any more (path, URL and administrators come from auto-detection or `init`).
- Scan reports end with concrete next steps.
- All messages, reports, rule descriptions and code comments are now in English. Report files are named `report_*.txt` / `findings_*.tsv`.
- The HTTP cloaking checks use configurable `Accept-Language` values (`HTTP_LANG`, `HTTP_LANG_ALT`) instead of hard-coded Colombian Spanish.

### Security
- `undo` no longer trusts the quarantine manifest: paths that climb out of the site (`..`), absolute paths, and files that would overwrite an existing one are skipped and reported.

### Fixed
- `<(...)` process substitution removed from `init` (not available on some shared hosts).
