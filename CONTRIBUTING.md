# Contributing

Thanks for helping. The most valuable contributions are **new detection rules**, **false-positive reports** and **testing on other hosting environments**.

## Quick orientation

```
bin/      one script per command; they only orchestrate
lib/      single-purpose modules (config, runtime, inventory, report, heal, notify, ...)
checks/   one file per check group; checks only READ the site and report findings
rules/    php.rules, js.rules - one signature per line
tests/    run.sh (end-to-end, fake site + simulated wp-cli), stub/wp
docs/     rules guide
```

- **New check:** one file in `checks/` defining `job_<name>`, plus one `spawn <group> <name> job_<name>` line in `lib/audit.sh`. Checks must never modify the site.
- **New signature:** one line in `rules/*.rules` — see [docs/rules.md](docs/rules.md).
- **New alert channel:** a block in `lib/notify.sh` plus an entry in the wizard in `lib/notify_setup.sh`.

## Before you open a pull request

```bash
make check        # = make lint (ShellCheck, warnings fail) + make test (must end with "0 failed")
```

No `make`? Run `bash tests/run.sh` and `shellcheck -x -S warning -s bash bin/* lib/*.sh checks/*.sh install.sh tests/run.sh tests/stub/wp`. CI runs the same on Ubuntu 22.04 and 24.04.

Variables that look unused to ShellCheck because another sourced file reads them are covered by a documented `# shellcheck disable=SC2034` at the top of the module; do not add global suppressions.

Add a test for what you change. For a new rule, add a sample to `tests/run.sh`.

### Code conventions

- Bash 4, GNU userland. Keep it dependency-free (no Python/Node/Perl for the core).
- **No process substitution `<(...)`**: some shared hosts have no `/dev/fd`. Use a temp file under `$TMP`.
- Unix line endings only (`.gitattributes` enforces this). CRLF breaks bash.
- Quote everything that comes from the filesystem: file names are attacker-controlled.
- Be conservative in `fix`: when in doubt, report it and leave it to the human.
- User-visible messages are in English.

### Test samples and antivirus

Never commit a complete working malware sample. Build samples at run time from fragments (see the helpers at the top of `tests/run.sh`), otherwise antivirus software will delete the test suite — this already happened once.

## Reporting a false positive

Open an issue with: the finding text, the file (or a minimal snippet, no secrets), the plugin/theme and version it belongs to, and your hosting. If the file is part of a popular plugin, that lets us add a precise exception instead of a broad one.

## Security issues

Do not use public issues. See [SECURITY.md](SECURITY.md).
