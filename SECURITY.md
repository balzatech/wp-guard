# Security policy

wp-guard runs with the permissions of your hosting account and can move files and change user roles, so its own security matters.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem in wp-guard itself. Report it privately through GitHub's *Security → Report a vulnerability* feature on this repository (private vulnerability reporting). Include what you did, what you expected, and what happened.

You can expect an acknowledgement within a week. Fixes are released with a CHANGELOG entry and credit, unless you prefer to stay anonymous.

## What counts as a vulnerability here

- A way for a malicious **file name, plugin name, site content or config value** to make wp-guard run code or write outside its intended places (command injection, path traversal in quarantine/restore, unsafe `eval`/`source`).
- A way to make `fix` quarantine, overwrite or delete files it should not touch.
- Leaking secrets (webhook URLs, tokens) to logs, reports or other channels.
- Insecure default permissions on `~/.wp_auditor` (config, quarantine, reports).

False positives/negatives of the malware rules are normal bugs: open a regular issue.

## Design choices relevant to security

- `config.sh` is **sourced as shell**, so it must be writable only by you; wp-guard creates it with mode 600 and `wp-guard init` shell-quotes every value it writes.
- `fix` never deletes. It moves files into a quarantine with a manifest (original path, sha256) so every action can be undone.
- Nothing about your site is sent to third parties. Outgoing traffic is limited to: requests to your own site (the HTTP checks also download the scripts your pages load, to scan them), wp-cli's calls to wordpress.org for checksums and plugin downloads, and the alert channels *you* configure. The channel URL is never written to `notify.log`.
- Scans scan hostile content. The tools used on it are plain `grep`/`find`/`awk`; findings are printed after `cat -v` so control characters in file names cannot hijack your terminal.

## Supported versions

Only the latest release receives security fixes while the project is pre-1.0.
