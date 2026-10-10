## What does this change, and why?

<!-- One or two sentences. Link the issue if there is one. -->

## How did you test it?

- [ ] `make test` passes (or `bash tests/run.sh`)
- [ ] `make lint` passes (ShellCheck)
- [ ] I added or updated a test for the change
- [ ] I ran it against a real site (read-only `scan`) and the findings make sense

## Checklist

- [ ] No complete malware samples in the repo (build them from fragments, see CONTRIBUTING.md)
- [ ] No process substitution `<(...)`, no CRLF line endings
- [ ] `fix` stays conservative: when in doubt it reports instead of acting
- [ ] User-facing messages are in English; README/CHANGELOG updated if behavior changed
