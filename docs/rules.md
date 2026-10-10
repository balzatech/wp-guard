# Writing detection rules

Signatures live in `rules/php.rules` (applied to PHP-like files) and `rules/js.rules` (JS/HTML/SVG). They are plain text, one rule per line, so you can add or tune a rule without touching any code.

## Format

```
LEVEL@@id@@description@@regex
```

| Field | Meaning |
|---|---|
| `LEVEL` | `ALERT` = almost certainly malicious. `WARN` = suspicious, a human should look. |
| `id` | Short unique name, e.g. `debug_dump`. |
| `description` | Shown in the report. Must not contain `@@`. |
| `regex` | POSIX **extended** regular expression (GNU `grep -E`), matched **case-insensitively**. May contain anything, including `@@`. |

Lines that are empty or start with `#` are ignored.

### Example

```
WARN@@debug_dump@@Leftover debugging output@@\b(var_dump|print_r)\s*\(\s*\$_(GET|POST|REQUEST)
```

Every file that matches is listed under the rule's description, grouped in the report by category.

## Choosing the level

- Use **ALERT** only when a legitimate plugin would essentially never match. ALERTs drive the exit code (2) and the notifications, so a noisy ALERT rule is costly.
- Use **WARN** for "this is sometimes legitimate" (file uploads, base64 blobs, redirects). It appears in the report but does not page anyone.

## Writing good patterns

- Anchor on the *dangerous combination*, not a single function: a call that executes code **and** its argument comes from the visitor or from decoded data.
- Allow for whitespace and comments tricks: `\s*`, optional `@` before calls.
- Keep patterns specific and short. All rules run in a single `grep` pass over many files, so a pathological regex (nested quantifiers such as `(a+)+`) slows the whole scan.
- GNU `grep -E` supports `\s`, `\b`, `\w`; it does not support lookahead/lookbehind.

## Testing a rule

1. Create a file with a sample that should match, outside your real site, in a scratch folder.
2. Check the pattern directly: `grep -iE 'YOUR_REGEX' sample.php`.
3. Run `bash tests/run.sh`, and add a sample for the new rule in the test suite. Build the sample from fragments at run time (see the top of `tests/run.sh`), never as a complete literal.

## Handling false positives

You do not need to edit the rule:

- Add a path or text fragment to `~/.wp_auditor/allow.txt` (one per line); matching findings are dropped.
- For a path pattern shipped by default, `ALLOW_RE` in the config takes a regular expression.

If a legitimate, popular plugin triggers a rule, please open an issue so the rule can be tightened for everyone.

## Other detection data

- `IOC_LIST` (config): space-separated attacker markers (file contents and paths) checked everywhere, including your public HTML.
- `KNOWN_HOSTS` (config): external domains considered normal; references to other domains in code are reported as warnings.
