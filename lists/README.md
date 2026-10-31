# Community lists

This folder holds lists maintained by the community, named `<topic>_<scanner>.json`. Currently:

- `false-positives_aur-scan.json`: false positives of aur-scan (opt-in in the app).
- `blocklist_aur.json`: known malicious AUR packages (on by default in the app).

## False positives (aur-scan)

`false-positives_aur-scan.json` lists findings of the heuristic scanner ks-aur-scanner that are known to be harmless for a
specific software version. The app only uses it if the user ticks **"Use the community false-positive list"**
for aur-scan in the settings. It only hides the listed findings for the listed versions; it cannot add findings.

## How it reaches the app
On every change to this folder the workflow `false-positives.yml` validates the file, signs it with the release key
and publishes it on the rolling release `lists`. The app downloads only from there and verifies the
signature. Hidden findings are noted in the scan log.

## Report a false positive
Open an issue with the *Report an aur-scan false positive* template, or send a pull request that adds an entry.
Please check the package yourself first. A maintainer reviews every entry.

```json
{
  "package": "heidisql",
  "versions": ["1:12.22-1"],
  "codes": ["DEEP-001"],
  "author": "your GitHub name (required)",
  "reported": "2026-10-31",
  "reason": "What triggers it and why it is harmless (10-500 characters, shown in the scan log).",
  "description": "Optional longer explanation (up to 2000 characters)."
}
```

Rules (checked by `python -m cachy_sec.signedlist validate lists/*.json` and in CI):
- `versions` are the full installed versions (`epoch:pkgver-pkgrel`); shell-style globs such as `1:12.*` are allowed
  but must contain a digit. Prefer exact versions: a new version should be reviewed again.
- `codes` are explicit rule codes (no wildcards).
- `author` and `reported` (ISO date) are required for every entry; `description` is optional.
- One reason per entry, written for other users to understand.

## Blocklist (`blocklist_aur.json`)
Known malicious or compromised AUR packages. The app matches them against the installed foreign packages (name and version)
and reports a match as critical; removal still needs the user's confirmation. Only add packages you have checked and
can explain; a wrong entry alarms every user. Use the issue template *Report a malicious AUR package* or a pull request.

```json
{
  "package": "evil-bin",
  "versions": ["1.2.*"],
  "author": "your GitHub name (required)",
  "reported": "2026-10-31",
  "reason": "What makes it malicious (10-500 characters, shown to the user).",
  "description": "Optional longer explanation (up to 2000 characters).",
  "reference": "https://… (optional, https only; an advisory or the AUR page is welcome)"
}
```
`versions` is optional (omit = every version); globs like `1.2.*` are allowed. The workflow adds a `published`
timestamp to the signed copy; do not set it yourself.
