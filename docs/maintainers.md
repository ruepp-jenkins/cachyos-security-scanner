# Maintainer notes

← [Help overview](README.md)

## Releasing

1. **One-time:** create a signing key, `ssh-keygen -t ed25519 -N "" -f release_key`. Put the public key line into
   `SIGNER_PUBKEY` in `src/cachy_sec/updater.py` (and check `GITHUB_REPO` there), and store the private key as the
   repository secret `RELEASE_SIGNING_KEY`. Keep the private key safe: if it is lost or leaked, installed versions
   cannot be moved to a new key without a manual reinstall.
2. **Nothing to bump in the code.** The version comes from the release tag. The workflow stamps it into
   `src/cachy_sec/__init__.py`, `pyproject.toml` and `PKGBUILD` with `scripts/set-version.sh` (the files in git stay at `0.0.0`).
3. **Create a GitHub release** tagged `vX.Y.Z` (the tag must point to a commit that contains the current workflows).
   `.github/workflows/release.yml` then stamps the version, runs the tests, builds `cachy-security-scanner-X.Y.Z.tar.gz`,
   `SHA256SUMS` and `SHA256SUMS.sig` (SSH signature), builds the Arch package `cachy-security-scanner.pkg.tar.zst` in an
   Arch container, and attaches everything plus the `PKGBUILD` to the release.

## Community lists

`lists/*.json` are validated, stamped with a `published` time, signed (one signature namespace per list) and uploaded
to the rolling release `lists` by `.github/workflows/lists.yml` on every push that touches `lists/`. Start the workflow
once by hand (*Run workflow*) after the first push, so the release exists. See [`lists/README.md`](https://github.com/ruepp-jenkins/cachyos-security-scanner/blob/master/lists/README.md) for
the entry format and review rules.

## How updates reach users

The app is pure Python, so an update is just the `cachy_sec` package as a tarball.

- It downloads only from `github.com` / `githubusercontent.com` over HTTPS, verifies the SSH signature of `SHA256SUMS`
  against the key embedded in the app (`ssh-keygen -Y verify`), then the SHA-256 of the tarball, and extracts it safely
  (no absolute paths, no `..`, no links) into `~/.local/share/cachy-security-scanner/updates/`.
- Without a configured key, or with a bad signature or checksum, nothing is installed.
- The pacman-installed files are never modified. A new version that crashes within 30 seconds of its start is discarded
  and the packaged version runs again. If the package later catches up to the downloaded version, the downloaded copy is dropped.
- A restart is triggered automatically only when the app was started through its `cachy-security-scanner` launcher.
- Updates replace Python files only; changes to system files (pacman hook, new package dependencies) need a newly installed package.

## Development

    python3 -m unittest discover -s tests     # core logic; the GUI tests run headless if PySide6 is installed
    PYTHONPATH=src python3 -m cachy_sec        # needs PySide6

The CI installs PySide6 and runs the GUI tests with `QT_QPA_PLATFORM=offscreen`. Beware of widget attributes that share a
name with Qt members (for example `accepted` or `scroll`): they silently replace Qt's signals and methods; a test checks for it.

## Website (GitHub Pages)

The help is also published as a website with Jekyll and the **Hacker** theme. *Settings → Pages* must use the branch
`master` and the folder `/ (root)`.

- `_config.yml` sets the theme and enables `jekyll-relative-links` (so `[x](page.md)` links work on the site as on GitHub).
- `_includes/head-custom.html` loads Mermaid, which turns the ` ```mermaid ` blocks into diagrams (Jekyll alone shows them as code).
- Jekyll (kramdown) is stricter than GitHub: **tables, lists and quotes need an empty line before them**, also directly after a heading.
- Links to files outside `docs/` (for example the lists) are absolute GitHub URLs.
