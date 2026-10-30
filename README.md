# CachyOS Security Scanner

Tray app for CachyOS/Arch desktops. It runs in the background, scans on a schedule, and shows a
notification when something is found. It only provides the UI and scheduling; detection is done by
external tools. Removal of flagged packages is optional and always needs your click.

## Backends (both AUR scanners enabled by default, toggle in Settings)
| Backend | Source | Notes |
|---|---|---|
| aur-malware-check | https://github.com/lenucksi/aur-malware-check | Blocklist/IOC check of installed AUR packages. Community tool, not endorsed by Arch. Needs Python 3.14+. Cloned and kept up to date automatically (`git clone`/`git pull --ff-only`); a corrupt or diverged checkout is deleted and re-cloned. |
| aur-scan | https://github.com/KiefStudioMA/ks-aur-scanner (AUR: `aur-scanner`) | Static analysis of installed AUR packages. Uses the `aur-scan` on PATH; otherwise cloned and built with `cargo` automatically (needs `git` + `cargo`). |
| Built-in blocklist | set `CACHY_SEC_BLOCKLIST_URL` (https, one package per line) | Independent fallback; inactive without a URL. |
| ClamUI | https://github.com/linx-systems/clamui | Required for binary scans, which run **only on request** from the tray menu. Settings can set up a weekly systemd user timer. |

Checkouts live in `~/.local/share/cachy-security-scanner/vendor/`; only directories there are ever deleted.

## Features
Tray menu (right click): check now (always reports, even when clean), ClamUI binary scan, last result, settings.
Scan at start, at intervals or manual only; after package installs/updates via a pacman hook;
skipped in gaming mode (gamemode/gamescope/Steam) or on battery if enabled.

## Develop
    python3 -m unittest discover -s tests     # core logic, no Qt needed
    PYTHONPATH=src python3 -m cachy_sec        # needs PySide6

## Status / caveats
The Qt UI and the real tools' JSON/exit-code formats were not run or verified against the live tools
(no Arch host, no PySide6 in the dev container). Adapters parse defensively; check them on a real system.

## Auto-update (GitHub Releases only)
The app checks the latest GitHub release at start and daily, and can be triggered from the tray menu.
No build is needed because the app is pure Python; GitHub Actions only packages and signs it.

Release flow for maintainers:
1. One-time: `ssh-keygen -t ed25519 -f release_key`; put the public key line into `SIGNER_PUBKEY`; check
   repo `GITHUB_REPO` (already set to `ruepp-jenkins/cachyos-security-scanner`) in `src/cachy_sec/updater.py`; store the private key as the
   repository secret `RELEASE_SIGNING_KEY`.
2. Bump `__version__` (`src/cachy_sec/__init__.py`) and `version` (`pyproject.toml`).
3. Create a GitHub release tagged `vX.Y.Z`. `.github/workflows/release.yml` tests, builds
   `cachy-security-scanner-X.Y.Z.tar.gz`, `SHA256SUMS` and `SHA256SUMS.sig` and attaches them.

Client side: downloads only from github.com / githubusercontent.com over HTTPS, verifies the SSH signature
(`ssh-keygen -Y verify`) against the embedded key, then the SHA-256, extracts safely into
`~/.local/share/cachy-security-scanner/updates/` and applies it on the next restart (tray: "Restart to apply
update"). Without a configured key updates are refused. A new version that crashes within 30 s of start is
discarded and the packaged version runs. The pacman-installed files are never modified; if the package
catches up to the downloaded version the downloaded copy is dropped.
