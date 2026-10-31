# CachyOS Security Scanner

Tray app for CachyOS/Arch desktops. It runs in the background, scans on a schedule, and shows a
notification when something is found. It only provides the UI and scheduling; detection is done by
external tools. Removal of flagged packages is optional and always needs your click.

## Install (CachyOS / Arch)
1. Open the [Releases page](https://github.com/ruepp-jenkins/cachyos-security-scanner/releases) and pick the
   newest release.
2. Under **Assets**, download `cachy-security-scanner.pkg.tar.zst`.
3. Open a terminal in the download folder and install it with pacman:

       sudo pacman -U cachy-security-scanner.pkg.tar.zst

pacman pulls in the dependencies (`python`, `pyside6`, `git`, `libnotify`, `openssh`).
4. Start "CachyOS Security Scanner" from the application menu (it also autostarts on next login).

Later versions update themselves from GitHub Releases (see Auto-update). Remove with
`sudo pacman -Rns cachy-security-scanner`.

If a release has no `.pkg.tar.zst` asset, you can build it yourself: download the `PKGBUILD` from the same
release into an empty directory and run `makepkg -si`.

## Backends (both AUR scanners enabled by default, toggle in Settings)
| Backend | Source | Notes |
|---|---|---|
| aur-malware-check | https://github.com/lenucksi/aur-malware-check | Blocklist/IOC check of installed AUR packages. Community tool, not endorsed by Arch. Needs Python 3.14+. Cloned and kept up to date automatically (`git clone`/`git pull --ff-only`); a corrupt or diverged checkout is deleted and re-cloned. Needs Python 3.14+ (checked; a clear error otherwise). |
| aur-scan | https://github.com/KiefStudioMA/ks-aur-scanner (AUR: `aur-scanner`) | Static analysis of installed AUR packages. Uses the `aur-scan` on PATH; otherwise cloned and built with `cargo build --release -p aur-scanner-cli` automatically and rebuilt after upstream changes (upstream ships no binaries; the package depends on `rust`, `clang`, `pkgconf`, `openssl` for this). A failed build is reported as an error with the build output in the history. |
| Built-in blocklist | set `CACHY_SEC_BLOCKLIST_URL` (https, one package per line) | Off by default (no public list exists yet). Independent fallback; inactive without a URL. |
| ClamAV (`clamdscan`) | https://www.clamav.net | Binary scans run **only on request** from the tray menu: a terminal window opens with the live `clamdscan --fdpass --multiscan -i` output and stays open until you press Enter. Needs the `clamav` package and a running daemon (`sudo systemctl enable --now clamav-daemon`). Settings can set up a weekly systemd user timer. |

Checkouts live in `~/.local/share/cachy-security-scanner/vendor/`; only directories there are ever deleted.

## Features
Tray menu (right click): check now (always reports, even when clean), ClamAV binary scan in a terminal window, last result, scan history, settings.
Scan at start, at intervals or manual only; after package installs/updates via a pacman hook;
skipped in gaming mode (gamemode/gamescope/Steam) or on battery if enabled.

## Develop
    python3 -m unittest discover -s tests     # core logic, no Qt needed
    PYTHONPATH=src python3 -m cachy_sec        # needs PySide6

## Status / caveats
The Qt UI and the real tools' JSON/exit-code formats were not run or verified against the live tools
(no Arch host, no PySide6 in the dev container). Adapters parse defensively; check them on a real system.

## Autostart
The app registers itself for login: on start it writes `~/.config/autostart/cachy-security-scanner.desktop`
(no root needed, setting "Start automatically at login", on by default). Turning it off removes that file, or, if the
package ships the system-wide entry, writes `Hidden=true` over it. If the panel is not ready right after login, the
app waits up to 60 s for the system tray.

## Scan history
Tray menu → "Scan history…" lists every scan, with **one entry per scanner** (start time, scanner, trigger, status, summary); selecting one shows its
full log, including the raw output of each scanner. A scanner that is enabled but cannot be set up or run gets an entry with status `error` and the reason
(and the scan is reported as incomplete, tray red). Automatic scans that were skipped (e.g. gaming mode) are recorded too. Binary scans are logged from the terminal window (`*-binaries.log`). Files live in
`~/.local/share/cachy-security-scanner/history/` as plain JSON/text; the number kept is set in Settings
(default 200, oldest are pruned).

## Auto-update (GitHub Releases only)
The app checks the latest GitHub release at start and daily, and can be triggered from the tray menu.
No build is needed because the app is pure Python; GitHub Actions only packages and signs it.

Release flow for maintainers:
1. One-time: `ssh-keygen -t ed25519 -f release_key`; put the public key line into `SIGNER_PUBKEY`; check
   repo `GITHUB_REPO` (already set to `ruepp-jenkins/cachyos-security-scanner`) in `src/cachy_sec/updater.py`; store the private key as the
   repository secret `RELEASE_SIGNING_KEY`.
2. Nothing to bump in the code: the version comes from the release tag. The workflow stamps it into
   `__init__.py`, `pyproject.toml` and `PKGBUILD` via `scripts/set-version.sh` (the files in git stay at `0.0.0`).
3. Create a GitHub release tagged `vX.Y.Z`. `.github/workflows/release.yml` stamps the version, tests, builds
   `cachy-security-scanner-X.Y.Z.tar.gz`, `SHA256SUMS` and `SHA256SUMS.sig` and attaches them.

Client side: downloads only from github.com / githubusercontent.com over HTTPS, verifies the SSH signature
(`ssh-keygen -Y verify`) against the embedded key, then the SHA-256, extracts safely into
`~/.local/share/cachy-security-scanner/updates/` and restarts the app by itself as soon as nothing is running
(no package scan, no open dialog); the tray menu also has "Restart to apply update". When started directly
instead of through the `cachy-security-scanner` launcher (e.g. from source) it only notifies. The running version
is shown in Settings and in the tray menu. Without a configured key updates are refused. A new version that crashes within 30 s of start is
discarded and the packaged version runs. The pacman-installed files are never modified; if the package
catches up to the downloaded version the downloaded copy is dropped.
