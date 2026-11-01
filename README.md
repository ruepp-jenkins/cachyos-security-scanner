# CachyOS Security Scanner

Tray app for CachyOS/Arch desktops. It runs in the background, scans on a schedule, and shows a
notification when something is found. It only provides the UI and scheduling; detection is done by
external tools. Removal of flagged packages is optional and always needs your click.

## Which projects do the AUR scans?
This app does not detect anything itself. The AUR scans are done by these independent open-source projects; this app
only runs them, keeps them up to date and shows their results. All credit for the detection goes to their authors.

| Project | Repository | What it does | License |
|---|---|---|---|
| **aur-malware-check** | [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check) | Checks installed AUR packages (and IOC files, pacman log, caches) against lists of packages compromised in known attack campaigns. | GPL-3.0 |
| **ks-aur-scanner** (`aur-scan`) | [KiefStudioMA/ks-aur-scanner](https://github.com/KiefStudioMA/ks-aur-scanner) | Heuristic analysis of the PKGBUILDs and install scripts of installed AUR packages (off by default). | GPL-3.0-or-later |
| **ClamAV** (binary scan on request) | [Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav) · [clamav.net](https://www.clamav.net/) | Antivirus engine (`clamdscan` / `clamd`) for scanning installed binaries. | GPL-2.0 |

The two [community lists](lists/) (blocklist, false positives) are maintained in this repository.
These tools are separate programs with their own licenses; this app starts them as external processes and does not
include their code.

## Screenshots
| | |
|---|---|
| **Tray menu**<br>![Tray menu](docs/screenshots/tray-menu.png) | **Notification**<br>![Notification when something is found](docs/screenshots/notification.png) |
| **Findings window**<br>![Findings window](docs/screenshots/findings.png) | **With details**<br>![Findings window with details](docs/screenshots/findings-details.png) |

_Screenshots show version 0.0.6; newer versions differ in details (for example per-entry Open files / Ignore buttons)._

## Install (CachyOS / Arch)
1. Open the [Releases page](https://github.com/ruepp-jenkins/cachyos-security-scanner/releases) and pick the
   newest release.
2. Under **Assets**, download `cachy-security-scanner.pkg.tar.zst`.
3. Open a terminal in the download folder and install it with pacman:

       sudo pacman -U cachy-security-scanner.pkg.tar.zst

pacman pulls in the dependencies (see the `PKGBUILD`).
4. Start "CachyOS Security Scanner" from the application menu.

Later versions update themselves from GitHub Releases. Remove with `sudo pacman -Rns cachy-security-scanner`.

If a release has no `.pkg.tar.zst` asset, you can build it yourself: download the `PKGBUILD` from the same
release into an empty directory and run `makepkg -si`.

## What it does
- Sits in the system tray, scans on a schedule, after package installs/updates and on request, and notifies you when
  something is found. Nothing is removed without your click and confirmation.
- Runs the scanners above with low priority, keeps them up to date by itself and shows each scanner's result separately in the scan history.
- A window per finding lets you open the files behind an entry in your editor, accept an entry for one software version
  or (if you wish) remove the package.
- Two signed community lists (known malicious packages, known false positives) are maintained in [`lists/`](lists/); proposals are welcome.
- Updates itself from signed GitHub releases.

## 📖 Help
The full help starts at **[docs/README.md](docs/README.md)**; the **Help** button in the settings opens it for your version.

| | |
|---|---|
| 🚀 [Getting started](docs/getting-started.md) | 🔔 [Tray icon and notifications](docs/tray-and-notifications.md) |
| 📜 [Scan history](docs/scan-history.md) | 🔎 [Findings window](docs/findings-window.md) |
| ⚙️ [Settings reference](docs/settings.md) | 🧪 [Scanners and community lists](docs/scanners-and-lists.md) |
| 🦠 [Set up ClamAV](docs/setup-clamav.md) | 🧰 [Requirements](docs/setup-requirements.md) |
| 🔄 [Updates](docs/updates.md) | 🩹 [Troubleshooting](docs/troubleshooting.md) |
| 🔬 [How it works (files, network, privileges)](docs/how-it-works.md) | 🏗️ [Maintainer notes](docs/maintainers.md) |

## License and disclaimer
Released under the [MIT License](LICENSE): everyone may use, copy, modify and distribute it, free of charge. It comes
**without any warranty and without liability** of the author(s) (see `LICENSE`).

This is a helper, not a guarantee. It can miss malicious packages and it can report harmless ones; a clean result does
not prove that your system is safe, and the tools it relies on have their own limits. You are responsible for what you
install and remove. Review findings yourself before acting on them.
