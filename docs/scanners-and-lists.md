# 🧪 Scanners and community lists

← [Help overview](README.md)

The app does not detect anything by itself. This page explains **who does what**, how reliable each part is, and how the
two community lists work.

## 🔧 The scanners

| | Scanner | Looks at | Finds | Default |
|---|---|---|---|---|
| 1️⃣ | **aur-malware-check** ([lenucksi](https://github.com/lenucksi/aur-malware-check)) | installed AUR packages, pacman log, systemd units, npm/bun caches, known IOC files | packages from **documented attack campaigns** (including the official Arch notice) | ✅ on |
| 2️⃣ | **aur-scan** ([ks-aur-scanner](https://github.com/KiefStudioMA/ks-aur-scanner)) | the PKGBUILDs and install scripts of installed AUR packages | **suspicious patterns** (heuristics) | ⬜ off |
| 3️⃣ | **Community blocklist** (this project, [`lists/`](https://github.com/ruepp-jenkins/cachyos-security-scanner/tree/master/lists)) | installed AUR packages, by name and version | **known-bad** packages reported by the community | ✅ on |
| 4️⃣ | **ClamAV** ([clamav.net](https://www.clamav.net/)) | binaries in the paths you configure | **known malware signatures** | on request / optional |

Choosing what to run: the app **only runs what is enabled** in the [settings](settings.md#aur-scanners). Each enabled
scanner gets its own entry in the [history](scan-history.md).

### How they differ in practice

| Property | aur-malware-check | aur-scan | blocklist | ClamAV |
|---|---|---|---|---|
| Finds **new**, unknown attacks | ❌ | ✅ (sometimes) | ❌ | ❌ (signatures only) |
| False positives | very few | **more** | very few | few |
| Needs | Python 3.14+, git | git + Rust (or the AUR package `aur-scanner`) | nothing | `clamav`, running `clamd` |
| Runs | with every package scan | with every package scan | with every package scan | on request / schedule |

A good default is to keep 1 and 3 on. Switch 2 on if you want deeper (and noisier) analysis.

### How the app keeps them up to date

*(Short version – the full procedure with all commands is in [Scanner lifecycle](scanner-lifecycle.md).)*

- The scanner programs are fetched with `git` into `~/.local/share/cachy-security-scanner/vendor/` and updated with
  `git pull` before a scan (setting *Update scanner sources before each scan*).
- A **broken checkout** is detected (`git fsck`) and deleted and cloned again.
- `aur-scan` is compiled with `cargo` when it changed. If the AUR package `aur-scanner` is installed, that binary is used.
- If something cannot be set up, you get an **error entry** in the history – never silence.

## 📋 Community lists

Two small lists are maintained in this repository, in [`lists/`](https://github.com/ruepp-jenkins/cachyos-security-scanner/tree/master/lists):

| List | File | Effect |
|---|---|---|
| **Blocklist** | `blocklist_aur.json` | package + version that are known to be malicious or compromised → **critical** finding |
| **False positives** | `false-positives_aur-scan.json` | known harmless `aur-scan` findings for an exact version → **hidden** (only with `aur-scan` on) |

Each entry records **who** reported it, **when**, **why**, and an optional description.

### Why you can trust them (or not)

- Every list is **signed** by the maintainer. The app verifies the signature on download *and* again every time it loads
  the list; a list that fails the check is ignored (nothing flagged, nothing hidden).
- A list can only **add a finding** (blocklist) or **hide a specific finding** (false positives). It cannot run anything.
- The false-positive list hides only for the **exact version** listed; after an update the finding is reported again.
- Every hidden finding is **noted in the scan log** with reason, author and date.
- You can switch each list off in the [settings](settings.md#community-lists).

### When they are downloaded

At app start, then re-checked hourly and downloaded again when older than 6 hours – **never per scan**. The settings
dialog shows the status of each list and the reason if a download failed, and its *Refresh lists* button downloads both lists at once.

### 📣 Reporting a false positive or a malicious package

Open an issue in the repository with the matching form (**False positive** or **Blocklist**):
[github.com/ruepp-jenkins/cachyos-security-scanner/issues](https://github.com/ruepp-jenkins/cachyos-security-scanner/issues/new/choose).
Entries are reviewed before they go into a list; the format and rules are in [`lists/README.md`](https://github.com/ruepp-jenkins/cachyos-security-scanner/blob/master/lists/README.md).

## 🧯 Limits

- None of these tools can prove that a package is safe. A clean result means "nothing known or suspicious was found".
- Heuristics (`aur-scan`) can flag harmless packages, especially large installers or packages that download sources.
- The app trusts the scanners' output as far as it can parse it; if a tool changes its output format, an update of the
  adapter may be needed.
- The authors of the scanners are independent from this app. Questions about *what* a rule means belong in their projects.
