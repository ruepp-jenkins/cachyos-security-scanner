# 🚀 Getting started

← [Help overview](README.md)

## Install

1. Open the [Releases page](https://github.com/ruepp-jenkins/cachyos-security-scanner/releases) and pick the newest release.
2. Under **Assets** download `cachy-security-scanner.pkg.tar.zst`.
3. Install it from the download folder:

   ```bash
   sudo pacman -U cachy-security-scanner.pkg.tar.zst
   ```

   pacman installs the dependencies (`python`, `pyside6`, `git`, `openssh`, `libnotify`, `rust`, …) on its own.
4. Start **CachyOS Security Scanner** from the application menu. From the next login on it starts by itself
   (see [autostart](settings.md#general)).

> 💡 No `.pkg.tar.zst` in a release? Download the `PKGBUILD` of that release into an empty folder and run `makepkg -si`.

**Remove it again:** `sudo pacman -Rns cachy-security-scanner`
(your settings and history stay in your home folder, see [where data is stored](how-it-works.md#-files-the-app-writes)).

## What happens in the first minutes

| When | What happens |
|---|---|
| right after start | the tray icon appears (blue app icon, no result yet); only **one** instance can run per login |
| ~3 s | the [community lists](scanners-and-lists.md#-community-lists) are downloaded and verified |
| ~1 min (default delay) | the **first scan** runs: the scanners are cloned/updated from GitHub into your home folder, then they scan |
| ~30 s | an update check for the app itself runs (then daily) |
| when done | the tray icon turns green / orange / red (or shows a ❌ if a scanner could not run) |

The first scan can take a few minutes: the scanner programs are downloaded, and `aur-scan` (if you switched it on) is
**compiled** with Rust once.

All of this runs with **low CPU and I/O priority**, so it should not disturb your work. You can lengthen the start delay
in the [settings](settings.md#when-to-scan).

## Check that it works

1. **Right-click** the tray icon → **Check for compromised packages now**.
   You always get feedback, also when nothing was found.
2. **Left-click** the tray icon → the [scan history](scan-history.md) opens. The new scan is on top, one line per scanner.
3. A line with a ❌ means a scanner could not run; select it to read why
   (see [Troubleshooting](troubleshooting.md)).

## First recommended settings

- 🟢 Keep the defaults if you are unsure: `aur-malware-check` and the community blocklist are on.
- 🧪 `aur-scan` is **off by default** because its heuristics produce false positives. Switch it on if you want deeper
  analysis, and keep the *community false-positive list* on.
- 🦠 Want binary scans? → [Set up ClamAV](setup-clamav.md), then enable the triggers you like in
  [Settings → Binary scan](settings.md#binary-scan-with-clamav).
- 🎮 Gaming? *Skip automatic scans in gaming mode* is already on.

## What the app will never do

- It never removes a package on its own. Removal is a button in the [findings window](findings-window.md) and asks again.
- It never runs files from a finding. *Open files* only opens a folder in your editor or file manager.
- It never changes system files. The only root action is the removal you confirm (via polkit), see
  [How it works](how-it-works.md#-privileges).

Next: [Tray icon and notifications](tray-and-notifications.md) →
