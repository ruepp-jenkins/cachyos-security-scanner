# Settings reference

← [Help overview](README.md)

This page describes every option in **Settings…** (tray icon → right click → *Settings…*), what it does, its default, and
the key used in the settings file. Changes are applied when you click **Save**; **Cancel** discards them. Two buttons act
immediately instead (*Revoke selected* and, if present, *Remove the old systemd timer*), as noted below.

The settings file is `~/.config/cachy-security-scanner/settings.json` (its path is also shown at the bottom of the dialog).
You can edit it by hand while the app is closed; unknown or wrongly typed values are ignored and replaced by the default.

- [When to scan](#when-to-scan)
- [AUR scanners](#aur-scanners)
- [Community lists](#community-lists)
- [Ignoring findings](#ignoring-findings)
- [Binary scan with ClamAV](#binary-scan-with-clamav)
- [General](#general)
- [Where the app keeps its data](#where-the-app-keeps-its-data)
- [Recipes](#recipes)

---

## When to scan

The *AUR package scans* (the scanners below) run on the triggers you switch on here. They are independent of each other:
switch on any combination, or none for manual scans only. Manual scans (*Check for compromised packages now*) always work
and are never skipped. The ClamAV binary scan has its own triggers, see [below](#binary-scan-with-clamav).

| Setting (key) | Default | What it does |
|---|---|---|
| **Scan at start** (`scan_on_start`) | on | One scan after the app starts. The app first downloads the [community lists](#community-lists), so the scan already uses current data. |
| **Delay after start** (`startup_delay_minutes`) | 1 min | How long to wait after the start (0 to 120 minutes) before the start scans begin. Gives the desktop time to finish starting after login, because scans, `git` updates and builds produce load. |
| **Scan after package installs/updates** (`scan_after_pkg_changes`) | on | A scan after `pacman` installed, upgraded or removed packages. Needs the pacman hook that the package installs (`/usr/share/libalpm/hooks/cachy-security-scanner.hook`); it does not exist if you run the app from source. A package change that happens during a running scan triggers one more scan afterwards. |
| **Wait after the last change** (`pkg_change_delay_seconds`) | 30 s | Each package change restarts this wait (5 to 3600 seconds), so a multi-step upgrade results in one scan. |
| **At most one scan per** (`pkg_scan_min_gap_minutes`) | 10 min | Upper limit for package-change scans: if the last scan finished less than this ago, the next one waits for the rest (0 to 1440 minutes, 0 = no limit). Protects you from scan after scan during a long update session. |
| **Scan at regular intervals** (`scan_periodic`) | on | A scan every *Every* period, counted from the start of the app. |
| **Every** (`interval_minutes`) | 6 hours | The period, entered as a number plus unit (minutes, hours, days or weeks). Allowed: 15 minutes to 52 weeks. |
| **Update scanner sources before each scan** (`update_sources_before_scan`) | on | Before a scan the app updates the scanner programs it manages itself: it runs `git pull` on `aur-malware-check` and, if `aur-scan` is not installed from the AUR, on `ks-aur-scanner` (rebuilding it when the source changed). A broken checkout is deleted and cloned again. This does **not** control the community lists (they have their own schedule) nor the app's own updates. |
| **Skip automatic scans in gaming mode** (`skip_in_gaming_mode`) | on | Automatic scans are skipped while one of these processes runs: `gamemoded` ([GameMode](https://github.com/FeralInteractive/gamemode)), `gamescope` / `gamescope-wl` / `gamescopereaper` ([gamescope](https://github.com/ValveSoftware/gamescope)), `reaper` / `SteamLaunch` ([Steam](https://store.steampowered.com/)) or `lutris-wrapper` ([Lutris](https://lutris.net/)). The skipped scan is recorded in the history as *skipped*. **Manual scans are never skipped.** |
| **Skip automatic scans on battery** (`skip_on_battery`) | off | Skips automatic scans while no AC adapter is connected (laptops). Manual scans still run. |
| **Run scans with low priority** (`low_priority_scans`) | on | Runs the scanners, their `git` updates and the `aur-scan` build with `nice -n 19` (lowest CPU priority) and `ionice -c 2 -n 7` (lowest best-effort I/O priority), so a scan does not slow down your work or a game. Scans may take somewhat longer on a busy machine. If `nice` or `ionice` (util-linux / coreutils) is missing the commands simply run normally. The ClamAV binary scan has its own switch, see [below](#binary-scan-with-clamav). |
| **Also notify when nothing was found** (`notify_when_clean`) | off | Automatic scans only notify you about findings or errors. With this on, a clean automatic scan shows a short notification too. Manual scans (*Check for compromised packages now*) always report their result, clean or not. |

## AUR scanners

The app does not detect anything itself; it runs external tools and shows their results. Each enabled scanner runs on every
scan and gets **its own entry** in the [history](#general). A scanner that is switched off is never run,
cloned, built or downloaded. A scanner that is switched on but cannot run (missing tool, failed build) is reported as an
**error** and the scan counts as incomplete (red tray icon); the reason is in the history.

| Setting (key) | Default | What it does |
|---|---|---|
| **aur-malware-check** (`use_aur_malware_check`) | on | Runs [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check): compares your installed AUR (foreign) packages, the pacman log, systemd units, npm/bun caches and known IOC files against lists of packages compromised in documented attack campaigns (including the official Arch Linux notice). Only matches **known** bad packages, so it has few false positives but cannot see new attacks. The app clones it into `~/.local/share/cachy-security-scanner/vendor/` and keeps it up to date. Needs `git` and Python 3.14 or newer. |
| **aur-scan (ks-aur-scanner)** (`use_aur_scan`) | **off** | Runs [KiefStudioMA/ks-aur-scanner](https://github.com/KiefStudioMA/ks-aur-scanner) (`aur-scan system`): a **heuristic** analysis of the PKGBUILD and install scripts of your installed AUR packages (142 rules, e.g. "decode and execute" patterns). It can find new kinds of attacks, but it also **produces false positives**, so it is off by default; enable it only if you are willing to judge findings. It uses the `aur-scan` from the AUR package [`aur-scanner`](https://aur.archlinux.org/packages/aur-scanner) if installed; otherwise the app clones the repository and builds it with `cargo` (needs `git`, `rust`, `clang`; the app's own package depends on them). It analyses the PKGBUILDs in your AUR helper's cache (for example `~/.cache/yay/<package>`). |
| **Community blocklist** (`use_community_blocklist`) | on | Matches your installed AUR packages by name and version against [`lists/blocklist_aur.json`](../lists/blocklist_aur.json), a list of known malicious or compromised packages maintained in this project. A match is a **critical** finding; the *Remove packages…* button then offers to remove it (after confirmation). Needs no extra software. See [community lists](#community-lists). |

## Community lists

Two signed lists are maintained in this repository ([`lists/`](../lists/)) and published automatically on the rolling
[`lists` release](https://github.com/ruepp-jenkins/cachyos-security-scanner/releases/tag/lists). The app downloads them only
from there and verifies the SSH signature against the key built into the app; a list without a valid signature is never
used. Proposals for new entries are welcome (see [`lists/README.md`](../lists/README.md)).

| Setting (key) | Default | What it does |
|---|---|---|
| **Community false-positive list** (`use_false_positive_list`) | on | Shown indented below *aur-scan* and only usable while *aur-scan* is on. Hides `aur-scan` findings that are listed as known false positives **for the exact software version** (for example `heidisql 1:12.22-1`, rule `DEEP-001`). It only ever hides; it cannot add findings. Every hidden finding is noted in the scan log with reason, author and date, and the findings window says when something was hidden. Untick it if you do not want to rely on the list. File: [`lists/false-positives_aur-scan.json`](../lists/false-positives_aur-scan.json). |

The grey line under each list in the dialog shows its state:

| Text | Meaning |
|---|---|
| `available, from 2026-10-31 20:22 UTC, 1 entry` | A verified copy is cached. The date is when the list was **published** on GitHub; the number is how many entries it has. |
| `not downloaded yet (fetched at start and then every few hours)` | No copy yet (first start, or no network so far). |
| `not available: the last download failed (…)` | The last attempt failed; the reason is in the brackets (for example `HTTP Error 404` if the `lists` release does not exist, or `signature verification failed`). The previous verified copy, if any, keeps being used. |

**When lists are downloaded:** at app start (the start scan waits for it), then checked every hour and downloaded again
when the cached copy is older than 6 hours, and right after you switch a list on. Scans do not download anything, except
that a scan fetches a list once if none is cached at all. After a failed download the app waits 15 minutes before it tries again.

## Ignoring findings

Both controls apply to **aur-scan** findings only (the other scanners report no rule codes).

| Setting (key) | Default | What it does |
|---|---|---|
| **aur-scan: findings to ignore** (`ignored_findings`) | `SCAN-001` | One entry per line. Hides findings everywhere, for all versions. Accepted forms: a **rule code** (`SCAN-001`), a **package name** (`heidisql`, hides all findings of that package) or **`package:CODE`** (`heidisql:DEEP-001`). The default hides `SCAN-001` ("package file could not be analyzed"), which is an analysis note rather than a finding. Use this sparingly: it is not tied to a version. |
| **Accepted findings** (list; stored in `~/.config/cachy-security-scanner/ignored_findings.json`) | empty | Findings you accepted with the **Ignore** button in the "Possible compromise" window. Each entry is bound to one **package, one version and one rule**: heidisql `1:12.22-1`, `DEEP-001`. After the package is updated the entry no longer matches, so the finding is reported again if it still applies. **Revoke selected** removes the highlighted entry **immediately** (without *Save*). |

In the "Possible compromise" window every entry has its own **Ignore** button (and its own **Open files** button). The re-scan runs once when you close the window.
The version used is that of the scanned PKGBUILD (from the `.SRCINFO` next to it in your AUR helper's cache), or the installed
version if there is none.

## Binary scan with ClamAV

Scans executables with `clamdscan`, which talks to the ClamAV daemon. It never deletes anything. Needs the
[`clamav`](https://www.clamav.net/) package and a running daemon: `sudo systemctl enable --now clamav-daemon` (virus
definitions are updated by `clamav-freshclam`).

- **On request** (tray menu → *Scan binaries with ClamAV (clamd)*): a terminal window shows the live output and stays open
  until you press Enter. The output is also saved to the [history](#general).
- **Automatically** (the options below, all off by default): the scan runs in the **background** without a window. The
  same log goes to the history; a notification appears when threats are found or the scan could not run (and, with
  *Also notify when nothing was found*, when it finished clean). Threats also turn the tray icon red. Automatic binary scans
  honour *Skip automatic scans in gaming mode / on battery*.

| Setting (key) | Default | What it does |
|---|---|---|
| **Paths to scan** (`binary_scan_paths`) | `/usr/bin`, `/usr/local/bin`, `/opt`, `~/.local/bin`, `/var/lib/flatpak/exports/bin` | One path per line; `~` is expanded, paths that do not exist are skipped. These are the usual places where installed applications live. |
| **Scan binaries at start** (`binary_on_start`) | off | A binary scan after the app started (after the *Delay after start*). |
| **Scan binaries after package installs/updates** (`binary_after_pkg_changes`) | off | A binary scan after package changes, with the same wait as the package scan. Needs the pacman hook. |
| **Scan binaries together with every AUR package scan** (`binary_with_aur_scans`) | off | Starts a binary scan whenever a package scan has finished (not for skipped scans), whatever triggered it. |
| **Scan binaries at regular intervals** (`binary_periodic`) | off | A binary scan when *Every* has passed since the last binary scan. The time of the last scan is remembered across restarts (checked every 10 minutes and five minutes after the start), so a weekly scan also happens if you restart often, and it catches up after the computer was off. |
| **Every** (`binary_interval_minutes`) | 1 week | Number plus unit (minutes, hours, days or weeks). Allowed: 1 hour to 52 weeks. |
| **At most one scan per (except interval)** (`binary_min_gap_hours`) | 24 h | Applies to the start, package change and *together with every AUR package scan* triggers, so that a full binary scan does not run after every `pacman -Syu`. 0 = no limit. The interval trigger is not limited by it. |
| **Run binary scans with low priority** (`binary_low_priority`) | on | Runs the `clamdscan` client with `nice -n 19` and `ionice -c 2 -n 7`. The scanning itself is done by the `clamd` daemon, which has the priority of its own service: set `Nice=` / `IOSchedulingClass=` with `systemctl edit clamav-daemon` to make it gentler as well. |

Without `clamdscan` the options of this section are greyed out with an install hint (the saved values are kept). The dialog also shows when the last binary scan started. If you set up the weekly systemd timer of an earlier version
(`cachy-sec-clamd.timer`), a button to remove it appears; the app itself no longer creates it.

## General

| Setting (key) | Default | What it does |
|---|---|---|
| **Editor for "Open files"** (`editor_command`) | empty | Command used by the **Open files** button that every entry of the "Possible compromise" window has, to show the folder with the files behind that entry (PKGBUILD, install script, …). Example: `codium` or `kate --new`. Empty = the first installed of `codium`, `vscodium`, `code`, `code-oss`, `cursor`, `zed`, `subl` ([VSCodium](https://vscodium.com/), [VS Code](https://code.visualstudio.com/), [Zed](https://zed.dev/), …), otherwise your file manager (`xdg-open`). Nothing in the folder is run; with VSCodium/VS Code keep the folder in **Restricted Mode** (do not "trust" it). |
| **Start automatically at login** (`autostart`) | on | Writes `~/.config/autostart/cachy-security-scanner.desktop` (the app waits up to a minute for the system tray after login). Switching it off removes that file; if the package also ships the system-wide entry `/etc/xdg/autostart/…`, a `Hidden=true` override is written instead. |
| **Check for app updates automatically and install them** (`auto_update`) | on | Looks for a newer version of this app on the project's [GitHub Releases](https://github.com/ruepp-jenkins/cachyos-security-scanner/releases) 30 seconds after the start and then daily. Updates are **signed**: the app verifies the signature and checksum and installs only into your home directory (`~/.local/share/cachy-security-scanner/updates/`), never into system folders. It then restarts itself when no scan is running and none of its windows is open (only when started through the `cachy-security-scanner` launcher; otherwise it asks you to restart). While it waits, the tray entry *Restart to apply update* says why (for example *waiting: the window "Scan history" is open*), and after a minute a notification explains it; the entry restarts immediately when clicked. **Off**: no automatic check at all. The tray entry *Check for app updates* still works, but then it only looks: if a newer version exists, a window says so and asks *Install it now?* before anything is downloaded. With the setting on, the manual check installs without asking. Changes to system files (pacman hook, new package dependencies) need a newly installed package. |
| **Keep the last N history entries** (`history_keep`) | 200 | Maximum number of entries in *Scan history…* (10 to 5000). One entry is written **per scanner and scan** (plus binary scan logs), so with two scanners 200 entries are about 100 scans. The oldest are deleted first. Files: `~/.local/share/cachy-security-scanner/history/`. |
| **Ask before removing packages** (`confirm_before_remove`) | on | After you click *Remove packages…* in the findings window, a confirmation shows the packages before `pkexec pacman -Rns` runs (you are asked for your password by polkit). With this off the removal starts right after the click. The app never removes anything on its own. Only critical findings with a known package offer removal. |

The dialog scrolls and never grows taller than your screen; **Save**, **Cancel** and **Help** stay visible at the bottom. The version and the settings file path are shown at the end of the options. **Help** opens this page.

## Where the app keeps its data

| What | Location |
|---|---|
| Settings | `~/.config/cachy-security-scanner/settings.json` |
| Accepted findings | `~/.config/cachy-security-scanner/ignored_findings.json` |
| Scan history and logs | `~/.local/share/cachy-security-scanner/history/` |
| Cloned scanner repositories | `~/.local/share/cachy-security-scanner/vendor/` |
| Downloaded app updates | `~/.local/share/cachy-security-scanner/updates/` |
| Cached community lists | `~/.cache/cachy-security-scanner/` |
| Autostart entry | `~/.config/autostart/cachy-security-scanner.desktop` |
| Old ClamAV timer (earlier versions only) | `~/.config/systemd/user/cachy-sec-clamd.{service,timer}` |
| Time of the last binary scan | `~/.local/share/cachy-security-scanner/binary-last-scan` |
| Single-instance lock | `$XDG_RUNTIME_DIR/cachy-security-scanner.lock` |

Only one instance of the app runs per login session; starting it again just says it is already running.

## Recipes

- **Only check when I decide:** switch off *Scan at start*, *Scan after package installs/updates* and *Scan at regular intervals*. Use the tray menu entries; nothing runs on its own.
- **Quiet while gaming, check otherwise:** keep *Skip automatic scans in gaming mode* on (default); the skipped scans show as *skipped* in the history.
- **Check after every install, nothing else:** *Scan after package installs/updates* on, the other two off.
- **Get fewer false positives from aur-scan:** keep the community false-positive list on, accept single entries with **Ignore**, and
  add rule codes you never want to see to *findings to ignore*.
- **Slow or metered connection:** switch off *Update scanner sources before each scan* and the app updates; the lists need only two small downloads every few hours.
- **Weekly full binary scan without noise:** *Scan binaries at regular intervals* every 1 week; leave the other binary triggers off.
- **Gentle login:** raise *Delay after start* (for example 5 minutes) so the desktop is up before any scan starts.
