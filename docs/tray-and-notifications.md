# 🔔 Tray icon and notifications

← [Help overview](README.md)

The app lives in the system tray. The icon tells you the state of the **last scan** at a glance.

## Icon states

| Icon | State | Meaning |
|---|---|---|
| 🛡️ blue (magnifier) | no result yet, **or a scan is running** | the app just started and has not scanned yet. It also shows whenever at least one scan is running (package scan or background binary scan) and returns to the result colour when the last scan has finished; the tooltip then says *scanning…* |
| 🟢 green shield | **clean** | all enabled scanners ran and found nothing |
| 🟠 orange shield | **warning** | at least one finding of warning level, none critical |
| 🔴 red shield | **critical** | at least one critical finding (for example a package from the blocklist) |
| ❌ red cross | **error** | an enabled scanner could not run, or no scanner is enabled |

Good to know:

- With several scanners the **worst finding wins**: warning + critical = red; a warning together with a scanner that
  could not run = orange (the finding matters more than the error).
- A scan that was **skipped** (gaming mode, battery) does *not* change the icon, so an earlier finding stays visible.
- A threat found by a [ClamAV binary scan](setup-clamav.md) turns the icon red as well, until the next package scan.
- The tooltip (hover) shows the summary of the last scan.

## Mouse actions

| Action | Result |
|---|---|
| **Left click** | opens the [scan history](scan-history.md) (or brings it to the front if already open) |
| **Right click** | opens the menu below |

## The menu

![The tray menu](screenshots/tray-menu.png)

Every entry has an icon from your desktop's icon theme (so it matches the rest of your desktop). **Scan history…** shows the shield of the last scan result instead.

```
Check for compromised packages now
Scan binaries with ClamAV (clamd)
Scan history…
─────────────────────────────
Check for app updates
Restart to apply update          ← only visible when an update waits
Settings…
Report a problem…
Help
About
Quit
```

| Entry | What it does |
|---|---|
| **Check for compromised packages now** | runs a package scan right away (all enabled scanners). Never skipped by gaming mode; always reports its result, also when clean |
| **Scan binaries with ClamAV (clamd)** | opens a terminal window with a live `clamdscan` of your configured paths. Greyed out if `clamdscan` is not installed (see [Set up ClamAV](setup-clamav.md)) |
| **Scan history…** | opens the [scan history](scan-history.md). Only one history window exists at a time |
| **Check for app updates** | manual update check. With automatic updates switched off it only *asks* before installing, see [Updates](updates.md) |
| **Restart to apply update** | restarts the app now to use an installed update. Otherwise it restarts by itself when idle |
| **Settings…** | opens the [settings](settings.md) (one window at a time) |
| **Report a problem…** | a small window with three choices: **False positive**, **Malicious package** and **Program error**. Each opens the matching form on GitHub in your browser (you need a GitHub account) and the window stays open, so you can report several things; if no browser can be started, the link is shown instead; the app sends nothing itself. See [reporting](scanners-and-lists.md#-reporting-a-false-positive-or-a-malicious-package) |
| **Help** | opens this help in your browser, at the page of **your version's tag** on GitHub (the latest `master` for a development build) |
| **About** | a small window with links to the help, project page, releases and issues, the copyright, and: this program (version, commit, kind of installation, location, Python, Qt); for each community list that is switched on its entries, publication time, commit, download time and a failed download; for `aur-malware-check` its path, version or commit, the size of its package lists and every definition file with its file date; for `aur-scan` its path, version, number and date of its threat indicators and an additional indicator file (the last two only if they exist or can be determined); ClamAV engine and signature database. The information is one text field: select and copy any part or all of it (*Ctrl+A*, *Ctrl+C*). Paths use `~` for your home directory and are links: a click opens the folder, for a file the folder containing it (files themselves are never opened). It only reads; nothing is downloaded or updated. One window at a time |
| **Quit** | stops the app. Nothing keeps running in the background |

## Notifications

Notifications use the standard desktop mechanism (`notify-send`, part of `libnotify`), so they look like every other
notification of your desktop.

| Notification | When | Urgency |
|---|---|---|
| **Security scanner: possible compromise** | a scan you started found something, or an automatic scan found something **new or changed** | critical – stays until you dismiss it |
| **Security scan finished** | your manual scan finished; or an automatic scan finished clean and *Also notify when nothing was found* is on; or a scan was incomplete | normal (critical if incomplete) |
| **Binary scan: threats found** | an automatic ClamAV scan found threats | critical |
| **Binary scan did not run** | e.g. `clamd` is not running | normal |
| **Binary scan finished** | an automatic ClamAV scan was clean and *Also notify when nothing was found* is on | normal |
| **Binary scan not started** | the scan you asked for in a terminal could not start (`clamdscan` or a terminal missing, no configured path exists, invalid extra arguments) | normal |
| **Security scan** | you asked for a package scan while one is already running; its result follows | normal |
| **Finding ignored** / **Ignore failed** | after you click *Ignore* | normal |
| **Package removal** | a removal you confirmed finished or failed | normal (critical if it failed) |
| **Settings could not be saved** | the settings file cannot be written; your choices apply until the app is restarted | normal |
| **Update check / Security scanner updated** | manual update check results, or an update was installed | normal |
| **Restart needed** | you click *Restart to apply update*, but the app was not started through its launcher: start it again yourself | normal |
| **Security scanner** | you start the app although it already runs (*Already running*) | normal |
| **Update waiting** | an update is installed but the restart waits (a scan runs, or a window is open) | normal |

When something is found, a [findings window](findings-window.md) opens along with the notification. There is only one;
later scans [update it](findings-window.md#-one-window-that-stays-current).

An automatic scan that finds **only what is already known** is quiet: no new notification and no new window. This
avoids repeats while a long system update triggers several scans. Nothing is skipped: every scan runs, sets the tray
icon and is recorded in the [history](scan-history.md). After a restart of the app, and with every scan you start
yourself, the findings are shown again.

### 🖱️ Clicking a notification

Notifications about a **finding, a binary-scan threat or a scan that could not run** are clickable. A click on the
notification (or on its **Open scan history** button) opens the [scan history](scan-history.md) with the **newest
matching entry already selected**, so you see the cause at once. Filters in the window are cleared so they cannot hide it.

| Notification | Entry that gets selected |
|---|---|
| possible compromise | newest entry with status warning or critical |
| binary scan: threats found | newest binary-scan entry with threats |
| scan incomplete / binary scan did not run | newest entry with status error |

Limits: a notification can only be clicked while it is still shown – once your desktop has moved it into its history, a
click may do nothing (the tray icon's left click always works). It needs a `libnotify` with `notify-send --action`
(current Arch has it); with an older one the notification is shown without the click feature.

![A notification after a finding (screenshot of version 0.0.6)](screenshots/notification.png)

> 🔕 No notifications at all? You need a notification daemon (KDE Plasma and GNOME have one) and `libnotify`.
> See [Requirements](setup-requirements.md#-notifications).

## Tray icon missing?

KDE Plasma, XFCE, Cinnamon, MATE, LXQt and others show it out of the box. **Stock GNOME does not show tray icons**;
install an AppIndicator extension. Details: [Requirements](setup-requirements.md#-system-tray).
