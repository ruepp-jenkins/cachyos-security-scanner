# 🩹 Troubleshooting

← [Help overview](README.md)

Start here: **left-click the tray icon** to open the [scan history](scan-history.md). A ❌ line says which scanner failed;
select it and read the log below. Most problems explain themselves there.

## 🔍 By symptom

### The tray icon does not appear
- GNOME has no tray → [install the AppIndicator extension](setup-requirements.md#-system-tray).
- Started too early in the session? The app waits up to a minute for the tray; log out and in, or start it again from the menu.
- No tray at all? The app waits up to a minute and then quits with *No system tray available* (run it from a terminal to see it).
- Already running? Only one instance runs: starting it again shows a notification *"Already running"*. Look for the icon in the
  tray's hidden-icons area.

### No notifications
- Install `libnotify` and make sure a notification daemon runs; test with `notify-send "test" "hello"`.
- Check *Do not disturb* in your desktop.
- A clean automatic scan is silent by default; see *Also notify when nothing was found*.

### A scanner shows ❌ / "not available"
| Message mentions | Meaning and fix |
|---|---|
| `git` | install git: `sudo pacman -S git` |
| `cargo` / `rust` | `aur-scan` needs Rust to be built → [Requirements](setup-requirements.md#-rust-only-for-aur-scan), or install the AUR package `aur-scanner` |
| Python 3.14 | `aur-malware-check` needs a newer Python → [Requirements](setup-requirements.md#-python-version-for-aur-malware-check) |
| network / clone failed | GitHub unreachable; it retries at the next scan |
| list / signature | the community list could not be verified; it is ignored until a good copy is downloaded (status in the settings) |

### "Scan incomplete" notifications keep coming
An enabled scanner cannot run, so the app does **not** report "clean". Fix the cause (history shows it), or switch that
scanner off in the [settings](settings.md#aur-scanners).

### The binary scan does nothing / fails
→ [Set up ClamAV](setup-clamav.md#-common-problems). Typical: `clamdscan` missing or `clamd` not running.

### Settings seem not to be saved
Make sure you run a current version (very old versions had a bug that prevented saving). The file is
`~/.config/cachy-security-scanner/settings.json`; if saving fails, the app notifies you and keeps your choices in memory.
Check that the folder is writable and the disk is not full.

### A harmless package is reported
- With `aur-scan` that happens (heuristics). Use **Ignore** in the [findings window](findings-window.md#-ignore) and keep
  the *community false-positive list* on.
- Report it so others benefit: [Reporting a false positive](scanners-and-lists.md#-reporting-a-false-positive-or-a-malicious-package).

### The system feels slow during a scan
- Keep *Run scans with low priority* on (default) – also for binary scans.
- Increase *Delay after start*, lower the scan frequency, raise *At most one scan per…*
  ([Settings](settings.md#when-to-scan)).
- `aur-scan` compiles Rust code the first time; install the AUR package `aur-scanner` to avoid that.
- ClamAV: the daemon's own priority is separate → [make it gentler](setup-clamav.md#make-clamav-gentler-optional).
- Find the cause: during the slowdown run `top` and look for `cargo`, `rustc`, `git`, `clamd`, `aur-scan`; compare the
  times with the *Started* column of the history.

### "Scan after package changes" does not trigger
- Check the hook: `ls -l /var/lib/cachy-security-scanner/trigger` – does the timestamp change after `pacman` runs?
- No hook when running from source; see [the pacman hook](setup-requirements.md#-the-pacman-hook).
- There is a wait and a limit (*Wait after the last change*, *At most one scan per*); a scan may be deferred, not lost.

### Update does not apply
→ [Updates](updates.md#if-an-update-does-not-install).

### Removal does not work
- You need polkit and an authentication agent → [Requirements](setup-requirements.md#-polkit-removing-packages).
- Check the output in the message box: pacman may refuse if other packages depend on the one you remove.

## 🧰 Collecting information for a bug report

Please include:
1. The app version (bottom of the settings dialog).
2. The relevant history entry (select it, copy the log). Remove anything private.
3. Your desktop and how you started the app (menu / autostart / terminal).
4. When started from a terminal: its output.

Run it from a terminal to see messages directly:

```bash
cachy-security-scanner
```

Open an issue: [github.com/ruepp-jenkins/cachyos-security-scanner/issues](https://github.com/ruepp-jenkins/cachyos-security-scanner/issues).

## 🧹 Reset

Stop the app (tray → **Quit**), then remove what you want to reset:

| Reset | Command |
|---|---|
| settings only | `rm ~/.config/cachy-security-scanner/settings.json` |
| accepted findings | `rm ~/.config/cachy-security-scanner/ignored_findings.json` |
| history | *Scan history → Clear history…* or `rm ~/.local/share/cachy-security-scanner/history/*` |
| scanner checkouts (re-cloned at the next scan) | `rm -rf ~/.local/share/cachy-security-scanner/vendor` |
| downloaded update (back to the packaged version) | `rm -rf ~/.local/share/cachy-security-scanner/updates` |
| everything | all of the above plus `rm -rf ~/.cache/cachy-security-scanner` |
