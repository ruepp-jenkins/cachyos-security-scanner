# 🦠 Set up ClamAV for binary scans

← [Help overview](README.md)

Binary scans use **ClamAV**, a well-known open-source antivirus engine. The app talks to its daemon `clamd` through the
client `clamdscan`. This page shows how to install, start and test it on CachyOS / Arch.

> ℹ️ Binary scans are **optional**. Without ClamAV everything else works; the tray entry is simply greyed out and the
> ClamAV options in the [settings](settings.md#binary-scan-with-clamav) are disabled.

## What you need

| Part | Package | Purpose |
|---|---|---|
| `clamdscan` | `clamav` | the client the app starts |
| `clamd` | `clamav` (service `clamav-daemon`) | the engine; keeps the virus signatures in memory |
| `freshclam` | `clamav` (service `clamav-freshclam`) | downloads and updates the signatures |

> 💾 `clamd` keeps all signatures in RAM – expect **well over 1 GB** of memory use while it runs. On small machines you
> may prefer to start it only when you need it.

## 1. Install

```bash
sudo pacman -S clamav
```

## 2. Download the virus signatures

The daemon will not start without signatures.

```bash
sudo systemctl stop clamav-freshclam.service     # if it is already running
sudo freshclam                                   # first download, takes a minute
sudo systemctl enable --now clamav-freshclam.service   # keeps them updated from now on
```

## 3. Start the daemon

```bash
sudo systemctl enable --now clamav-daemon.service
systemctl status clamav-daemon.service           # should say "active (running)"
```

Starting can take a while at first: `clamd` loads the signatures.

> 🛠️ **If the service does not start:** look at `journalctl -u clamav-daemon -b`. The most common cause is a missing
> signature database (repeat step 2). The configuration is `/etc/clamav/clamd.conf`; if the file still contains a line
> that only says `Example`, remove or comment it out, as the file instructs. The
> [Arch Wiki page on ClamAV](https://wiki.archlinux.org/title/ClamAV) covers the details.

## 4. Test it

First check that the client can reach the daemon:

```bash
clamdscan --fdpass /usr/bin/ls
```

Expected: `… OK` and a summary with `Infected files: 0`.

Then check that **detection** works with the harmless standard antivirus test file (EICAR). It is not a virus, and every
antivirus reacts to it. It is deliberately **not** included in this repository; get it from the official page
[eicar.org – Anti-malware test file](https://www.eicar.org/download-anti-malware-testfile/), save it somewhere
(for example `~/Downloads/eicar.com.txt`) and scan it:

```bash
clamdscan --fdpass ~/Downloads/eicar.com.txt     # expected: "Eicar-Signature FOUND"
```

Delete the file afterwards. Your browser or another antivirus may block or quarantine the download; that is the test
file doing its job.

> 🔎 Why `--fdpass`? `clamd` runs as its own user and normally cannot read files in your home folder. With `--fdpass`
> the client opens the file itself and passes it to the daemon. The app always uses this option.

## 5. Use it from the app

- **On request:** tray icon → right click → **Scan binaries with ClamAV (clamd)**. A terminal window shows the live output
  and stays open until you press Enter. The log is saved to the [history](scan-history.md).
- **Automatically:** *Settings → Binary scan with ClamAV*. You can pick any of these triggers (all off by default):

  | Trigger | Good for |
  |---|---|
  | at regular intervals (for example weekly) | the usual "scan everything now and then" |
  | at start | a scan after each login |
  | after package installs/updates | catching what a system update brought in |
  | together with every AUR package scan | maximum coverage; expect a full scan after every package scan |

  There is **no minimum time between scans**: a package installed right after a scan must be scanned, too. If a new
  trigger arrives while a scan is still running, the running scan is **cancelled** and a fresh one starts (the history
  shows the cancelled one as *skipped*). The interval trigger never cancels a running scan; it waits.
  Automatic scans run **in the background without a window**; the result is in the history, threats raise a notification.
  Details: [Settings](settings.md#binary-scan-with-clamav).

Paths scanned by default: `/usr/bin`, `/usr/local/bin`, `/opt`, `~/.local/bin`, `/var/lib/flatpak/exports/bin`. Add your
own (one per line); paths that do not exist are skipped.

> 🧱 **The app never deletes anything** it finds with ClamAV. `clamdscan` is started with `-i` (list infected files only)
> and without any `--remove`/`--move` option.

## Make ClamAV gentler (optional)

The app lowers the priority of the **client** (`nice`/`ionice`). The actual scanning is done by the **daemon**, which has
the priority of its own service. To lower it as well:

```bash
sudo systemctl edit clamav-daemon.service
```

Add:

```ini
[Service]
Nice=19
IOSchedulingClass=idle
```

Save, then `sudo systemctl restart clamav-daemon.service`.

Other limits (maximum file size, archive depth, …) are in `/etc/clamav/clamd.conf` (`MaxFileSize`, `MaxScanSize`, …).
Very large files or deeply nested archives may be skipped by default; the app does not change this configuration.

## 🧯 Common problems

| Symptom | Likely cause and fix |
|---|---|
| Tray entry greyed out | `clamdscan` not installed → `sudo pacman -S clamav` |
| `Can't connect to clamd` / "Is clamd running?" in the log | the daemon is not running → step 3 |
| `ERROR: Could not lock … database` or daemon stops right after start | no signatures yet → step 2 |
| `Failed to open file` for a few files, `Total errors: N` | normal: files your user may not read (root-only files, locks, secrets) are skipped. If `Infected files: 0` the scan counts as **clean**, and the history says how many files were skipped. To include them you would have to scan as root, which the app does not do |
| `Permission denied` when you test by hand | missing `--fdpass` |
| Scan is slow | normal for large trees; narrow the paths, keep low priority on, or scan less often |
| High memory use | expected, the signatures are loaded in RAM; stop the daemon when you do not need it: `sudo systemctl stop clamav-daemon` |
