# 🧰 Requirements and optional parts

← [Help overview](README.md)

The Arch package pulls in everything that is required. This page explains **what each part is for**, how to check it and
what to do if something is missing – for example when you run the app from source or on another desktop.

## At a glance

| Part | Needed for | Package | Required? |
|---|---|---|---|
| Python 3.12+ and PySide6 (Qt 6) | the app itself | `python`, `pyside6` | ✅ |
| `git` | fetching and updating the scanners | `git` | ✅ |
| `openssh` | verifying signatures (`ssh-keygen -Y verify`) of updates and lists | `openssh` | ✅ |
| `libnotify` | desktop notifications (`notify-send`) | `libnotify` | ✅ |
| `pacman` | package data, removal | `pacman` | ✅ |
| Python 3.14+ | the scanner `aur-malware-check` | `python` (CachyOS often has it) | for that scanner |
| Rust toolchain | building `aur-scan` once | `rust`, `clang`, `pkgconf`, `openssl` | only if `aur-scan` is on and not installed from the AUR |
| `polkit` + an authentication agent | removing a package | `polkit` | only for removal |
| `clamav` | binary scans | `clamav` | optional → [Set up ClamAV](setup-clamav.md) |
| System tray | showing the icon | desktop | see below |
| pacman hook | "scan after package changes" | shipped by the package | only for that trigger |

## 🪟 System tray

The app shows a tray icon through the standard *StatusNotifierItem* protocol.

| Desktop | Tray icon |
|---|---|
| KDE Plasma | ✅ works out of the box |
| XFCE, Cinnamon, MATE, LXQt, Budgie, Deepin | ✅ (XFCE: enable the *Status Tray Plugin* in the panel if it is missing) |
| i3 / sway / Hyprland | ✅ with a bar that supports tray icons (for example waybar's `tray` module) |
| **GNOME** | ❌ stock GNOME has no tray. Install the *AppIndicator and KStatusNotifierItem Support* extension (`gnome-shell-extension-appindicator`), enable it, log out and in |

Without a tray the app waits up to a minute for one and then quits with the message *No system tray available* (visible when started from a terminal).

## 🔔 Notifications

The app calls `notify-send` from `libnotify`. You need a notification daemon, which every full desktop has (Plasma,
GNOME, XFCE's `xfce4-notifyd`, …). Test it:

```bash
notify-send "Hello" "Notifications work"
```

If nothing appears, install `libnotify` and a notification daemon for your desktop, or check *Do not disturb* mode.

## 🔐 polkit (removing packages)

Only the optional **Remove packages…** button needs administrator rights, through `pkexec`:

```bash
pkexec --version          # polkit installed?
```

Your desktop needs a *polkit authentication agent* (KDE: `polkit-kde-agent`, GNOME: `polkit-gnome` / built in). It shows
the password dialog. Without an agent `pkexec` fails and nothing is removed.

## 🐍 Python version for aur-malware-check

`aur-malware-check` requires Python **3.14 or newer**. The app looks for `python3.15`, `python3.14` or `python3` and uses
the first that is new enough. Check:

```bash
python3 --version
```

If yours is older, the scanner shows an **error entry** with the reason in the history (not silence). Options: update
your system, or switch that scanner off in the [settings](settings.md#aur-scanners) and use the blocklist instead.

## 🦀 Rust (only for aur-scan)

`aur-scan` has no binary release. The app clones it and builds it with `cargo build --release --locked` – once, and again
only when the source changes. This needs `rust`, `clang`, `pkgconf` and `openssl` (all dependencies of the package) and
downloads Rust crates from crates.io. The build can take a few minutes and uses CPU – with low priority if you keep that
setting on.

**Skip the build:** install the AUR package `aur-scanner` (it provides `aur-scan`); the app then uses it instead.

## 🪝 The pacman hook

The package installs `/usr/share/libalpm/hooks/cachy-security-scanner.hook`. After every pacman transaction (install,
upgrade, remove) it runs one harmless command as root:

```
touch /var/lib/cachy-security-scanner/trigger
```

The app watches that file and starts a scan after a short wait. The hook never runs a scan and never blocks pacman. The
folder `/var/lib/cachy-security-scanner/` is created by `systemd-tmpfiles` from
`/usr/lib/tmpfiles.d/cachy-security-scanner.conf`.

- This also fires when you install with `paru` or `yay`, because they end with `pacman -U`. It does **not** fire for
  Flatpaks, AppImages or manual `makepkg` without installing.
- Running from source? There is no hook, so "scan after package changes" does nothing. Copy the files from `data/` to
  the places above if you want it.
- Check: `ls -l /var/lib/cachy-security-scanner/trigger` – the timestamp changes after each pacman transaction.

## 🚦 Autostart

The package ships `/etc/xdg/autostart/cachy-security-scanner.desktop`. The setting *Start automatically at login* writes
`~/.config/autostart/cachy-security-scanner.desktop` (or, to turn it off, an override with `Hidden=true`). The app waits up
to a minute for the tray to appear after login.
