# 🧩 AUR helpers: paru is supported, yay needs a setting

← [Help overview](README.md)

The package scanner `aur-scan` reads what **your AUR helper** (paru, yay, …) has left in its cache. What a scan can see
therefore depends on the helper. For packages that are in no cache at all, the app can
[fetch and unpack them itself](scanner-lifecycle.md#-packages-that-no-helper-cache-holds) (opt-in).

## What is supported

| Helper | Status | Why |
|---|---|---|
| **paru** | ✅ supported, the default of CachyOS | keeps the build folder (`src/`) with the extracted sources after a build, so the scanner can look at them |
| **yay** | ⚠️ experimental | deletes `src/` and `pkg/` after building unless its option `keepSrc` is on, so the scanner sees less. See [yay workaround](#-yay-workaround-experimental) |
| pikaur, trizen, aura, pakku, rua, aurman, pacaur | ❓ not tested | the scanner knows their cache folders, but what they keep is not checked by this project |

> 🔎 **What can go wrong:** a package built with a helper that removes its sources can end up with *little or nothing* to
> scan. The result then says `OK` although less was looked at. The scan log lists which packages were *not found in cache*.

Paru is the recommended choice. On CachyOS it is installed with `sudo pacman -S paru`; otherwise build it from the AUR
(check its `PKGBUILD` first).

## 💡 The start-up hint

At every start the app checks (in the background, shortly after the start) whether an AUR helper **other than paru** is
installed. If so, a window says that paru is the supported helper and that other helpers can lead to problems such as
nothing being scanned. If **yay** is installed it also tells you whether its `keepSrc` option is on.

| Button | What it does |
|---|---|
| **Set up yay: keep build files (experimental)** | only shown with yay installed and `keepSrc` not on. Runs `yay --keepsrc --save`, then reads the setting back with `yay -P -g` and says whether it worked |
| **Details** | opens this page |
| **Close** (or closing the window) | the hint comes back at the **next start** |
| **Don't show again** | switches the hint off for good. You can switch it on again in the [settings](settings.md#general) (*Warn at start when an AUR helper other than paru is installed*, key `warn_other_aur_helper`) |

The app only **reads** the yay setting by itself (`yay -P -g`). It changes yay's configuration **only when you click** the
button. Nothing runs as root.

## 🧪 yay workaround (experimental)

yay stores its options in `~/.config/yay/config.json` and changes them with `--save`. The workaround is:

```bash
yay --keepsrc --save
```

Check it:

```bash
yay -P -g | grep -i keepsrc      # expected: "keepSrc": true
```

Notes:

- The setting only applies to packages built **from now on**. Rebuild a package to get its `src/` back, for example
  `yay -S --rebuild <package>`, then look into `~/.cache/yay/<package>`.
- It is **experimental**: even with the folder kept, what is inside depends on the package's `PKGBUILD` (some move files out
  of `src/` in `package()`), so the result can still differ from paru. Switching to paru is the better fix.
- If both helpers are installed, `aur-scan` looks in `~/.cache/yay` before `~/.cache/paru/clone` and takes the **first**
  copy it finds. After switching to paru, delete `~/.cache/yay` so old copies are not scanned.

## Switching to paru

```bash
sudo pacman -S paru            # CachyOS repositories; otherwise: yay -S paru
paru --version
```

Installed packages stay installed. paru's cache starts empty, so the scan reports *not found in cache* for a package until
paru has fetched or built it (for example with the next update).

See also: [Troubleshooting](troubleshooting.md#a-package-is-not-found-in-cache--little-is-scanned), [Scanner lifecycle](scanner-lifecycle.md#aur-scan).
