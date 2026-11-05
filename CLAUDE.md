# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A PySide6 tray app for CachyOS/Arch that **orchestrates external scanners** (aur-malware-check, aur-scan, ClamAV, a signed community blocklist) and shows their results. It contains no detection logic of its own. Python 3.12+, only dependency PySide6, stdlib `unittest`.

## Commands

```bash
python3 -m unittest discover -s tests                      # core tests; GUI tests are skipped without PySide6
python3 -m unittest tests.test_core.SchedulerTest          # one class (or ...SchedulerTest.test_name for one test)
QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s tests -v   # incl. GUI tests (needs PySide6 + Qt libs)
PYTHONPATH=src python3 -m cachy_sec                        # run the app (needs PySide6 and a tray)
PYTHONPATH=src python3 -m cachy_sec.signedlist validate lists/*.json   # what CI runs on the community lists
```

- PySide6 is usually **not installed** in the dev container, so GUI code (`app.py`, `*_dialog.py`) is often only compile-checked locally; CI (`.github/workflows/ci.yml`) is what runs `tests/test_gui.py`. When Docker works, build a throwaway `python:3.12-slim` image with PySide6 + `libgl1 libegl1 libxkbcommon0 libfontconfig1 libdbus-1-3` (use `--network host` for the build, apt hangs otherwise).
- `release.yml` runs the tests **without** PySide6, so GUI tests are skipped there.
- There is no linter configured.

## Architecture (the parts that span several files)

**Process model.** `cachy-security-scanner` → `bootstrap.main()` is a supervisor that runs `python -m cachy_sec` as a child. It prefers a verified downloaded update (`~/.local/share/cachy-security-scanner/updates/<ver>/`, put on `PYTHONPATH`), discards it if it crashes within 30 s, and restarts the child on exit code 75 (`updater.RESTART_EXIT_CODE`). `app.main()` takes a single-instance `flock` (`singleton.py`) and builds `app.Tray`, which owns all timers and dialogs.

**Scan flow.** Triggers (start, pacman hook, interval, tray click) → `Tray.scan()` → worker thread (`_Job` on `QThreadPool`) → `engine.run_scan()` → for each *enabled* scanner (`engine.enabled_scanners`): `update()` (git clone/pull, cargo build) then `scan()` → `engine.Report` → `history.record()` (one JSON file per scanner) → `Tray._finished()` sets the tray icon (`Report.icon_status`), notifies (`notify.py`, `notify-send`) and opens a `FindingsDialog`. Settings are re-read from disk before each scan (`_reload_settings`). Only one package scan at a time; a package change during a scan queues one more.

**Scanners** (`scanners/`): subclass `base.Scanner` (`available`, `update`, `scan` → `ScanResult` with `Finding`s). A scanner that cannot be set up or run must return an `ERROR` result, never "clean". All subprocesses go through `base.run()` (no shell; `low_priority=True` prefixes `nice`/`ionice`). Upstream repos are managed by `vendor.py` (shallow clone, `git fsck` health check, `pull --ff-only`, delete + re-clone on trouble; deletion is restricted to the vendor root). ClamAV is separate from the package scanners: terminal scan on request, or `clamd.run_background()` for scheduled scans; its exit code is interpreted in `clamd.interpret()` (exit 2 with `Infected files: 0` is a clean scan).

**Signed lists.** `signedlist.py` downloads a JSON list + SSH signature from the `lists` release, verifies it with `ssh-keygen -Y verify` against the key embedded in `updater.SIGNER_PUBKEY` (one namespace per list), and caches it in `~/.cache/cachy-security-scanner/`. `blocklist.py` / `fplist.py` hold list-specific validation and matching. The false-positive list only hides `aur-scan` findings for the exact scanned PKGBUILD version (taken from `.SRCINFO`, see `ignores.py`).

**Scheduling.** Pure functions in `scheduler.py` (testable without Qt) decide delays and "binary scan due" (package scans have a wait but no minimum gap: every change must be scanned); `Tray` wires them to timers. Binary-scan timing is persisted in two state files (`binary-last-scan` = last attempt, `binary-last-success`). Background binary scans are one process at a time: an event trigger cancels the running one (`clamd.cancel_background`) and restarts (`Tray._binary_next`); `Tray._refresh_tray` shows the blue icon while any scan runs.

**Version & updates.** The version in git is always `0.0.0`; the release tag is the source of truth (`scripts/set-version.sh` stamps it in CI). `updater.py` only talks to GitHub hosts, verifies signature + SHA-256, and extracts safely. `updater.docs_url()` builds the Help links from the running version's tag.

**Notifications & tray.** `notify.py` runs `notify-send`; clickable ones (`--action … --wait`, one helper thread each, max 10) open the history with the matching entry selected (`Tray._click_to`, `SELECTORS`, `HistoryDialog.select_latest`). The tray icon is the colour of the last result (`Report.icon_status`) but the blue app icon while any scan runs (`Tray._refresh_tray`); menu entries use theme icons.

**Reporting.** `report.py` builds links to this repo's issue forms (`.github/ISSUE_TEMPLATE/*.yml`; query parameters must equal the form field ids) and only opens them in the browser, never sending anything; only short facts go into the URL, never log text. Buttons: findings window (per entry), history window, tray *Report a problem…* (`report_dialog.py`). Renaming a form field id means changing `report.py`.

**Options.** Per-scanner choices and validated extra arguments live in `scanopts.py` (specs, command-line builders, denylists) and are edited in `options_dialog.py` (opened by the *Options…* buttons of `settings_dialog.py`); the scanners build their commands from them.

**Website.** The docs are also published with Jekyll/GitHub Pages (`_config.yml`, theme in `_config.yml`, `_includes/head-custom.html` loads Mermaid). Pages always serves `master`; the app's Help links point at the *tag* on GitHub instead.

## Conventions that are easy to break

- **Keep the documentation in sync with every change.** Whenever behaviour, a setting (key, default, label), a menu entry, a notification, a command the app runs, a file it writes or a default changes, update the matching pages in `docs/` in the same commit: `settings.md` (every setting and its default), `tray-and-notifications.md`, `scan-history.md`, `scanner-lifecycle.md` (commands, exit codes), `how-it-works.md` (files, programs, network, privileges, runtime behaviour), `setup-*.md`, `troubleshooting.md`, plus the root `README.md` and this file when the overview or the architecture changes. Then re-check links/anchors and the table rules below. Do not finish a change without asking: "which help page describes this?"
- **Security tool, no throttling of checks:** never add a minimum gap or rate limit that can skip scanning a newly installed package (a good scan followed by a bad install must still be scanned). Debounce waits are fine; if a scan is running, queue/replace it instead of dropping the trigger.
- **Markdown must render in both GitHub and Jekyll (kramdown):** an empty line before every table, list and quote (also directly after a heading); no raw `{{`/`{%`; use ` ```mermaid ` for diagrams; links to files outside `docs/` are absolute GitHub URLs.

- **Language:** all code, UI strings and docs are **English**, even when the conversation is in German.
- **Every `Settings` field must be documented in `docs/settings.md`** (by its key); `test_every_setting_is_documented` fails otherwise. Bump `Settings.schema` and add a migration in `Settings.load()` when a default changes meaning (saved files contain every field, so a new default would otherwise never apply); add a test for the migration.
- **Qt attribute shadowing:** never name a widget attribute like a Qt member (`accepted`, `scroll`, …); it silently replaces the signal/method. A GUI test guards the dialogs.
- **Never silence setup problems:** surface them as `ERROR` results/notifications. Only scanners enabled in the settings may run.
- **Scanner options** (`scanopts.py`, `options_dialog.py`): user-supplied extra arguments must go through `scanopts.parse_extra` (options only, no shell characters, per-scanner denylist incl. anything that removes/moves/writes files). Never pass them to a shell or build commands from them elsewhere.
- **Removal is always user-confirmed** (`remove.py`, `pkexec pacman -Rns`); "Open files" opens a *folder* and never executes anything.
- **Help pages** live in `docs/` (start at `docs/README.md`); keep relative links and anchors valid when editing (GitHub anchors: lowercase, emoji dropped, e.g. `#-the-pacman-hook`). Do not put the EICAR test string or other antivirus test signatures anywhere in the repo.
- **Privacy:** the maintainer's real name/username must not appear in files or git history (screenshots were redacted).
- **Commits:** commit after each change, **without** a `Co-Authored-By` line. Do not push unless asked.
