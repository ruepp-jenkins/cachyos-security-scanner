# 📜 Scan history

← [Help overview](README.md)

The scan history is the logbook of the app: every scan, with the result of **each scanner** and the complete output.
Open it with a **left click on the tray icon** or the menu entry **Scan history…**.

It is the place to look when:

- you want to know what a scan found or why it failed,
- the tray icon is red/orange and you want the details,
- you want to check *when* scans ran (for example to correlate them with system load).

## The window

```
┌───────────────────────────────────────────────────────────────────────────────┐
│ [ Filter: search all columns and the scan details…        ] ☐ Only scans with  │
│                                                              detected threats │
├──┬─────────────────────┬─────────────┬────────────────┬──────────────────────┤
│  │ Started ▼           │ Type        │ Trigger        │ Summary              │
├──┼─────────────────────┼─────────────┼────────────────┼──────────────────────┤
│🟢│ 2026-11-01 09:15:02 │ aur_malware…│ startup        │ No threats found     │
│🟠│ 2026-11-01 09:15:40 │ aur_scan    │ startup        │ 2 findings           │
│❌│ 2026-11-01 08:00:11 │ aur_scan    │ interval       │ not available: cargo │
├──┴─────────────────────┴─────────────┴────────────────┴──────────────────────┤
│ log of the selected scan (full output of the scanner)                          │
└───────────────────────────────────────────────────────────────────────────────┘
        [ Refresh ] [ Open folder ] [ Clear history… ]                [ Close ]
```

### Columns

| Column | Content |
|---|---|
| *(icon)* | the status of the scan, see the table below. Hover for the status word |
| **Started** | date **and** time the scan started |
| **Type** | which scanner produced the entry (`aur_malware_check`, `aur_scan`, `blocklist`, …) or `binaries` for a ClamAV scan |
| **Trigger** | what started it: `startup`, `interval`, `package change`, `manual`, `after ignore`, `with package scan` |
| **Summary** | one line: *No threats found*, *N findings*, the error, or why it was skipped |

All columns size themselves to their content; *Summary* takes the remaining space.

### Status icons

Scanner **results** have a shield; **system states** have other shapes, so you can tell them apart immediately.

| Icon | Status | Source | Meaning |
|---|---|---|---|
| 🟢 green shield | `clean` | scanner | nothing found |
| 🟠 orange shield | `warning` | scanner | findings of warning level |
| 🔴 red shield | `critical` | scanner | critical findings |
| ❌ red cross | `error` | system | the scanner could not run or crashed (message in the log) |
| ⏭️ grey "next" | `skipped` | system | the scan was skipped (gaming mode, battery) |
| 🟣 purple question mark | `unknown` | system | no result recorded: a binary scan is still running, or its window was closed early |

### Working with the list

| You want to… | Do this |
|---|---|
| **sort** | click a column header (click again to reverse). The default is *Started*, newest first. Sorting by the icon column groups by severity |
| **search** | type in the filter field. It looks in **all columns and in the full text of every scan** – for example a package name or a rule code – and updates while you type |
| **see only problems** | tick *Only scans with detected threats* (shows `warning` and `critical`) |
| **read the details** | select a line (only **one** can be selected); the log appears below |
| **open the files on disk** | **Open folder** |
| **start over** | **Clear history…** (asks first) |

The window is **live**: new scans appear by themselves every few seconds, and the log of a running scan keeps growing.
Your selection stays where it is, also while you sort or filter.

## Where the entries are stored

Plain files in `~/.local/share/cachy-security-scanner/history/`:

| File | Content |
|---|---|
| `<date>T<time>-<scanner>.json` | one package-scan result of one scanner |
| `<date>T<time>-skipped.json` | a skipped scan |
| `<date>T<time>-binaries.log` | the output of a ClamAV scan |

You can read, copy or delete them without the app. How many are kept is set by *Keep the last N history entries*
(default 200, one entry per scanner and scan); the oldest are deleted first. See [Settings](settings.md#general).

## Reading a log

A package-scan entry starts with the header (start time, trigger, process id, duration, status, summary) and then lists
one block per scanner:

```
===== aur_scan – warning =====
[warning] some-package: suspicious install script
    rule DEEP-001 … details …
community false-positive list: on, 1 entries (cached copy)
--- output ---
(the raw output of the tool)
```

- Lines in `[brackets]` are the findings with their severity.
- *Notes* tell you what the app did with the results, for example *"1 finding(s) were hidden by the community
  false-positive list"* (with the reason, author and date in the log), or that the list is switched off or not available.
  Hidden findings are never dropped silently.
- The *process id* shows which app instance ran the scan. Two different ids in a short time would mean two instances (the
  app prevents this).

## From the history to a decision

Found something? Continue in the [findings window](findings-window.md): it shows the same entries with buttons to open
the files, accept an entry or remove the package.
