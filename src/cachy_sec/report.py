"""Links that open a prefilled GitHub issue form in the browser.

The app sends nothing itself: it only builds a URL to this project's issue templates (`.github/ISSUE_TEMPLATE/`) and
the user submits the form on GitHub, with their own account. Only short facts (package, version, rule codes, and the
versions of the app, scanners and lists, see about.report_summary) are put into the URL; never log text or file paths
(logs are long, and paths can contain the user name).
"""
from __future__ import annotations

import platform
from urllib.parse import urlencode

from . import __commit__, updater

NEW_ISSUE = f"https://github.com/{updater.GITHUB_REPO}/issues/new"
MAX_FIELD = 200  # values come from scanner output (untrusted) and must keep the URL short
MAX_ENVIRONMENT = 1500  # the block with the versions
_environment = ""  # collected in the background (it starts other programs), so a click never has to wait


def set_environment(text: str) -> None:
    global _environment
    _environment = text


def environment() -> str:
    """The versions block of a report; only the basics as long as nothing was collected."""
    return _environment or (f"App: {updater.effective_version()}" + (f" (commit {__commit__[:7]})" if __commit__ else "")
                            + f"\nPython: {platform.python_version()}")


def _tint(rgb: str) -> str:
    """Very faint coloured button: translucent, so it fits light and dark themes and does not shout."""
    return (f"QPushButton {{ background-color: rgba({rgb}, 28); border: 1px solid rgba({rgb}, 90); "
            f"border-radius: 4px; padding: 4px 10px; }} "
            f"QPushButton:hover {{ background-color: rgba({rgb}, 55); }} "
            f"QPushButton:disabled {{ background-color: transparent; border-color: rgba({rgb}, 40); }}")


STYLE_FALSE_POSITIVE = _tint("46, 160, 67")  # green: "the finding is wrong"
STYLE_MALICIOUS = _tint("218, 54, 51")  # red: "the package is bad"


def _clean(value: str) -> str:
    return "".join(c for c in str(value) if c.isprintable())[:MAX_FIELD].strip()


def _url(template: str, **fields: str) -> str:
    query = {"template": template}
    query.update({k: v for k, v in ((k, _clean(v)) for k, v in fields.items()) if v})
    lines = ("".join(c for c in line if c.isprintable())[:MAX_FIELD] for line in environment().splitlines())
    query["environment"] = "\n".join(lines)[:MAX_ENVIRONMENT]
    return f"{NEW_ISSUE}?{urlencode(query)}"


def false_positive_url(package: str = "", version: str = "", codes: list[str] | None = None) -> str:
    codes_text = ", ".join(codes or [])
    title = "False positive: " + " ".join(p for p in (package, version, codes_text) if p) if package else ""
    return _url("false-positive.yml", title=title, package=package, version=version, codes=codes_text)


def blocklist_url(package: str = "", version: str = "") -> str:
    title = f"Blocklist: {package}" if package else ""
    return _url("blocklist.yml", title=title, package=package, versions=version)


def bug_url() -> str:
    return _url("bug.yml", version=updater.effective_version())
