"""Links that open a prefilled GitHub issue form in the browser.

The app sends nothing itself: it only builds a URL to this project's issue templates (`.github/ISSUE_TEMPLATE/`) and
the user submits the form on GitHub, with their own account. Only short facts (package, version, rule codes, app
version) are put into the URL; never log text (it is long and can contain the user name in file paths).
"""
from __future__ import annotations

from urllib.parse import urlencode

from . import updater

NEW_ISSUE = f"https://github.com/{updater.GITHUB_REPO}/issues/new"
MAX_FIELD = 200  # values come from scanner output (untrusted) and must keep the URL short


def _clean(value: str) -> str:
    return "".join(c for c in str(value) if c.isprintable())[:MAX_FIELD].strip()


def _url(template: str, **fields: str) -> str:
    query = {"template": template}
    query.update({k: v for k, v in ((k, _clean(v)) for k, v in fields.items()) if v})
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
