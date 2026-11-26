"""Tray entry "About": icon, versions of the app, the scanners and their data, and links."""
from __future__ import annotations

import re
from html import escape
from pathlib import Path

from PySide6 import __version__ as pyside_version
from PySide6.QtCore import QEvent, Qt, QUrl, qVersion
from PySide6.QtGui import (QDesktopServices, QFont, QFontMetricsF, QIcon, QPalette, QTextBlockFormat, QTextCharFormat,
                           QTextCursor, QTextOption)
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QTextBrowser, QVBoxLayout

from . import about, icons


def _value(text: str) -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.PlainText)  # output of other programs is untrusted
    label.setText(text)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return label


_PATH = re.compile(r"(?<![\w:/.])(?:~/|/)[^\s,;()]+")  # a path inside a longer value
_PATH_ROWS = ("Path", "Location", "Definition files")  # rows whose whole value is a path (it may contain spaces)
_LEFT = 12  # indentation of the rows below their heading
_GAP = 16  # between the longest key and the values
_HANGING = "  "  # wrapped lines start this much right of the value's first line, so they are recognisable as such


def folder_of(path: str) -> Path | None:
    """The folder to open for a shown path: itself if it is a folder, else the one containing it. Files are never
    opened: some are programs, others come from third-party repositories."""
    p = Path(path).expanduser()
    if p.is_dir():
        return p
    return p.parent if p.is_file() else None


def path_spans(key: str, value: str) -> list[tuple[int, int, str]]:
    """(start, end, path) of the parts of `value` that are paths."""
    if key in _PATH_ROWS and value.startswith(("~/", "/")):
        return [(0, len(value), value)]
    return [(m.start(), m.end(), m.group().rstrip(".:")) for m in _PATH.finditer(value)]


class InfoView(QTextBrowser):
    """Read-only text that can be selected and copied as a whole or in parts: bold headings, "key<tab>value" lines
    with both columns left-aligned, and paths that open their folder when clicked. All text is inserted as plain
    text, so output of other programs cannot add markup."""

    def __init__(self) -> None:
        super().__init__()
        self.setOpenLinks(False)
        self.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)  # long paths wrap instead of being cut off
        self.anchorClicked.connect(self.open_link)
        self._sections: list = []

    def changeEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().changeEvent(event)
        # the column positions depend on the font: build the text again if it changes
        if event.type() in (QEvent.FontChange, QEvent.ApplicationFontChange) and getattr(self, "_sections", None):
            self.show_sections(self._sections)

    def open_link(self, url: QUrl) -> None:
        folder = folder_of(url.toLocalFile())
        if folder is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def _insert(self, cursor: QTextCursor, text: str, plain: QTextCharFormat, spans: list[tuple[int, int, str]]) -> None:
        position = 0
        for start, end, path in spans:
            if folder_of(path) is None:
                continue
            cursor.insertText(text[position:start], plain)
            link = QTextCharFormat(plain)
            link.setAnchor(True)
            link.setAnchorHref(QUrl.fromLocalFile(str(Path(path).expanduser())).toString())
            link.setForeground(self.palette().brush(QPalette.Link))
            link.setFontUnderline(True)
            link.setToolTip(f"Open the folder {folder_of(path)}")
            cursor.insertText(text[start:end], link)
            position = end
        cursor.insertText(text[position:], plain)

    def show_sections(self, sections) -> None:
        self._sections = list(sections)
        self.clear()
        cursor = self.textCursor()
        normal = QTextCharFormat()
        bold = QTextCharFormat()
        bold.setFontWeight(QFont.Bold)
        groups: list[list[int]] = []  # block numbers of the rows of each section
        first = True
        for name, rows in sections:
            heading = QTextBlockFormat()
            heading.setTopMargin(0 if first else 12)
            if first:
                cursor.setBlockFormat(heading)
                first = False
            else:
                cursor.insertBlock(heading)
            cursor.insertText(name, bold)
            group: list[int] = []
            base = ""
            for key, value in rows:
                cursor.insertBlock(QTextBlockFormat())
                group.append(cursor.blockNumber())
                is_file = base and key.endswith((".json", ".txt"))
                self._insert(cursor, f"{key}:", normal, [(0, len(key), f"{base}/{key}")] if is_file else [])
                cursor.insertText("\t", normal)
                self._insert(cursor, value, normal, path_spans(key, value))
                if key == "Definition files":
                    base = value
            groups.append(group)
        for group in groups:
            self._align(group)
        self.moveCursor(QTextCursor.Start)

    def value_start(self, number: int) -> float | None:
        """Where the value of a row really begins, measured from the start of its first line; None while the text
        is not laid out yet (asking an empty layout for a line crashes Qt)."""
        self.document().documentLayout().documentSize()  # make sure the layout is up to date
        block = self.document().findBlockByNumber(number)
        layout = block.layout()
        if layout is None or layout.lineCount() == 0:
            return None
        line = layout.lineAt(0)
        x = line.cursorToX(block.text().index("\t") + 1)
        return (x[0] if isinstance(x, tuple) else x) - line.x()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        # filled before it was visible: only now the text can be measured (not on un-minimising: keeps the selection)
        if self._sections and not event.spontaneous():
            self.show_sections(self._sections)

    def _format_rows(self, numbers: list[int], tab: float, wrap_at: float) -> None:
        fmt = QTextBlockFormat()
        fmt.setTabPositions([QTextOption.Tab(tab, QTextOption.LeftTab)])
        fmt.setLeftMargin(wrap_at)  # where wrapped lines start ...
        fmt.setTextIndent(_LEFT - wrap_at)  # ... while the first line starts below the heading
        for number in numbers:
            cursor = QTextCursor(self.document().findBlockByNumber(number))
            cursor.setBlockFormat(fmt)

    def _align(self, numbers: list[int]) -> None:
        """One column per section. Positions are measured on the laid-out text instead of being predicted from font
        metrics, which differ between fonts, styles and screen scales."""
        if not numbers:
            return
        metrics = QFontMetricsF(self.document().defaultFont())
        keys = [self.document().findBlockByNumber(n).text().split("\t")[0] for n in numbers]
        tab = max(metrics.horizontalAdvance(k) for k in keys) + _GAP
        hanging = metrics.horizontalAdvance(_HANGING)
        value = tab  # until the real position can be measured
        for _ in range(5):
            self._format_rows(numbers, tab, _LEFT + value + hanging)
            starts = [x for x in map(self.value_start, numbers) if x is not None]
            if not starts:
                break
            value = max(starts)
            if value - min(starts) < 1:
                break
            tab = value + _GAP  # a key reached past the column: widen it
        self._format_rows(numbers, tab, _LEFT + value + hanging)


def _links(items: list[tuple[str, str]]) -> QLabel:
    label = QLabel(" · ".join(f'<a href="{escape(url)}">{escape(name)}</a>' for name, url in items))
    label.setWordWrap(True)
    label.setOpenExternalLinks(True)
    label.setTextInteractionFlags(Qt.TextBrowserInteraction)
    return label


class AboutDialog(QDialog):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("About CachyOS Security Scanner")
        self.setWindowIcon(QIcon(icons.path(icons.APP)))
        root = QVBoxLayout(self)

        head = QHBoxLayout()
        pic = QLabel()
        pic.setPixmap(QIcon(icons.path(icons.APP)).pixmap(72, 72))
        head.addWidget(pic, 0, Qt.AlignTop)
        text = QVBoxLayout()
        title = QLabel("<h2>CachyOS Security Scanner</h2>")
        text.addWidget(title)
        text.addWidget(_value(f"Version {about.app_version()}"))
        intro = QLabel("A tray front end for external malware scanners. All detection is done by the projects below.")
        intro.setWordWrap(True)
        text.addWidget(intro)
        head.addLayout(text, 1)
        root.addLayout(head)
        root.addWidget(_links(about.links()))

        self.view = InfoView()
        self.view.setPlainText("Reading versions…")
        self.loaded = False
        root.addWidget(self.view, 1)

        root.addWidget(QLabel("Scanners used:"))
        root.addWidget(_links(about.UPSTREAM))
        row = QHBoxLayout()
        row.addWidget(_value(about.COPYRIGHT), 1)
        close = QPushButton("Close")
        close.clicked.connect(self.reject)
        row.addWidget(close)
        root.addLayout(row)
        self.resize(720, 700)

    def show_info(self, sections: list[about.Section]) -> None:
        sections = [(name, rows + [("Qt / PySide6", f"{qVersion()} / {pyside_version}")] if name == about.PROGRAM else rows)
                    for name, rows in sections]
        self.view.show_sections(sections)
        self.loaded = True
