"""Tray entry "About": icon, versions of the app, the scanners and their data, and links."""
from __future__ import annotations

from html import escape

from PySide6 import __version__ as pyside_version
from PySide6.QtCore import Qt, qVersion
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QDialog, QFormLayout, QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea,
                               QVBoxLayout, QWidget)

from . import about, icons


def _value(text: str) -> QLabel:
    label = QLabel()
    label.setTextFormat(Qt.PlainText)  # output of other programs is untrusted
    label.setText(text)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return label


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

        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.StyledPanel)
        inner = QWidget()
        self.content = QVBoxLayout(inner)
        self.loading = QLabel("Reading versions…")
        self.content.addWidget(self.loading)
        self.content.addStretch()
        area.setWidget(inner)
        root.addWidget(area, 1)

        root.addWidget(QLabel("Scanners used:"))
        root.addWidget(_links(about.UPSTREAM))
        row = QHBoxLayout()
        row.addStretch()
        close = QPushButton("Close")
        close.clicked.connect(self.reject)
        row.addWidget(close)
        root.addLayout(row)
        self.resize(680, 620)

    def show_info(self, sections: list[about.Section]) -> None:
        self.loading.hide()
        sections = [(name, rows + [("Qt / PySide6", f"{qVersion()} / {pyside_version}")] if name == "System" else rows)
                    for name, rows in sections]
        for name, rows in sections:
            heading = QLabel(f"<b>{escape(name)}</b>")
            self.content.insertWidget(self.content.count() - 1, heading)
            form = QFormLayout()
            form.setContentsMargins(12, 0, 0, 8)
            for key, value in rows:
                form.addRow(f"{key}:", _value(value))
            self.content.insertLayout(self.content.count() - 1, form)
