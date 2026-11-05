"""Tray entry "Report a problem…": choose what to report; the matching GitHub form opens in the browser."""
from __future__ import annotations

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices, QIcon
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from . import icons, report

CHOICES = (  # (button text, explanation, URL builder, style)
    ("False positive", "A finding of a scanner that is wrong for a package version.", report.false_positive_url,
     report.STYLE_FALSE_POSITIVE),
    ("Malicious package", "A package that is malicious or compromised (proposal for the community blocklist).",
     report.blocklist_url, report.STYLE_MALICIOUS),
    ("Program error", "The app itself misbehaves: crash, wrong behaviour, unclear message.", report.bug_url, ""),
)


class ReportDialog(QDialog):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Report a problem")
        self.setWindowIcon(QIcon(icons.path(icons.APP)))
        root = QVBoxLayout(self)
        intro = QLabel("What do you want to report? A form opens on GitHub (you need a GitHub account). "
                       "The app sends nothing by itself. Please check packages yourself before reporting them.")
        intro.setWordWrap(True)
        root.addWidget(intro)
        self.buttons: list[QPushButton] = []
        for text, hint, builder, style in CHOICES:
            b = QPushButton(text)
            b.setToolTip(hint)
            b.setStyleSheet(style)
            b.clicked.connect(lambda _=False, fn=builder: self._open(fn()))
            self.buttons.append(b)
            root.addWidget(b)
            note = QLabel(hint)
            note.setEnabled(False)  # greyed hint text
            note.setWordWrap(True)
            root.addWidget(note)
        row = QHBoxLayout()
        row.addStretch()
        close = QPushButton("Cancel")
        close.clicked.connect(self.reject)
        row.addWidget(close)
        root.addLayout(row)

    def _open(self, url: str) -> None:
        QDesktopServices.openUrl(QUrl(url))
        self.accept()
