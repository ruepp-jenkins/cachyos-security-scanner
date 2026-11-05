"""Tray entry "Report a problem…": choose what to report; the matching GitHub form opens in the browser."""
from __future__ import annotations

from PySide6.QtCore import Qt, QUrl
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
            note = QLabel(hint)  # normal text colour: greyed text is hard to read and does not match the other windows
            note.setWordWrap(True)
            note.setContentsMargins(0, 0, 0, 8)
            root.addWidget(note)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.status.setVisible(False)
        root.addWidget(self.status)
        row = QHBoxLayout()
        row.addStretch()
        close = QPushButton("Close")
        close.clicked.connect(self.reject)
        row.addWidget(close)
        root.addLayout(row)
        self.resize(640, self.sizeHint().height())

    def _open(self, url: str) -> None:
        """Open the form. The window stays open like the history window does: closing it right away can cancel the
        browser start on some desktops (the portal call is asynchronous). If no browser can be started, show the link."""
        if QDesktopServices.openUrl(QUrl(url)):
            self.status.setText("Opened in your browser.")
        else:
            self.status.setText("Could not start a browser. Open this link yourself:\n" + url)
        self.status.setVisible(True)
