"""Start-up hint: the supported AUR helper is paru; other helpers (yay …) may leave the scanner nothing to scan."""
from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtCore import QObject, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QIcon
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from . import helpers, icons, updater


class _Result(QObject):
    done = Signal(bool, str)


class HelperDialog(QDialog):
    def __init__(self, info: helpers.Info, on_never: Callable[[], None],
                 enable: Callable[[], tuple[bool, str]] = helpers.enable_yay_keepsrc) -> None:
        super().__init__()
        self.info, self.on_never, self._enable = info, on_never, enable
        self.setWindowTitle("AUR helper")
        self.setWindowIcon(QIcon(icons.path(icons.APP)))
        root = QVBoxLayout(self)
        found = ", ".join(info.found)
        text = (f"Found AUR helper(s): {found}.\n\n"
                "The package scanner supports **paru** (the default AUR helper of CachyOS). Other helpers can keep fewer "
                "build files in their cache, which can lead to problems such as little or nothing being scanned. "
                + ("" if info.paru else "paru is not installed: `sudo pacman -S paru`."))
        intro = QLabel(text)
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.MarkdownText)
        root.addWidget(intro)

        self.yay_note = QLabel("")
        self.yay_note.setWordWrap(True)
        self.enable_btn = QPushButton("Set up yay: keep build files (experimental)")
        self.enable_btn.setToolTip("Runs `yay --keepsrc --save`. Experimental: using paru is the better choice.")
        self.enable_btn.clicked.connect(self._enable_clicked)
        self.result = QLabel("")
        self.result.setWordWrap(True)
        if "yay" in info.found:
            if info.yay_keepsrc is True:
                self.yay_note.setText("yay: the option **keepSrc** is on, build files are kept.")
                self.enable_btn.setVisible(False)
            else:
                state = "off" if info.yay_keepsrc is False else "not readable"
                self.yay_note.setText(f"yay: the option **keepSrc** is {state}. Without it yay deletes the build folder "
                                      "(`src/`) after each build and the scan sees less. **Experimental:** this setting "
                                      "is a workaround, using paru is recommended.")
            self.yay_note.setTextFormat(Qt.MarkdownText)
            root.addWidget(self.yay_note)
            root.addWidget(self.enable_btn)
            root.addWidget(self.result)
        else:
            self.enable_btn.setVisible(False)

        row = QHBoxLayout()
        details = QPushButton("Details")
        details.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(updater.docs_url("aur-helpers.md"))))
        row.addWidget(details)
        row.addStretch()
        self.never_btn = QPushButton("Don't show again")
        self.never_btn.setToolTip("You can switch the hint on again in the settings.")
        self.never_btn.clicked.connect(self._never)
        self.close_btn = QPushButton("Close")
        self.close_btn.setToolTip("The hint appears again at the next start.")
        self.close_btn.clicked.connect(self.reject)
        row.addWidget(self.never_btn)
        row.addWidget(self.close_btn)
        root.addLayout(row)
        self.resize(560, self.sizeHint().height())
        self._signal = _Result()
        self._signal.done.connect(self._enabled)

    def _enable_clicked(self) -> None:
        self.enable_btn.setEnabled(False)
        self.result.setText("Running…")
        signal, enable = self._signal.done, self._enable
        threading.Thread(target=lambda: signal.emit(*enable()), daemon=True).start()

    def _enabled(self, ok: bool, message: str) -> None:
        self.result.setText(message)
        self.enable_btn.setEnabled(not ok)
        if ok:
            self.info.yay_keepsrc = True

    def _never(self) -> None:
        self.on_never()
        self.accept()
