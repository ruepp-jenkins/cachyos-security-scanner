"""Options of a single scanner: the typed choices and validated extra arguments (see scanopts.py)."""
from __future__ import annotations

import copy

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QIcon
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit, QPlainTextEdit,
                               QPushButton, QVBoxLayout)

from . import icons, scanopts
from .settings import Settings


class OptionsDialog(QDialog):
    def __init__(self, which: str, s: Settings, parent=None) -> None:
        super().__init__(parent)
        self.which = which
        self.spec = scanopts.SPECS[which]
        self.defaults = Settings()
        self.s = copy.deepcopy(s)
        self.setWindowTitle(self.spec.title)
        self.setWindowIcon(QIcon(icons.path(icons.APP)))
        self.setMinimumWidth(560)
        lay = QVBoxLayout(self)
        intro = QLabel(self.spec.intro)
        intro.setWordWrap(True)
        lay.addWidget(intro)

        self.paths_edit = None
        if self.spec.paths_key:
            lay.addWidget(QLabel("Paths to scan, one per line (missing paths are skipped):"))
            self.paths_edit = QPlainTextEdit("\n".join(getattr(self.s, self.spec.paths_key)))
            self.paths_edit.setMaximumHeight(120)
            lay.addWidget(self.paths_edit)

        form = QFormLayout()
        lay.addLayout(form)
        self.widgets: dict[str, QCheckBox | QComboBox] = {}
        for o in self.spec.opts:
            if o.kind == "bool":
                w = QCheckBox(o.label)
                w.setChecked(bool(getattr(self.s, o.key)))
                w.toggled.connect(self._update)
                form.addRow(w)
            else:
                w = QComboBox()
                w.addItems(o.choices)
                w.setCurrentText(str(getattr(self.s, o.key)))
                w.currentTextChanged.connect(self._update)
                form.addRow(o.label, w)
            w.setToolTip(o.tip)
            self.widgets[o.key] = w

        lay.addWidget(QLabel("Extra arguments (optional), added after the options above:"))
        self.extra = QLineEdit(getattr(self.s, self.spec.extra_key))
        self.extra.setPlaceholderText("for example: --verbose")
        self.extra.textChanged.connect(self._update)
        lay.addWidget(self.extra)
        rules = QLabel("Only options of this scanner are accepted: they must start with - or --, values must follow their option, "
                       "and shell characters (; & | < > ` $) as well as options that delete, move or write files are rejected. "
                       "No shell is ever used.")
        rules.setWordWrap(True)
        rules.setEnabled(False)
        lay.addWidget(rules)
        self.error = QLabel()
        self.error.setWordWrap(True)
        self.error.setStyleSheet("color: #c0392b;")
        lay.addWidget(self.error)

        lay.addWidget(QLabel("The scanner will be started like this:"))
        self.preview = QLabel()
        self.preview.setWordWrap(True)
        self.preview.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.preview.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(self.preview)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        reset = QPushButton("Defaults")
        buttons.addButton(reset, QDialogButtonBox.ResetRole)
        reset.clicked.connect(self._reset)
        buttons.accepted.connect(self._ok)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)
        self._update()

    def _apply(self, target: Settings) -> None:
        for o in self.spec.opts:
            w = self.widgets[o.key]
            setattr(target, o.key, w.isChecked() if isinstance(w, QCheckBox) else w.currentText())
        setattr(target, self.spec.extra_key, self.extra.text().strip())
        if self.paths_edit is not None:
            setattr(target, self.spec.paths_key, [p.strip() for p in self.paths_edit.toPlainText().splitlines() if p.strip()])

    def _update(self, *_args) -> None:
        tmp = copy.deepcopy(self.s)
        self._apply(tmp)
        self.preview.setText(scanopts.preview(self.which, tmp))
        try:
            scanopts.extra(self.spec, tmp)
            self.error.setText("")
        except ValueError as e:
            self.error.setText(f"Extra arguments: {e}")

    def _reset(self) -> None:
        for o in self.spec.opts:
            w = self.widgets[o.key]
            v = getattr(self.defaults, o.key)
            w.setChecked(bool(v)) if isinstance(w, QCheckBox) else w.setCurrentText(str(v))
        self.extra.setText("")
        if self.paths_edit is not None:
            self.paths_edit.setPlainText("\n".join(getattr(self.defaults, self.spec.paths_key)))

    def _ok(self) -> None:
        if self.error.text():
            return  # the reason is shown in red; the dialog stays open
        self._apply(self.s)
        self.accept()

    def result_settings(self) -> Settings:
        return self.s
