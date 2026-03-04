from __future__ import annotations

import sys
import traceback
from dataclasses import dataclass
from pathlib import Path

try:
    from PySide6 import QtCore, QtWidgets
except Exception as e:  # pragma: no cover
    print("ERROR: PySide6 is not installed (GUI is optional).", file=sys.stderr)
    print("Install it with: pip install PySide6", file=sys.stderr)
    raise

from extract import export_view, temp_log_handler, view_specs


@dataclass(frozen=True)
class ExportRequest:
    snapshot: Path
    view: str
    out_csv: Path


class ExportWorker(QtCore.QObject):
    log_line = QtCore.Signal(str)
    finished = QtCore.Signal(int)
    failed = QtCore.Signal(str)

    def __init__(self, req: ExportRequest):
        super().__init__()
        self._req = req

    @QtCore.Slot()
    def run(self) -> None:
        try:
            with temp_log_handler(self.log_line.emit):
                rc = export_view(self._req.snapshot, view=self._req.view, out_csv=self._req.out_csv, limit=0)
            self.finished.emit(int(rc))
        except Exception:
            self.failed.emit(traceback.format_exc())
            self.finished.emit(1)


class SnapshotPage(QtWidgets.QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Select RAMMap snapshot")

        self._path_edit = QtWidgets.QLineEdit()
        self._browse_btn = QtWidgets.QPushButton("Browse…")
        self._browse_btn.clicked.connect(self._browse)

        row = QtWidgets.QHBoxLayout()
        row.addWidget(self._path_edit)
        row.addWidget(self._browse_btn)

        layout = QtWidgets.QVBoxLayout()
        layout.addLayout(row)
        self.setLayout(layout)

        self.registerField("snapshot*", self._path_edit)

    def _browse(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select .RMP snapshot",
            "",
            "RAMMap Snapshots (*.rmp *.RMP);;All files (*)",
        )
        if path:
            self._path_edit.setText(path)

    def validatePage(self) -> bool:
        p = Path(self.field("snapshot"))
        if not p.exists() or not p.is_file():
            QtWidgets.QMessageBox.critical(self, "Invalid file", "Snapshot file not found.")
            return False
        return True


class ViewPage(QtWidgets.QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Choose export view")

        self._combo = QtWidgets.QComboBox()
        for v in view_specs():
            self._combo.addItem(v.name)
            self._combo.setItemData(self._combo.count() - 1, v.description, QtCore.Qt.ItemDataRole.ToolTipRole)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self._combo)
        self.setLayout(layout)

        # Use a text-changed notifier so QWizard reliably updates the field value.
        self.registerField("view*", self._combo, "currentText", self._combo.currentTextChanged)

        # Some QWizard/PySide combinations don't populate a mandatory field
        # until the notify signal fires. If the default selection is used
        # without any user interaction, the page can incorrectly block Next.
        self._combo.currentIndexChanged.connect(self._sync_field)

    def initializePage(self) -> None:
        # Ensure the wizard sees a concrete value even if the user doesn't
        # touch the default selection.
        if self._combo.count() > 0 and self._combo.currentIndex() < 0:
            self._combo.setCurrentIndex(0)
        self._sync_field()

    def isComplete(self) -> bool:
        # Don't rely solely on QWizard's mandatory-field tracking for QComboBox.
        return bool(self._combo.currentText().strip())

    def _sync_field(self) -> None:
        self.setField("view", self._combo.currentText())
        self.completeChanged.emit()


class ExportPage(QtWidgets.QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Choose output CSV and export")

        self._out_edit = QtWidgets.QLineEdit()
        self._browse_btn = QtWidgets.QPushButton("Browse…")
        self._browse_btn.clicked.connect(self._browse_out)

        out_row = QtWidgets.QHBoxLayout()
        out_row.addWidget(self._out_edit)
        out_row.addWidget(self._browse_btn)

        self._run_btn = QtWidgets.QPushButton("Run export")
        self._run_btn.clicked.connect(self._run_export)

        self._status = QtWidgets.QLabel("")
        self._progress = QtWidgets.QProgressBar()
        self._progress.setRange(0, 1)
        self._log = QtWidgets.QPlainTextEdit()
        self._log.setReadOnly(True)

        layout = QtWidgets.QVBoxLayout()
        layout.addLayout(out_row)
        layout.addWidget(self._run_btn)
        layout.addWidget(self._status)
        layout.addWidget(self._progress)
        layout.addWidget(self._log)
        self.setLayout(layout)

        self.registerField("out_csv*", self._out_edit)

        self._thread: QtCore.QThread | None = None
        self._worker: ExportWorker | None = None
        self._done = False
        self._last_rc: int | None = None

    def initializePage(self) -> None:
        # If user hasn't chosen an output path yet, suggest one.
        if not self._out_edit.text().strip():
            snap = Path(self.wizard().field("snapshot"))
            view = str(self.wizard().field("view"))
            stem = snap.stem
            suggested = snap.parent / f"{stem}.{view}.csv"
            self._out_edit.setText(str(suggested))

        self._status.setText("")
        self._progress.setRange(0, 1)
        self._progress.setValue(0)
        self._log.clear()
        self._done = False
        self._last_rc = None
        self.completeChanged.emit()

    def isComplete(self) -> bool:
        # Enable Finish only after an export attempt completes.
        return bool(self._done)

    def _browse_out(self) -> None:
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save CSV as…",
            self._out_edit.text().strip() or "",
            "CSV files (*.csv);;All files (*)",
        )
        if path:
            self._out_edit.setText(path)

    def _append_log(self, line: str) -> None:
        self._log.appendPlainText(line)

    def _run_export(self) -> None:
        if self._thread is not None:
            return

        snap = Path(self.wizard().field("snapshot"))
        view = str(self.wizard().field("view"))
        out_text = self._out_edit.text().strip()
        out_csv = Path(out_text) if out_text else Path()

        if not snap.exists():
            QtWidgets.QMessageBox.critical(self, "Invalid file", "Snapshot file not found.")
            return
        if not out_text:
            QtWidgets.QMessageBox.critical(self, "Invalid output", "Output CSV path is required.")
            return

        self._status.setText("Exporting…")
        self._progress.setRange(0, 0)  # indeterminate
        self._run_btn.setEnabled(False)
        self._browse_btn.setEnabled(False)

        req = ExportRequest(snapshot=snap, view=view, out_csv=out_csv)
        # Keep strong references to avoid GC while the thread is running.
        worker = ExportWorker(req)
        thread = QtCore.QThread(self)
        worker.moveToThread(thread)

        worker.log_line.connect(self._append_log)
        worker.failed.connect(self._on_failed)
        worker.finished.connect(self._on_finished)

        thread.started.connect(worker.run)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        # Safety: if the thread exits unexpectedly without calling _on_finished,
        # restore UI state so the wizard doesn't get stuck on "Exporting…".
        thread.finished.connect(self._on_thread_finished)

        self._thread = thread
        self._worker = worker
        thread.start()

    def _on_failed(self, tb: str) -> None:
        self._append_log(tb)

    def _on_finished(self, rc: int) -> None:
        self._last_rc = int(rc)
        self._progress.setRange(0, 1)
        self._progress.setValue(1)

        if int(rc) == 0:
            self._status.setText("Done.")
        else:
            self._status.setText(f"Failed (exit code {int(rc)}).")

        self._run_btn.setEnabled(True)
        self._browse_btn.setEnabled(True)

        self._done = True
        self.completeChanged.emit()

        self._thread = None
        self._worker = None

    def _on_thread_finished(self) -> None:
        # If we still look like we're exporting, unwind UI state.
        if self._status.text() == "Exporting…" and not self._done:
            self._status.setText("Failed (export worker terminated).")
            self._progress.setRange(0, 1)
            self._progress.setValue(1)
            self._run_btn.setEnabled(True)
            self._browse_btn.setEnabled(True)
            self._done = True
            self.completeChanged.emit()

        self._thread = None
        self._worker = None


class ExportWizard(QtWidgets.QWizard):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("rmp2csv")

        self.addPage(SnapshotPage())
        self.addPage(ViewPage())
        self.addPage(ExportPage())

        self.setOption(QtWidgets.QWizard.NoBackButtonOnStartPage, True)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    _ = argv  # currently unused (reserved for future CLI flags)

    app = QtWidgets.QApplication(sys.argv)
    wiz = ExportWizard()
    wiz.resize(840, 520)
    wiz.show()
    return int(app.exec())


def gui() -> None:
    """Console-script entrypoint."""

    raise SystemExit(main())


if __name__ == "__main__":
    raise SystemExit(main())
