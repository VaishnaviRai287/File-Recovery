"""
gui/forensic_gui.py  — PyQt6 Forensic Investigation Dashboard
"""
import sys
import json
import logging
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QPushButton, QLabel, QLineEdit, QFileDialog,
        QTableWidget, QTableWidgetItem, QTextEdit, QProgressBar,
        QComboBox, QGroupBox, QFormLayout, QSplitter, QFrame,
        QHeaderView, QMessageBox, QStatusBar,
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QFont, QColor, QPalette, QIcon
    PYQT_VERSION = 6
except ImportError:
    try:
        from PyQt5.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QTabWidget, QPushButton, QLabel, QLineEdit, QFileDialog,
            QTableWidget, QTableWidgetItem, QTextEdit, QProgressBar,
            QComboBox, QGroupBox, QFormLayout, QSplitter, QFrame,
            QHeaderView, QMessageBox, QStatusBar,
        )
        from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
        from PyQt5.QtGui import QFont, QColor, QPalette, QIcon
        PYQT_VERSION = 5
    except ImportError:
        print("ERROR: PyQt6 or PyQt5 required. Install with: pip install PyQt6")
        sys.exit(1)

logger = logging.getLogger(__name__)

# ── Dark forensic stylesheet ─────────────────────────────────────────────────
DARK_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #0f1923;
    color: #e8f4fd;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 13px;
}
QTabWidget::pane {
    border: 1px solid #2a3d52;
    background: #1e2d3d;
    border-radius: 4px;
}
QTabBar::tab {
    background: #1a2332;
    color: #8899aa;
    padding: 8px 20px;
    border: 1px solid #2a3d52;
    border-bottom: none;
    border-radius: 4px 4px 0 0;
    font-size: 12px;
    letter-spacing: 1px;
}
QTabBar::tab:selected {
    background: #1e2d3d;
    color: #00d4aa;
    border-bottom: 2px solid #00d4aa;
}
QPushButton {
    background: linear-gradient(135deg, #00d4aa, #00b894);
    color: #0f1923;
    border: none;
    padding: 8px 20px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 12px;
    letter-spacing: 1px;
}
QPushButton:hover { background: #00e5bb; }
QPushButton:pressed { background: #00b894; }
QPushButton:disabled { background: #2a3d52; color: #8899aa; }
QPushButton#dangerBtn {
    background: linear-gradient(135deg, #ff4757, #c0392b);
    color: white;
}
QPushButton#secondaryBtn {
    background: #1a2332;
    color: #00d4aa;
    border: 1px solid #00d4aa;
}
QLineEdit, QComboBox {
    background: #1a2332;
    border: 1px solid #2a3d52;
    border-radius: 4px;
    padding: 6px 10px;
    color: #e8f4fd;
}
QLineEdit:focus, QComboBox:focus { border-color: #00d4aa; }
QGroupBox {
    border: 1px solid #2a3d52;
    border-radius: 6px;
    margin-top: 1em;
    padding-top: 0.5em;
    color: #00d4aa;
    font-weight: bold;
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
}
QTableWidget {
    background: #1a2332;
    gridline-color: #2a3d52;
    border: none;
    alternate-background-color: #1e2d3d;
}
QTableWidget::item { padding: 4px 8px; }
QTableWidget::item:selected { background: #00d4aa22; color: #00d4aa; }
QHeaderView::section {
    background: #0f1923;
    color: #00d4aa;
    padding: 6px 8px;
    border: none;
    border-bottom: 2px solid #00d4aa;
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
}
QTextEdit {
    background: #1a2332;
    border: 1px solid #2a3d52;
    border-radius: 4px;
    color: #00d4aa;
    font-family: 'Courier New', monospace;
    font-size: 11px;
}
QProgressBar {
    border: 1px solid #2a3d52;
    border-radius: 4px;
    background: #1a2332;
    text-align: center;
    height: 18px;
}
QProgressBar::chunk { background: #00d4aa; border-radius: 3px; }
QStatusBar {
    background: #0f1923;
    color: #8899aa;
    border-top: 1px solid #2a3d52;
}
QLabel#statValue {
    color: #00d4aa;
    font-size: 24px;
    font-weight: bold;
}
QLabel#statLabel {
    color: #8899aa;
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
}
QLabel#headerLabel {
    color: #00d4aa;
    font-size: 18px;
    font-weight: bold;
    letter-spacing: 2px;
}
QFrame#separator {
    color: #2a3d52;
    background: #2a3d52;
}
"""


class InvestigationWorker(QThread):
    """Background thread for running forensic investigations without freezing the GUI."""
    progress = pyqtSignal(str)       # Log message
    finished = pyqtSignal(object)    # InvestigationResult
    error = pyqtSignal(str)          # Error message

    def __init__(self, image_path, case_id, examiner, output_dir, fs_type=None):
        super().__init__()
        self.image_path = image_path
        self.case_id = case_id
        self.examiner = examiner
        self.output_dir = output_dir
        self.fs_type = fs_type

    def run(self):
        try:
            from core.recovery_engine import RecoveryEngine

            class QLogHandler(logging.Handler):
                def __init__(self, signal): self.signal = signal; super().__init__()
                def emit(self, record): self.signal.emit(self.format(record))

            handler = QLogHandler(self.progress)
            handler.setFormatter(logging.Formatter("%(levelname)s | %(message)s"))
            root_logger = logging.getLogger()
            root_logger.addHandler(handler)

            engine = RecoveryEngine(self.case_id, self.examiner, self.output_dir)
            result = engine.investigate(self.image_path, filesystem_type=self.fs_type or None)

            root_logger.removeHandler(handler)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class StatCard(QWidget):
    """A stat card widget showing a large number and a label."""
    def __init__(self, value: str, label: str, color: str = "#00d4aa"):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter if PYQT_VERSION == 6 else Qt.AlignCenter)

        val_label = QLabel(value)
        val_label.setObjectName("statValue")
        val_label.setStyleSheet(f"color: {color}; font-size: 26px; font-weight: bold;")
        val_label.setAlignment(Qt.AlignmentFlag.AlignCenter if PYQT_VERSION == 6 else Qt.AlignCenter)

        lbl = QLabel(label.upper())
        lbl.setObjectName("statLabel")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter if PYQT_VERSION == 6 else Qt.AlignCenter)

        layout.addWidget(val_label)
        layout.addWidget(lbl)

        self.setStyleSheet("""
            background: #1a2332;
            border: 1px solid #2a3d52;
            border-radius: 8px;
            padding: 12px;
        """)
        self.val_label = val_label

    def update_value(self, value: str):
        self.val_label.setText(value)


class EvidenceTab(QWidget):
    """Tab for loading and registering forensic evidence."""
    scan_requested = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # Header
        hdr = QLabel("🔍 EVIDENCE LOADER")
        hdr.setObjectName("headerLabel")
        layout.addWidget(hdr)

        # Image group
        img_group = QGroupBox("Forensic Image")
        img_layout = QFormLayout(img_group)

        self.image_path_edit = QLineEdit()
        self.image_path_edit.setPlaceholderText("Path to forensic image (.dd, .img, .raw, .e01)")
        browse_btn = QPushButton("Browse…")
        browse_btn.setObjectName("secondaryBtn")
        browse_btn.clicked.connect(self._browse_image)

        path_row = QHBoxLayout()
        path_row.addWidget(self.image_path_edit)
        path_row.addWidget(browse_btn)
        img_layout.addRow("Image File:", path_row)

        self.fs_combo = QComboBox()
        self.fs_combo.addItems(["Auto-Detect", "ntfs", "ext4", "xfs"])
        img_layout.addRow("Filesystem:", self.fs_combo)

        layout.addWidget(img_group)

        # Case group
        case_group = QGroupBox("Case Information")
        case_layout = QFormLayout(case_group)

        self.case_id_edit = QLineEdit()
        self.case_id_edit.setPlaceholderText("e.g. IR-2024-042")
        case_layout.addRow("Case ID:", self.case_id_edit)

        self.examiner_edit = QLineEdit()
        self.examiner_edit.setPlaceholderText("Full name of forensic examiner")
        case_layout.addRow("Examiner:", self.examiner_edit)

        self.output_edit = QLineEdit("./reports")
        output_browse = QPushButton("Browse…")
        output_browse.setObjectName("secondaryBtn")
        output_browse.clicked.connect(self._browse_output)
        output_row = QHBoxLayout()
        output_row.addWidget(self.output_edit)
        output_row.addWidget(output_browse)
        case_layout.addRow("Output Dir:", output_row)

        layout.addWidget(case_group)

        # Scan button
        self.scan_btn = QPushButton("🚀  START FORENSIC INVESTIGATION")
        self.scan_btn.clicked.connect(self._on_scan)
        self.scan_btn.setMinimumHeight(44)
        layout.addWidget(self.scan_btn)

        layout.addStretch()

    def _browse_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Forensic Image", "",
            "Forensic Images (*.dd *.img *.raw *.bin *.e01);;All Files (*)"
        )
        if path:
            self.image_path_edit.setText(path)

    def _browse_output(self):
        path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if path:
            self.output_edit.setText(path)

    def _on_scan(self):
        if not self.image_path_edit.text():
            QMessageBox.warning(self, "Missing Input", "Please select a forensic image file.")
            return
        if not self.case_id_edit.text():
            QMessageBox.warning(self, "Missing Input", "Please enter a Case ID.")
            return
        if not self.examiner_edit.text():
            QMessageBox.warning(self, "Missing Input", "Please enter the examiner name.")
            return

        fs = self.fs_combo.currentText()
        self.scan_requested.emit({
            "image": self.image_path_edit.text(),
            "case_id": self.case_id_edit.text(),
            "examiner": self.examiner_edit.text(),
            "output": self.output_edit.text(),
            "fs_type": None if fs == "Auto-Detect" else fs,
        })


class ResultsTab(QWidget):
    """Tab showing recovered artifacts in a filterable table."""

    def __init__(self):
        super().__init__()
        self._result = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # Stats row
        stats_row = QHBoxLayout()
        self.stat_deleted = StatCard("—", "Deleted Found")
        self.stat_recovered = StatCard("—", "Recovered", "#2ed573")
        self.stat_rate = StatCard("—", "Recovery Rate")
        self.stat_duration = StatCard("—", "Duration (s)", "#ffa502")
        for card in [self.stat_deleted, self.stat_recovered, self.stat_rate, self.stat_duration]:
            stats_row.addWidget(card)
        layout.addLayout(stats_row)

        # Filter bar
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by filename, type, confidence…")
        self.filter_edit.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self.filter_edit)
        self.recovered_only = QPushButton("Show Recovered Only")
        self.recovered_only.setObjectName("secondaryBtn")
        self.recovered_only.setCheckable(True)
        self.recovered_only.toggled.connect(self._apply_filter)
        filter_row.addWidget(self.recovered_only)
        layout.addLayout(filter_row)

        # Table
        self.table = QTableWidget()
        cols = ["#", "ID", "Filename", "FS", "Size (bytes)", "Modified",
                "MIME Type", "Confidence", "Recovered", "SHA256"]
        self.table.setColumnCount(len(cols))
        self.table.setHorizontalHeaderLabels(cols)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch if PYQT_VERSION == 6 else QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows if PYQT_VERSION == 6 else QTableWidget.SelectRows)
        self.table.setSortingEnabled(True)
        layout.addWidget(self.table)

    def load_result(self, result):
        self._result = result
        self.stat_deleted.update_value(str(result.total_deleted_found))
        self.stat_recovered.update_value(str(result.total_recovered))
        self.stat_rate.update_value(f"{result.recovery_rate:.1%}")
        self.stat_duration.update_value(f"{result.duration_seconds:.1f}")
        self._populate_table(result.artifacts)

    def _populate_table(self, artifacts):
        self.table.setRowCount(0)
        filter_text = self.filter_edit.text().lower() if hasattr(self, 'filter_edit') else ""
        recovered_only = self.recovered_only.isChecked() if hasattr(self, 'recovered_only') else False

        row_idx = 0
        for i, art in enumerate(artifacts):
            m = art.metadata
            name = m.filename or f"inode:{m.identifier}"
            if filter_text and filter_text not in name.lower() and filter_text not in m.mime_type.lower():
                continue
            if recovered_only and not art.recovered:
                continue

            self.table.insertRow(row_idx)
            cells = [
                str(i + 1), m.identifier, name, m.filesystem_type.upper(),
                f"{m.size_bytes:,}",
                m.modified.strftime("%Y-%m-%d %H:%M") if m.modified else "—",
                m.mime_type, m.recovery_confidence,
                "✓ YES" if art.recovered else "✗ NO",
                art.sha256[:16] + "…" if art.sha256 else "—",
            ]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(val)
                if col == 8:  # Recovered
                    item.setForeground(QColor("#2ed573") if art.recovered else QColor("#8899aa"))
                if col == 7:  # Confidence
                    colors = {"high": "#2ed573", "medium": "#ffa502", "low": "#ff4757"}
                    item.setForeground(QColor(colors.get(val, "#e8f4fd")))
                self.table.setItem(row_idx, col, item)
            row_idx += 1

    def _apply_filter(self):
        if self._result:
            self._populate_table(self._result.artifacts)


class LogTab(QWidget):
    """Tab showing live investigation log."""

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Live Investigation Log"))
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        layout.addWidget(self.log_view)
        clear_btn = QPushButton("Clear Log")
        clear_btn.setObjectName("secondaryBtn")
        clear_btn.clicked.connect(self.log_view.clear)
        layout.addWidget(clear_btn)

    def append(self, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        color = "#ff4757" if "ERROR" in message or "CRITICAL" in message else \
                "#ffa502" if "WARNING" in message else "#00d4aa"
        self.log_view.append(f'<span style="color:{color}">[{ts}] {message}</span>')
        self.log_view.verticalScrollBar().setValue(
            self.log_view.verticalScrollBar().maximum()
        )


class TimelineTab(QWidget):
    """Tab showing forensic timeline."""

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("🕒 FORENSIC TIMELINE"))
        self.table = QTableWidget()
        cols = ["Timestamp", "Event Type", "Artifact", "Filesystem", "Size (bytes)"]
        self.table.setColumnCount(len(cols))
        self.table.setHorizontalHeaderLabels(cols)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch if PYQT_VERSION == 6 else QHeaderView.Stretch
        )
        layout.addWidget(self.table)

    def load_timeline(self, events):
        self.table.setRowCount(0)
        for i, ev in enumerate(events):
            self.table.insertRow(i)
            for col, val in enumerate([
                ev.get("timestamp", ""), ev.get("event_type", ""),
                ev.get("artifact", ""), ev.get("filesystem", ""),
                str(ev.get("size_bytes", 0)),
            ]):
                self.table.setItem(i, col, QTableWidgetItem(val))


class MainWindow(QMainWindow):
    """Main forensic dashboard window."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"🔍 Deleted File Recovery Forensics Tool — NTFS | EXT4 | XFS")
        self.setMinimumSize(1200, 800)
        self._worker = None
        self._result = None
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Title bar
        title_bar = QWidget()
        title_bar.setStyleSheet("background: #1a2332; border-bottom: 2px solid #00d4aa;")
        title_layout = QHBoxLayout(title_bar)
        title_lbl = QLabel("🔍  DFIR FORENSICS PLATFORM  |  NTFS · EXT4 · XFS")
        title_lbl.setStyleSheet("color: #00d4aa; font-size: 14px; font-weight: bold; letter-spacing: 2px;")
        version_lbl = QLabel("v1.0.0  |  CONFIDENTIAL")
        version_lbl.setStyleSheet("color: #8899aa; font-size: 11px;")
        title_layout.addWidget(title_lbl)
        title_layout.addStretch()
        title_layout.addWidget(version_lbl)
        main_layout.addWidget(title_bar)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        main_layout.addWidget(self.progress_bar)

        # Tabs
        self.tabs = QTabWidget()
        self.evidence_tab = EvidenceTab()
        self.results_tab = ResultsTab()
        self.log_tab = LogTab()
        self.timeline_tab = TimelineTab()

        self.tabs.addTab(self.evidence_tab, "📁  Evidence")
        self.tabs.addTab(self.results_tab, "🗂  Artifacts")
        self.tabs.addTab(self.timeline_tab, "🕒  Timeline")
        self.tabs.addTab(self.log_tab, "📋  Log")

        main_layout.addWidget(self.tabs)

        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Ready — Load a forensic image to begin investigation")

        # Connect signals
        self.evidence_tab.scan_requested.connect(self._on_scan_requested)

    def _on_scan_requested(self, params: dict):
        """Start investigation in background thread."""
        self.progress_bar.setVisible(True)
        self.status.showMessage(f"Investigation in progress: {params['image']}")
        self.evidence_tab.scan_btn.setEnabled(False)
        self.log_tab.append(f"Starting investigation: {params['image']}")
        self.tabs.setCurrentWidget(self.log_tab)

        self._worker = InvestigationWorker(
            image_path=params["image"],
            case_id=params["case_id"],
            examiner=params["examiner"],
            output_dir=params["output"],
            fs_type=params["fs_type"],
        )
        self._worker.progress.connect(self.log_tab.append)
        self._worker.finished.connect(self._on_investigation_complete)
        self._worker.error.connect(self._on_investigation_error)
        self._worker.start()

    def _on_investigation_complete(self, result):
        """Handle completed investigation."""
        self._result = result
        self.progress_bar.setVisible(False)
        self.evidence_tab.scan_btn.setEnabled(True)
        self.results_tab.load_result(result)
        self.timeline_tab.load_timeline(result.timeline)
        self.tabs.setCurrentWidget(self.results_tab)
        self.status.showMessage(
            f"✓ Complete — {result.total_recovered}/{result.total_deleted_found} files recovered "
            f"({result.duration_seconds:.1f}s)"
        )
        self.log_tab.append(
            f"Investigation complete: {result.total_recovered} recovered / "
            f"{result.total_deleted_found} found"
        )
        # Auto-generate HTML report
        try:
            from core.report_generator import ReportGenerator
            reporter = ReportGenerator(result.image_info.get("path", "./reports"))
            paths = reporter.generate(result, ["html"])
            html_path = paths.get("html")
            if html_path:
                self.log_tab.append(f"HTML report: {html_path}")
        except Exception as e:
            self.log_tab.append(f"Report generation error: {e}")

    def _on_investigation_error(self, error_msg: str):
        self.progress_bar.setVisible(False)
        self.evidence_tab.scan_btn.setEnabled(True)
        self.status.showMessage(f"✗ Error: {error_msg}")
        self.log_tab.append(f"ERROR: {error_msg}")
        QMessageBox.critical(self, "Investigation Error", error_msg)


def launch_gui():
    """Launch the forensic GUI application."""
    app = QApplication(sys.argv)
    app.setApplicationName("DFIR Forensics Platform")
    app.setStyleSheet(DARK_STYLESHEET)
    window = MainWindow()
    window.show()
    sys.exit(app.exec() if PYQT_VERSION == 6 else app.exec_())


if __name__ == "__main__":
    launch_gui()
