from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from dashboard_app.data_access import build_dashboard_payload
from dashboard_app.runtime_manager import RuntimeManager


REFRESH_INTERVAL_MS = 1000
EVEN_ROW = QColor("#121e31")
ODD_ROW = QColor("#0f1828")


class StatCard(QFrame):
    def __init__(self, title: str) -> None:
        super().__init__()
        self.setObjectName("StatCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)
        title_label = QLabel(title)
        title_label.setObjectName("StatLabel")
        self.value_label = QLabel("0")
        self.value_label.setObjectName("StatValue")
        self.note_label = QLabel("")
        self.note_label.setObjectName("StatNote")
        self.note_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.note_label)
        layout.addStretch()

    def set_value(self, value: str, note: str = "") -> None:
        self.value_label.setText(value)
        self.note_label.setText(note)


class PanelFrame(QFrame):
    def __init__(self, title: str, subtitle: str | None = None) -> None:
        super().__init__()
        self.setObjectName("Panel")
        self.outer_layout = QVBoxLayout(self)
        self.outer_layout.setContentsMargins(18, 18, 18, 18)
        self.outer_layout.setSpacing(14)
        header = QHBoxLayout()
        header.setSpacing(12)
        title_label = QLabel(title)
        title_label.setObjectName("PanelTitle")
        header.addWidget(title_label)
        header.addStretch()
        if subtitle:
            note = QLabel(subtitle)
            note.setObjectName("PanelNote")
            header.addWidget(note)
        self.outer_layout.addLayout(header)


class SummaryStrip(QFrame):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("Panel")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)
        self.items: dict[str, tuple[QLabel, QLabel]] = {}
        specs = [
            ("alerts", "Alerts"),
            ("packets", "Total Packets"),
            ("ml_analyzed", "ML Analyzed"),
            ("active_flows", "Active Flows"),
            ("cpu", "CPU"),
        ]
        for key, title in specs:
            item = QWidget()
            item.setObjectName("SummaryCell")
            item_layout = QHBoxLayout(item)
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(6)
            name_label = QLabel(f"{title}:")
            name_label.setObjectName("SummaryName")
            if key == "alerts":
                name_label.setProperty("tone", "alert")
            elif key == "ml_analyzed":
                name_label.setProperty("tone", "ml")
            value_label = QLabel("0")
            value_label.setObjectName("SummaryValue")
            item_layout.addWidget(name_label)
            item_layout.addWidget(value_label)
            item_layout.addStretch()
            self.items[key] = (name_label, value_label)
            layout.addWidget(item, 1)

    def set_values(self, values: dict[str, str]) -> None:
        for key, (_, value_label) in self.items.items():
            value_label.setText(values.get(key, "0"))


class SentinelFlowQtApp(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.runtime_manager = RuntimeManager(launcher_command=self._build_launcher_command())
        self.payload: dict = {}
        self.threat_items: list[dict] = []
        self.session_items: list[dict] = []

        self.setWindowTitle("ML Network Analyzer")
        self.resize(1560, 980)
        self.setMinimumSize(1320, 860)
        self._apply_stylesheet()
        self._build_ui()
        self.refresh_all()

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_all)
        self.refresh_timer.start(REFRESH_INTERVAL_MS)

    def _build_launcher_command(self) -> list[str]:
        if getattr(sys, "frozen", False):
            return [sys.executable]
        return [sys.executable, str(Path(__file__).resolve())]

    def _apply_stylesheet(self) -> None:
        self.setStyleSheet(
            """
            QWidget { background: #09111d; color: #edf3ff; font-family: "Segoe UI"; font-size: 10pt; }
            QMainWindow { background: #09111d; }
            QLabel#HeroTitle { font-size: 28pt; font-weight: 700; color: #f5f8ff; }
            QLabel#HeroSubtitle { color: #93a4bd; font-size: 10.5pt; }
            QFrame#Panel, QFrame#StatCard { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #131d31, stop:1 #10192a); border: 1px solid #22304b; border-radius: 20px; }
            QWidget#SummaryCell, QWidget#SectionBlock { background: transparent; }
            QLabel#PanelTitle { font-size: 12pt; font-weight: 600; color: #f5f8ff; background: transparent; }
            QLabel#PanelNote, QLabel#StatNote { color: #8ea1bc; font-size: 9pt; background: transparent; }
            QLabel#StatLabel { color: #7f96b8; font-size: 8.5pt; background: transparent; }
            QLabel#StatValue { font-size: 22pt; font-weight: 700; color: #f7fbff; background: transparent; }
            QLabel#SummaryName { color: #a9bad6; font-size: 12pt; font-weight: 600; background: transparent; }
            QLabel#SummaryName[tone="alert"] { color: #ef8b96; }
            QLabel#SummaryName[tone="ml"] { color: #e7c86b; }
            QLabel#SummaryValue { color: #f7fbff; font-size: 13pt; font-weight: 700; background: transparent; }
            QTabWidget::pane { border: none; }
            QTabBar::tab { background: #111a2b; color: #8ea1bc; border: 1px solid #22304b; border-bottom: none; border-top-left-radius: 14px; border-top-right-radius: 14px; padding: 12px 18px; margin-right: 8px; min-width: 130px; font-weight: 600; }
            QTabBar::tab:selected { background: #17233a; color: #f5f8ff; }
            QPushButton { background: #16233a; border: 1px solid #243654; border-radius: 14px; padding: 10px 16px; color: #eef5ff; font-weight: 600; }
            QPushButton:hover { background: #1a2a45; }
            QPushButton:disabled { background: #223047; color: #73839d; border: 1px solid #2b3b57; }
            QPushButton#PrimaryButton { background: #4fd1c5; color: #081117; border: none; }
            QPushButton#PrimaryButton:hover { background: #78e5dc; }
            QPushButton#PrimaryButton:disabled { background: #265f60; color: #9bb7b5; border: none; }
            QPushButton#DangerButton { background: #f36b7f; color: white; border: none; }
            QPushButton#DangerButton:hover { background: #ff8596; }
            QPushButton#DangerButton:disabled { background: #6f4550; color: #caaab2; border: none; }
            QComboBox, QLineEdit, QTextEdit { background: #0d1626; border: 1px solid #22304b; border-radius: 14px; padding: 10px 12px; color: #eef5ff; selection-background-color: #2b6d79; }
            QTableWidget { background: #0d1626; border: 1px solid #22304b; border-radius: 16px; gridline-color: #1a2740; selection-background-color: #285f6a; selection-color: #ffffff; }
            QHeaderView::section { background: #16233a; color: #eef5ff; padding: 10px 8px; border: none; border-right: 1px solid #22304b; font-weight: 600; }
            QScrollBar:vertical { background: transparent; width: 12px; margin: 8px 0 8px 0; }
            QScrollBar::handle:vertical { background: #2a3b5b; border-radius: 6px; min-height: 30px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
            QSplitter::handle { background: #0b1220; }
            """
        )

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(18)

        header = QHBoxLayout()
        title_wrap = QVBoxLayout()
        title = QLabel("ML Network Analyzer")
        title.setObjectName("HeroTitle")
        subtitle = QLabel("Live monitoring, ML detections, analysis jobs, and packet telemetry in one native Windows app.")
        subtitle.setObjectName("HeroSubtitle")
        title_wrap.addWidget(title)
        title_wrap.addWidget(subtitle)
        header.addLayout(title_wrap)
        header.addStretch()
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_all)
        header.addWidget(refresh_button)
        root.addLayout(header)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self.dashboard_tab = self._build_dashboard_tab()
        self.monitor_tab = self._build_monitor_tab()
        self.threats_tab = self._build_threats_tab()
        self.sessions_tab = self._build_sessions_tab()
        self.packets_tab = self._build_packets_tab()
        self.analysis_tab = self._build_analysis_tab()
        self.tabs.addTab(self.monitor_tab, "Monitoring")
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.threats_tab, "Threats")
        self.tabs.addTab(self.sessions_tab, "Sessions")
        self.tabs.addTab(self.packets_tab, "Packet Log")
        self.tabs.addTab(self.analysis_tab, "Analysis")

    def _build_dashboard_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(16)

        self.summary_strip = SummaryStrip()
        layout.addWidget(self.summary_strip)

        landscape = PanelFrame("Threat Landscape", "Recent detections and traffic shape")
        landscape_grid = QGridLayout()
        landscape_grid.setSpacing(12)
        self.family_text = self._make_text(read_only=True, max_height=110)
        self.protocol_text = self._make_text(read_only=True, max_height=110)
        self.sources_text = self._make_text(read_only=True, max_height=110)
        landscape_grid.addWidget(self._section_block("Attack Families", self.family_text), 0, 0)
        landscape_grid.addWidget(self._section_block("Protocol Mix", self.protocol_text), 0, 1)
        landscape_grid.addWidget(self._section_block("Top Sources", self.sources_text), 0, 2)
        landscape.outer_layout.addLayout(landscape_grid)
        layout.addWidget(landscape)

        threat_panel = PanelFrame("Recent Threat Traffic")
        self.recent_alerts_table = self._create_table(["Timestamp", "Family", "Severity", "Score", "Source", "Destination"])
        self._stretch_columns(self.recent_alerts_table, [0, 4, 5])
        threat_panel.outer_layout.addWidget(self.recent_alerts_table)
        layout.addWidget(threat_panel, 1)

        ml_panel = PanelFrame("Packets Sent to ML", "Why each flow was routed into the detection engine")
        self.ml_packets_table = self._create_table(["Timestamp", "Packets", "Protocol", "Source", "Destination", "Reason"])
        self._stretch_columns(self.ml_packets_table, [0, 3, 4, 5])
        ml_panel.outer_layout.addWidget(self.ml_packets_table)
        layout.addWidget(ml_panel, 1)
        return tab

    def _build_monitor_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(16)

        top = QHBoxLayout()
        top.setSpacing(16)

        controls = PanelFrame("Runtime Control")
        controls.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.interface_combo = QComboBox()
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.setObjectName("PrimaryButton")
        self.start_button.clicked.connect(self.start_monitor)
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setObjectName("DangerButton")
        self.stop_button.clicked.connect(self.stop_monitor)
        self.stop_button.setEnabled(False)
        controls.outer_layout.addWidget(self._label("Capture Interface"))
        controls.outer_layout.addWidget(self.interface_combo)
        button_row = QHBoxLayout()
        button_row.setSpacing(10)
        button_row.addWidget(self.start_button)
        button_row.addWidget(self.stop_button)
        button_row.addStretch()
        controls.outer_layout.addLayout(button_row)
        controls.outer_layout.addStretch()

        status = PanelFrame("Live Runtime Status")
        self.monitor_status_text = self._make_text(read_only=True)
        status.outer_layout.addWidget(self.monitor_status_text)
        top.addWidget(controls, 1)
        top.addWidget(status, 1)
        layout.addLayout(top)

        console = PanelFrame("Operator Console", "Live stdout from the monitoring worker")
        self.console_text = self._make_text(read_only=True)
        console.outer_layout.addWidget(self.console_text)
        layout.addWidget(console, 1)
        return tab

    def _build_threats_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 10, 0, 0)

        splitter = QSplitter(Qt.Horizontal)
        left = PanelFrame("Detected Malicious Traffic")
        self.threats_table = self._create_table(["Family", "Severity", "Score", "Confidence", "Source", "Destination"])
        self._stretch_columns(self.threats_table, [4, 5])
        self.threats_table.itemSelectionChanged.connect(self.on_threat_selected)
        left.outer_layout.addWidget(self.threats_table)

        right = PanelFrame("Threat Intelligence Detail")
        detail_grid = QGridLayout()
        detail_grid.setSpacing(12)
        self.threat_detail_labels: dict[str, QLabel] = {}
        details = [
            ("Attack Family", "family"),
            ("Severity", "severity"),
            ("Score", "score"),
            ("Confidence", "confidence"),
            ("Source", "source"),
            ("Destination", "destination"),
            ("Protocol", "protocol"),
            ("Capture Source", "source_name"),
            ("Models", "models"),
            ("Traffic Volume", "volume"),
        ]
        for index, (title, key) in enumerate(details):
            row = index // 2
            col = (index % 2) * 2
            detail_grid.addWidget(self._label(title), row, col)
            value = QLabel("-")
            value.setWordWrap(True)
            detail_grid.addWidget(value, row, col + 1)
            self.threat_detail_labels[key] = value
        right.outer_layout.addLayout(detail_grid)
        right.outer_layout.addWidget(self._label("Analyst Reasons"))
        self.threat_reasons_text = self._make_text(read_only=True, max_height=150)
        right.outer_layout.addWidget(self.threat_reasons_text)
        right.outer_layout.addWidget(self._label("Feature Summary"))
        self.threat_features_text = self._make_text(read_only=True)
        right.outer_layout.addWidget(self.threat_features_text, 1)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)
        return tab

    def _build_sessions_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 10, 0, 0)
        splitter = QSplitter(Qt.Horizontal)

        left = PanelFrame("Monitoring Session Archive")
        self.sessions_table = self._create_table(["Started", "Uptime", "Packets", "Threats", "Interface"])
        self._stretch_columns(self.sessions_table, [0, 4])
        self.sessions_table.itemSelectionChanged.connect(self.on_session_selected)
        left.outer_layout.addWidget(self.sessions_table)

        right = PanelFrame("Session Summary")
        self.session_detail_text = self._make_text(read_only=True)
        right.outer_layout.addWidget(self.session_detail_text)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)
        return tab

    def _build_packets_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 10, 0, 0)
        panel = PanelFrame("Live Packet Stream")
        self.packet_table = self._create_table(["Timestamp", "Protocol", "Bytes", "Source", "Destination", "Flags", "Capture"])
        self._stretch_columns(self.packet_table, [0, 3, 4, 6])
        panel.outer_layout.addWidget(self.packet_table)
        layout.addWidget(panel)
        return tab

    def _build_analysis_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(16)

        launcher = PanelFrame("Dataset Analysis Launcher")
        launcher.outer_layout.addWidget(self._label("Prepared Dataset"))
        self.dataset_combo = QComboBox()
        launcher.outer_layout.addWidget(self.dataset_combo)
        launcher.outer_layout.addWidget(self._label("Custom Dataset Path"))
        entry_row = QHBoxLayout()
        entry_row.setSpacing(12)
        self.dataset_path_input = QLineEdit()
        self.dataset_path_input.setPlaceholderText(r"C:\path\to\dataset.csv")
        self.run_analysis_button = QPushButton("Run Analysis Job")
        self.run_analysis_button.setObjectName("PrimaryButton")
        self.run_analysis_button.clicked.connect(self.start_analysis)
        entry_row.addWidget(self.dataset_path_input, 1)
        entry_row.addWidget(self.run_analysis_button)
        launcher.outer_layout.addLayout(entry_row)
        layout.addWidget(launcher)

        jobs = PanelFrame("Analysis Queue")
        self.jobs_table = self._create_table(["Dataset", "State", "Alerts", "Flows", "Exit"])
        self._stretch_columns(self.jobs_table, [0])
        jobs.outer_layout.addWidget(self.jobs_table)
        layout.addWidget(jobs, 1)
        return tab

    def _section_block(self, title: str, widget: QWidget) -> QWidget:
        frame = QWidget()
        frame.setObjectName("SectionBlock")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self._label(title))
        layout.addWidget(widget)
        return frame

    def _label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet("color:#4fd1c5;font-weight:600;font-size:10pt;background:transparent;")
        return label

    def _make_text(self, *, read_only: bool, max_height: int | None = None) -> QTextEdit:
        widget = QTextEdit()
        widget.setReadOnly(read_only)
        widget.setAcceptRichText(False)
        if max_height is not None:
            widget.setMaximumHeight(max_height)
        return widget

    def _create_table(self, headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setShowGrid(False)
        table.setWordWrap(False)
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setMinimumSectionSize(80)
        return table

    def _stretch_columns(self, table: QTableWidget, indexes: list[int]) -> None:
        header = table.horizontalHeader()
        for index in indexes:
            header.setSectionResizeMode(index, QHeaderView.ResizeMode.Stretch)

    def refresh_all(self) -> None:
        try:
            self.payload = build_dashboard_payload(self.runtime_manager)
            self._render_all()
        except Exception as exc:
            QMessageBox.critical(self, "SentinelFlow", str(exc))

    def _render_all(self) -> None:
        self._render_monitor()
        self._render_dashboard()
        self._render_threats()
        self._render_sessions()
        self._render_packets()
        self._render_analysis()

    def _render_monitor(self) -> None:
        monitor = self.payload.get("monitor", {})
        status = monitor.get("status") or {}
        interfaces = self.payload.get("interfaces", [])
        options = ["Auto-select busiest interface", *interfaces]

        current = self.interface_combo.currentText()
        self.interface_combo.clear()
        self.interface_combo.addItems(options)
        if current and current in options:
            self.interface_combo.setCurrentText(current)
        elif options:
            self.interface_combo.setCurrentIndex(0)

        running = bool(monitor.get("running"))
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)

        lines = [
            f"State: {'Running' if running else 'Idle'}",
            f"Target: {monitor.get('interface') or monitor.get('label') or 'Auto-select'}",
            f"PID: {monitor.get('pid') or '-'}",
            f"Started: {monitor.get('started_at') or '-'}",
            f"Uptime: {status.get('uptime') or '-'}",
            f"Analyzed packets: {status.get('analyzed_packets', 0)}",
            f"ML analyzed flows: {status.get('ml_analyzed_flows', 0)}",
            f"Completed flows: {status.get('completed_flows', 0)}",
            f"Alerts: {status.get('alerts', 0)}",
            f"Active flows: {status.get('active_flows', 0)}",
            f"CPU: {float(status.get('avg_cpu', 0) or 0):.1f}%",
            f"Memory: {float(status.get('avg_memory', 0) or 0):.1f}%",
        ]
        self.monitor_status_text.setPlainText("\n".join(lines))
        self.console_text.setPlainText("\n".join(monitor.get("output_tail", [])) or "Runtime console output will appear here.")

    def _render_dashboard(self) -> None:
        summary = self.payload.get("summary", {})
        monitor_status = self.payload.get("monitor", {}).get("status") or {}
        system = self.payload.get("system") or {}

        self.summary_strip.set_values(
            {
                "alerts": str(summary.get("total_alerts", 0)),
                "packets": str(monitor_status.get("analyzed_packets", 0)),
                "ml_analyzed": str(monitor_status.get("ml_analyzed_flows", 0)),
                "active_flows": str(monitor_status.get("active_flows", 0)),
                "cpu": f"{float(system.get('cpu_percent', 0) or 0):.1f}%",
            }
        )

        self.family_text.setPlainText(self._format_count_block(summary.get("family_counts", [])))
        self.protocol_text.setPlainText(self._format_count_block(summary.get("protocol_counts", [])))
        self.sources_text.setPlainText(self._format_count_block(summary.get("top_sources", [])))

        self._set_table_rows(
            self.recent_alerts_table,
            [
                [
                    alert.get("timestamp", ""),
                    alert.get("attack_family", ""),
                    alert.get("severity", ""),
                    f"{float(alert.get('score', 0.0) or 0):.4f}",
                    f"{alert.get('src_ip', '')}:{alert.get('src_port', '')}",
                    f"{alert.get('dst_ip', '')}:{alert.get('dst_port', '')}",
                ]
                for alert in self.payload.get("recent_alerts", [])
            ],
        )
        self._set_table_rows(
            self.ml_packets_table,
            [
                [
                    flow.get("timestamp", ""),
                    str(flow.get("packets", 0)),
                    flow.get("protocol", ""),
                    f"{flow.get('src_ip', '')}:{flow.get('src_port', '')}",
                    f"{flow.get('dst_ip', '')}:{flow.get('dst_port', '')}",
                    self._format_ml_reason(flow),
                ]
                for flow in self.payload.get("recent_ml_packets", [])
            ],
        )

    def _render_threats(self) -> None:
        alerts = self.payload.get("recent_alerts", [])
        self.threat_items = alerts
        self._set_table_rows(
            self.threats_table,
            [
                [
                    alert.get("attack_family", ""),
                    alert.get("severity", ""),
                    f"{float(alert.get('score', 0.0) or 0):.4f}",
                    f"{float(alert.get('confidence', 0.0) or 0):.3f}",
                    f"{alert.get('src_ip', '')}:{alert.get('src_port', '')}",
                    f"{alert.get('dst_ip', '')}:{alert.get('dst_port', '')}",
                ]
                for alert in alerts
            ],
        )
        if alerts:
            self.threats_table.selectRow(0)
            self._show_threat_detail(alerts[0])
        else:
            self._clear_threat_detail()

    def _render_sessions(self) -> None:
        sessions = self.payload.get("session_history", [])
        self.session_items = sessions
        self._set_table_rows(
            self.sessions_table,
            [
                [
                    session.get("started_at", ""),
                    session.get("uptime", ""),
                    str(session.get("total_packets", 0)),
                    str(session.get("total_threats", 0)),
                    session.get("label", ""),
                ]
                for session in sessions
            ],
        )
        if sessions:
            self.sessions_table.selectRow(0)
            self._show_session_detail(sessions[0])
        else:
            self.session_detail_text.setPlainText("No completed monitoring sessions archived yet.")

    def _render_packets(self) -> None:
        self._set_table_rows(
            self.packet_table,
            [
                [
                    packet.get("timestamp", ""),
                    packet.get("protocol", ""),
                    str(packet.get("size", 0)),
                    f"{packet.get('src_ip', '')}:{packet.get('src_port', '')}",
                    f"{packet.get('dst_ip', '')}:{packet.get('dst_port', '')}",
                    packet.get("tcp_flags") or "-",
                    packet.get("source_name") or packet.get("mode") or "-",
                ]
                for packet in self.payload.get("recent_packets", [])
            ],
        )

    def _render_analysis(self) -> None:
        datasets = self.payload.get("datasets", [])
        selected = self.dataset_combo.currentText()
        values = [f"{item['name']} | {item['path']}" for item in datasets]
        self.dataset_combo.clear()
        self.dataset_combo.addItems(values)
        if selected and selected in values:
            self.dataset_combo.setCurrentText(selected)

        self._set_table_rows(
            self.jobs_table,
            [
                [
                    job.get("label", ""),
                    "Running" if job.get("running") else ("Complete" if job.get("exit_code") == 0 else "Stopped"),
                    str((job.get("status") or {}).get("alerts", 0)),
                    str((job.get("status") or {}).get("completed_flows", 0)),
                    str(job.get("exit_code", "-")),
                ]
                for job in self.payload.get("analysis_jobs", [])
            ],
        )

    def _set_table_rows(self, table: QTableWidget, rows: list[list[str]]) -> None:
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            background = EVEN_ROW if row_index % 2 == 0 else ODD_ROW
            for col_index, value in enumerate(row):
                item = QTableWidgetItem(value)
                item.setBackground(background)
                table.setItem(row_index, col_index, item)
        if rows:
            table.resizeRowsToContents()

    def on_threat_selected(self) -> None:
        index = self.threats_table.currentRow()
        if 0 <= index < len(self.threat_items):
            self._show_threat_detail(self.threat_items[index])

    def on_session_selected(self) -> None:
        index = self.sessions_table.currentRow()
        if 0 <= index < len(self.session_items):
            self._show_session_detail(self.session_items[index])

    def _show_threat_detail(self, alert: dict) -> None:
        self.threat_detail_labels["family"].setText(str(alert.get("attack_family", "-")))
        self.threat_detail_labels["severity"].setText(str(alert.get("severity", "-")))
        self.threat_detail_labels["score"].setText(f"{float(alert.get('score', 0.0) or 0):.4f}")
        self.threat_detail_labels["confidence"].setText(f"{float(alert.get('confidence', 0.0) or 0):.3f}")
        self.threat_detail_labels["source"].setText(f"{alert.get('src_ip', '-') or '-'}:{alert.get('src_port', '-')}")
        self.threat_detail_labels["destination"].setText(f"{alert.get('dst_ip', '-') or '-'}:{alert.get('dst_port', '-')}")
        self.threat_detail_labels["protocol"].setText(str(alert.get("protocol", "-")))
        self.threat_detail_labels["source_name"].setText(str(alert.get("source_name", "-")))
        self.threat_detail_labels["models"].setText(f"{alert.get('binary_model_name', '-')} | {alert.get('multiclass_model_name', '-')}")
        self.threat_detail_labels["volume"].setText(f"{alert.get('packets', 0)} packets / {alert.get('bytes', 0)} bytes")
        self.threat_reasons_text.setPlainText("\n".join(f"- {reason}" for reason in alert.get("reasons", [])) or "No reasons available.")
        features = alert.get("features") or {}
        self.threat_features_text.setPlainText("\n".join(f"{key}: {value}" for key, value in sorted(features.items())) or "No feature data available.")

    def _clear_threat_detail(self) -> None:
        for label in self.threat_detail_labels.values():
            label.setText("-")
        self.threat_reasons_text.setPlainText("No active threat selected.")
        self.threat_features_text.setPlainText("No active threat selected.")

    def _show_session_detail(self, session: dict) -> None:
        lines = [
            f"Session ID: {session.get('session_id', '-')}",
            f"Started: {session.get('started_at', '-')}",
            f"Stopped: {session.get('stopped_at', '-')}",
            f"Interface: {session.get('label', '-')}",
            f"Uptime: {session.get('uptime', '-')}",
            f"Total packets: {session.get('total_packets', 0)}",
            f"ML analyzed flows: {session.get('ml_analyzed_flows', 0)}",
            f"Completed flows: {session.get('completed_flows', 0)}",
            f"Total threats: {session.get('total_threats', 0)}",
            f"Average CPU: {float(session.get('avg_cpu', 0) or 0):.1f}%",
            f"Average memory: {float(session.get('avg_memory', 0) or 0):.1f}%",
            "",
            "Top attack families:",
        ]
        for item in session.get("top_attack_families", []):
            lines.append(f"- {item.get('label', 'unknown')}: {item.get('count', 0)}")
        lines.append("")
        lines.append("Severity breakdown:")
        for item in session.get("severity_breakdown", []):
            lines.append(f"- {item.get('label', 'unknown')}: {item.get('count', 0)}")
        self.session_detail_text.setPlainText("\n".join(lines))

    def _format_count_block(self, rows: list[dict]) -> str:
        if not rows:
            return "No recent data."
        return "\n".join(f"{row.get('label', 'unknown')}: {row.get('count', 0)}" for row in rows)

    def _format_ml_reason(self, flow: dict) -> str:
        reason = str(flow.get("decision_reason") or "candidate for detection")
        tags = [str(tag).replace("_", " ") for tag in (flow.get("features") or {}).get("filter_tags", [])]
        if tags:
            return f"{reason} | tags: {', '.join(tags[:4])}"
        return reason

    def start_monitor(self) -> None:
        try:
            interface = self.interface_combo.currentText()
            if interface == "Auto-select busiest interface":
                interface = None
            self.runtime_manager.start_monitor(interface=interface)
            self.refresh_all()
        except Exception as exc:
            QMessageBox.critical(self, "SentinelFlow", str(exc))

    def stop_monitor(self) -> None:
        try:
            self.runtime_manager.stop_monitor()
            self.refresh_all()
        except Exception as exc:
            QMessageBox.critical(self, "SentinelFlow", str(exc))

    def start_analysis(self) -> None:
        try:
            dataset_path = self.dataset_path_input.text().strip()
            if not dataset_path:
                selected = self.dataset_combo.currentText().split("|", 1)
                dataset_path = selected[1].strip() if len(selected) == 2 else ""
            if not dataset_path:
                raise ValueError("Choose a prepared dataset or enter a custom path.")
            self.runtime_manager.start_analysis(dataset_path=dataset_path)
            self.refresh_all()
        except Exception as exc:
            QMessageBox.critical(self, "SentinelFlow", str(exc))


def run_monitor_worker() -> None:
    from main import main as monitor_main

    monitor_main()


def run_analysis_worker(dataset_path: str) -> None:
    from dataset_main import main as analysis_main

    sys.argv = [sys.argv[0], dataset_path]
    analysis_main()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SentinelFlow desktop app")
    parser.add_argument("--worker", choices=["monitor", "analysis"])
    parser.add_argument("--dataset")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.worker == "monitor":
        run_monitor_worker()
        return
    if args.worker == "analysis":
        if not args.dataset:
            raise SystemExit("--dataset is required for analysis worker mode")
        run_analysis_worker(args.dataset)
        return

    app = QApplication(sys.argv)
    window = SentinelFlowQtApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
