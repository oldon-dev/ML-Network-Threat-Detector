from __future__ import annotations

import argparse
import json
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from dashboard_app.data_access import build_dashboard_payload
from dashboard_app.runtime_manager import RuntimeManager


REFRESH_INTERVAL_MS = 2500


class SentinelFlowDesktopApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        launcher = self._build_launcher_command()
        self.runtime_manager = RuntimeManager(launcher_command=launcher)
        self.payload: dict = {}
        self.threats_tree_items: list[dict] = []
        self._refresh_after_id: str | None = None
        self.title("SentinelFlow Desktop Console")
        self.geometry("1540x960")
        self.minsize(1280, 820)
        self.configure(bg="#0b1220")
        self.option_add("*Font", "{Segoe UI} 10")
        self.option_add("*tearOff", False)

        self._configure_style()
        self._build_layout()
        self.refresh_all()
        self._schedule_refresh()

    def _build_launcher_command(self) -> list[str]:
        if getattr(sys, "frozen", False):
            return [sys.executable]
        return [sys.executable, str(Path(__file__).resolve())]

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        bg = "#0b1220"
        panel = "#121a2b"
        panel_alt = "#172133"
        field = "#0f1726"
        edge = "#22314d"
        text = "#edf4ff"
        muted = "#93a4bd"
        accent = "#4fd1c5"
        accent_hover = "#7ce6dc"
        danger = "#f36b7f"
        selection = "#1f6f78"

        style.configure(".", background=bg, foreground=text, fieldbackground=field)
        style.configure("TFrame", background=bg)
        style.configure("Card.TFrame", background=panel_alt, relief="flat")

        style.configure("TNotebook", background=bg, borderwidth=0, tabmargins=(0, 0, 0, 10))
        style.configure(
            "TNotebook.Tab",
            background=panel,
            foreground=muted,
            padding=(18, 12),
            borderwidth=0,
            font=("{Segoe UI Semibold}", 10),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", panel_alt), ("active", "#16233a")],
            foreground=[("selected", text), ("active", text)],
        )

        style.configure("TLabelframe", background=bg, borderwidth=1, relief="solid", bordercolor=edge)
        style.configure(
            "TLabelframe.Label",
            background=bg,
            foreground=text,
            font=("{Segoe UI Semibold}", 11),
            padding=(2, 0, 2, 8),
        )
        style.configure("TLabel", background=bg, foreground=text)
        style.configure("Muted.TLabel", background=bg, foreground=muted, font=("{Segoe UI}", 10))
        style.configure("Hero.TLabel", background=bg, font=("{Segoe UI Semibold}", 27), foreground=text)
        style.configure("Section.TLabel", background=bg, font=("{Segoe UI Semibold}", 10), foreground=accent)
        style.configure("Value.TLabel", background=panel_alt, font=("{Segoe UI Semibold}", 22), foreground=text)

        style.configure(
            "TButton",
            background=panel_alt,
            foreground=text,
            padding=(16, 10),
            borderwidth=0,
            focusthickness=0,
            font=("{Segoe UI Semibold}", 10),
        )
        style.map("TButton", background=[("active", "#22314a")], foreground=[("disabled", "#5e708a")])
        style.configure("Primary.TButton", background=accent, foreground="#081117")
        style.map("Primary.TButton", background=[("active", accent_hover), ("disabled", "#2f6a68")])
        style.configure("Danger.TButton", background=danger, foreground="#ffffff")
        style.map("Danger.TButton", background=[("active", "#ff8596"), ("disabled", "#7b4750")])

        style.configure(
            "TCombobox",
            fieldbackground=field,
            background=panel_alt,
            foreground=text,
            bordercolor=edge,
            lightcolor=edge,
            darkcolor=edge,
            arrowsize=16,
            padding=8,
        )
        style.map("TCombobox", fieldbackground=[("readonly", field)], selectbackground=[("readonly", field)])
        style.configure(
            "TEntry",
            fieldbackground=field,
            foreground=text,
            bordercolor=edge,
            lightcolor=edge,
            darkcolor=edge,
            insertcolor=text,
            padding=8,
        )
        style.configure(
            "Vertical.TScrollbar",
            background=panel_alt,
            troughcolor=bg,
            bordercolor=bg,
            arrowcolor=muted,
            darkcolor=panel_alt,
            lightcolor=panel_alt,
        )

        style.configure(
            "Treeview",
            background=field,
            fieldbackground=field,
            foreground=text,
            rowheight=34,
            borderwidth=0,
            relief="flat",
            font=("{Segoe UI}", 10),
        )
        style.map("Treeview", background=[("selected", selection)], foreground=[("selected", "#ffffff")])
        style.configure(
            "Treeview.Heading",
            background=panel_alt,
            foreground=text,
            borderwidth=0,
            relief="flat",
            font=("{Segoe UI Semibold}", 10),
            padding=(10, 10),
        )
        style.map("Treeview.Heading", background=[("active", "#22314a")])

    def _build_layout(self) -> None:
        container = ttk.Frame(self, padding=22)
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(1, weight=1)

        header = ttk.Frame(container)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text="SentinelFlow Desktop Command Console", style="Hero.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="Live network telemetry, ML detections, and analyst workflow in a cleaner local control surface.",
            style="Muted.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(6, 0))

        action_bar = ttk.Frame(header)
        action_bar.grid(row=0, column=1, rowspan=2, sticky="e")
        ttk.Button(action_bar, text="Refresh", command=self.refresh_all).pack(side="left", padx=6)

        self.notebook = ttk.Notebook(container)
        self.notebook.grid(row=1, column=0, sticky="nsew")

        self.monitor_tab = ttk.Frame(self.notebook, padding=16)
        self.analysis_tab = ttk.Frame(self.notebook, padding=16)
        self.dashboard_tab = ttk.Frame(self.notebook, padding=16)
        self.threats_tab = ttk.Frame(self.notebook, padding=16)
        self.sessions_tab = ttk.Frame(self.notebook, padding=16)
        self.log_tab = ttk.Frame(self.notebook, padding=16)

        self.notebook.add(self.monitor_tab, text="Monitoring Control")
        self.notebook.add(self.analysis_tab, text="Analysis Jobs")
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.notebook.add(self.threats_tab, text="Threats")
        self.notebook.add(self.sessions_tab, text="Session Logs")
        self.notebook.add(self.log_tab, text="Live Packet Log")

        self._build_monitor_tab()
        self._build_analysis_tab()
        self._build_dashboard_tab()
        self._build_threats_tab()
        self._build_sessions_tab()
        self._build_log_tab()
        self._apply_text_widget_styles()

    def _apply_text_widget_styles(self) -> None:
        common_text = {
            "bg": "#0f1726",
            "fg": "#edf4ff",
            "insertbackground": "#edf4ff",
            "relief": "flat",
            "bd": 0,
            "highlightthickness": 1,
            "highlightbackground": "#22314d",
            "highlightcolor": "#4fd1c5",
            "padx": 12,
            "pady": 12,
            "font": ("Consolas", 10),
        }
        console_text = {
            **common_text,
            "bg": "#0a1020",
            "fg": "#b9fff6",
            "insertbackground": "#b9fff6",
        }
        for widget in [
            self.monitor_status_text,
            self.threat_reasons_text,
            self.threat_features_text,
            self.session_detail_text,
        ]:
            widget.configure(**common_text)
        self.console_text.configure(**console_text)

    def _build_monitor_tab(self) -> None:
        self.monitor_tab.columnconfigure(0, weight=1)
        self.monitor_tab.columnconfigure(1, weight=1)
        self.monitor_tab.rowconfigure(1, weight=1)

        controls = ttk.LabelFrame(self.monitor_tab, text="Runtime Control", padding=14)
        controls.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=(0, 10))
        controls.columnconfigure(0, weight=1)

        ttk.Label(controls, text="Capture Interface", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(controls, textvariable=self.interface_var, state="readonly")
        self.interface_combo.grid(row=1, column=0, sticky="ew", pady=(8, 12))

        button_row = ttk.Frame(controls)
        button_row.grid(row=2, column=0, sticky="ew")
        ttk.Button(button_row, text="Start Monitoring", style="Primary.TButton", command=self.start_monitor).pack(side="left", padx=(0, 8))
        ttk.Button(button_row, text="Stop Monitoring", style="Danger.TButton", command=self.stop_monitor).pack(side="left")

        status_frame = ttk.LabelFrame(self.monitor_tab, text="Live Runtime Status", padding=14)
        status_frame.grid(row=0, column=1, sticky="nsew", padx=(8, 0), pady=(0, 10))
        status_frame.columnconfigure(0, weight=1)
        self.monitor_status_text = tk.Text(status_frame, height=12, bg="#081117", fg="#d6fff4", insertbackground="#66f7c6", relief="flat")
        self.monitor_status_text.grid(row=0, column=0, sticky="nsew")

        console_frame = ttk.LabelFrame(self.monitor_tab, text="Operator Console", padding=14)
        console_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
        console_frame.columnconfigure(0, weight=1)
        console_frame.rowconfigure(0, weight=1)
        self.console_text = tk.Text(console_frame, bg="#03080c", fg="#99ffd7", insertbackground="#66f7c6", relief="flat")
        self.console_text.grid(row=0, column=0, sticky="nsew")

    def _build_analysis_tab(self) -> None:
        self.analysis_tab.columnconfigure(0, weight=1)
        self.analysis_tab.rowconfigure(1, weight=1)

        control = ttk.LabelFrame(self.analysis_tab, text="Dataset Analysis Launcher", padding=14)
        control.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        control.columnconfigure(1, weight=1)

        ttk.Label(control, text="Prepared Dataset", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.dataset_var = tk.StringVar()
        self.dataset_combo = ttk.Combobox(control, textvariable=self.dataset_var, state="readonly")
        self.dataset_combo.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 12))

        ttk.Label(control, text="Custom Dataset Path", style="Section.TLabel").grid(row=2, column=0, sticky="w")
        self.dataset_path_var = tk.StringVar()
        ttk.Entry(control, textvariable=self.dataset_path_var).grid(row=3, column=0, sticky="ew", pady=(8, 0), padx=(0, 8))
        ttk.Button(control, text="Run Analysis Job", style="Primary.TButton", command=self.start_analysis).grid(row=3, column=1, sticky="e")

        jobs_frame = ttk.LabelFrame(self.analysis_tab, text="Analysis Queue", padding=14)
        jobs_frame.grid(row=1, column=0, sticky="nsew")
        jobs_frame.columnconfigure(0, weight=1)
        jobs_frame.rowconfigure(0, weight=1)

        self.jobs_tree = ttk.Treeview(
            jobs_frame,
            columns=("dataset", "running", "alerts", "flows", "exit"),
            show="headings",
        )
        for key, label, width in [
            ("dataset", "Dataset", 420),
            ("running", "State", 120),
            ("alerts", "Alerts", 90),
            ("flows", "Flows", 90),
            ("exit", "Exit", 80),
        ]:
            self.jobs_tree.heading(key, text=label)
            self.jobs_tree.column(key, width=width, anchor="w")
        self.jobs_tree.grid(row=0, column=0, sticky="nsew")

    def _build_dashboard_tab(self) -> None:
        self.dashboard_tab.columnconfigure(0, weight=1)
        self.dashboard_tab.rowconfigure(1, weight=0)
        self.dashboard_tab.rowconfigure(2, weight=1)

        cards = ttk.Frame(self.dashboard_tab)
        cards.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        for idx in range(6):
            cards.columnconfigure(idx, weight=1)

        self.dashboard_cards: dict[str, ttk.Label] = {}
        card_specs = [
            ("alerts", "Alerts"),
            ("packets", "Total Packets"),
            ("ml_analyzed", "ML Analyzed"),
            ("active_flows", "Active Flows"),
            ("cpu", "CPU"),
            ("memory", "Memory"),
        ]
        for idx, (key, title) in enumerate(card_specs):
            frame = ttk.Frame(cards, style="Card.TFrame", padding=14)
            frame.grid(row=0, column=idx, sticky="nsew", padx=6)
            ttk.Label(frame, text=title, style="Section.TLabel").pack(anchor="w")
            label = ttk.Label(frame, text="0", style="Value.TLabel")
            label.pack(anchor="w", pady=(10, 0))
            self.dashboard_cards[key] = label

        landscape = ttk.LabelFrame(self.dashboard_tab, text="Threat Landscape", padding=14)
        landscape.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        landscape.columnconfigure(0, weight=1)
        landscape.columnconfigure(1, weight=1)
        landscape.columnconfigure(2, weight=1)
        landscape.rowconfigure(1, weight=1)

        ttk.Label(landscape, text="Attack Families", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(landscape, text="Protocol Mix", style="Section.TLabel").grid(row=0, column=1, sticky="w")
        ttk.Label(landscape, text="Top Sources", style="Section.TLabel").grid(row=0, column=2, sticky="w")
        self.family_text = tk.Text(landscape, height=6, bg="#081117", fg="#d6fff4", relief="flat")
        self.protocol_text = tk.Text(landscape, height=6, bg="#081117", fg="#d6fff4", relief="flat")
        self.sources_text = tk.Text(landscape, height=6, bg="#081117", fg="#d6fff4", relief="flat")
        self.family_text.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        self.protocol_text.grid(row=1, column=1, sticky="nsew", padx=8)
        self.sources_text.grid(row=1, column=2, sticky="nsew", padx=(8, 0))

        traffic_row = ttk.Frame(self.dashboard_tab)
        traffic_row.grid(row=2, column=0, sticky="nsew")
        traffic_row.columnconfigure(0, weight=1)
        traffic_row.rowconfigure(0, weight=1)
        traffic_row.rowconfigure(1, weight=1)

        recent = ttk.LabelFrame(traffic_row, text="Recent Threat Traffic", padding=14)
        recent.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        recent.columnconfigure(0, weight=1)
        recent.rowconfigure(0, weight=1)
        self.recent_alerts_tree = ttk.Treeview(
            recent,
            columns=("time", "family", "severity", "score", "src", "dst"),
            show="headings",
        )
        for key, label, width in [
            ("time", "Timestamp", 180),
            ("family", "Family", 130),
            ("severity", "Severity", 100),
            ("score", "Score", 80),
            ("src", "Source", 220),
            ("dst", "Destination", 220),
        ]:
            self.recent_alerts_tree.heading(key, text=label)
            self.recent_alerts_tree.column(key, width=width, anchor="w")
        self.recent_alerts_tree.grid(row=0, column=0, sticky="nsew")
        recent_scroll = ttk.Scrollbar(recent, orient="vertical", command=self.recent_alerts_tree.yview)
        recent_scroll.grid(row=0, column=1, sticky="ns")
        self.recent_alerts_tree.configure(yscrollcommand=recent_scroll.set)

        ml_panel = ttk.LabelFrame(traffic_row, text="Packets Sent to ML", padding=14)
        ml_panel.grid(row=1, column=0, sticky="nsew")
        ml_panel.columnconfigure(0, weight=1)
        ml_panel.rowconfigure(0, weight=1)
        self.ml_packets_tree = ttk.Treeview(
            ml_panel,
            columns=("time", "packets", "protocol", "src", "dst", "reason"),
            show="headings",
        )
        for key, label, width in [
            ("time", "Timestamp", 170),
            ("packets", "Packets", 70),
            ("protocol", "Protocol", 80),
            ("src", "Source", 180),
            ("dst", "Destination", 180),
            ("reason", "Reason", 280),
        ]:
            self.ml_packets_tree.heading(key, text=label)
            self.ml_packets_tree.column(key, width=width, anchor="w")
        self.ml_packets_tree.grid(row=0, column=0, sticky="nsew")
        ml_scroll = ttk.Scrollbar(ml_panel, orient="vertical", command=self.ml_packets_tree.yview)
        ml_scroll.grid(row=0, column=1, sticky="ns")
        self.ml_packets_tree.configure(yscrollcommand=ml_scroll.set)

    def _build_threats_tab(self) -> None:
        self.threats_tab.columnconfigure(0, weight=1)
        self.threats_tab.columnconfigure(1, weight=1)
        self.threats_tab.rowconfigure(0, weight=1)

        left = ttk.LabelFrame(self.threats_tab, text="Detected Malicious Traffic", padding=14)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)

        self.threats_tree = ttk.Treeview(
            left,
            columns=("family", "severity", "score", "confidence", "src", "dst"),
            show="headings",
        )
        for key, label, width in [
            ("family", "Family", 120),
            ("severity", "Severity", 90),
            ("score", "Score", 80),
            ("confidence", "Confidence", 90),
            ("src", "Source", 220),
            ("dst", "Destination", 220),
        ]:
            self.threats_tree.heading(key, text=label)
            self.threats_tree.column(key, width=width, anchor="w")
        self.threats_tree.grid(row=0, column=0, sticky="nsew")
        self.threats_tree.bind("<<TreeviewSelect>>", self.on_threat_selected)

        right = ttk.LabelFrame(self.threats_tab, text="Threat Intelligence Detail", padding=14)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(4, weight=1)

        detail_grid = ttk.Frame(right)
        detail_grid.grid(row=0, column=0, sticky="ew")
        for idx in range(4):
            detail_grid.columnconfigure(idx, weight=1)

        self.threat_detail_vars = {
            "family": tk.StringVar(value="-"),
            "severity": tk.StringVar(value="-"),
            "score": tk.StringVar(value="-"),
            "confidence": tk.StringVar(value="-"),
            "source": tk.StringVar(value="-"),
            "destination": tk.StringVar(value="-"),
            "protocol": tk.StringVar(value="-"),
            "source_name": tk.StringVar(value="-"),
            "models": tk.StringVar(value="-"),
            "volume": tk.StringVar(value="-"),
        }
        detail_specs = [
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
        for idx, (label, key) in enumerate(detail_specs):
            row = idx // 2
            col = (idx % 2) * 2
            ttk.Label(detail_grid, text=label, style="Section.TLabel").grid(row=row, column=col, sticky="w", padx=(0, 8), pady=(0, 6))
            ttk.Label(detail_grid, textvariable=self.threat_detail_vars[key], style="Muted.TLabel").grid(row=row, column=col + 1, sticky="w", pady=(0, 6))

        ttk.Label(right, text="Analyst Reasons", style="Section.TLabel").grid(row=1, column=0, sticky="w", pady=(14, 6))
        self.threat_reasons_text = tk.Text(right, height=7, bg="#081117", fg="#d6fff4", relief="flat")
        self.threat_reasons_text.grid(row=2, column=0, sticky="ew")

        ttk.Label(right, text="Feature Summary", style="Section.TLabel").grid(row=3, column=0, sticky="w", pady=(14, 6))
        self.threat_features_text = tk.Text(right, bg="#081117", fg="#d6fff4", relief="flat")
        self.threat_features_text.grid(row=4, column=0, sticky="nsew")

    def _build_sessions_tab(self) -> None:
        self.sessions_tab.columnconfigure(0, weight=1)
        self.sessions_tab.columnconfigure(1, weight=1)
        self.sessions_tab.rowconfigure(0, weight=1)

        left = ttk.LabelFrame(self.sessions_tab, text="Monitoring Session Archive", padding=14)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)

        self.sessions_tree = ttk.Treeview(
            left,
            columns=("started", "uptime", "packets", "threats", "interface"),
            show="headings",
        )
        for key, label, width in [
            ("started", "Started", 180),
            ("uptime", "Uptime", 110),
            ("packets", "Packets", 100),
            ("threats", "Threats", 90),
            ("interface", "Interface", 180),
        ]:
            self.sessions_tree.heading(key, text=label)
            self.sessions_tree.column(key, width=width, anchor="w")
        self.sessions_tree.grid(row=0, column=0, sticky="nsew")
        self.sessions_tree.bind("<<TreeviewSelect>>", self.on_session_selected)

        right = ttk.LabelFrame(self.sessions_tab, text="Session Summary", padding=14)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)
        self.session_detail_text = tk.Text(right, bg="#081117", fg="#d6fff4", relief="flat")
        self.session_detail_text.grid(row=0, column=0, sticky="nsew")

    def _build_log_tab(self) -> None:
        self.log_tab.columnconfigure(0, weight=1)
        self.log_tab.rowconfigure(0, weight=1)

        frame = ttk.LabelFrame(self.log_tab, text="Live Packet Stream", padding=14)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        self.packet_tree = ttk.Treeview(
            frame,
            columns=("time", "protocol", "size", "src", "dst", "flags", "source"),
            show="headings",
        )
        for key, label, width in [
            ("time", "Timestamp", 180),
            ("protocol", "Protocol", 90),
            ("size", "Bytes", 80),
            ("src", "Source", 250),
            ("dst", "Destination", 250),
            ("flags", "Flags", 100),
            ("source", "Capture", 160),
        ]:
            self.packet_tree.heading(key, text=label)
            self.packet_tree.column(key, width=width, anchor="w")
        self.packet_tree.grid(row=0, column=0, sticky="nsew")

    def _schedule_refresh(self) -> None:
        if self._refresh_after_id is not None:
            self.after_cancel(self._refresh_after_id)
        self._refresh_after_id = self.after(REFRESH_INTERVAL_MS, self._poll_refresh)

    def _poll_refresh(self) -> None:
        self._refresh_after_id = None
        self.refresh_all()
        self._schedule_refresh()

    def refresh_all(self) -> None:
        try:
            self.payload = build_dashboard_payload(self.runtime_manager)
            self._render_all()
        except Exception as exc:
            messagebox.showerror("SentinelFlow", str(exc))

    def _render_all(self) -> None:
        self._render_monitor()
        self._render_analysis()
        self._render_dashboard()
        self._render_threats()
        self._render_sessions()
        self._render_packets()

    def _render_monitor(self) -> None:
        monitor = self.payload.get("monitor", {})
        status = monitor.get("status") or {}
        interfaces = self.payload.get("interfaces", [])

        options = ["Auto-select busiest interface", *interfaces]
        self.interface_combo["values"] = options
        if not self.interface_var.get():
            self.interface_var.set(options[0] if options else "Auto-select busiest interface")

        runtime_lines = [
            f"State: {'Running' if monitor.get('running') else 'Idle'}",
            f"Target: {monitor.get('interface') or monitor.get('label') or 'Auto-select'}",
            f"PID: {monitor.get('pid') or '-'}",
            f"Started: {monitor.get('started_at') or '-'}",
            f"Uptime: {status.get('uptime') or '-'}",
            f"Analyzed packets: {status.get('analyzed_packets', 0)}",
            f"ML analyzed flows: {status.get('ml_analyzed_flows', 0)}",
            f"Completed flows: {status.get('completed_flows', 0)}",
            f"Alerts: {status.get('alerts', 0)}",
            f"Active flows: {status.get('active_flows', 0)}",
            f"CPU: {status.get('avg_cpu', 0):.1f}%",
            f"Memory: {status.get('avg_memory', 0):.1f}%",
        ]
        self._replace_text(self.monitor_status_text, "\n".join(runtime_lines))
        self._replace_text(self.console_text, "\n".join(monitor.get("output_tail", [])) or "Runtime console output will appear here.")

    def _render_analysis(self) -> None:
        datasets = self.payload.get("datasets", [])
        dataset_values = [f"{item['name']} | {item['path']}" for item in datasets]
        self.dataset_combo["values"] = dataset_values
        if dataset_values and not self.dataset_var.get():
            self.dataset_var.set(dataset_values[0])

        self._replace_tree(
            self.jobs_tree,
            [
                (
                    job.get("label", ""),
                    "Running" if job.get("running") else ("Complete" if job.get("exit_code") == 0 else "Stopped"),
                    job.get("status", {}).get("alerts", 0),
                    job.get("status", {}).get("completed_flows", 0),
                    job.get("exit_code", "-"),
                )
                for job in self.payload.get("analysis_jobs", [])
            ],
        )

    def _render_dashboard(self) -> None:
        summary = self.payload.get("summary", {})
        monitor_status = self.payload.get("monitor", {}).get("status") or {}
        system = self.payload.get("system") or {}

        self.dashboard_cards["alerts"].configure(text=str(summary.get("total_alerts", 0)))
        self.dashboard_cards["packets"].configure(text=str(monitor_status.get("analyzed_packets", 0)))
        self.dashboard_cards["ml_analyzed"].configure(text=str(monitor_status.get("ml_analyzed_flows", 0)))
        self.dashboard_cards["active_flows"].configure(text=str(monitor_status.get("active_flows", 0)))
        self.dashboard_cards["cpu"].configure(text=f"{system.get('cpu_percent', 0):.1f}%")
        self.dashboard_cards["memory"].configure(text=f"{system.get('memory_percent', 0):.1f}%")

        self._replace_text(self.family_text, self._format_count_block(summary.get("family_counts", [])))
        self._replace_text(self.protocol_text, self._format_count_block(summary.get("protocol_counts", [])))
        self._replace_text(self.sources_text, self._format_count_block(summary.get("top_sources", [])))

        self._replace_tree(
            self.recent_alerts_tree,
            [
                (
                    alert.get("timestamp", ""),
                    alert.get("attack_family", ""),
                    alert.get("severity", ""),
                    f"{float(alert.get('score', 0.0)):.4f}",
                    f"{alert.get('src_ip', '')}:{alert.get('src_port', '')}",
                    f"{alert.get('dst_ip', '')}:{alert.get('dst_port', '')}",
                )
                for alert in self.payload.get("recent_alerts", [])
            ],
        )
        self._replace_tree(
            self.ml_packets_tree,
            [
                (
                    flow.get("timestamp", ""),
                    flow.get("packets", 0),
                    flow.get("protocol", ""),
                    f"{flow.get('src_ip', '')}:{flow.get('src_port', '')}",
                    f"{flow.get('dst_ip', '')}:{flow.get('dst_port', '')}",
                    self._format_ml_reason(flow),
                )
                for flow in self.payload.get("recent_ml_packets", [])
            ],
        )

    def _render_threats(self) -> None:
        alerts = self.payload.get("recent_alerts", [])
        self._replace_tree(
            self.threats_tree,
            [
                (
                    alert.get("attack_family", ""),
                    alert.get("severity", ""),
                    f"{float(alert.get('score', 0.0)):.4f}",
                    f"{float(alert.get('confidence', 0.0)):.3f}",
                    f"{alert.get('src_ip', '')}:{alert.get('src_port', '')}",
                    f"{alert.get('dst_ip', '')}:{alert.get('dst_port', '')}",
                )
                for alert in alerts
            ],
        )
        self.threats_tree_items = alerts
        if alerts:
            self._show_threat_detail(alerts[0])
        else:
            self._clear_threat_detail()

    def _render_sessions(self) -> None:
        sessions = self.payload.get("session_history", [])
        self._replace_tree(
            self.sessions_tree,
            [
                (
                    session.get("started_at", ""),
                    session.get("uptime", ""),
                    session.get("total_packets", 0),
                    session.get("total_threats", 0),
                    session.get("label", ""),
                )
                for session in sessions
            ],
        )
        self.session_items = sessions
        if sessions:
            self._show_session_detail(sessions[0])
        else:
            self._replace_text(self.session_detail_text, "No completed monitoring sessions archived yet.")

    def _render_packets(self) -> None:
        packets = self.payload.get("recent_packets", [])
        self._replace_tree(
            self.packet_tree,
            [
                (
                    packet.get("timestamp", ""),
                    packet.get("protocol", ""),
                    packet.get("size", 0),
                    f"{packet.get('src_ip', '')}:{packet.get('src_port', '')}",
                    f"{packet.get('dst_ip', '')}:{packet.get('dst_port', '')}",
                    packet.get("tcp_flags") or "-",
                    packet.get("source_name") or packet.get("mode") or "-",
                )
                for packet in packets
            ],
        )

    def on_threat_selected(self, _event=None) -> None:
        selection = self.threats_tree.selection()
        if not selection:
            return
        index = self.threats_tree.index(selection[0])
        if 0 <= index < len(getattr(self, "threats_tree_items", [])):
            self._show_threat_detail(self.threats_tree_items[index])

    def on_session_selected(self, _event=None) -> None:
        selection = self.sessions_tree.selection()
        if not selection:
            return
        index = self.sessions_tree.index(selection[0])
        if 0 <= index < len(getattr(self, "session_items", [])):
            self._show_session_detail(self.session_items[index])

    def _show_threat_detail(self, alert: dict) -> None:
        self.threat_detail_vars["family"].set(str(alert.get("attack_family", "-")))
        self.threat_detail_vars["severity"].set(str(alert.get("severity", "-")))
        self.threat_detail_vars["score"].set(f"{float(alert.get('score', 0.0)):.4f}")
        self.threat_detail_vars["confidence"].set(f"{float(alert.get('confidence', 0.0)):.3f}")
        self.threat_detail_vars["source"].set(f"{alert.get('src_ip', '-') or '-'}:{alert.get('src_port', '-')}")
        self.threat_detail_vars["destination"].set(f"{alert.get('dst_ip', '-') or '-'}:{alert.get('dst_port', '-')}")
        self.threat_detail_vars["protocol"].set(str(alert.get("protocol", "-")))
        self.threat_detail_vars["source_name"].set(str(alert.get("source_name", "-")))
        self.threat_detail_vars["models"].set(
            f"{alert.get('binary_model_name', '-')} | {alert.get('multiclass_model_name', '-')}"
        )
        self.threat_detail_vars["volume"].set(f"{alert.get('packets', 0)} packets / {alert.get('bytes', 0)} bytes")
        reasons = alert.get("reasons", [])
        features = alert.get("features") or {}
        feature_lines = [f"{key}: {value}" for key, value in sorted(features.items())]
        self._replace_text(self.threat_reasons_text, "\n".join(f"- {reason}" for reason in reasons) or "No reasons available.")
        self._replace_text(self.threat_features_text, "\n".join(feature_lines) or "No feature data available.")

    def _clear_threat_detail(self) -> None:
        for variable in self.threat_detail_vars.values():
            variable.set("-")
        self._replace_text(self.threat_reasons_text, "No active threat selected.")
        self._replace_text(self.threat_features_text, "No active threat selected.")

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
            f"Average CPU: {session.get('avg_cpu', 0):.1f}%",
            f"Average memory: {session.get('avg_memory', 0):.1f}%",
            "",
            "Top attack families:",
        ]
        for item in session.get("top_attack_families", []):
            lines.append(f"  - {item.get('label', 'unknown')}: {item.get('count', 0)}")
        lines.append("")
        lines.append("Severity breakdown:")
        for item in session.get("severity_breakdown", []):
            lines.append(f"  - {item.get('label', 'unknown')}: {item.get('count', 0)}")
        self._replace_text(self.session_detail_text, "\n".join(lines))

    def _replace_tree(self, tree: ttk.Treeview, rows: list[tuple]) -> None:
        for item in tree.get_children():
            tree.delete(item)
        tree.tag_configure("even", background="#0f1726")
        tree.tag_configure("odd", background="#121c2e")
        for index, row in enumerate(rows):
            tree.insert("", "end", values=row, tags=("even" if index % 2 == 0 else "odd",))

    def _replace_text(self, widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

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
            interface = self.interface_var.get()
            if interface == "Auto-select busiest interface":
                interface = None
            self.runtime_manager.start_monitor(interface=interface)
            self.refresh_all()
        except Exception as exc:
            messagebox.showerror("SentinelFlow", str(exc))

    def stop_monitor(self) -> None:
        try:
            self.runtime_manager.stop_monitor()
            self.refresh_all()
        except Exception as exc:
            messagebox.showerror("SentinelFlow", str(exc))

    def start_analysis(self) -> None:
        try:
            dataset_path = self.dataset_path_var.get().strip()
            if not dataset_path:
                selected = self.dataset_var.get().split("|", 1)
                dataset_path = selected[1].strip() if len(selected) == 2 else ""
            if not dataset_path:
                raise ValueError("Choose a prepared dataset or enter a custom path.")
            self.runtime_manager.start_analysis(dataset_path=dataset_path)
            self.refresh_all()
        except Exception as exc:
            messagebox.showerror("SentinelFlow", str(exc))


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

    app = SentinelFlowDesktopApp()
    app.mainloop()


if __name__ == "__main__":
    main()
