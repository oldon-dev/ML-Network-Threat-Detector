from __future__ import annotations

import os
import subprocess
import sys
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from dashboard_app.session_store import append_session_summary, build_session_summary


ROOT_DIR = Path(__file__).resolve().parents[2]
LOG_DIR = ROOT_DIR / "logs"
JOB_STATUS_DIR = LOG_DIR / "jobs"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso_now() -> str:
    return _utc_now().isoformat()


def _safe_read_json(path: Path | None) -> dict | None:
    if path is None or not path.exists():
        return None
    try:
        import json

        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


@dataclass
class ManagedProcessState:
    process_type: str
    label: str
    command: list[str]
    status_snapshot_path: str | None = None
    job_id: str | None = None
    dataset_path: str | None = None
    interface: str | None = None
    session_id: str | None = None
    running: bool = False
    pid: int | None = None
    started_at: str | None = None
    stopped_at: str | None = None
    exit_code: int | None = None
    error: str | None = None
    output_tail: deque[str] = field(default_factory=lambda: deque(maxlen=80))

    def to_dict(self) -> dict:
        status = _safe_read_json(Path(self.status_snapshot_path)) if self.status_snapshot_path else None
        return {
            "process_type": self.process_type,
            "label": self.label,
            "command": self.command,
            "status_snapshot_path": self.status_snapshot_path,
            "job_id": self.job_id,
            "dataset_path": self.dataset_path,
            "interface": self.interface,
            "session_id": self.session_id,
            "running": self.running,
            "pid": self.pid,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "exit_code": self.exit_code,
            "error": self.error,
            "output_tail": list(self.output_tail),
            "status": status,
        }


class ManagedProcess:
    def __init__(
        self,
        process_type: str,
        label: str,
        command: list[str],
        status_snapshot_path: Path | None = None,
        dataset_path: str | None = None,
        interface: str | None = None,
        job_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        self.state = ManagedProcessState(
            process_type=process_type,
            label=label,
            command=command,
            status_snapshot_path=str(status_snapshot_path) if status_snapshot_path else None,
            job_id=job_id,
            dataset_path=dataset_path,
            interface=interface,
            session_id=session_id,
        )
        self._status_snapshot_path = status_snapshot_path
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()

    def start(self, env: dict[str, str]) -> None:
        if self._status_snapshot_path:
            self._status_snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            if self._status_snapshot_path.exists():
                self._status_snapshot_path.unlink()

        self._process = subprocess.Popen(
            self.state.command,
            cwd=str(ROOT_DIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        with self._lock:
            self.state.running = True
            self.state.pid = self._process.pid
            self.state.started_at = _iso_now()
            self.state.stopped_at = None
            self.state.exit_code = None
            self.state.error = None

        threading.Thread(target=self._read_output, daemon=True).start()
        threading.Thread(target=self._wait_for_exit, daemon=True).start()

    def _read_output(self) -> None:
        if self._process is None or self._process.stdout is None:
            return

        for line in self._process.stdout:
            cleaned = line.rstrip()
            with self._lock:
                self.state.output_tail.append(cleaned)
                if "[ERROR]" in cleaned or "Traceback" in cleaned:
                    self.state.error = cleaned

    def _wait_for_exit(self) -> None:
        if self._process is None:
            return

        exit_code = self._process.wait()
        with self._lock:
            self.state.running = False
            self.state.exit_code = exit_code
            self.state.stopped_at = _iso_now()

    def stop(self) -> None:
        if self._process is None:
            return
        if self._process.poll() is not None:
            return

        self._process.terminate()
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()

    def snapshot(self) -> dict:
        with self._lock:
            return self.state.to_dict()


class RuntimeManager:
    def __init__(self, launcher_command: list[str] | None = None) -> None:
        self._lock = threading.Lock()
        self._monitor: ManagedProcess | None = None
        self._jobs: dict[str, ManagedProcess] = {}
        self._launcher_command = launcher_command
        LOG_DIR.mkdir(exist_ok=True)
        JOB_STATUS_DIR.mkdir(parents=True, exist_ok=True)

    def _command_for_monitor(self) -> list[str]:
        if self._launcher_command:
            return [*self._launcher_command, "--worker", "monitor"]
        return [sys.executable, "src/main.py"]

    def _command_for_analysis(self, dataset_path: str) -> list[str]:
        if self._launcher_command:
            return [*self._launcher_command, "--worker", "analysis", "--dataset", dataset_path]
        return [sys.executable, "src/dataset_main.py", dataset_path]

    def start_monitor(self, interface: str | None = None) -> dict:
        with self._lock:
            if self._monitor and self._monitor.snapshot()["running"]:
                return self._monitor.snapshot()

            snapshot_path = LOG_DIR / "runtime_live.json"
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            env["SENTINEL_RUNTIME_STATUS_PATH"] = str(snapshot_path)
            session_id = uuid.uuid4().hex[:12]
            env["SENTINEL_SESSION_ID"] = session_id
            if interface:
                env["SENTINEL_INTERFACE"] = interface
            else:
                env.pop("SENTINEL_INTERFACE", None)

            process = ManagedProcess(
                process_type="monitor",
                label=interface or "auto-select",
                command=self._command_for_monitor(),
                status_snapshot_path=snapshot_path,
                interface=interface,
                session_id=session_id,
            )
            process.start(env=env)
            self._monitor = process
            return process.snapshot()

    def stop_monitor(self) -> dict:
        with self._lock:
            if self._monitor is None:
                return {"running": False}
            self._monitor.stop()
            snapshot = self._monitor.snapshot()
            session_id = snapshot.get("session_id")
            if session_id:
                append_session_summary(build_session_summary(session_id, snapshot))
            snapshot["output_tail"] = []
            snapshot["status"] = None
            self._monitor = None
            return snapshot

    def get_monitor(self) -> dict:
        with self._lock:
            if self._monitor is None:
                return {
                    "process_type": "monitor",
                    "running": False,
                    "label": "inactive",
                    "output_tail": [],
                    "status": None,
                }
            return self._monitor.snapshot()

    def start_analysis(self, dataset_path: str) -> dict:
        dataset = Path(dataset_path).expanduser()
        if not dataset.is_absolute():
            dataset = (ROOT_DIR / dataset).resolve()

        if not dataset.exists():
            raise FileNotFoundError(f"Dataset not found: {dataset}")

        if dataset.suffix.lower() not in {".pcap", ".pcapng", ".csv"}:
            raise ValueError("Unsupported dataset type. Use .pcap, .pcapng, or .csv.")

        job_id = uuid.uuid4().hex[:10]
        snapshot_path = JOB_STATUS_DIR / f"{job_id}.json"

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["SENTINEL_RUNTIME_STATUS_PATH"] = str(snapshot_path)

        process = ManagedProcess(
            process_type="analysis",
            label=dataset.name,
            command=self._command_for_analysis(str(dataset)),
            status_snapshot_path=snapshot_path,
            dataset_path=str(dataset),
            job_id=job_id,
        )
        process.start(env=env)

        with self._lock:
            self._jobs[job_id] = process
            return process.snapshot()

    def list_jobs(self) -> list[dict]:
        with self._lock:
            jobs = [job.snapshot() for job in self._jobs.values()]
        return sorted(jobs, key=lambda item: item.get("started_at") or "", reverse=True)
