from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from common.config import ALERT_LOG, LOG_DIR, PACKET_LOG


SESSION_HISTORY_PATH = LOG_DIR / "session_history.json"


def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def load_session_history() -> list[dict]:
    data = _read_json(SESSION_HISTORY_PATH, [])
    if not isinstance(data, list):
        return []
    return data


def save_session_history(history: list[dict]) -> None:
    LOG_DIR.mkdir(exist_ok=True)
    SESSION_HISTORY_PATH.write_text(json.dumps(history, indent=2), encoding="utf-8")


def append_session_summary(summary: dict) -> None:
    history = load_session_history()
    history.append(summary)
    history = history[-60:]
    save_session_history(history)


def _tail_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    items: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                items.append(json.loads(stripped))
            except json.JSONDecodeError:
                continue
    return items


def build_session_summary(session_id: str, monitor_snapshot: dict) -> dict:
    status = monitor_snapshot.get("status") or {}
    alerts = [item for item in _tail_jsonl(ALERT_LOG) if item.get("session_id") == session_id]
    packets = [item for item in _tail_jsonl(PACKET_LOG) if item.get("session_id") == session_id]

    family_counts = Counter(str(item.get("attack_family", "unknown")) for item in alerts)
    severity_counts = Counter(str(item.get("severity", "unknown")) for item in alerts)

    return {
        "session_id": session_id,
        "label": monitor_snapshot.get("interface") or monitor_snapshot.get("label") or "auto-select",
        "started_at": monitor_snapshot.get("started_at"),
        "stopped_at": monitor_snapshot.get("stopped_at") or datetime.now(UTC).isoformat(),
        "uptime": status.get("uptime") or "-",
        "uptime_seconds": status.get("uptime_seconds", 0),
        "total_packets": status.get("analyzed_packets", 0),
        "ml_analyzed_flows": status.get("ml_analyzed_flows", 0),
        "completed_flows": status.get("completed_flows", 0),
        "total_threats": status.get("alerts", 0),
        "avg_cpu": status.get("avg_cpu", 0),
        "avg_memory": status.get("avg_memory", 0),
        "top_attack_families": [{"label": key, "count": value} for key, value in family_counts.most_common(5)],
        "severity_breakdown": [{"label": key, "count": value} for key, value in severity_counts.most_common(5)],
        "threat_count_from_log": len(alerts),
        "packet_count_from_log": len(packets),
    }
