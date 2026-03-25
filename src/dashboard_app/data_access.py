from __future__ import annotations

import json
from collections import Counter, defaultdict, deque
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    import psutil
except ImportError:  # pragma: no cover - fallback for limited environments
    psutil = None

from capture.sniff import list_interfaces
from common.config import (
    ACTIVE_FLOW_TIMEOUT,
    ALERT_LOG,
    BINARY_MODEL_PATH,
    BINARY_THRESHOLD,
    FAMILY_CONFIDENCE_THRESHOLD,
    FLOW_LOG,
    INACTIVE_FLOW_TIMEOUT,
    INTERFACE_PROBE_SECONDS,
    MIN_BYTES_FOR_SCORING,
    MIN_PACKETS_FOR_SCORING,
    MULTICLASS_MODEL_PATH,
    PACKET_LOG,
    STATUS_INTERVAL_SECONDS,
)
from dashboard_app.session_store import load_session_history


ROOT_DIR = Path(__file__).resolve().parents[2]
SUPPORTED_DATASET_SUFFIXES = {".pcap", ".pcapng", ".csv"}


def _tail_jsonl(path: Path, limit: int) -> list[dict]:
    if not path.exists():
        return []

    records: deque[dict] = deque(maxlen=limit)
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                records.append(json.loads(stripped))
            except json.JSONDecodeError:
                continue

    return list(records)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _most_common(counter: Counter, limit: int = 5) -> list[dict]:
    return [{"label": label, "count": count} for label, count in counter.most_common(limit)]


def _build_activity_series(alerts: list[dict]) -> list[dict]:
    buckets: defaultdict[str, int] = defaultdict(int)
    for alert in alerts:
        parsed = _parse_timestamp(alert.get("timestamp"))
        if parsed is None:
            continue
        bucket = parsed.astimezone(UTC).strftime("%m-%d %H:00")
        buckets[bucket] += 1

    return [{"label": label, "count": buckets[label]} for label in sorted(buckets.keys())[-8:]]


def _dataset_candidates() -> list[dict]:
    candidates: list[Path] = []
    for base in [ROOT_DIR / "data" / "raw", ROOT_DIR / "data" / "processed"]:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in SUPPORTED_DATASET_SUFFIXES:
                candidates.append(path)

    candidates.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    return [
        {
            "name": path.name,
            "path": str(path),
            "size_mb": round(path.stat().st_size / (1024 * 1024), 2),
        }
        for path in candidates[:24]
    ]


def _system_snapshot() -> dict:
    if psutil is None:
        return {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
        }
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": psutil.virtual_memory().percent,
    }


def _settings_snapshot() -> dict:
    return {
        "binary_model_path": str(BINARY_MODEL_PATH),
        "multiclass_model_path": str(MULTICLASS_MODEL_PATH),
        "binary_threshold": BINARY_THRESHOLD,
        "family_confidence_threshold": FAMILY_CONFIDENCE_THRESHOLD,
        "inactive_flow_timeout": INACTIVE_FLOW_TIMEOUT,
        "active_flow_timeout": ACTIVE_FLOW_TIMEOUT,
        "status_interval_seconds": STATUS_INTERVAL_SECONDS,
        "interface_probe_seconds": INTERFACE_PROBE_SECONDS,
        "min_packets_for_scoring": MIN_PACKETS_FOR_SCORING,
        "min_bytes_for_scoring": MIN_BYTES_FOR_SCORING,
    }


def build_dashboard_payload(runtime_manager) -> dict:
    all_alerts = list(reversed(_tail_jsonl(ALERT_LOG, 240)))
    all_flows = list(reversed(_tail_jsonl(FLOW_LOG, 240)))
    all_packets = list(reversed(_tail_jsonl(PACKET_LOG, 400)))
    monitor = runtime_manager.get_monitor()
    active_session_id = monitor.get("session_id") if monitor.get("running") else None
    alerts = [item for item in all_alerts if item.get("session_id") == active_session_id] if active_session_id else []
    flows = [item for item in all_flows if item.get("session_id") == active_session_id] if active_session_id else []
    packets = [item for item in all_packets if item.get("session_id") == active_session_id] if active_session_id else []
    ml_packets = [item for item in flows if item.get("sent_to_ml") is True]
    now = datetime.now(UTC)
    alerts_last_day = 0

    family_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    port_counts: Counter[str] = Counter()
    score_total = 0.0

    for alert in alerts:
        family_counts[str(alert.get("attack_family", "unknown"))] += 1
        severity_counts[str(alert.get("severity", "unknown"))] += 1
        source_counts[str(alert.get("src_ip", "unknown"))] += 1
        destination_counts[str(alert.get("dst_ip", "unknown"))] += 1
        port_counts[str(alert.get("dst_port", "unknown"))] += 1
        score_total += float(alert.get("score", 0.0) or 0.0)

        parsed = _parse_timestamp(alert.get("timestamp"))
        if parsed and now - parsed.astimezone(UTC) <= timedelta(hours=24):
            alerts_last_day += 1

    bytes_total = 0
    suspicious_flows = 0
    for flow in flows:
        protocol_counts[str(flow.get("protocol", "OTHER"))] += 1
        bytes_total += int(flow.get("bytes", 0) or 0)
        if flow.get("mode") in {"dataset", "live", "replay"}:
            suspicious_flows += 1

    average_score = round(score_total / len(alerts), 4) if alerts else 0.0

    try:
        interfaces = list_interfaces()
    except Exception as exc:
        interfaces = [f"Interface enumeration unavailable: {exc}"]

    return {
        "generated_at": _isoformat(now),
        "monitor": monitor,
        "analysis_jobs": runtime_manager.list_jobs(),
        "session_history": list(reversed(load_session_history())),
        "interfaces": interfaces,
        "datasets": _dataset_candidates(),
        "settings": _settings_snapshot(),
        "system": _system_snapshot(),
        "summary": {
            "total_alerts": len(alerts),
            "alerts_last_24h": alerts_last_day,
            "total_flows": len(flows),
            "traffic_bytes_total": bytes_total,
            "average_alert_score": average_score,
            "family_counts": _most_common(family_counts, limit=6),
            "severity_counts": _most_common(severity_counts, limit=4),
            "protocol_counts": _most_common(protocol_counts, limit=4),
            "top_sources": _most_common(source_counts, limit=5),
            "top_destinations": _most_common(destination_counts, limit=5),
            "top_ports": _most_common(port_counts, limit=5),
            "activity_series": _build_activity_series(alerts),
            "suspicious_flows": suspicious_flows,
        },
        "recent_alerts": alerts[:40],
        "recent_flows": flows[:40],
        "recent_packets": packets[:80],
        "recent_ml_packets": ml_packets[:80],
    }


def _isoformat(value: datetime) -> str:
    return value.isoformat()
