import json
from datetime import datetime, UTC

from common.config import ALERT_LOG, FLOW_LOG, LOG_DIR, PACKET_LOG, SESSION_ID


def _ensure_log_dir():
    LOG_DIR.mkdir(exist_ok=True)


def log_flow(
    flow,
    features,
    source_name: str | None = None,
    mode: str | None = None,
    *,
    sent_to_ml: bool | None = None,
    decision_reason: str | None = None,
):
    _ensure_log_dir()
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "mode": mode,
        "source_name": source_name,
        "session_id": SESSION_ID,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "packets": flow.total_packets(),
        "bytes": flow.total_bytes(),
        "features": features,
        "sent_to_ml": sent_to_ml,
        "decision_reason": decision_reason,
    }
    with open(FLOW_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def log_packet(packet, source_name: str | None = None, mode: str | None = None):
    _ensure_log_dir()
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "mode": mode,
        "source_name": source_name,
        "session_id": SESSION_ID,
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "src_port": packet.src_port,
        "dst_port": packet.dst_port,
        "protocol": packet.protocol,
        "size": packet.size,
        "tcp_flags": packet.tcp_flags,
        "packet_timestamp": packet.timestamp,
    }
    with open(PACKET_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def log_alert(flow, result, features, reasons, source_name: str | None = None, mode: str | None = None):
    _ensure_log_dir()
    alert = {
        "timestamp": datetime.now(UTC).isoformat(),
        "mode": mode,
        "source_name": source_name,
        "session_id": SESSION_ID,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "packets": flow.total_packets(),
        "bytes": flow.total_bytes(),
        "score": result["score"],
        "attack_family": result["attack_family"],
        "confidence": result["confidence"],
        "severity": result.get("severity", "unknown"),
        "binary_model_name": result.get("binary_model_name"),
        "multiclass_model_name": result.get("multiclass_model_name"),
        "features": features,
        "reasons": reasons,
    }

    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")

    print("\nALERT DETECTED")
    print(json.dumps(alert, indent=2))
