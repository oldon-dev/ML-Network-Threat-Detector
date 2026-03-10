import json
from datetime import datetime, UTC

from common.config import ALERT_LOG, FLOW_LOG, LOG_DIR


def _ensure_log_dir():
    LOG_DIR.mkdir(exist_ok=True)


def log_flow(flow, features):
    _ensure_log_dir()
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "packets": flow.total_packets(),
        "bytes": flow.total_bytes(),
        "features": features,
    }
    with open(FLOW_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def log_alert(flow, result, features, reasons):
    _ensure_log_dir()
    alert = {
        "timestamp": datetime.now(UTC).isoformat(),
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
        "binary_model_name": result.get("binary_model_name"),
        "multiclass_model_name": result.get("multiclass_model_name"),
        "features": features,
        "reasons": reasons,
    }

    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")

    print("\nALERT DETECTED")
    print(json.dumps(alert, indent=2))