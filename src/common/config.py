import os
from pathlib import Path


def _env_str(name: str, default: str | None) -> str | None:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return int(value)


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return float(value)


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_path(name: str, default: Path) -> Path:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return Path(value)

# Network capture
# Set to a specific interface string to force it.
# Set to None to auto-select the busiest interface at startup.
INTERFACE = _env_str("SENTINEL_INTERFACE", None)
SESSION_ID = _env_str("SENTINEL_SESSION_ID", None)
CAPTURE_TIMEOUT = None  # None = continuous mode

# Interface auto-selection
INTERFACE_PROBE_SECONDS = _env_int("SENTINEL_INTERFACE_PROBE_SECONDS", 5)

# Flow handling
INACTIVE_FLOW_TIMEOUT = _env_int("SENTINEL_INACTIVE_FLOW_TIMEOUT", 5)
ACTIVE_FLOW_TIMEOUT = _env_int("SENTINEL_ACTIVE_FLOW_TIMEOUT", 30)

# Models
BINARY_MODEL_PATH = _env_path("SENTINEL_BINARY_MODEL_PATH", Path("data/models/rf_binary_global.joblib"))
MULTICLASS_MODEL_PATH = _env_path("SENTINEL_MULTICLASS_MODEL_PATH", Path("data/models/rf_multiclass_global.joblib"))

# Detection thresholds
BINARY_THRESHOLD = _env_float("SENTINEL_BINARY_THRESHOLD", 0.80)
FAMILY_CONFIDENCE_THRESHOLD = _env_float("SENTINEL_FAMILY_CONFIDENCE_THRESHOLD", 0.60)

# Runtime / status
STATUS_INTERVAL_SECONDS = _env_int("SENTINEL_STATUS_INTERVAL_SECONDS", 10)

# Logs
LOG_DIR = _env_path("SENTINEL_LOG_DIR", Path("logs"))
ALERT_LOG = _env_path("SENTINEL_ALERT_LOG", LOG_DIR / "alerts.jsonl")
FLOW_LOG = _env_path("SENTINEL_FLOW_LOG", LOG_DIR / "flows.jsonl")
PACKET_LOG = _env_path("SENTINEL_PACKET_LOG", LOG_DIR / "packets.jsonl")
STATUS_SNAPSHOT_PATH = _env_path("SENTINEL_RUNTIME_STATUS_PATH", LOG_DIR / "runtime_status.json")
APP_DB_PATH = _env_path("SENTINEL_APP_DB_PATH", LOG_DIR / "app_state.db")

# Filtering
MIN_PACKETS_FOR_SCORING = _env_int("SENTINEL_MIN_PACKETS_FOR_SCORING", 2)
MIN_BYTES_FOR_SCORING = _env_int("SENTINEL_MIN_BYTES_FOR_SCORING", 80)
ALLOW_PRIVATE_TO_PRIVATE = _env_bool("SENTINEL_ALLOW_PRIVATE_TO_PRIVATE", False)
SKIP_LOOPBACK = _env_bool("SENTINEL_SKIP_LOOPBACK", True)
SKIP_MULTICAST = _env_bool("SENTINEL_SKIP_MULTICAST", True)
SKIP_BROADCAST = _env_bool("SENTINEL_SKIP_BROADCAST", True)
