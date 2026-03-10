from pathlib import Path

# Network capture
# Set to a specific interface string to force it.
# Set to None to auto-select the busiest interface at startup.
INTERFACE = None
CAPTURE_TIMEOUT = None  # None = continuous mode

# Interface auto-selection
INTERFACE_PROBE_SECONDS = 5

# Flow handling
INACTIVE_FLOW_TIMEOUT = 5
ACTIVE_FLOW_TIMEOUT = 30

# Models
BINARY_MODEL_PATH = Path("data/models/rf_binary_global.joblib")
MULTICLASS_MODEL_PATH = Path("data/models/rf_multiclass_global.joblib")

# Detection thresholds
BINARY_THRESHOLD = 0.80
FAMILY_CONFIDENCE_THRESHOLD = 0.60

# Runtime / status
STATUS_INTERVAL_SECONDS = 10

# Logs
LOG_DIR = Path("logs")
ALERT_LOG = LOG_DIR / "alerts.jsonl"
FLOW_LOG = LOG_DIR / "flows.jsonl"

# Filtering
MIN_PACKETS_FOR_SCORING = 2
MIN_BYTES_FOR_SCORING = 80
ALLOW_PRIVATE_TO_PRIVATE = False
SKIP_LOOPBACK = True
SKIP_MULTICAST = True
SKIP_BROADCAST = True