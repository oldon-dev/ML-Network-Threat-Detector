import json
from datetime import UTC, datetime

from common.config import LOG_DIR, SESSION_ID, STATUS_SNAPSHOT_PATH


def write_status_snapshot(payload: dict) -> None:
    LOG_DIR.mkdir(exist_ok=True)
    data = dict(payload)
    data["session_id"] = SESSION_ID
    data["updated_at"] = datetime.now(UTC).isoformat()
    STATUS_SNAPSHOT_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
