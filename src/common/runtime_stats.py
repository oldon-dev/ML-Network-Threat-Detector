from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass
class RuntimeStats:
    packets_seen: int = 0
    completed_flows: int = 0
    skipped_flows: int = 0
    alerts_triggered: int = 0
    ml_analyzed_flows: int = 0

    def __post_init__(self):
        self.started_at = datetime.now(UTC)

    def uptime_seconds(self) -> float:
        return (datetime.now(UTC) - self.started_at).total_seconds()