from datetime import timedelta

from common.runtime_stats import RuntimeStats
from common.runtime_events import write_status_snapshot
from common.system_metrics import SystemMetricsTracker


def print_status(
    stats: RuntimeStats,
    active_flows: int,
    metrics: SystemMetricsTracker,
    mode: str = "live",
    source_name: str | None = None,
) -> None:
    uptime = timedelta(seconds=int(stats.uptime_seconds()))
    write_status_snapshot(
        {
            "mode": mode,
            "source_name": source_name,
            "uptime": str(uptime),
            "uptime_seconds": stats.uptime_seconds(),
            "analyzed_packets": stats.packets_seen,
            "skipped_flows": stats.skipped_flows,
            "ml_analyzed_flows": stats.ml_analyzed_flows,
            "completed_flows": stats.completed_flows,
            "alerts": stats.alerts_triggered,
            "active_flows": active_flows,
            "avg_cpu": metrics.average_cpu(),
            "avg_memory": metrics.average_memory(),
        }
    )
