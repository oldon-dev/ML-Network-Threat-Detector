from datetime import timedelta

from common.runtime_stats import RuntimeStats
from common.system_metrics import SystemMetricsTracker


def print_status(
    stats: RuntimeStats,
    active_flows: int,
    metrics: SystemMetricsTracker,
) -> None:
    uptime = timedelta(seconds=int(stats.uptime_seconds()))
    print(
        "\n[STATUS] \n"
        f"uptime={uptime} \n"
        f"analyzed_packets={stats.packets_seen} \n"
        f"skipped_flows={stats.skipped_flows} \n"
        f"ml_analyzed_flows={stats.ml_analyzed_flows} \n"
        f"completed_flows={stats.completed_flows} \n"
        f"alerts={stats.alerts_triggered} \n"
        f"active_flows={active_flows} \n"
        f"avg_cpu={metrics.average_cpu():.1f}% \n"
        f"avg_memory={metrics.average_memory():.1f}% \n"
    )