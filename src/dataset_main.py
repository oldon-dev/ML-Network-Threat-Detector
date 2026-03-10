import sys
import time
from pathlib import Path

import pandas as pd

from alerts.logger import log_alert, log_flow
from capture.replay import pcap_packet_stream
from common.config import (
    ACTIVE_FLOW_TIMEOUT,
    BINARY_MODEL_PATH,
    BINARY_THRESHOLD,
    FAMILY_CONFIDENCE_THRESHOLD,
    INACTIVE_FLOW_TIMEOUT,
    MULTICLASS_MODEL_PATH,
    STATUS_INTERVAL_SECONDS,
)
from common.runtime_stats import RuntimeStats
from common.status import print_status
from common.system_metrics import SystemMetricsTracker
from detection.attack_classifier import AttackClassifier
from detection.explainer import explain_prediction, get_severity
from detection.filtering import should_skip_flow
from features.extractor import flow_to_features
from flows.flow_table import FlowTable


class CsvFlowRecord:
    """
    Minimal flow-like object for prepared CSV rows so we can reuse
    the same logging and alert pipeline.
    """

    def __init__(self, row: dict):
        self.src_ip = row.get("src_ip", "csv_flow")
        self.dst_ip = row.get("dst_ip", "csv_flow")
        self.src_port = int(row.get("src_port", 0) or 0)
        self.dst_port = int(row.get("dst_port", 0) or 0)
        self.protocol = str(row.get("protocol", "CSV"))

        self._total_packets = int(
            row.get(
                "total_packets",
                (row.get("forward_packets", 0) or 0) + (row.get("reverse_packets", 0) or 0),
            )
            or 0
        )
        self._total_bytes = int(
            row.get(
                "total_bytes",
                (row.get("forward_bytes", 0) or 0) + (row.get("reverse_bytes", 0) or 0),
            )
            or 0
        )

    def total_packets(self) -> int:
        return self._total_packets

    def total_bytes(self) -> int:
        return self._total_bytes


def process_feature_dict(
    flow_like,
    features: dict,
    detector,
    stats: RuntimeStats,
    source_name: str,
):
    # CSV rows do not go through live-flow filtering because they are already prepared.
    # We still add an empty filter tag field for consistency.
    features = dict(features)
    features["filter_tags"] = features.get("filter_tags", [])

    log_flow(flow_like, features)

    try:
        result = detector.predict(features)
    except Exception as e:
        print(f"[ERROR] inference failed for {source_name}: {e}")
        return

    stats.completed_flows += 1
    stats.ml_analyzed_flows += 1

    if result["is_suspicious"]:
        reasons = explain_prediction(
            features=features,
            attack_family=result["attack_family"],
            suspicious_score=result["score"],
            family_confidence=result["confidence"],
        )
        severity = get_severity(
            suspicious_score=result["score"],
            family_confidence=result["confidence"],
        )

        print(
            f"\n[ALERT] "
            f"source={source_name} "
            f"family={result['attack_family']} "
            f"score={result['score']:.4f} "
            f"confidence={result['confidence']:.3f} "
            f"severity={severity} "
            f"src={flow_like.src_ip}:{flow_like.src_port} "
            f"dst={flow_like.dst_ip}:{flow_like.dst_port} "
            f"proto={flow_like.protocol}"
        )
        print(f"Reasons: {', '.join(reasons)}")

        result["severity"] = severity
        log_alert(flow_like, result, features, reasons)
        stats.alerts_triggered += 1


def process_completed_flow(flow, detector, stats: RuntimeStats, source_name: str):
    features = flow_to_features(flow)

    decision = should_skip_flow(flow)
    features["filter_tags"] = decision.tags

    log_flow(flow, features)

    if decision.skip:
        stats.skipped_flows += 1
        return

    try:
        result = detector.predict(features)
    except Exception as e:
        print(f"[ERROR] inference failed for flow from {source_name}: {e}")
        return

    stats.completed_flows += 1
    stats.ml_analyzed_flows += 1

    if result["is_suspicious"]:
        reasons = explain_prediction(
            features=features,
            attack_family=result["attack_family"],
            suspicious_score=result["score"],
            family_confidence=result["confidence"],
        )
        severity = get_severity(
            suspicious_score=result["score"],
            family_confidence=result["confidence"],
        )

        print(
            f"\n[ALERT] "
            f"source={source_name} "
            f"family={result['attack_family']} "
            f"score={result['score']:.4f} "
            f"confidence={result['confidence']:.3f} "
            f"severity={severity} "
            f"src={flow.src_ip}:{flow.src_port} "
            f"dst={flow.dst_ip}:{flow.dst_port} "
            f"proto={flow.protocol}"
        )
        print(f"Reasons: {', '.join(reasons)}")

        result["severity"] = severity
        log_alert(flow, result, features, reasons)
        stats.alerts_triggered += 1


def analyze_pcap(dataset_path: Path, detector, stats: RuntimeStats, metrics: SystemMetricsTracker):
    flow_table = FlowTable(
        inactive_timeout=INACTIVE_FLOW_TIMEOUT,
        active_timeout=ACTIVE_FLOW_TIMEOUT,
    )
    last_status_time = time.time()

    try:
        for packet in pcap_packet_stream(str(dataset_path)):
            stats.packets_seen += 1

            completed_flows = flow_table.consume(packet)
            for flow in completed_flows:
                process_completed_flow(
                    flow=flow,
                    detector=detector,
                    stats=stats,
                    source_name=dataset_path.name,
                )

            metrics.sample()

            now = time.time()
            if now - last_status_time >= STATUS_INTERVAL_SECONDS:
                print_status(
                    stats=stats,
                    active_flows=len(flow_table.flows),
                    metrics=metrics,
                )
                last_status_time = now

    except KeyboardInterrupt:
        print("\nStopping dataset analysis...")

    finally:
        remaining_flows = flow_table.flush_all()
        for flow in remaining_flows:
            process_completed_flow(
                flow=flow,
                detector=detector,
                stats=stats,
                source_name=dataset_path.name,
            )


def analyze_csv(dataset_path: Path, detector, stats: RuntimeStats, metrics: SystemMetricsTracker):
    df = pd.read_csv(dataset_path, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]

    required_feature_columns = set(detector.binary_feature_columns) | set(detector.multiclass_feature_columns)
    missing = [col for col in required_feature_columns if col not in df.columns]
    if missing:
        raise ValueError(
            "CSV is missing required model feature columns:\n"
            + "\n".join(f"- {col}" for col in missing)
        )

    last_status_time = time.time()

    try:
        for _, row in df.iterrows():
            stats.packets_seen += 1  # using packets_seen as generic processed-row counter
            metrics.sample()

            row_dict = row.to_dict()
            flow_like = CsvFlowRecord(row_dict)

            feature_dict = {col: row_dict.get(col) for col in required_feature_columns}
            process_feature_dict(
                flow_like=flow_like,
                features=feature_dict,
                detector=detector,
                stats=stats,
                source_name=dataset_path.name,
            )

            now = time.time()
            if now - last_status_time >= STATUS_INTERVAL_SECONDS:
                print_status(
                    stats=stats,
                    active_flows=0,
                    metrics=metrics,
                )
                last_status_time = now

    except KeyboardInterrupt:
        print("\nStopping CSV dataset analysis...")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("python src/dataset_main.py <path_to_pcap_pcapng_or_csv>")
        return

    dataset_path = Path(sys.argv[1])

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    supported_suffixes = {".pcap", ".pcapng", ".csv"}
    if dataset_path.suffix.lower() not in supported_suffixes:
        raise ValueError(
            f"Unsupported dataset file type: {dataset_path.suffix}. "
            "dataset_main.py expects .pcap, .pcapng, or .csv."
        )

    print("Dataset analysis starting...\n")
    print(f"Source file: {dataset_path}\n")
    print("Only malicious alerts will be printed immediately.")
    print(f"Status will be printed every {STATUS_INTERVAL_SECONDS} seconds.\n")

    detector = AttackClassifier(
        binary_model_path=str(BINARY_MODEL_PATH),
        multiclass_model_path=str(MULTICLASS_MODEL_PATH),
        threshold=BINARY_THRESHOLD,
        family_confidence_threshold=FAMILY_CONFIDENCE_THRESHOLD,
    )
    stats = RuntimeStats()
    metrics = SystemMetricsTracker()

    if dataset_path.suffix.lower() in {".pcap", ".pcapng"}:
        analyze_pcap(dataset_path, detector, stats, metrics)
    else:
        analyze_csv(dataset_path, detector, stats, metrics)

    print_status(
        stats=stats,
        active_flows=0,
        metrics=metrics,
    )
    print(f"\nDataset analysis complete for: {dataset_path.name}")


if __name__ == "__main__":
    main()