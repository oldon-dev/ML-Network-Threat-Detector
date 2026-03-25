import time

from alerts.logger import log_alert, log_flow, log_packet
from capture.sniff import auto_select_interface, list_interfaces, packet_stream
from common.config import (
    ACTIVE_FLOW_TIMEOUT,
    BINARY_MODEL_PATH,
    BINARY_THRESHOLD,
    FAMILY_CONFIDENCE_THRESHOLD,
    INACTIVE_FLOW_TIMEOUT,
    INTERFACE,
    INTERFACE_PROBE_SECONDS,
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


def resolve_interface() -> str:
    if INTERFACE:
        print(f"Using configured interface: {INTERFACE}")
        return INTERFACE

    print("No interface configured. Probing all interfaces for traffic...\n")

    selected, counts = auto_select_interface(seconds=INTERFACE_PROBE_SECONDS)

    print("Interface probe results:")
    for i, (iface, count) in enumerate(counts.items()):
        print(f"[{i}] {iface} -> packets={count}")

    if not selected:
        raise RuntimeError("Could not auto-select an interface with traffic.")

    print(f"\nSelected interface: {selected}\n")
    return selected


def process_completed_flow(flow, detector, stats: RuntimeStats, source_name: str):
    features = flow_to_features(flow)

    decision = should_skip_flow(flow)
    features["filter_tags"] = decision.tags

    log_flow(
        flow,
        features,
        source_name=source_name,
        mode="live",
        sent_to_ml=not decision.skip,
        decision_reason=decision.reason,
    )

    if decision.skip:
        stats.skipped_flows += 1
        return

    try:
        result = detector.predict(features)
    except Exception as e:
        print(f"[ERROR] inference failed for flow: {e}")
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
        log_alert(flow, result, features, reasons, source_name=source_name, mode="live")
        stats.alerts_triggered += 1


def main():
    print("Network Malware Detector starting...\n")

    selected_interface = resolve_interface()

    print("Starting continuous capture...")
    print("Only malicious alerts will be printed immediately.")
    print(f"Status will be printed every {STATUS_INTERVAL_SECONDS} seconds.")
    print("Press Ctrl+C to stop.\n")

    flow_table = FlowTable(
        inactive_timeout=INACTIVE_FLOW_TIMEOUT,
        active_timeout=ACTIVE_FLOW_TIMEOUT,
    )
    detector = AttackClassifier(
        binary_model_path=str(BINARY_MODEL_PATH),
        multiclass_model_path=str(MULTICLASS_MODEL_PATH),
        threshold=BINARY_THRESHOLD,
        family_confidence_threshold=FAMILY_CONFIDENCE_THRESHOLD,
    )
    stats = RuntimeStats()
    metrics = SystemMetricsTracker()

    last_status_time = time.time()

    try:
        for packet in packet_stream(interface=selected_interface):
            stats.packets_seen += 1
            log_packet(packet, source_name=selected_interface, mode="live")

            completed_flows = flow_table.consume(packet)
            for flow in completed_flows:
                process_completed_flow(flow, detector, stats, selected_interface)

            metrics.sample()

            now = time.time()
            if now - last_status_time >= STATUS_INTERVAL_SECONDS:
                print_status(
                    stats=stats,
                    active_flows=len(flow_table.flows),
                    metrics=metrics,
                    mode="live",
                    source_name=selected_interface,
                )
                last_status_time = now

    except KeyboardInterrupt:
        print("\nStopping detector...")

    finally:
        remaining_flows = flow_table.flush_all()
        for flow in remaining_flows:
            process_completed_flow(flow, detector, stats, selected_interface)

        print_status(
            stats=stats,
            active_flows=0,
            metrics=metrics,
            mode="live",
            source_name=selected_interface,
        )
        print("\nShutdown complete.")


if __name__ == "__main__":
    main()
