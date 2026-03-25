import sys
from pathlib import Path

from alerts.logger import log_alert, log_flow
from capture.replay import pcap_packet_stream
from detection.attack_classifier import AttackClassifier
from detection.explainer import explain_prediction
from detection.filtering import should_skip_flow
from features.extractor import flow_to_features
from flows.flow_table import FlowTable


def process_completed_flow(flow, detector, source_name: str):
    features = flow_to_features(flow)
    decision = should_skip_flow(flow)
    log_flow(
        flow,
        features,
        source_name=source_name,
        mode="replay",
        sent_to_ml=not decision.skip,
        decision_reason=decision.reason,
    )

    if decision.skip:
        return

    #if skip:
    #    print(
    #        f"Skipped flow [{source_name}]: "
    #        f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
    #        f"{flow.protocol} reason={skip_reason}"
    #    )
    #    return

    result = detector.predict(features)

    #print(
    #    f"Completed flow [{source_name}]: "
    #    f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
    #    f"{flow.protocol} packets={flow.total_packets()} bytes={flow.total_bytes()} "
    #    f"suspicious_score={result['score']:.4f}"
    #)

    if result["is_suspicious"]:
        reasons = explain_prediction(
            features=features,
            attack_family=result["attack_family"],
            suspicious_score=result["score"],
            family_confidence=result["confidence"],
        )

        print(
            f"ALERT: attack_family={result['attack_family']} "
            f"confidence={result['confidence']:.3f}"
        )
        print(f"Reasons: {', '.join(reasons)}")

        log_alert(flow, result, features, reasons, source_name=source_name, mode="replay")
    #else:
    #    print("Detection result: normal")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("python src/replay_main.py <path_to_pcap>")
        return

    pcap_path = Path(sys.argv[1])

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    print("Replay mode starting...\n")
    print(f"Source PCAP: {pcap_path}\n")

    flow_table = FlowTable(inactive_timeout=5, active_timeout=30)
    detector = AttackClassifier(
        binary_model_path="data/models/rf_binary_cic2017.joblib",
        multiclass_model_path="data/models/rf_multiclass_cic2017.joblib",
        threshold=0.80,
        family_confidence_threshold=0.60,
    )

    packet_count = 0

    for packet in pcap_packet_stream(str(pcap_path)):
        packet_count += 1
        completed_flows = flow_table.consume(packet)

        for flow in completed_flows:
            process_completed_flow(flow, detector, pcap_path.name)

    remaining_flows = flow_table.flush_all()
    for flow in remaining_flows:
        process_completed_flow(flow, detector, pcap_path.name)

    print(f"\nReplay finished. Packets processed: {packet_count}")


if __name__ == "__main__":
    main()
