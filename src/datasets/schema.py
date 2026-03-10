SCHEMA_VERSION = "v1_common_flow"

FEATURE_COLUMNS = [
    "dst_port",
    "flow_duration",
    "forward_packets",
    "reverse_packets",
    "forward_bytes",
    "reverse_bytes",
    "flow_bytes_per_second",
    "flow_packets_per_second",
]

TARGET_COLUMNS = [
    "attack_family",
    "binary_target",
]

METADATA_COLUMNS = [
    "raw_label",
    "source_file",
    "dataset_name",
]

ALL_COLUMNS = FEATURE_COLUMNS + TARGET_COLUMNS + METADATA_COLUMNS

NULLABLE_FEATURE_COLUMNS = {
    "dst_port",
}