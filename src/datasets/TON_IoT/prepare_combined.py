from pathlib import Path
import json
import sys

import numpy as np
import pandas as pd

CURRENT_DIR = Path(__file__).resolve().parent
PARENT_DATASETS_DIR = CURRENT_DIR.parent
if str(PARENT_DATASETS_DIR) not in sys.path:
    sys.path.append(str(PARENT_DATASETS_DIR))

from schema import ALL_COLUMNS, SCHEMA_VERSION  # noqa: E402
from label_mapping import normalize_attack_family  # noqa: E402

RAW_DIR = Path("data/raw/ton_iot")
OUT_PATH = Path("data/processed/ton_iot_prepared_common.csv")
MANIFEST_PATH = Path("data/processed/ton_iot_manifest.json")
DATASET_NAME = "ton_iot"


def prepare_file(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]

    required_columns = [
        "dst_port",
        "duration",
        "src_pkts",
        "dst_pkts",
        "src_bytes",
        "dst_bytes",
        "label",
        "type",
    ]
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        raise ValueError(f"{path.name} is missing columns: {missing}")

    out = pd.DataFrame(
        {
            "dst_port": pd.to_numeric(df["dst_port"], errors="coerce"),
            "flow_duration": pd.to_numeric(df["duration"], errors="coerce"),
            "forward_packets": pd.to_numeric(df["src_pkts"], errors="coerce"),
            "reverse_packets": pd.to_numeric(df["dst_pkts"], errors="coerce"),
            "forward_bytes": pd.to_numeric(df["src_bytes"], errors="coerce"),
            "reverse_bytes": pd.to_numeric(df["dst_bytes"], errors="coerce"),
            "raw_label": df["type"].astype(str).str.strip(),
            "binary_target": pd.to_numeric(df["label"], errors="coerce"),
        }
    )

    duration_safe = out["flow_duration"].replace(0, np.nan)

    out["flow_bytes_per_second"] = (
        (out["forward_bytes"] + out["reverse_bytes"]) / duration_safe
    )
    out["flow_packets_per_second"] = (
        (out["forward_packets"] + out["reverse_packets"]) / duration_safe
    )

    out = out.replace([np.inf, -np.inf], np.nan)
    out = out.dropna()

    numeric_non_negative = [
        "dst_port",
        "flow_duration",
        "forward_packets",
        "reverse_packets",
        "forward_bytes",
        "reverse_bytes",
        "flow_bytes_per_second",
        "flow_packets_per_second",
        "binary_target",
    ]

    for col in numeric_non_negative:
        out = out[out[col] >= 0]

    out["binary_target"] = out["binary_target"].astype(int)
    out["attack_family"] = out["raw_label"].apply(normalize_attack_family)
    out["source_file"] = path.name
    out["dataset_name"] = DATASET_NAME

    return out[ALL_COLUMNS].copy()


def main() -> None:
    files = sorted(RAW_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {RAW_DIR}")

    parts = []
    for path in files:
        print(f"Preparing {path.name} ...")
        part = prepare_file(path)
        print(f"Rows kept: {len(part)}")
        parts.append(part)

    final_df = pd.concat(parts, ignore_index=True)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    final_df.to_csv(OUT_PATH, index=False)

    manifest = {
        "dataset_name": DATASET_NAME,
        "schema_version": SCHEMA_VERSION,
        "row_count": int(len(final_df)),
        "source_files": [p.name for p in files],
        "output_path": str(OUT_PATH),
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\nSaved:", OUT_PATH)
    print("\nAttack family distribution:")
    print(final_df["attack_family"].value_counts())
    print("\nBinary target distribution:")
    print(final_df["binary_target"].value_counts())


if __name__ == "__main__":
    main()