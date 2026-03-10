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

RAW_DIR = Path("data/raw/cic_ids_2018")
OUT_PATH = Path("data/processed/cic_ids_2018_prepared_common.csv")
MANIFEST_PATH = Path("data/processed/cic_ids_2018_manifest.json")
DATASET_NAME = "cic_ids_2018"


def prepare_file(path: Path) -> pd.DataFrame:
    df = pd.read_parquet(path)
    df.columns = [str(c).strip() for c in df.columns]

    required_columns = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Fwd Packets Length Total",
        "Bwd Packets Length Total",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Label",
    ]
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        raise ValueError(f"{path.name} is missing columns: {missing}")

    out = pd.DataFrame(
        {
            # CIC-IDS-2018 parquet files do not expose destination port here
            "dst_port": np.nan,
            "flow_duration": pd.to_numeric(df["Flow Duration"], errors="coerce"),
            "forward_packets": pd.to_numeric(df["Total Fwd Packets"], errors="coerce"),
            "reverse_packets": pd.to_numeric(df["Total Backward Packets"], errors="coerce"),
            "forward_bytes": pd.to_numeric(df["Fwd Packets Length Total"], errors="coerce"),
            "reverse_bytes": pd.to_numeric(df["Bwd Packets Length Total"], errors="coerce"),
            "flow_bytes_per_second": pd.to_numeric(df["Flow Bytes/s"], errors="coerce"),
            "flow_packets_per_second": pd.to_numeric(df["Flow Packets/s"], errors="coerce"),
            "raw_label": df["Label"].astype(str).str.strip(),
        }
    )

    out = out.replace([np.inf, -np.inf], np.nan)

    required_non_null = [
        "flow_duration",
        "forward_packets",
        "reverse_packets",
        "forward_bytes",
        "reverse_bytes",
        "flow_bytes_per_second",
        "flow_packets_per_second",
        "raw_label",
    ]
    out = out.dropna(subset=required_non_null)

    numeric_non_negative = [
        "flow_duration",
        "forward_packets",
        "reverse_packets",
        "forward_bytes",
        "reverse_bytes",
        "flow_bytes_per_second",
        "flow_packets_per_second",
    ]
    for col in numeric_non_negative:
        out = out[out[col] >= 0]

    out["attack_family"] = out["raw_label"].apply(normalize_attack_family)
    out["binary_target"] = (out["attack_family"] != "benign").astype(int)
    out["source_file"] = path.name
    out["dataset_name"] = DATASET_NAME

    return out[ALL_COLUMNS].copy()


def main() -> None:
    files = sorted(RAW_DIR.glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No parquet files found in {RAW_DIR}")

    parts = []
    for path in files:
        print(f"Preparing {path.name} ...")
        part = prepare_file(path)
        print(f"Rows kept: {len(part)}")
        print(part["attack_family"].value_counts().to_string())
        print()
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
        "notes": {
            "dst_port_missing_in_source": True,
        },
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("Done.")
    print(f"Saved combined file to: {OUT_PATH}")
    print()
    print("Final attack family distribution:")
    print(final_df["attack_family"].value_counts())
    print()
    print("Final binary target distribution:")
    print(final_df["binary_target"].value_counts())


if __name__ == "__main__":
    main()