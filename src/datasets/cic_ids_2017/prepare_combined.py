from pathlib import Path
import json
import numpy as np
import pandas as pd

# Add src directory to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.path_setup import ensure_src_on_path
ensure_src_on_path(__file__)

from datasets.schema import ALL_COLUMNS, FEATURE_COLUMNS, SCHEMA_VERSION
from datasets.cic_ids_2017.label_mapping import (
    map_attack_family,
    binary_target_from_family,
)


RAW_DIR = Path("data/raw/CIC-IDS-2017")
OUTPUT_CSV = Path("data/processed/cic_ids_2017_prepared.csv")
OUTPUT_MANIFEST = Path("data/processed/manifests/cic_ids_2017.json")
DATASET_NAME = "cic_ids_2017"


def find_csv_files() -> list[Path]:
    return sorted(RAW_DIR.rglob("*.csv"))


def prepare_one_file(file_path: Path) -> pd.DataFrame:
    print(f"Preparing: {file_path.name}")

    df = pd.read_csv(file_path)
    original_rows = len(df)
    df.columns = df.columns.str.strip()

    required_columns = [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Label",
    ]

    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        raise ValueError(
            f"{file_path.name} is missing required columns:\n" + "\n".join(missing)
        )

    out = pd.DataFrame()

    out["dst_port"] = pd.to_numeric(df["Destination Port"], errors="coerce")
    out["flow_duration"] = pd.to_numeric(df["Flow Duration"], errors="coerce")
    out["forward_packets"] = pd.to_numeric(df["Total Fwd Packets"], errors="coerce")
    out["reverse_packets"] = pd.to_numeric(df["Total Backward Packets"], errors="coerce")
    out["forward_bytes"] = pd.to_numeric(df["Total Length of Fwd Packets"], errors="coerce")
    out["reverse_bytes"] = pd.to_numeric(df["Total Length of Bwd Packets"], errors="coerce")
    out["flow_bytes_per_second"] = pd.to_numeric(df["Flow Bytes/s"], errors="coerce")
    out["flow_packets_per_second"] = pd.to_numeric(df["Flow Packets/s"], errors="coerce")

    out["raw_label"] = df["Label"].astype(str).str.strip()
    out["attack_family"] = out["raw_label"].apply(map_attack_family)
    out["binary_target"] = out["attack_family"].apply(binary_target_from_family)
    out["source_file"] = file_path.name
    out["dataset_name"] = DATASET_NAME

    out[FEATURE_COLUMNS] = out[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan)
    out = out.dropna(subset=FEATURE_COLUMNS)

    out = out[out["flow_duration"] >= 0]
    for col in FEATURE_COLUMNS:
        out = out[out[col] >= 0]

    out = out[out["attack_family"] != "unknown"].copy()

    print(f"  original rows: {original_rows}")
    print(f"  prepared rows: {len(out)}")
    print(f"  removed rows : {original_rows - len(out)}")
    print()

    return out[ALL_COLUMNS].copy()


def write_manifest(df: pd.DataFrame) -> None:
    manifest = {
        "dataset_name": DATASET_NAME,
        "schema_version": SCHEMA_VERSION,
        "prepared_csv": str(OUTPUT_CSV),
        "feature_columns": FEATURE_COLUMNS,
        "row_count": int(len(df)),
        "attack_families": sorted(df["attack_family"].unique().tolist()),
    }

    OUTPUT_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


def main():
    if not RAW_DIR.exists():
        raise FileNotFoundError(f"Directory not found: {RAW_DIR}")

    files = find_csv_files()
    if not files:
        raise FileNotFoundError(f"No CSV files found in: {RAW_DIR}")

    print(f"Found {len(files)} CIC CSV file(s).\n")

    frames = [prepare_one_file(path) for path in files]
    combined = pd.concat(frames, ignore_index=True)

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(OUTPUT_CSV, index=False)
    write_manifest(combined)

    print("CIC prepared summary")
    print("--------------------")
    print(f"Rows: {len(combined)}")
    print()
    print(combined["attack_family"].value_counts())
    print()
    print(f"Saved CSV to: {OUTPUT_CSV}")
    print(f"Saved manifest to: {OUTPUT_MANIFEST}")


if __name__ == "__main__":
    main()