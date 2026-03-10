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
from datasets.ctu13.label_mapping import (
    map_attack_family,
    binary_target_from_family,
)


RAW_DIR = Path("data/raw/CTU-13")
OUTPUT_CSV = Path("data/processed/ctu13_prepared.csv")
OUTPUT_MANIFEST = Path("data/processed/manifests/ctu13.json")
DATASET_NAME = "ctu13"


def find_binetflow_files() -> list[Path]:
    return sorted(RAW_DIR.rglob("*.binetflow"))


def parse_port(value) -> int:
    try:
        if pd.isna(value):
            return 0
        text = str(value).strip().lower()
        if text in {"", "nan"}:
            return 0
        return int(float(text))
    except Exception:
        return 0


def prepare_one_file(file_path: Path) -> pd.DataFrame:
    print(f"Preparing: {file_path.name}")

    df = pd.read_csv(file_path)
    original_rows = len(df)

    required_columns = ["Dur", "Dport", "TotPkts", "TotBytes", "SrcBytes", "Label"]
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        raise ValueError(
            f"{file_path.name} is missing required columns:\n" + "\n".join(missing)
        )

    out = pd.DataFrame()

    out["dst_port"] = df["Dport"].apply(parse_port)
    out["flow_duration"] = pd.to_numeric(df["Dur"], errors="coerce")

    total_packets = pd.to_numeric(df["TotPkts"], errors="coerce")
    total_bytes = pd.to_numeric(df["TotBytes"], errors="coerce")
    src_bytes = pd.to_numeric(df["SrcBytes"], errors="coerce").fillna(0)

    # Approximation because CTU binetflow does not expose full directional packet split.
    out["forward_packets"] = total_packets.fillna(0).clip(lower=0)
    out["reverse_packets"] = 0
    out["forward_bytes"] = src_bytes.clip(lower=0)
    out["reverse_bytes"] = (total_bytes - src_bytes).clip(lower=0)

    duration_safe = out["flow_duration"].replace(0, np.nan)
    out["flow_bytes_per_second"] = total_bytes / duration_safe
    out["flow_packets_per_second"] = total_packets / duration_safe

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

    files = find_binetflow_files()
    if not files:
        raise FileNotFoundError(f"No .binetflow files found in: {RAW_DIR}")

    print(f"Found {len(files)} CTU .binetflow file(s).\n")

    frames = [prepare_one_file(path) for path in files]
    combined = pd.concat(frames, ignore_index=True)

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(OUTPUT_CSV, index=False)
    write_manifest(combined)

    print("CTU13 prepared summary")
    print("----------------------")
    print(f"Rows: {len(combined)}")
    print()
    print(combined["attack_family"].value_counts())
    print()
    print(f"Saved CSV to: {OUTPUT_CSV}")
    print(f"Saved manifest to: {OUTPUT_MANIFEST}")


if __name__ == "__main__":
    main()