from pathlib import Path
import sys

import numpy as np
import pandas as pd

CURRENT_DIR = Path(__file__).resolve().parent
PARENT_DATASETS_DIR = CURRENT_DIR.parent
if str(PARENT_DATASETS_DIR) not in sys.path:
    sys.path.append(str(PARENT_DATASETS_DIR))

from schema import ALL_COLUMNS  # noqa: E402
from label_mapping import normalize_attack_family, to_binary_target  # noqa: E402

RAW_DIR = Path("data/raw/unsw_nb15")
OUT_PATH = Path("data/processed/unsw_nb15_prepared_common.csv")
MANIFEST_PATH = Path("data/processed/unsw_nb15_manifest.json")
DATASET_NAME = "unsw_nb15"


def main() -> None:
    files = sorted(RAW_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {RAW_DIR}")

    parts = []

    for path in files:
        print(f"Preparing {path.name} ...")
        df = pd.read_csv(path, low_memory=False)
        df.columns = [str(c).strip() for c in df.columns]

        required = ["dsport", "dur", "spkts", "dpkts", "sbytes", "dbytes", "attack_cat"]
        missing = [col for col in required if col not in df.columns]
        if missing:
            raise ValueError(f"{path.name} missing columns: {missing}")

        out = pd.DataFrame(
            {
                "dst_port": pd.to_numeric(df["dsport"], errors="coerce"),
                "flow_duration": pd.to_numeric(df["dur"], errors="coerce"),
                "forward_packets": pd.to_numeric(df["spkts"], errors="coerce"),
                "reverse_packets": pd.to_numeric(df["dpkts"], errors="coerce"),
                "forward_bytes": pd.to_numeric(df["sbytes"], errors="coerce"),
                "reverse_bytes": pd.to_numeric(df["dbytes"], errors="coerce"),
                "raw_label": df["attack_cat"].astype(str),
            }
        )

        duration_safe = out["flow_duration"].replace(0, np.nan)
        out["flow_bytes_per_second"] = (out["forward_bytes"] + out["reverse_bytes"]) / duration_safe
        out["flow_packets_per_second"] = (out["forward_packets"] + out["reverse_packets"]) / duration_safe

        out = out.replace([np.inf, -np.inf], np.nan)
        out = out.dropna()

        out = out[out["flow_duration"] >= 0]
        out = out[out["forward_packets"] >= 0]
        out = out[out["reverse_packets"] >= 0]
        out = out[out["forward_bytes"] >= 0]
        out = out[out["reverse_bytes"] >= 0]

        out["attack_family"] = out["raw_label"].apply(normalize_attack_family)
        out["binary_target"] = out["attack_family"].apply(to_binary_target)
        out["source_file"] = path.name
        out["dataset_name"] = DATASET_NAME

        out = out[ALL_COLUMNS].copy()
        print(f"Rows kept: {len(out)}")
        parts.append(out)

    final_df = pd.concat(parts, ignore_index=True)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    final_df.to_csv(OUT_PATH, index=False)

    manifest = {
        "dataset_name": DATASET_NAME,
        "schema_version": "v1_common_flow",
        "row_count": int(len(final_df)),
        "source_files": [p.name for p in files],
        "output_path": str(OUT_PATH),
    }

    import json
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\nDone.")
    print(f"Saved: {OUT_PATH}")
    print(final_df["attack_family"].value_counts())


if __name__ == "__main__":
    main()