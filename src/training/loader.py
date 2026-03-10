from pathlib import Path
import pandas as pd

from common.path_setup import ensure_src_on_path
ensure_src_on_path(__file__)

from datasets.schema import ALL_COLUMNS, FEATURE_COLUMNS, SCHEMA_VERSION


def load_prepared_datasets(manifests: list[dict]) -> pd.DataFrame:
    frames = []

    for manifest in manifests:
        if manifest["schema_version"] != SCHEMA_VERSION:
            raise ValueError(
                f"Schema mismatch for {manifest['dataset_name']}: "
                f"{manifest['schema_version']} != {SCHEMA_VERSION}"
            )

        if manifest["feature_columns"] != FEATURE_COLUMNS:
            raise ValueError(
                f"Feature column mismatch for {manifest['dataset_name']}"
            )

        csv_path = Path(manifest["prepared_csv"])
        if not csv_path.exists():
            raise FileNotFoundError(f"Prepared CSV not found: {csv_path}")

        df = pd.read_csv(csv_path)

        missing = [col for col in ALL_COLUMNS if col not in df.columns]
        if missing:
            raise ValueError(
                f"{csv_path} is missing required columns:\n" + "\n".join(missing)
            )

        frames.append(df[ALL_COLUMNS].copy())

    return pd.concat(frames, ignore_index=True)