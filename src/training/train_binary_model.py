from pathlib import Path

# Add src directory to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from common.path_setup import ensure_src_on_path
ensure_src_on_path(__file__)

from training.discovery import select_manifests
from training.loader import load_prepared_datasets
from training.model_utils import (
    build_random_forest,
    print_dataset_summary,
    print_report,
    save_model_artifact,
    split_data,
    split_features_and_target,
)
from datasets.schema import FEATURE_COLUMNS


ENABLED_DATASETS = None
# Example later:
# ENABLED_DATASETS = ["cic_ids_2017", "ctu13"]

MODEL_PATH = Path("data/models/rf_binary_global.joblib")


def main():
    manifests = select_manifests(ENABLED_DATASETS)
    df = load_prepared_datasets(manifests)

    print_dataset_summary(df, "binary_target")

    X, y = split_features_and_target(df, "binary_target")
    X_train, X_test, y_train, y_test = split_data(X, y)

    print("\nTraining global binary Random Forest")
    model = build_random_forest(
        X_train=X_train,
        y_train=y_train,
        total_trees=200,
        batch_size=10,
        max_depth=18,
    )

    y_pred = model.predict(X_test)
    print_report(y_test, y_pred)

    save_model_artifact(
        MODEL_PATH,
        {
            "model": model,
            "feature_columns": FEATURE_COLUMNS,
            "model_name": "rf_binary_global_v1",
            "target_type": "binary",
            "datasets": [m["dataset_name"] for m in manifests],
        },
    )

    print(f"\nSaved binary model to: {MODEL_PATH}")


if __name__ == "__main__":
    main()