from pathlib import Path
import joblib
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

# Add src directory to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from common.path_setup import ensure_src_on_path
ensure_src_on_path(__file__)

from training.discovery import select_manifests
from training.loader import load_prepared_datasets
from training.model_utils import split_data, split_features_and_target


ENABLED_DATASETS = None
MODEL_PATH = Path("data/models/rf_binary_global.joblib")


def main():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

    manifests = select_manifests(ENABLED_DATASETS)
    df = load_prepared_datasets(manifests)

    artifact = joblib.load(MODEL_PATH)
    model = artifact["model"]

    X, y = split_features_and_target(df, "binary_target")
    _, X_test, _, y_test = split_data(X, y)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print()

    print("Classification Report:")
    print(classification_report(y_test, y_pred, digits=4))
    print()

    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")


if __name__ == "__main__":
    main()