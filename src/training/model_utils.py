from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from tqdm import tqdm

from common.path_setup import ensure_src_on_path
ensure_src_on_path(__file__)

from datasets.schema import FEATURE_COLUMNS


def split_features_and_target(df, target_column: str):
    X = df[FEATURE_COLUMNS].copy()
    y = df[target_column].copy()
    return X, y


def split_data(X, y, test_size: float = 0.2, random_state: int = 42):
    return train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )


def build_random_forest(
    X_train,
    y_train,
    total_trees: int = 200,
    batch_size: int = 10,
    max_depth: int = 18,
):
    model = RandomForestClassifier(
        n_estimators=0,
        warm_start=True,
        max_depth=max_depth,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    for _ in tqdm(range(0, total_trees, batch_size), desc="Building trees"):
        model.n_estimators += batch_size
        model.fit(X_train, y_train)

    return model


def print_dataset_summary(df, target_column: str):
    print("\nDataset summary")
    print("------------------------")
    print(f"Rows: {len(df)}")
    print("\nBy dataset:")
    print(df["dataset_name"].value_counts())
    print(f"\nTarget distribution ({target_column}):")
    print(df[target_column].value_counts())


def print_report(y_true, y_pred):
    print("\nClassification Report")
    print("---------------------")
    print(classification_report(y_true, y_pred, digits=4))


def save_model_artifact(model_path: Path, artifact: dict):
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, model_path)