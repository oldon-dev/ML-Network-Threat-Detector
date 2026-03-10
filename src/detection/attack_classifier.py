from pathlib import Path

import joblib
import pandas as pd


class AttackClassifier:
    def __init__(
        self,
        binary_model_path: str,
        multiclass_model_path: str,
        threshold: float = 0.80,
        family_confidence_threshold: float = 0.60,
    ):
        binary_artifact = joblib.load(Path(binary_model_path))
        multi_artifact = joblib.load(Path(multiclass_model_path))

        self.binary_model = binary_artifact["model"]
        self.binary_feature_columns = binary_artifact["feature_columns"]
        self.binary_model_name = binary_artifact.get("model_name", "binary_model")

        self.multiclass_model = multi_artifact["model"]
        self.multiclass_feature_columns = multi_artifact["feature_columns"]
        self.class_names = multi_artifact.get("class_names")
        self.multiclass_model_name = multi_artifact.get("model_name", "multiclass_model")

        self.threshold = threshold
        self.family_confidence_threshold = family_confidence_threshold

    def _build_input(self, features: dict, feature_columns: list[str]) -> pd.DataFrame:
        missing = [col for col in feature_columns if col not in features]
        if missing:
            raise ValueError(f"Missing features for inference: {missing}")

        row = {col: features[col] for col in feature_columns}
        return pd.DataFrame([row], columns=feature_columns)

    def predict(self, features: dict) -> dict:
        X_binary = self._build_input(features, self.binary_feature_columns)
        suspicious_prob = float(self.binary_model.predict_proba(X_binary)[0][1])

        if suspicious_prob < self.threshold:
            return {
                "is_suspicious": False,
                "score": suspicious_prob,
                "attack_family": "benign",
                "confidence": 1.0 - suspicious_prob,
                "binary_model_name": self.binary_model_name,
                "multiclass_model_name": self.multiclass_model_name,
            }

        X_multi = self._build_input(features, self.multiclass_feature_columns)
        probs = self.multiclass_model.predict_proba(X_multi)[0]
        predicted_index = int(probs.argmax())
        confidence = float(probs[predicted_index])

        if self.class_names is not None:
            family = self.class_names[predicted_index]
        else:
            family = self.multiclass_model.predict(X_multi)[0]

        if confidence < self.family_confidence_threshold:
            family = "suspicious_unknown"

        return {
            "is_suspicious": True,
            "score": suspicious_prob,
            "attack_family": family,
            "confidence": confidence,
            "binary_model_name": self.binary_model_name,
            "multiclass_model_name": self.multiclass_model_name,
        }