"""Random Forest detector using the canonical FlowFeatures schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from iot_defense.detection.detector import Detector
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.ml.schema import FEATURE_COLUMNS, LABEL_NAMES, NUMERIC_FEATURE_COLUMNS


def build_random_forest_pipeline(*, seed: int = 7, n_estimators: int = 64) -> Pipeline:
    """Build the fitted-model-compatible preprocessing and small RF together."""
    preprocessing = ColumnTransformer(
        transformers=[
            ("protocol", OneHotEncoder(handle_unknown="ignore"), ["protocol"]),
            ("numeric", "passthrough", list(NUMERIC_FEATURE_COLUMNS)),
        ]
    )
    return Pipeline(
        steps=[
            ("preprocessing", preprocessing),
            ("classifier", RandomForestClassifier(n_estimators=n_estimators, random_state=seed, n_jobs=2, class_weight="balanced")),
        ]
    )


class RandomForestDetector(Detector):
    """Load a trained canonical-schema model and emit operational ThreatEvents."""

    model_version = "random-forest-flow-v1"

    def __init__(self, model_path: str | Path) -> None:
        self.model_path = Path(model_path)
        if not self.model_path.exists():
            raise FileNotFoundError(f"Random Forest model not found: {self.model_path}")
        import joblib

        self.pipeline: Pipeline = joblib.load(self.model_path)

    def detect(self, features: dict[str, Any]) -> ThreatEvent:
        frame = pd.DataFrame([{column: features.get(column) for column in FEATURE_COLUMNS}])
        prediction = int(self.pipeline.predict(frame)[0])
        probabilities = self.pipeline.predict_proba(frame)[0]
        confidence = float(max(probabilities))
        attack_type = LABEL_NAMES[prediction]
        return ThreatEvent.from_result(
            source_ip=str(features.get("source_ip", "unknown")),
            destination_ip=str(features.get("destination_ip", "unknown")),
            attack_type=attack_type,
            threat_score=confidence if prediction else 1.0 - confidence,
            confidence=confidence,
            detection_reason=f"Random Forest prediction from canonical flow features: {attack_type}",
            features=features,
            detector_name=f"{self.model_version}:RandomForestClassifier",
        )


def save_model_metadata(path: str | Path, metadata: dict[str, Any]) -> None:
    """Write human-readable training metadata beside a persisted model."""
    output = Path(path)
    output.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
