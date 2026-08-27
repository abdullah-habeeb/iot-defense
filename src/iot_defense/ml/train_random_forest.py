"""Train and evaluate the controlled-data Random Forest baseline."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import pandas as pd

from iot_defense.detection.detector import RuleBasedReconDetector
from iot_defense.ml.evaluation import classification_metrics, split_by_run
from iot_defense.ml.random_forest import build_random_forest_pipeline, save_model_metadata
from iot_defense.ml.schema import DATASET_COLUMNS, FEATURE_COLUMNS, validate_dataset


def train_and_evaluate(
    *,
    dataset_path: str | Path = "data/ml/controlled_flows.csv",
    model_path: str | Path = "models/random_forest_detector.joblib",
    seed: int = 7,
) -> dict[str, Any]:
    """Fit on training groups, inspect validation groups, and report held-out test metrics."""
    data = pd.read_csv(dataset_path)
    missing = [column for column in DATASET_COLUMNS if column not in data.columns]
    if missing:
        raise ValueError(f"Dataset is missing columns: {missing}")
    anomalies = validate_dataset(data)
    unseen_mask = data["scenario_id"].astype(str).str.startswith("unseen_")
    unseen = data[unseen_mask].copy()
    ordinary = data[~unseen_mask].copy()
    train, validation, test = split_by_run(ordinary, seed=seed)
    pipeline = build_random_forest_pipeline(seed=seed, n_estimators=64)
    pipeline.fit(train[list(FEATURE_COLUMNS)], train["label"])

    validation_predictions = pipeline.predict(validation[list(FEATURE_COLUMNS)])
    test_predictions = pipeline.predict(test[list(FEATURE_COLUMNS)])
    rule_detector = RuleBasedReconDetector()
    rule_predictions = []
    for row in test.to_dict("records"):
        event = rule_detector.detect(row)
        rule_predictions.append(int(event.attack_type == "reconnaissance_port_scan"))
    unseen_predictions = pipeline.predict(unseen[list(FEATURE_COLUMNS)]) if not unseen.empty else []
    unseen_rule_predictions = []
    for row in unseen.to_dict("records"):
        event = rule_detector.detect(row)
        unseen_rule_predictions.append(int(event.attack_type == "reconnaissance_port_scan"))

    import joblib

    model = Path(model_path)
    model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model)
    metrics = {
        "dataset_rows": len(data),
        "class_counts": {str(key): int(value) for key, value in data["label"].value_counts().sort_index().items()},
        "run_counts": {"total": int(data["run_id"].nunique()), "ordinary": int(ordinary["run_id"].nunique()), "train": int(train["run_id"].nunique()), "validation": int(validation["run_id"].nunique()), "test": int(test["run_id"].nunique()), "unseen_pattern": int(unseen["run_id"].nunique())},
        "row_counts": {"train": len(train), "validation": len(validation), "test": len(test)},
        "anomalies": anomalies,
        "random_forest": classification_metrics(test["label"], test_predictions),
        "rule_based": classification_metrics(test["label"], rule_predictions),
        "unseen_pattern_random_forest": classification_metrics(unseen["label"], unseen_predictions) if len(unseen) else {},
        "unseen_pattern_rule_based": classification_metrics(unseen["label"], unseen_rule_predictions) if len(unseen) else {},
        "validation_random_forest": classification_metrics(validation["label"], validation_predictions),
        "feature_columns": list(FEATURE_COLUMNS),
        "model_path": str(model),
        "seed": seed,
        "trained_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    save_model_metadata(model.with_suffix(".metadata.json"), metrics)
    print(json.dumps(metrics, indent=2))
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="data/ml/controlled_flows.csv")
    parser.add_argument("--model", default="models/random_forest_detector.joblib")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    train_and_evaluate(dataset_path=args.dataset, model_path=args.model, seed=args.seed)


if __name__ == "__main__":
    main()
