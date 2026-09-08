"""Group-aware splitting and held-out classification metrics."""

from __future__ import annotations

from typing import Any

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit

from iot_defense.ml.schema import LABEL_NAMES


def split_by_run(
    data: pd.DataFrame,
    *,
    seed: int = 7,
    train_fraction: float = 0.7,
    validation_fraction: float = 0.15,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split whole simulation runs so no run crosses train/validation/test."""
    if data["run_id"].nunique() < 3:
        raise ValueError("At least three independent run groups are required for splitting.")
    groups = data["run_id"].to_numpy()
    train_splitter = GroupShuffleSplit(n_splits=1, train_size=train_fraction, random_state=seed)
    train_indices, remainder_indices = next(train_splitter.split(data, groups=groups))
    remainder = data.iloc[remainder_indices]
    remainder_groups = remainder["run_id"].to_numpy()
    validation_share = validation_fraction / (1.0 - train_fraction)
    validation_splitter = GroupShuffleSplit(n_splits=1, train_size=validation_share, random_state=seed + 1)
    validation_indices, test_indices = next(validation_splitter.split(remainder, groups=remainder_groups))
    return data.iloc[train_indices].copy(), remainder.iloc[validation_indices].copy(), remainder.iloc[test_indices].copy()


def classification_metrics(y_true: Any, y_pred: Any) -> dict[str, Any]:
    """Calculate classification metrics from held-out labels.

    Returns the original binary tn/fp/fn/tp/FPR/FNR summary unchanged when
    only classes 0/1 are present (normal/reconnaissance), so existing binary
    evaluations keep the exact same shape. With a third class present (e.g.
    dos_flood=2), tn/fp/fn/tp are not well-defined, so a macro-averaged
    summary plus a full confusion matrix and per-class breakdown are
    returned instead.
    """
    true_labels = set(int(v) for v in y_true)
    pred_labels = set(int(v) for v in y_pred)
    present = true_labels | pred_labels

    if present.issubset({0, 1}):
        matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = matrix.ravel()
        return {
            "confusion_matrix": matrix.tolist(),
            "labels": [0, 1],
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
            "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
        }

    # Force every registered label into the report even if a particular
    # split happens to contain zero instances of it, so output shape stays
    # stable across splits/runs -- generic over however many classes are
    # currently registered (LABEL_NAMES), not a hardcoded {0, 1, 2}.
    labels = sorted(present | set(LABEL_NAMES.keys()))
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    per_class_precision = precision_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
    per_class_recall = recall_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
    per_class_f1 = f1_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
    return {
        "confusion_matrix": matrix.tolist(),
        "labels": labels,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "per_class": {
            str(label): {
                "precision": float(per_class_precision[i]),
                "recall": float(per_class_recall[i]),
                "f1": float(per_class_f1[i]),
            }
            for i, label in enumerate(labels)
        },
    }
