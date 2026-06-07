#!/usr/bin/env python3
"""Diagnose Stage 1 model — investigate suspicious F1=1.0 results.

Loads a ValidationResult and reports:
  - Score distribution per class (any overlap?)
  - Separability gap (min-malicious vs max-benign raw score)
  - Misclassified samples (the few cases where model was wrong)
  - Token analysis: discriminative tokens for malicious vs benign
  - Optional: cross-distribution sanity check on real ELK events

Usage:
  # Diagnose on val set
  python scripts/diagnose_stage1.py \\
    --valid-result models/process_creation/valid_rslt_ensemble_f1.zip

  # Plus check real-world events distribution (to spot overfitting)
  python scripts/diagnose_stage1.py \\
    --valid-result models/process_creation/valid_rslt_ensemble_f1.zip \\
    --real-events /tmp/events.jsonl \\
    --config config/process_creation.yaml
"""

import os
import sys
import json
import argparse
import logging
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from red.persist import load_result
from red.normalize import Normalizer
from red.data import resolve_event_paths

logger = logging.getLogger("diagnose_stage1")


def _percentile_summary(values: np.ndarray, name: str) -> None:
    p = np.percentile(values, [0, 5, 25, 50, 75, 95, 100])
    logger.info(
        "%-10s n=%4d  min=%.3f  p5=%.3f  p25=%.3f  median=%.3f  p75=%.3f  p95=%.3f  max=%.3f  mean=%.3f",
        name, len(values), p[0], p[1], p[2], p[3], p[4], p[5], p[6], values.mean(),
    )


def diagnose_separability(df_values: np.ndarray, labels: np.ndarray) -> None:
    benign_scores = df_values[labels == 0]
    malicious_scores = df_values[labels == 1]

    logger.info("=== Raw decision_function score distribution ===")
    _percentile_summary(benign_scores, "Benign")
    _percentile_summary(malicious_scores, "Malicious")

    gap = malicious_scores.min() - benign_scores.max()
    overlap_zone = (benign_scores.max(), malicious_scores.min())

    logger.info("")
    logger.info("=== Separability analysis ===")
    logger.info("max(benign)  = %.4f", benign_scores.max())
    logger.info("min(malicious) = %.4f", malicious_scores.min())
    logger.info("Gap = min_mal - max_ben = %.4f  %s",
                gap, "(POSITIVE → perfectly separable)" if gap > 0 else "(NEGATIVE → overlap)")

    # Overlap count
    overlap_benign = int((benign_scores >= malicious_scores.min()).sum())
    overlap_malicious = int((malicious_scores <= benign_scores.max()).sum())
    logger.info("Benign samples scoring ≥ min(malicious): %d / %d",
                overlap_benign, len(benign_scores))
    logger.info("Malicious samples scoring ≤ max(benign): %d / %d",
                overlap_malicious, len(malicious_scores))

    # Raw threshold metrics
    raw_pred = (df_values >= 0).astype(int)
    tp = int(((raw_pred == 1) & (labels == 1)).sum())
    fp = int(((raw_pred == 1) & (labels == 0)).sum())
    tn = int(((raw_pred == 0) & (labels == 0)).sum())
    fn = int(((raw_pred == 0) & (labels == 1)).sum())
    logger.info("")
    logger.info("=== Raw threshold=0 confusion matrix ===")
    logger.info("TP=%d  FP=%d  TN=%d  FN=%d", tp, fp, tn, fn)
    if tp + fp > 0 and tp + fn > 0:
        prec = tp / (tp + fp)
        rec = tp / (tp + fn)
        f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0
        logger.info("Precision=%.4f  Recall=%.4f  F1=%.4f", prec, rec, f1)


def show_misclassified(df_values: np.ndarray, labels: np.ndarray, top_n: int = 10) -> None:
    """Show samples where model was most wrong (lowest score for malicious, highest for benign)."""
    raw_pred = (df_values >= 0).astype(int)
    wrong_mask = raw_pred != labels
    n_wrong = int(wrong_mask.sum())

    logger.info("")
    logger.info("=== Misclassified samples (raw threshold=0) ===")
    logger.info("Total wrong: %d / %d (%.2f%%)",
                n_wrong, len(labels), 100 * n_wrong / len(labels))

    if n_wrong == 0:
        logger.info("ZERO errors. Either model is perfect OR task is too easy/data leaked.")
        return

    # Worst FN (malicious scored low)
    mal_idx = np.where(labels == 1)[0]
    mal_sorted = mal_idx[np.argsort(df_values[mal_idx])]
    logger.info("Lowest-scored MALICIOUS (top candidates for FN):")
    for i in mal_sorted[:top_n]:
        logger.info("  idx=%d  score=%+.3f  label=mal", i, df_values[i])

    # Worst FP (benign scored high)
    ben_idx = np.where(labels == 0)[0]
    ben_sorted = ben_idx[np.argsort(-df_values[ben_idx])]
    logger.info("Highest-scored BENIGN (top candidates for FP):")
    for i in ben_sorted[:top_n]:
        logger.info("  idx=%d  score=%+.3f  label=ben", i, df_values[i])


def show_top_features(estimator, vectorizer, top_n: int = 20) -> None:
    """For linear classifiers, show top-weighted features."""
    logger.info("")
    logger.info("=== Top discriminative features (linear SVM weights) ===")

    # For Ensemble, try to get SVM member
    svc = None
    if hasattr(estimator, "classifiers"):  # EnsembleClassifier
        clf = estimator.classifiers.get("svm")
        if clf is not None:
            svc = getattr(clf, "best_estimator_", clf)
    elif hasattr(estimator, "coef_"):
        svc = estimator
    elif hasattr(estimator, "best_estimator_"):
        svc = estimator.best_estimator_

    if svc is None or not hasattr(svc, "coef_"):
        logger.info("Cannot extract feature weights (not a linear SVM)")
        return

    feature_names = vectorizer.get_feature_names_out()
    weights = svc.coef_.toarray().ravel() if hasattr(svc.coef_, "toarray") else svc.coef_.ravel()

    top_mal = np.argsort(-weights)[:top_n]
    top_ben = np.argsort(weights)[:top_n]

    logger.info("Top tokens → MALICIOUS:")
    for i in top_mal:
        logger.info("  %+.4f  %s", weights[i], feature_names[i])

    logger.info("Top tokens → BENIGN:")
    for i in top_ben:
        logger.info("  %+.4f  %s", weights[i], feature_names[i])


def check_real_events_distribution(real_events_path: str, config_path: str,
                                    estimator, vectorizer,
                                    train_benign_score_max: float) -> None:
    """Score real ELK events and compare distribution to train data."""
    import yaml
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    data_cfg = cfg.get("data", {})
    search_fields = data_cfg.get("search_fields", ["CommandLine"])
    event_field_map = data_cfg.get("event_field_map", {})
    event_paths = resolve_event_paths(search_fields, event_field_map)

    with open(real_events_path, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    normalizer = Normalizer()
    texts = []
    for event in events:
        for path in event_paths:
            obj = event
            for key in path.split("."):
                obj = obj.get(key) if isinstance(obj, dict) else None
            if obj and isinstance(obj, str):
                texts.append(obj)
                break

    normalized = [normalizer.normalize(t) for t in texts]
    normalized = [n for n in normalized if n]

    if not normalized:
        logger.info("No usable real events")
        return

    X = vectorizer.transform(normalized)
    real_scores = np.asarray(estimator.decision_function(X)).ravel()

    logger.info("")
    logger.info("=== Real ELK events distribution (these are mostly benign in practice) ===")
    _percentile_summary(real_scores, "Real")

    above_train_benign = int((real_scores > train_benign_score_max).sum())
    logger.info("Real events scoring above max(train_benign)=%.3f: %d / %d (%.1f%%)",
                train_benign_score_max, above_train_benign, len(real_scores),
                100 * above_train_benign / len(real_scores))
    logger.info(
        "→ If this %% is high, model overfits to LMD benign distribution. "
        "Real Windows commands look 'malicious' to the model."
    )


def main():
    parser = argparse.ArgumentParser(description="Stage 1 diagnostic")
    parser.add_argument("--valid-result", type=str, required=True,
                        help="Path to valid_rslt_*.zip")
    parser.add_argument("--real-events", type=str, default=None,
                        help="Optional: JSONL of real ELK events for distribution check")
    parser.add_argument("--config", type=str, default=None,
                        help="Config (required if --real-events given)")
    parser.add_argument("--top-n", type=int, default=10)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    logger.info("Loading validation result: %s", args.valid_result)
    rslt = load_result(args.valid_result)
    df_values = np.asarray(rslt["predict"]).ravel()
    labels = np.asarray(rslt["labels"]).ravel()
    estimator = rslt["estimator"]
    vectorizer = rslt["vectorizer"]

    logger.info("Loaded: %d samples (%d benign, %d malicious)",
                len(labels), int((labels == 0).sum()), int((labels == 1).sum()))

    diagnose_separability(df_values, labels)
    show_misclassified(df_values, labels, args.top_n)
    show_top_features(estimator, vectorizer, args.top_n)

    if args.real_events:
        if not args.config:
            parser.error("--config required when --real-events given")
        train_benign_max = float(df_values[labels == 0].max())
        check_real_events_distribution(
            args.real_events, args.config, estimator, vectorizer, train_benign_max
        )


if __name__ == "__main__":
    main()
