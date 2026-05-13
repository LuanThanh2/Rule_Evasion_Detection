#!/usr/bin/env python3
"""Validate a trained misuse classification model.

Loads a TrainingResult, applies the feature extractor to validation data
(benign + evasions), and computes decision_function values.

Pipeline:
  1. Load TrainingResult from .zip
  2. Load benign validation samples + evasion events
  3. Transform using saved vectorizer
  4. Calculate decision_function values
  5. Save ValidationResult (.zip)

Usage:
  python scripts/validate.py --config config/process_creation.yaml
  python scripts/validate.py --result-path models/train_rslt_*.zip \\
                             --benign-samples ../data/socbed/.../validation \\
                             --events-dir ... --rules-dir ...
"""

import os
import sys
import argparse
import logging
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from red.data import (
    load_rule_set,
    benign_samples_iter,
    count_benign_samples,
    extract_commandlines,
    get_all_evasions,
    get_all_matches,
    get_all_yaml_filter_values,
    create_labels,
    resolve_event_paths,
)
from red.normalize import normalize_samples
from red.persist import load_result, save_result
from red.models import EnsembleClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("validate")


def validation_samples_iter(benign_path, malicious_samples, benign_field=None, max_benign=None):
    """Yield validation samples: benign first, then malicious."""
    for sample in benign_samples_iter(benign_path, benign_field, max_samples=max_benign):
        yield sample
    for sample in malicious_samples:
        yield sample


def main():
    parser = argparse.ArgumentParser(description="Validate misuse classification model")
    parser.add_argument("--config", type=str, help="Path to YAML config file")
    parser.add_argument("--result-path", type=str, help="Path to TrainingResult .zip")
    parser.add_argument("--benign-samples", type=str, help="Path to benign validation samples")
    parser.add_argument("--events-dir", type=str, help="Path to events directory")
    parser.add_argument("--rules-dir", type=str, help="Path to rules directory")
    parser.add_argument("--malicious-type", type=str, default=None,
                        choices=["evasions", "matches", "rule_filters", "both"])
    parser.add_argument("--search-fields", type=str, nargs="+", default=None)
    parser.add_argument("--benign-field", type=str, default=None)
    parser.add_argument("--max-benign-samples", type=int, default=None)
    parser.add_argument("--out-dir", type=str, default="models")
    parser.add_argument("--result-name", type=str)
    args = parser.parse_args()

    # Load config if provided
    if args.config:
        import yaml
        with open(args.config, "r") as f:
            cfg = yaml.safe_load(f)
        data_cfg = cfg.get("data", {})
        valid_cfg = cfg.get("validation", {})
        out_cfg = cfg.get("output", {})
        args.benign_samples = args.benign_samples or data_cfg.get("benign_valid") or data_cfg.get("benign_train")
        args.events_dir = args.events_dir or data_cfg.get("events_dir")
        args.rules_dir = args.rules_dir or data_cfg.get("rules_dir")
        args.evasions_dir = data_cfg.get("evasions_dir")
        args.search_fields = data_cfg.get("search_fields", args.search_fields)
        args.event_field_map = data_cfg.get("event_field_map", {})
        args.benign_field = data_cfg.get("benign_field", args.benign_field)
        args.max_benign_samples = data_cfg.get("max_benign_samples", args.max_benign_samples)
        args.malicious_type = args.malicious_type or valid_cfg.get("malicious_samples")
        args.out_dir = out_cfg.get("dir", args.out_dir)
        args.result_name = args.result_name or out_cfg.get("result_name")
        if not args.result_path:
            args.result_path = out_cfg.get("train_result_path")

    if not args.result_path:
        parser.error("--result-path is required")
    if not args.benign_samples:
        parser.error("--benign-samples is required")
    args.malicious_type = args.malicious_type or "evasions"

    # Expand ~ in paths
    args.benign_samples = os.path.expanduser(args.benign_samples)
    if args.events_dir:
        args.events_dir = os.path.expanduser(args.events_dir)
    if args.rules_dir:
        args.rules_dir = os.path.expanduser(args.rules_dir)
    args.out_dir = os.path.expanduser(args.out_dir)

    search_fields = args.search_fields
    event_field_map = getattr(args, "event_field_map", {}) or {}
    event_paths = resolve_event_paths(search_fields, event_field_map)
    logger.info("Sigma fields: %s → event paths: %s", search_fields, event_paths)

    # ── Step 1: Load TrainingResult ──
    logger.info("Loading training result from %s", args.result_path)
    train_result = load_result(args.result_path)
    estimator = train_result["estimator"]
    vectorizer = train_result["vectorizer"]

    # ── Step 2: Load validation data ──
    malicious_samples = []
    effective_malicious_type = args.malicious_type

    if args.events_dir and args.rules_dir:
        logger.info("Loading rule set data...")
        evasions_dir = os.path.expanduser(getattr(args, "evasions_dir", None) or "")
        evasions_dir = evasions_dir if os.path.isdir(evasions_dir) else None
        rule_set = load_rule_set(args.events_dir, args.rules_dir, evasions_dir=evasions_dir)

        if args.malicious_type in ("evasions", "both"):
            events = get_all_evasions(rule_set)
            evasion_samples = extract_commandlines(events, event_paths)
            malicious_samples += evasion_samples
            logger.info("Evasion samples: %d", len(evasion_samples))

        if args.malicious_type in ("matches", "both"):
            events = get_all_matches(rule_set)
            match_samples = extract_commandlines(events, event_paths)
            malicious_samples += match_samples
            logger.info("Match samples: %d", len(match_samples))

        if args.malicious_type == "evasions" and not malicious_samples:
            events = get_all_matches(rule_set)
            match_samples = extract_commandlines(events, event_paths)
            if match_samples:
                malicious_samples += match_samples
                effective_malicious_type = "matches_fallback"
                logger.warning(
                    "No evasion samples found; falling back to %d match samples. "
                    "Run scripts/generate_evasions.py or set validation.malicious_samples "
                    "in the config to control this explicitly.",
                    len(match_samples),
                )

    if args.malicious_type in ("rule_filters", "both") and args.rules_dir:
        filter_samples = get_all_yaml_filter_values(args.rules_dir, search_fields or [])
        logger.info("Rule filter samples: %d", len(filter_samples))
        malicious_samples += filter_samples

    malicious_samples = list(set(malicious_samples))
    malicious_normalized = normalize_samples(malicious_samples)

    max_benign = args.max_benign_samples
    num_benign = count_benign_samples(args.benign_samples, args.benign_field, max_samples=max_benign)
    logger.info(
        "Validation data: %d benign + %d malicious (%s)",
        num_benign, len(malicious_normalized), effective_malicious_type,
    )
    if len(malicious_normalized) == 0:
        logger.warning(
            "Validation set has 0 malicious samples; evaluation metrics will be "
            "diagnostic only. Check evasions_dir/events_dir/rules_dir or pass "
            "--malicious-type matches."
        )

    # ── Step 3: Transform validation data ──
    logger.info("Transforming validation data...")
    feature_vectors = vectorizer.transform(
        validation_samples_iter(args.benign_samples, malicious_normalized, args.benign_field, max_benign)
    )
    labels = create_labels(num_benign, len(malicious_normalized))

    # ── Step 4: Calculate decision function values ──
    logger.info("Calculating decision function values...")
    df_values = estimator.decision_function(feature_vectors)

    logger.info(
        "Decision function: min=%.4f, max=%.4f, mean=%.4f",
        df_values.min(), df_values.max(), df_values.mean(),
    )

    # ── Step 4a: Raw threshold=0 metrics (mọi model) ──
    # So sánh hiệu năng "trần" TRƯỚC khi MCC calibration. Đây là metric thể hiện
    # rõ nhất sự khác biệt giữa Ensemble và SVM đơn — sau MCC scaling cả 2 có
    # thể đều đạt 1.0 (data dễ tách), nhưng raw threshold sẽ phơi bày ưu thế.
    raw_preds = (df_values >= 0).astype(int)
    n_tp = int(((raw_preds == 1) & (labels == 1)).sum())
    n_fp = int(((raw_preds == 1) & (labels == 0)).sum())
    n_tn = int(((raw_preds == 0) & (labels == 0)).sum())
    n_fn = int(((raw_preds == 0) & (labels == 1)).sum())
    raw_precision = n_tp / max(n_tp + n_fp, 1)
    raw_recall = n_tp / max(n_tp + n_fn, 1)
    raw_f1 = 2 * raw_precision * raw_recall / max(raw_precision + raw_recall, 1e-9)
    logger.info(
        "RAW threshold=0: TP=%d FP=%d TN=%d FN=%d | P=%.4f R=%.4f F1=%.4f",
        n_tp, n_fp, n_tn, n_fn, raw_precision, raw_recall, raw_f1,
    )

    # ── Step 4b: Per-classifier diagnostics (chỉ khi là Ensemble) ──
    # Mục đích: xác nhận ensemble thực sự dùng cả 3 classifier, không phải
    # silently fallback về SVM. Nếu pairwise agreement = 100% → 3 model
    # đồng ý hoàn toàn → ensemble == SVM về mặt prediction (do data quá dễ).
    if isinstance(estimator, EnsembleClassifier):
        logger.info("=== Ensemble per-classifier diagnostics ===")
        member_preds = {}
        for name in estimator.classifiers:
            scores = estimator._raw_scores(name, feature_vectors)
            preds = (scores >= 0).astype(int)
            member_preds[name] = preds
            n_mal = int(preds.sum())
            n_ben_correct = int(((preds == 0) & (labels == 0)).sum())
            n_mal_correct = int(((preds == 1) & (labels == 1)).sum())
            logger.info(
                "[%s] raw min=%.4f max=%.4f | predicts %d/%d malicious | "
                "TN=%d FN=%d FP=%d TP=%d",
                name, scores.min(), scores.max(),
                n_mal, len(preds),
                n_ben_correct,
                int(((preds == 0) & (labels == 1)).sum()),
                int(((preds == 1) & (labels == 0)).sum()),
                n_mal_correct,
            )
        # Pairwise prediction agreement
        members = list(member_preds.keys())
        for i, m1 in enumerate(members):
            for m2 in members[i + 1:]:
                agree = float((member_preds[m1] == member_preds[m2]).mean()) * 100
                logger.info("[%s vs %s] prediction agreement: %.2f%%", m1, m2, agree)
        # Show how many samples each member predicts differently from ensemble
        ensemble_pred = (df_values >= 0).astype(int)
        for name in members:
            diff = int((member_preds[name] != ensemble_pred).sum())
            logger.info("[%s differs from ensemble decision] %d / %d samples",
                        name, diff, len(ensemble_pred))

    # ── Step 5: Save ValidationResult ──
    result_name = args.result_name or train_result.get("config", {}).get("result_name", "model")
    valid_result = {
        "estimator": estimator,
        "vectorizer": vectorizer,
        "scaler": train_result.get("scaler"),
        "shift": train_result.get("shift", 0.0),
        "predict": df_values,
        "labels": labels,
        "num_benign": num_benign,
        "num_malicious": len(malicious_normalized),
        "config": train_result.get("config", {}),
    }

    info = {
        "result_name": result_name,
        "num_benign": num_benign,
        "num_malicious": len(malicious_normalized),
        "df_min": float(df_values.min()),
        "df_max": float(df_values.max()),
        "df_mean": float(df_values.mean()),
    }

    save_result(valid_result, f"valid_rslt_{result_name}", args.out_dir, info=info)
    logger.info("Validation complete.")


if __name__ == "__main__":
    main()
