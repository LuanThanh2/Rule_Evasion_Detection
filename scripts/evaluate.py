#!/usr/bin/env python3
"""Evaluate a validated model with MCC-based scaling and threshold sweep.

Loads a ValidationResult, applies MCC scaling, sweeps thresholds in [0, 1],
and computes Precision / Recall / F1 / MCC at each threshold.

Pipeline:
  1. Load ValidationResult (contains df_values and labels)
  2. Optionally recompute MCC scaler from training data
  3. Scale df_values to [0, 1]
  4. Sweep thresholds, compute metrics
  5. Save BinaryEvaluationResult

Usage:
  python scripts/evaluate.py --config config/process_creation.yaml
  python scripts/evaluate.py --result-path models/valid_rslt_*.zip --num-thresholds 50
"""

import os
import sys
import argparse
import logging
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from red.evaluate import BinaryEvaluation, create_mcc_scaler, scale_df_values
from red.persist import load_result, save_result

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("evaluate")


def main():
    parser = argparse.ArgumentParser(description="Evaluate model with threshold sweep")
    parser.add_argument("--config", type=str, help="Path to YAML config file")
    parser.add_argument("--result-path", type=str, help="Path to ValidationResult .zip")
    parser.add_argument("--result-name", type=str, default=None,
                        help="Result name to derive valid_rslt_<name>.zip (CLI overrides config)")
    parser.add_argument("--num-thresholds", type=int, default=50)
    parser.add_argument("--mcc-threshold", type=float, default=0.1)
    parser.add_argument("--out-dir", type=str, default=None)
    parser.add_argument("--use-threshold", type=float, default=None,
                        help="If provided, skip threshold sweep and report metrics at this "
                             "single threshold only (used for test set evaluation with a "
                             "threshold pre-selected from validation set).")
    args = parser.parse_args()

    _cli_result_name = args.result_name  # track CLI value before config loading

    if args.config:
        import yaml
        with open(args.config, "r") as f:
            cfg = yaml.safe_load(f)
        eval_cfg = cfg.get("evaluation", {})
        out_cfg = cfg.get("output", {})
        args.num_thresholds = eval_cfg.get("num_thresholds", args.num_thresholds)
        args.out_dir = os.path.expanduser(args.out_dir or out_cfg.get("dir", "models"))
        # CLI --result-name wins over config
        args.result_name = _cli_result_name or out_cfg.get("result_name")
        if not args.result_path:
            args.result_path = out_cfg.get("valid_result_path")
            if not args.result_path and args.result_name:
                args.result_path = os.path.join(args.out_dir, f"valid_rslt_{args.result_name}.zip")
    else:
        args.out_dir = args.out_dir or "models"
        if not args.result_path and args.result_name:
            args.result_path = os.path.join(args.out_dir, f"valid_rslt_{args.result_name}.zip")

    if not args.result_path:
        parser.error("--result-path is required")

    # ── Step 1: Load ValidationResult ──
    logger.info("Loading validation result from %s", args.result_path)
    valid_result = load_result(args.result_path)

    df_values = valid_result["predict"]
    labels = valid_result["labels"]
    scaler = valid_result.get("scaler")
    shift = valid_result.get("shift", 0.0)

    # ── Step 2: Recompute scaler if not available ──
    if scaler is None:
        logger.info("No scaler found, computing MCC scaler from validation data...")
        scaler, shift = create_mcc_scaler(
            df_values, labels,
            num_samples=args.num_thresholds,
            mcc_threshold=args.mcc_threshold,
        )

    # ── Step 3: Scale df_values ──
    scaled = scale_df_values(df_values, scaler, shift)
    logger.info(
        "Scaled df values: min=%.4f, max=%.4f, mean=%.4f",
        scaled.min(), scaled.max(), scaled.mean(),
    )

    # ── Step 4: Threshold sweep (or fixed threshold) ──
    if args.use_threshold is not None:
        # Test mode: report metrics at single threshold (no sweep, no data leakage)
        logger.info("Using fixed threshold T=%.6f (skipping sweep)", args.use_threshold)
        preds = (scaled >= args.use_threshold).astype(int)
        n_tp = int(((preds == 1) & (labels == 1)).sum())
        n_fp = int(((preds == 1) & (labels == 0)).sum())
        n_tn = int(((preds == 0) & (labels == 0)).sum())
        n_fn = int(((preds == 0) & (labels == 1)).sum())
        precision = n_tp / max(n_tp + n_fp, 1)
        recall = n_tp / max(n_tp + n_fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)
        # MCC
        import math
        denom = math.sqrt(
            (n_tp + n_fp) * (n_tp + n_fn) * (n_tn + n_fp) * (n_tn + n_fn)
        )
        mcc = (n_tp * n_tn - n_fp * n_fn) / denom if denom > 0 else 0.0

        summary = {
            "fixed_threshold": {
                "threshold": float(args.use_threshold),
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "mcc": mcc,
                "tp": n_tp, "fp": n_fp, "tn": n_tn, "fn": n_fn,
                "n_benign": n_tn + n_fp,
                "n_malicious": n_tp + n_fn,
            }
        }
        logger.info(
            "FIXED threshold=%.4f: TP=%d FP=%d TN=%d FN=%d | P=%.4f R=%.4f F1=%.4f MCC=%.4f",
            args.use_threshold, n_tp, n_fp, n_tn, n_fn, precision, recall, f1, mcc,
        )
        evaluation = None  # no sweep object
    else:
        evaluation = BinaryEvaluation(num_thresholds=args.num_thresholds)
        evaluation.evaluate(labels, scaled)

        summary = evaluation.summary()
        logger.info("Optimal: %s", summary["optimal"])
        logger.info("Default: %s", summary["default_0.5"])

    # ── Step 5: Save result ──
    result_name = os.path.basename(args.result_path).replace("valid_rslt_", "").replace(".zip", "")
    eval_data = {
        "evaluation": evaluation,
        "scaler": scaler,
        "shift": shift,
        "summary": summary,
    }
    save_result(eval_data, f"eval_rslt_{result_name}", args.out_dir, info=summary)
    logger.info("Evaluation complete.")


if __name__ == "__main__":
    main()
