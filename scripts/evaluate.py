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
    parser.add_argument("--num-thresholds", type=int, default=50)
    parser.add_argument("--mcc-threshold", type=float, default=0.1)
    parser.add_argument("--out-dir", type=str, default="models")
    args = parser.parse_args()

    if args.config:
        import yaml
        with open(args.config, "r") as f:
            cfg = yaml.safe_load(f)
        eval_cfg = cfg.get("evaluation", {})
        out_cfg = cfg.get("output", {})
        args.num_thresholds = eval_cfg.get("num_thresholds", args.num_thresholds)
        args.out_dir = out_cfg.get("dir", args.out_dir)
        if not args.result_path:
            args.result_path = out_cfg.get("valid_result_path")

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

    # ── Step 4: Threshold sweep ──
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
