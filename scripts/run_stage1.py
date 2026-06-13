#!/usr/bin/env python3
"""Run Stage 1 pipeline: train + validate + evaluate.

Gộp 3 bước train.py → validate.py → evaluate.py vào 1 lệnh.
Mặc định dùng EnsembleClassifier (SVM + LR + CNB) và 100% benign data
(benign_train = benign_valid trong config) cho production deployment.

Usage:
  python scripts/run_stage1.py --config config/process_creation.yaml
  python scripts/run_stage1.py --config config/powershell.yaml --no-ensemble
  python scripts/run_stage1.py --config config/process_creation.yaml --result-name svm_baseline --no-ensemble
"""

import os
import sys
import argparse
import subprocess
import logging
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("run_stage1")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))


def run_step(name, script, args_list):
    cmd = [sys.executable, os.path.join(SCRIPTS_DIR, script)] + args_list
    logger.info("=" * 70)
    logger.info("STEP: %s", name)
    logger.info("CMD:  %s", " ".join(cmd))
    logger.info("=" * 70)
    t0 = time.time()
    result = subprocess.run(cmd)
    elapsed = time.time() - t0
    if result.returncode != 0:
        logger.error("STEP '%s' FAILED (exit code %d, %.1fs)", name, result.returncode, elapsed)
        sys.exit(result.returncode)
    logger.info("STEP '%s' done in %.1fs.\n", name, elapsed)


def main():
    parser = argparse.ArgumentParser(
        description="Run Stage 1 pipeline (train + validate + evaluate)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", type=str, required=True,
                        help="Path to YAML config (config/process_creation.yaml, ...)")
    parser.add_argument("--ensemble", dest="ensemble", action="store_true", default=True,
                        help="Use EnsembleClassifier SVM+LR+CNB (default)")
    parser.add_argument("--no-ensemble", dest="ensemble", action="store_false",
                        help="Use single SVM (baseline so sánh)")
    parser.add_argument("--result-name", type=str, default=None,
                        help="Override output name (default: lấy từ config.output.result_name)")
    args = parser.parse_args()

    common = ["--config", args.config]
    if args.result_name:
        common += ["--result-name", args.result_name]

    # Step 1: Train
    train_args = list(common)
    if args.ensemble:
        train_args.append("--ensemble")
    run_step("TRAIN", "train.py", train_args)

    # Step 2: Validate (dùng benign_valid trong config — production: = benign_train)
    run_step("VALIDATE", "validate.py", list(common))

    # Step 3: Evaluate (threshold sweep)
    run_step("EVALUATE", "evaluate.py", list(common))

    logger.info("=" * 70)
    logger.info("STAGE 1 PIPELINE COMPLETE — train + validate + evaluate")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
