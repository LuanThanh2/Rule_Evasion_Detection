#!/usr/bin/env python3
"""Run the complete AMIDES-style pipeline end-to-end.

Executes all stages sequentially:
  1. Train misuse classifier (C1/C2)
  2. Validate with evasions
  3. Evaluate with MCC scaling + threshold sweep
  4. Train per-rule attribution models (C3)
  5. Evaluate rule attribution
  6. Generate plots

Usage:
  python scripts/run_pipeline.py --config config/process_creation.yaml
"""

import os
import sys
import subprocess
import argparse
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("pipeline")

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))


def run_step(name, script, args_list):
    """Run a pipeline step as a subprocess."""
    cmd = [sys.executable, os.path.join(SCRIPTS_DIR, script)] + args_list
    logger.info("=" * 60)
    logger.info("STEP: %s", name)
    logger.info("CMD:  %s", " ".join(cmd))
    logger.info("=" * 60)

    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        logger.error("Step '%s' failed with return code %d", name, result.returncode)
        sys.exit(result.returncode)
    logger.info("Step '%s' completed successfully.\n", name)


def main():
    parser = argparse.ArgumentParser(description="Run complete RED pipeline")
    parser.add_argument("--config", type=str, required=True, help="Path to YAML config")
    parser.add_argument("--skip-attribution", action="store_true",
                        help="Skip C3 attribution steps")
    parser.add_argument("--skip-plots", action="store_true", help="Skip plot generation")
    args = parser.parse_args()

    import yaml
    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f)

    out_dir = cfg.get("output", {}).get("dir", "models")
    result_name = cfg.get("output", {}).get("result_name", "misuse_svc_rules_f1")
    attr_name = cfg.get("output", {}).get("attr_result_name", "attr_svc_rules")

    train_rslt_path = os.path.join(out_dir, f"train_rslt_{result_name}.zip")
    valid_rslt_path = os.path.join(out_dir, f"valid_rslt_{result_name}.zip")
    eval_rslt_path = os.path.join(out_dir, f"eval_rslt_{result_name}.zip")
    attr_train_path = os.path.join(out_dir, f"train_rslt_{attr_name}.zip")
    attr_eval_path = os.path.join(out_dir, f"eval_attr_{attr_name}.zip")

    # Step 1: Train misuse model
    run_step("Train Misuse Model (C1/C2)", "train.py", [
        "--config", args.config, "--search-params",
    ])

    # Step 2: Validate
    run_step("Validate Model", "validate.py", [
        "--config", args.config,
        "--result-path", train_rslt_path,
    ])

    # Step 3: Evaluate
    run_step("Evaluate Model", "evaluate.py", [
        "--config", args.config,
        "--result-path", valid_rslt_path,
    ])

    if not args.skip_attribution:
        # Step 4: Train attribution models
        run_step("Train Attribution Models (C3)", "train_attribution.py", [
            "--config", args.config,
            "--model-params", train_rslt_path,
        ])

        # Step 5: Evaluate attribution
        run_step("Evaluate Attribution", "eval_attribution.py", [
            "--config", args.config,
            "--result-path", attr_train_path,
        ])

    if not args.skip_plots:
        figures_dir = os.path.join(out_dir, "figures")
        os.makedirs(figures_dir, exist_ok=True)

        # Plot PR curve
        run_step("Plot PR Curve", "plot.py", [
            "pr",
            "--result-paths", eval_rslt_path,
            "--output", os.path.join(figures_dir, "figure_3_misuse_classification.pdf"),
        ])

        if not args.skip_attribution:
            # Plot attribution
            run_step("Plot Attribution", "plot.py", [
                "attr",
                "--result-path", attr_eval_path,
                "--output", os.path.join(figures_dir, "figure_4_rule_attribution.pdf"),
            ])

    logger.info("=" * 60)
    logger.info("PIPELINE COMPLETE")
    logger.info("Results in: %s/", out_dir)
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
