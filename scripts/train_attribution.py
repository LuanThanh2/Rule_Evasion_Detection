#!/usr/bin/env python3
"""Train per-rule attribution models (C3).

Trains one binary SVM per Sigma rule: benign vs. rule_X filter values.
Uses the best hyperparameters from the misuse model (C1) training.

Pipeline:
  1. Load rule set data
  2. Load best params from misuse training result
  3. For each rule with evasions:
     a. Create training data: benign vs. rule_X filters
     b. Normalize → TF-IDF → SVC with fixed params
     c. Create MCC scaler
  4. Save MultiTrainingResult (.zip)

Usage:
  python scripts/train_attribution.py --config config/process_creation.yaml
  python scripts/train_attribution.py --benign-samples ... --events-dir ... \\
         --rules-dir ... --model-params models/train_rslt_*_info.json
"""

import os
import sys
import json
import argparse
import logging
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from red.data import (
    load_rule_set,
    benign_samples_iter,
    count_benign_samples,
    extract_filter_values,
    create_labels,
)
from red.normalize import normalize_samples
from red.features import create_vectorizer
from red.models import train_svc_fixed
from red.evaluate import create_mcc_scaler
from red.persist import save_result, load_result

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("train_attribution")


def train_samples_iter(benign_path, malicious_samples):
    for sample in benign_samples_iter(benign_path):
        yield sample
    for sample in malicious_samples:
        yield sample


def main():
    parser = argparse.ArgumentParser(description="Train per-rule attribution models")
    parser.add_argument("--config", type=str, help="Path to YAML config file")
    parser.add_argument("--benign-samples", type=str)
    parser.add_argument("--events-dir", type=str)
    parser.add_argument("--rules-dir", type=str)
    parser.add_argument("--search-fields", type=str, nargs="+",
                        default=["process.command_line"])
    parser.add_argument("--model-params", type=str,
                        help="JSON file or TrainingResult .zip with best SVC params")
    parser.add_argument("--vectorization", type=str, default="tfidf")
    parser.add_argument("--ngram-range", type=str, default="(1,1)")
    parser.add_argument("--mcc-scaling", action="store_true", default=True)
    parser.add_argument("--mcc-threshold", type=float, default=0.1)
    parser.add_argument("--out-dir", type=str, default="models")
    parser.add_argument("--result-name", type=str, default="attr_svc_rules")
    args = parser.parse_args()

    if args.config:
        import yaml
        with open(args.config, "r") as f:
            cfg = yaml.safe_load(f)
        data_cfg = cfg.get("data", {})
        train_cfg = cfg.get("training", {})
        scale_cfg = cfg.get("scaling", {})
        out_cfg = cfg.get("output", {})
        args.benign_samples = args.benign_samples or data_cfg.get("benign_train")
        args.events_dir = args.events_dir or data_cfg.get("events_dir")
        args.rules_dir = args.rules_dir or data_cfg.get("rules_dir")
        args.evasions_dir = data_cfg.get("evasions_dir")
        args.search_fields = data_cfg.get("search_fields", args.search_fields)
        args.vectorization = train_cfg.get("vectorization", args.vectorization)
        args.mcc_scaling = scale_cfg.get("mcc_scaling", args.mcc_scaling)
        args.mcc_threshold = scale_cfg.get("mcc_threshold", args.mcc_threshold)
        args.out_dir = out_cfg.get("dir", args.out_dir)
        args.result_name = out_cfg.get("attr_result_name", args.result_name)
        args.model_params = args.model_params or out_cfg.get("train_result_path")

        ngram = train_cfg.get("ngram_range", [1, 1])
        args.ngram_range = f"({ngram[0]},{ngram[1]})"

    if not args.benign_samples or not args.events_dir or not args.rules_dir:
        parser.error("--benign-samples, --events-dir, and --rules-dir are required")

    ngram_range = eval(args.ngram_range)

    # Load best params from misuse training
    svc_params = {"C": 1.0, "kernel": "linear", "class_weight": "balanced"}
    if args.model_params:
        if args.model_params.endswith(".zip"):
            train_rslt = load_result(args.model_params)
            svc_params = {
                "C": train_rslt["best_params"].get("C", 1.0),
                "kernel": train_rslt["best_params"].get("kernel", "linear"),
                "class_weight": train_rslt["best_params"].get("class_weight", "balanced"),
            }
        elif args.model_params.endswith(".json"):
            with open(args.model_params) as f:
                info = json.load(f)
            if "estimator_params" in info:
                p = info["estimator_params"]
                svc_params = {"C": p.get("C", 1.0), "kernel": p.get("kernel", "linear"),
                              "class_weight": p.get("class_weight", "balanced")}
            elif "best_params" in info:
                svc_params = info["best_params"]

    logger.info("Using SVC params: %s", svc_params)

    # Load rule set
    evasions_dir = os.path.expanduser(getattr(args, "evasions_dir", None) or "")
    evasions_dir = evasions_dir if os.path.isdir(evasions_dir) else None
    rule_set = load_rule_set(args.events_dir, args.rules_dir, evasions_dir=evasions_dir)
    num_benign = count_benign_samples(args.benign_samples)

    # Train per-rule models
    rule_models = {}
    trained_count = 0

    for rule_name, rule_data in rule_set.items():
        if len(rule_data.evasions) == 0:
            continue

        # Get malicious samples for this rule
        rule_filter_values = []
        for filt in rule_data.filters:
            vals = extract_filter_values(filt, args.search_fields)
            rule_filter_values.extend(vals)

        if len(rule_filter_values) == 0:
            logger.warning("Rule %s has no filter values, skipping", rule_name)
            continue

        malicious_normalized = normalize_samples(rule_filter_values)
        if len(malicious_normalized) == 0:
            continue

        # Create vectorizer and transform
        vectorizer = create_vectorizer(args.vectorization, ngram_range=ngram_range)
        feature_vectors = vectorizer.fit_transform(
            train_samples_iter(args.benign_samples, malicious_normalized)
        )
        labels = create_labels(num_benign, len(malicious_normalized))

        # Train SVC with fixed params
        estimator = train_svc_fixed(feature_vectors, labels, **svc_params)

        # MCC scaler
        scaler, shift = None, 0.0
        if args.mcc_scaling:
            df_values = estimator.decision_function(feature_vectors)
            try:
                scaler, shift = create_mcc_scaler(
                    df_values, labels, mcc_threshold=args.mcc_threshold,
                )
            except Exception as e:
                logger.warning("MCC scaler failed for %s: %s", rule_name, e)

        rule_models[rule_name] = {
            "estimator": estimator,
            "vectorizer": vectorizer,
            "scaler": scaler,
            "shift": shift,
        }
        trained_count += 1
        logger.info("Trained model for rule: %s (%d malicious samples)", rule_name, len(malicious_normalized))

    logger.info("Trained %d rule models", trained_count)

    # Save
    result = {"rule_models": rule_models, "svc_params": svc_params}
    info = {
        "result_name": args.result_name,
        "num_rules": trained_count,
        "svc_params": svc_params,
        "rules": list(rule_models.keys()),
    }
    save_result(result, f"train_rslt_{args.result_name}", args.out_dir, info=info)
    logger.info("Attribution training complete.")


if __name__ == "__main__":
    main()
