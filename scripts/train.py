#!/usr/bin/env python3
"""Train a misuse classification model (C1/C2).

Trains a binary SVM classifier: benign samples vs. malicious samples.
Malicious samples come from either:
  - rule_filters: field values extracted from Sigma rule YAML (AMIDES approach)
  - matches: CommandLine extracted from match events

Pipeline:
  1. Load benign samples + rule set data
  2. Create malicious sample list (from rule_filters or matches)
  3. Normalize all malicious samples
  4. Concatenate [benign_iter, malicious] → fit TF-IDF vectorizer
  5. Train SVC with GridSearchCV (or fixed params)
  6. Create MCC-based scaler on training data
  7. Save TrainingResult (.zip)

Usage:
  python scripts/train.py --config config/process_creation.yaml
  python scripts/train.py --benign-samples ../data/socbed/.../train \\
                          --events-dir ../data/sigma/events/... \\
                          --rules-dir ../data/sigma/rules/... \\
                          --model-type misuse
"""

import os
import sys
import argparse
import logging
import json
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from red.data import (
    load_rule_set,
    benign_samples_iter,
    count_benign_samples,
    extract_commandlines,
    get_all_filter_values,
    get_all_matches,
    create_labels,
)
from red.normalize import normalize_samples
from red.features import create_vectorizer
from red.models import train_svc_gridsearch, train_svc_fixed
from red.evaluate import create_mcc_scaler
from red.persist import save_result

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("train")


def load_config(config_path):
    import yaml
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def create_malicious_samples(rule_set, malicious_type, search_fields):
    """Create normalized malicious sample list from rule set."""
    if malicious_type == "matches":
        events = get_all_matches(rule_set)
        samples = extract_commandlines(events, search_fields)
    else:  # rule_filters
        samples = get_all_filter_values(rule_set, search_fields)

    logger.info("Raw malicious samples: %d (%s)", len(samples), malicious_type)
    normalized = normalize_samples(samples)
    logger.info("Normalized malicious samples: %d", len(normalized))
    return normalized


def training_samples_iter(benign_path, malicious_samples, benign_field=None):
    """Yield all training samples: benign first, then malicious."""
    for sample in benign_samples_iter(benign_path, benign_field):
        yield sample
    for sample in malicious_samples:
        yield sample


def main():
    parser = argparse.ArgumentParser(description="Train misuse classification model")
    parser.add_argument("--config", type=str, help="Path to YAML config file")
    parser.add_argument("--benign-samples", type=str, help="Path to benign samples file")
    parser.add_argument("--events-dir", type=str, help="Path to events directory")
    parser.add_argument("--rules-dir", type=str, help="Path to rules directory")
    parser.add_argument("--model-type", type=str, default="misuse", choices=["misuse"])
    parser.add_argument("--malicious-samples", type=str, default="rule_filters",
                        choices=["rule_filters", "matches"])
    parser.add_argument("--search-fields", type=str, nargs="+",
                        default=["process.command_line"])
    parser.add_argument("--vectorization", type=str, default="tfidf",
                        choices=["tfidf", "count", "hashing", "binary_count", "scaled_count"])
    parser.add_argument("--ngram-range", type=str, default="(1,1)")
    parser.add_argument("--search-params", action="store_true",
                        help="Use GridSearchCV for hyperparameter optimization")
    parser.add_argument("--scoring", type=str, default="f1", choices=["f1", "mcc"])
    parser.add_argument("--cv", type=int, default=5)
    parser.add_argument("--num-jobs", type=int, default=3)
    parser.add_argument("--model-params", type=str, help="JSON file with fixed SVC params")
    parser.add_argument("--benign-field", type=str, default=None,
                        help="Dot-separated field path to extract from JSON/CSV benign data")
    parser.add_argument("--mcc-scaling", action="store_true", default=True)
    parser.add_argument("--mcc-threshold", type=float, default=0.1)
    parser.add_argument("--out-dir", type=str, default="models")
    parser.add_argument("--result-name", type=str, default="misuse_svc_rules_f1")
    args = parser.parse_args()

    # Load config file if provided (overrides CLI args)
    if args.config:
        cfg = load_config(args.config)
        data_cfg = cfg.get("data", {})
        train_cfg = cfg.get("training", {})
        scale_cfg = cfg.get("scaling", {})
        out_cfg = cfg.get("output", {})

        args.benign_samples = args.benign_samples or data_cfg.get("benign_train")
        args.events_dir = args.events_dir or data_cfg.get("events_dir")
        args.rules_dir = args.rules_dir or data_cfg.get("rules_dir")
        args.search_fields = data_cfg.get("search_fields", args.search_fields)
        args.benign_field = data_cfg.get("benign_field", None)
        args.malicious_samples = train_cfg.get("malicious_samples", args.malicious_samples)
        args.vectorization = train_cfg.get("vectorization", args.vectorization)
        args.search_params = train_cfg.get("search_params", args.search_params)
        args.scoring = train_cfg.get("scoring", args.scoring)
        args.cv = train_cfg.get("cv_folds", args.cv)
        args.num_jobs = train_cfg.get("num_jobs", args.num_jobs)
        args.mcc_scaling = scale_cfg.get("mcc_scaling", args.mcc_scaling)
        args.mcc_threshold = scale_cfg.get("mcc_threshold", args.mcc_threshold)
        args.out_dir = out_cfg.get("dir", args.out_dir)
        args.result_name = out_cfg.get("result_name", args.result_name)

        ngram = train_cfg.get("ngram_range", [1, 1])
        args.ngram_range = f"({ngram[0]},{ngram[1]})"

    # Validate required args
    if not args.benign_samples or not args.events_dir or not args.rules_dir:
        parser.error("--benign-samples, --events-dir, and --rules-dir are required")

    # Expand ~ in paths
    args.benign_samples = os.path.expanduser(args.benign_samples)
    args.events_dir = os.path.expanduser(args.events_dir)
    args.rules_dir = os.path.expanduser(args.rules_dir)
    args.out_dir = os.path.expanduser(args.out_dir)

    ngram_range = eval(args.ngram_range)

    # ── Step 1: Load data ──
    logger.info("Loading rule set data...")
    rule_set = load_rule_set(args.events_dir, args.rules_dir)

    # ── Step 2: Create malicious samples ──
    malicious_samples = create_malicious_samples(
        rule_set, args.malicious_samples, args.search_fields
    )

    # ── Step 3: Create vectorizer and transform ──
    logger.info("Fitting vectorizer (%s)...", args.vectorization)
    vectorizer = create_vectorizer(args.vectorization, ngram_range=ngram_range)

    num_benign = count_benign_samples(args.benign_samples, args.benign_field)
    feature_vectors = vectorizer.fit_transform(
        training_samples_iter(args.benign_samples, malicious_samples, args.benign_field)
    )
    labels = create_labels(num_benign, len(malicious_samples))

    logger.info(
        "Training data: %d samples (%d benign + %d malicious), %s features",
        len(labels), num_benign, len(malicious_samples),
        feature_vectors.shape[1] if hasattr(feature_vectors, 'shape') else "?"
    )

    # ── Step 4: Train model ──
    if args.search_params:
        estimator, best_params, best_score = train_svc_gridsearch(
            feature_vectors, labels,
            scoring=args.scoring,
            cv=args.cv,
            n_jobs=args.num_jobs,
        )
    elif args.model_params:
        with open(args.model_params) as f:
            params = json.load(f)
        estimator = train_svc_fixed(feature_vectors, labels, **params)
        best_params = params
        best_score = None
    else:
        estimator = train_svc_fixed(feature_vectors, labels)
        best_params = {"C": 1.0, "kernel": "linear", "class_weight": "balanced"}
        best_score = None

    # ── Step 5: Create MCC scaler ──
    scaler, shift = None, 0.0
    if args.mcc_scaling:
        df_values = estimator.decision_function(feature_vectors)
        scaler, shift = create_mcc_scaler(
            df_values, labels,
            num_samples=50,
            mcc_threshold=args.mcc_threshold,
        )

    # ── Step 6: Save result ──
    result = {
        "estimator": estimator,
        "vectorizer": vectorizer,
        "scaler": scaler,
        "shift": shift,
        "labels": labels,
        "best_params": best_params,
        "best_score": best_score,
        "config": {
            "malicious_samples": args.malicious_samples,
            "vectorization": args.vectorization,
            "ngram_range": ngram_range,
            "scoring": args.scoring,
            "mcc_scaling": args.mcc_scaling,
        },
    }

    info = {
        "result_name": args.result_name,
        "num_benign": num_benign,
        "num_malicious": len(malicious_samples),
        "num_features": feature_vectors.shape[1] if hasattr(feature_vectors, 'shape') else 0,
        "best_params": best_params,
        "best_score": best_score,
        "estimator_params": estimator.get_params(),
    }

    save_result(result, f"train_rslt_{args.result_name}", args.out_dir, info=info)
    logger.info("Training complete. Result saved to %s/", args.out_dir)


if __name__ == "__main__":
    main()
