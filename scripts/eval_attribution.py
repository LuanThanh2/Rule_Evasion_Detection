#!/usr/bin/env python3
"""Evaluate rule attribution models (C3).

For each evasion sample, scores it against all per-rule classifiers,
ranks rules by decision_function value, and checks the position of the
true evaded rule in the ranking.

Pipeline:
  1. Load MultiTrainingResult (per-rule models)
  2. Load rule set data to get evasion → rule mapping
  3. For each evasion: normalize, score with all rule models, rank
  4. Calculate top-k hit rates
  5. Save RuleAttributionEvaluationResult

Usage:
  python scripts/eval_attribution.py --config config/process_creation.yaml
  python scripts/eval_attribution.py --result-path models/train_rslt_attr_*.zip \\
         --events-dir ... --rules-dir ...
"""

import os
import sys
import argparse
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from red.data import load_rule_set, extract_commandlines
from red.normalize import Normalizer
from red.attribution import RuleAttributionEvaluation, reciprocal_rank_fusion
from red.persist import load_result, save_result

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("eval_attribution")


def main():
    parser = argparse.ArgumentParser(description="Evaluate rule attribution models")
    parser.add_argument("--config", type=str, help="Path to YAML config file")
    parser.add_argument("--result-path", type=str, help="Path to attribution TrainingResult .zip")
    parser.add_argument("--events-dir", type=str)
    parser.add_argument("--rules-dir", type=str)
    parser.add_argument("--method", type=str, default="svm",
                        choices=["svm", "cosine", "hybrid"],
                        help="Scoring method: svm (per-rule SVM), cosine (similarity), or hybrid (RRF fusion)")
    parser.add_argument("--rrf-k", type=int, default=60,
                        help="RRF smoothing constant (only used by hybrid method)")
    parser.add_argument("--out-dir", type=str, default="models")
    args = parser.parse_args()

    if args.config:
        import yaml
        with open(args.config, "r") as f:
            cfg = yaml.safe_load(f)
        data_cfg = cfg.get("data", {})
        out_cfg = cfg.get("output", {})
        args.events_dir = args.events_dir or data_cfg.get("events_dir")
        args.rules_dir = args.rules_dir or data_cfg.get("rules_dir")
        args.evasions_dir = data_cfg.get("evasions_dir")
        args.out_dir = out_cfg.get("dir", args.out_dir)
        if not args.result_path:
            args.result_path = out_cfg.get("attr_result_path")

    if not args.result_path:
        parser.error("--result-path is required")
    if not args.events_dir or not args.rules_dir:
        parser.error("--events-dir and --rules-dir are required")

    # ── Step 1: Load attribution models ──
    logger.info("Loading attribution models from %s", args.result_path)
    multi_result = load_result(args.result_path)
    rule_models = multi_result["rule_models"]
    cosine_attributor = multi_result.get("cosine_attributor")
    logger.info("Loaded %d rule models (cosine: %s)",
                len(rule_models), "available" if cosine_attributor else "missing")

    if args.method in ("cosine", "hybrid") and cosine_attributor is None:
        parser.error(
            f"--method {args.method} requires a cosine attributor in the result file. "
            "Re-run train_attribution.py with --cosine (default)."
        )

    # ── Step 2: Load evasion data ──
    evasions_dir = os.path.expanduser(getattr(args, "evasions_dir", None) or "")
    evasions_dir = evasions_dir if os.path.isdir(evasions_dir) else None
    rule_set = load_rule_set(args.events_dir, args.rules_dir, evasions_dir=evasions_dir)

    # Build evasion → rule mapping
    evasion_to_rule = {}
    normalizer = Normalizer()

    for rule_name, rule_data in rule_set.items():
        if len(rule_data.evasions) == 0:
            continue
        evasion_cmdlines = extract_commandlines(rule_data.evasions)
        for cmd in evasion_cmdlines:
            evasion_to_rule[cmd] = rule_name

    logger.info("Total evasion samples: %d", len(evasion_to_rule))

    # ── Step 3: Normalize and score ──
    sorted_evasions = sorted(evasion_to_rule.keys())
    normalized = [normalizer.normalize(ev) for ev in sorted_evasions]
    logger.info("Scoring with method: %s", args.method)

    # SVM rankings (computed when method is svm or hybrid)
    svm_rankings = None
    if args.method in ("svm", "hybrid"):
        sample_results = [{} for _ in sorted_evasions]
        for rule_name, model in rule_models.items():
            vectorizer = model["vectorizer"]
            estimator = model["estimator"]
            transformed = vectorizer.transform(normalized)
            df_values = estimator.decision_function(transformed)
            for i in range(len(sorted_evasions)):
                sample_results[i][rule_name] = float(df_values[i])
        svm_rankings = [
            sorted(scores.items(), key=lambda x: x[1], reverse=True)
            for scores in sample_results
        ]

    # Cosine rankings (computed when method is cosine or hybrid)
    cosine_rankings = None
    if args.method in ("cosine", "hybrid"):
        cosine_rankings = cosine_attributor.score_samples(normalized)

    # Final ranking depends on method
    if args.method == "svm":
        per_sample_ranked = svm_rankings
    elif args.method == "cosine":
        per_sample_ranked = cosine_rankings
    else:  # hybrid
        per_sample_ranked = [
            reciprocal_rank_fusion([svm_r, cos_r], k=args.rrf_k)
            for svm_r, cos_r in zip(svm_rankings, cosine_rankings)
        ]

    # ── Step 4: Evaluate rankings ──
    eval_result = RuleAttributionEvaluation(num_rules=len(rule_models))

    for i, evasion in enumerate(sorted_evasions):
        true_rule = evasion_to_rule[evasion]
        eval_result.evaluate_single(true_rule, per_sample_ranked[i])

    eval_result.calculate_hit_rates()

    summary = eval_result.summary()
    summary["method"] = args.method
    if args.method == "hybrid":
        summary["rrf_k"] = args.rrf_k
    logger.info("Attribution results (%s): %s", args.method, summary)

    # ── Step 5: Save ──
    result_name = os.path.basename(args.result_path).replace("train_rslt_", "").replace(".zip", "")
    eval_data = {
        "evaluation": eval_result,
        "summary": summary,
        "method": args.method,
    }
    save_result(
        eval_data,
        f"eval_attr_{args.method}_{result_name}",
        args.out_dir,
        info=summary,
    )
    logger.info("Attribution evaluation complete.")


if __name__ == "__main__":
    main()
