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
import csv
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from red.data import load_rule_set, extract_commandlines, resolve_event_paths
from red.normalize import Normalizer
from red.attribution import RuleAttributionEvaluation, reciprocal_rank_fusion
from red.persist import load_result, save_result

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("eval_attribution")


def _true_rank(true_rule, ranked_attributions):
    """Return 1-based rank of true_rule, or None if absent."""
    for idx, (rule_name, _) in enumerate(ranked_attributions, start=1):
        if rule_name == true_rule:
            return idx
    return None


def _build_detail_rows(samples, normalized_samples, evasion_to_rule, rankings, top_k):
    """Create per-sample attribution detail rows for CSV/JSONL export."""
    rows = []
    for idx, sample in enumerate(samples):
        true_rule = evasion_to_rule[sample]
        ranked = rankings[idx]
        top_items = ranked[:top_k]
        rank = _true_rank(true_rule, ranked)
        rows.append({
            "sample_index": idx,
            "sample": sample,
            "sample_preview": sample[:240],
            "normalized_sample": normalized_samples[idx],
            "true_rule": true_rule,
            "true_rank": rank,
            "is_top_1": rank == 1,
            "is_top_k": rank is not None and rank <= top_k,
            "top_rules": [
                {"rank": i + 1, "rule": rule, "score": float(score)}
                for i, (rule, score) in enumerate(top_items)
            ],
        })
    return rows


def _write_detail_exports(rows, out_dir, result_stem, top_k):
    """Write per-sample attribution details to JSONL and CSV."""
    jsonl_path = os.path.join(out_dir, f"{result_stem}_details_top{top_k}.jsonl")
    csv_path = os.path.join(out_dir, f"{result_stem}_details_top{top_k}.csv")

    def _open_writable(path, **kwargs):
        try:
            return open(path, "w", **kwargs), path
        except PermissionError:
            base, ext = os.path.splitext(path)
            for suffix in ("new", "new_2", "new_3", "new_4", "new_5"):
                fallback = f"{base}_{suffix}{ext}"
                try:
                    return open(fallback, "w", **kwargs), fallback
                except PermissionError:
                    continue
            raise

    jsonl_file, jsonl_path = _open_writable(jsonl_path, encoding="utf-8")
    with jsonl_file as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    fieldnames = [
        "sample_index", "true_rule", "true_rank", "is_top_1", "is_top_k",
        "sample", "sample_preview", "normalized_sample",
    ]
    for i in range(1, top_k + 1):
        fieldnames.extend([f"top_{i}_rule", f"top_{i}_score"])

    csv_file, csv_path = _open_writable(csv_path, encoding="utf-8", newline="")
    with csv_file as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            flat = {
                "sample_index": row["sample_index"],
                "true_rule": row["true_rule"],
                "true_rank": row["true_rank"],
                "is_top_1": row["is_top_1"],
                "is_top_k": row["is_top_k"],
                "sample": row["sample"],
                "sample_preview": row["sample_preview"],
                "normalized_sample": row["normalized_sample"],
            }
            for item in row["top_rules"]:
                rank = item["rank"]
                flat[f"top_{rank}_rule"] = item["rule"]
                flat[f"top_{rank}_score"] = item["score"]
            writer.writerow(flat)

    return jsonl_path, csv_path


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
    parser.add_argument("--top-k-details", type=int, default=3,
                        help="Number of top ranked rules to export per sample")
    parser.add_argument("--no-details", action="store_true",
                        help="Do not export per-sample attribution detail CSV/JSONL")
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
        args.search_fields = data_cfg.get("search_fields", ["CommandLine"])
        args.event_field_map = data_cfg.get("event_field_map", {})
        args.out_dir = out_cfg.get("dir", args.out_dir)
        if not args.result_path:
            attr_result_path = out_cfg.get("attr_result_path")
            if not attr_result_path:
                attr_result_name = out_cfg.get("attr_result_name")
                if attr_result_name and args.out_dir:
                    attr_result_path = os.path.join(args.out_dir, f"train_rslt_{attr_result_name}.zip")
            args.result_path = attr_result_path
    else:
        args.search_fields = ["CommandLine"]
        args.event_field_map = {}

    args.events_dir = os.path.expanduser(args.events_dir) if args.events_dir else args.events_dir
    args.rules_dir = os.path.expanduser(args.rules_dir) if args.rules_dir else args.rules_dir
    args.out_dir = os.path.expanduser(args.out_dir) if args.out_dir else args.out_dir

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
    event_paths = resolve_event_paths(args.search_fields, args.event_field_map)
    logger.info("Sigma fields: %s → event paths: %s", args.search_fields, event_paths)
    evasion_to_rule = {}
    normalizer = Normalizer()

    for rule_name, rule_data in rule_set.items():
        if len(rule_data.evasions) == 0:
            continue
        evasion_cmdlines = extract_commandlines(rule_data.evasions, event_paths)
        for cmd in evasion_cmdlines:
            evasion_to_rule[cmd] = rule_name

    if not evasion_to_rule:
        logger.warning(
            "No evasion samples found; falling back to match events for attribution "
            "evaluation. This is useful for event types such as registry_event where "
            "synthetic evasions may be unavailable."
        )
        for rule_name, rule_data in rule_set.items():
            match_cmdlines = extract_commandlines(rule_data.matches, event_paths)
            for cmd in match_cmdlines:
                evasion_to_rule[cmd] = rule_name

    logger.info("Total attribution evaluation samples: %d", len(evasion_to_rule))

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
    detail_rows = _build_detail_rows(
        sorted_evasions, normalized, evasion_to_rule,
        per_sample_ranked, args.top_k_details,
    )

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
    result_stem = f"eval_attr_{args.method}_{result_name}"
    if not args.no_details:
        jsonl_path, csv_path = _write_detail_exports(
            detail_rows, args.out_dir, result_stem, args.top_k_details,
        )
        logger.info("Saved attribution details to %s", csv_path)
        logger.info("Saved attribution details to %s", jsonl_path)
        summary["details_csv"] = csv_path
        summary["details_jsonl"] = jsonl_path
        summary["details_top_k"] = args.top_k_details
    eval_data = {
        "evaluation": eval_result,
        "summary": summary,
        "method": args.method,
        "details": detail_rows,
    }
    save_result(
        eval_data,
        result_stem,
        args.out_dir,
        info=summary,
    )
    logger.info("Attribution evaluation complete.")


if __name__ == "__main__":
    main()
