#!/usr/bin/env python3
"""Generate plots from evaluation results.

Supports two plot types:
  - pr: Precision-Recall-Threshold plot (from BinaryEvaluationResult)
  - attr: Rule Attribution distribution + CDF (from RuleAttributionEvaluationResult)

Usage:
  python scripts/plot.py pr --result-paths models/eval_rslt_*.zip --output figures/fig3.pdf
  python scripts/plot.py attr --result-path models/eval_attr_*.zip --output figures/fig4.pdf
"""

import os
import sys
import argparse
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from red.persist import load_result
from red.visualize import plot_pr_threshold, plot_attribution

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("plot")


def cmd_pr(args):
    """Generate Precision-Recall-Threshold plot."""
    evaluations = []
    labels = []
    for path in args.result_paths:
        data = load_result(path)
        evaluations.append(data["evaluation"])
        name = os.path.basename(path).replace("eval_rslt_", "").replace(".zip", "")
        labels.append(name)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    plot_pr_threshold(evaluations, labels=labels, output_path=args.output, title=args.title)
    logger.info("PR plot saved to %s", args.output)


def cmd_attr(args):
    """Generate Rule Attribution plot."""
    data = load_result(args.result_path)
    eval_result = data["evaluation"]

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    plot_attribution(eval_result.top_n_hits, output_path=args.output, title=args.title)
    logger.info("Attribution plot saved to %s", args.output)


def main():
    parser = argparse.ArgumentParser(description="Generate plots from evaluation results")
    subparsers = parser.add_subparsers(dest="command")

    # PR plot
    pr_parser = subparsers.add_parser("pr", help="Precision-Recall-Threshold plot")
    pr_parser.add_argument("--result-paths", type=str, nargs="+", required=True)
    pr_parser.add_argument("--output", type=str, default="figures/pr_threshold.pdf")
    pr_parser.add_argument("--title", type=str, default="Misuse Classification (C1/C2)")

    # Attribution plot
    attr_parser = subparsers.add_parser("attr", help="Rule Attribution plot")
    attr_parser.add_argument("--result-path", type=str, required=True)
    attr_parser.add_argument("--output", type=str, default="figures/attribution.pdf")
    attr_parser.add_argument("--title", type=str, default="Rule Attribution (C3)")

    args = parser.parse_args()

    if args.command == "pr":
        cmd_pr(args)
    elif args.command == "attr":
        cmd_attr(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
