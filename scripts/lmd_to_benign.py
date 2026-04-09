#!/usr/bin/env python3
"""
Convert LMD Collections CSV → benign text files per event type.

Usage:
    python3 lmd_to_benign.py \
        --lmd-dir ~/KLTN/KLTN/datasets/benign_data/Lateral-Movement-Dataset--LMD_Collections \
        --output-dir ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection/data/benign
"""

import argparse
import csv
import logging
from pathlib import Path
from collections import defaultdict

csv.field_size_limit(10 * 1024 * 1024)  # 10MB — handle long CommandLine fields

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

EVENT_MAP = {
    "1":  ("process_creation", "CommandLine"),
    "12": ("registry_event",   "TargetObject"),
    "13": ("registry_event",   "TargetObject"),
    "14": ("registry_event",   "TargetObject"),
}

LMD_NORMAL_FILES = [
    "LMD-2022/LMD-2022 [870K Elements]/Labelled LMD-2022/Labelled Subsets/Normal.csv",
    "LMD-2023/LMD-2023 [2.3M Elements]/LMD-2023 [2.3M Elements]Checked/Labelled LMD-2023/Labelled Subsets/LMD-2023 [2.3M Elements - Normal]checked.csv",
]


def convert(lmd_dir: str, output_dir: str):
    lmd_path = Path(lmd_dir)
    out_path = Path(output_dir)

    # Collect into sets for automatic deduplication
    samples = defaultdict(set)  # etype -> set of values

    for rel_path in LMD_NORMAL_FILES:
        csv_path = lmd_path / rel_path
        if not csv_path.exists():
            logger.warning("File not found: %s", csv_path)
            continue

        logger.info("Processing: %s", csv_path.name)
        with open(csv_path, encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                eid = str(row.get("EventID", "")).strip().split(".")[0]
                if eid not in EVENT_MAP:
                    continue
                etype, field = EVENT_MAP[eid]
                value = row.get(field, "").strip()
                if not value or value in ("0", "-", ""):
                    continue
                samples[etype].add(value)

    # Write deduplicated samples
    for etype, values in sorted(samples.items()):
        out_dir = out_path / etype
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "benign_train.txt"
        with open(out_file, "w", encoding="utf-8") as f:
            for v in sorted(values):
                f.write(v + "\n")
        logger.info("  %s: %d samples (deduplicated) → %s", etype, len(values), out_file)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lmd-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    convert(args.lmd_dir, args.output_dir)


if __name__ == "__main__":
    main()
