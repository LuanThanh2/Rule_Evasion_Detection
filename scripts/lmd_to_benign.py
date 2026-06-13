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


def find_normal_csvs(lmd_path: Path) -> list:
    """Tự động tìm tất cả file CSV chứa 'Normal' trong tên, bỏ qua Preprocessed."""
    found = sorted(
        p for p in lmd_path.rglob("*.csv")
        if "Normal" in p.name and "Preprocessed" not in str(p)
    )
    return found


def convert(lmd_dir: str, output_dir: str, csv_files: list = None):
    lmd_path = Path(lmd_dir)
    out_path = Path(output_dir)

    if csv_files:
        normal_files = [Path(f) for f in csv_files]
    else:
        normal_files = find_normal_csvs(lmd_path)

    if not normal_files:
        logger.error("Không tìm thấy file Normal CSV nào trong: %s", lmd_path)
        return

    logger.info("Tìm thấy %d file Normal CSV:", len(normal_files))
    for p in normal_files:
        logger.info("  %s", p)

    # Collect into sets for automatic deduplication
    samples = defaultdict(set)  # etype -> set of values

    for csv_path in normal_files:
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
    parser.add_argument("--lmd-dir", required=True,
                        help="Thư mục gốc chứa LMD Collections (tự động tìm file Normal CSV)")
    parser.add_argument("--output-dir", required=True,
                        help="Thư mục output cho benign_train.txt")
    parser.add_argument("--files", nargs="+", default=None,
                        help="Chỉ định file CSV cụ thể (bỏ qua auto-discover)")
    args = parser.parse_args()
    convert(args.lmd_dir, args.output_dir, csv_files=args.files)


if __name__ == "__main__":
    main()
