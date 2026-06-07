#!/usr/bin/env python3
"""Split per-rule event directories into train/valid/test (or valid/test only).

Used for match events (events_dir) and evasion variants (evasions_dir).

Stratification: each rule is split INDEPENDENTLY → every rule appears in
all output splits (proportionally), avoiding the issue where rare rules
fall entirely into one split.

Input structure:
    INPUT_DIR/
    ├── rule_a/event1.json, event2.json, ...
    ├── rule_b/event1.json, ...
    └── ...

Output structure (3-way):
    OUTPUT_BASE_train/rule_a/event1.json, event2.json, ...
    OUTPUT_BASE_valid/rule_a/event3.json, ...
    OUTPUT_BASE_test/rule_a/event4.json, ...
    OUTPUT_BASE_train/rule_b/...
    ...

Output structure (2-way, e.g. for evasion):
    OUTPUT_BASE_valid/rule_a/...
    OUTPUT_BASE_test/rule_a/...

Usage:

# 3-way 70/15/15 for match events
python scripts/split_events.py \\
    --input-dir ~/data/sigma/events_hayabusa/windows/process_creation \\
    --output-base ~/data/sigma/events_hayabusa/windows/process_creation \\
    --ratios 0.70 0.15 0.15 --seed 42

# 2-way 50/50 for evasion (no train)
python scripts/split_events.py \\
    --input-dir ~/data/sigma/evasions/windows/process_creation \\
    --output-base ~/data/sigma/evasions/windows/process_creation \\
    --ratios 0.0 0.5 0.5 --seed 42
"""

import argparse
import json
import os
import random
import shutil
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Stratified split per-rule events into train/valid/test"
    )
    parser.add_argument("--input-dir", required=True,
                        help="Input dir containing per-rule subdirectories of JSON events")
    parser.add_argument("--output-base", required=True,
                        help="Output base path. Suffixes _train, _valid, _test will be appended")
    parser.add_argument("--ratios", nargs=3, type=float, required=True,
                        metavar=("TRAIN", "VALID", "TEST"),
                        help="3 ratios summing to 1.0. Use 0.0 for train to skip (e.g. evasion)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--min-events", type=int, default=10,
                        help="Skip rules with fewer than this many events (default 10)")
    parser.add_argument("--copy-mode", choices=("copy", "symlink", "hardlink"),
                        default="copy",
                        help="How to materialize files in output dirs (default copy)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print stats without writing files")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing output dirs")
    args = parser.parse_args()

    train_r, valid_r, test_r = args.ratios
    total = train_r + valid_r + test_r
    if abs(total - 1.0) > 1e-6:
        parser.error(f"Ratios must sum to 1.0 (got {total})")
    if min(train_r, valid_r, test_r) < 0:
        parser.error("Ratios must be >= 0")
    if valid_r == 0 and test_r == 0:
        parser.error("At least one of valid/test must be > 0")

    input_dir = Path(os.path.expanduser(args.input_dir)).resolve()
    if not input_dir.is_dir():
        sys.exit(f"Input dir not found: {input_dir}")

    output_base = Path(os.path.expanduser(args.output_base)).resolve()
    out_train = Path(f"{output_base}_train")
    out_valid = Path(f"{output_base}_valid")
    out_test = Path(f"{output_base}_test")

    # ── Pre-flight checks ──
    for out_dir, ratio in [(out_train, train_r), (out_valid, valid_r), (out_test, test_r)]:
        if ratio == 0:
            continue
        if out_dir.exists():
            if args.force:
                if not args.dry_run:
                    shutil.rmtree(out_dir)
                    print(f"[force] Removed existing {out_dir}")
            else:
                sys.exit(f"Output dir already exists (use --force to overwrite): {out_dir}")

    # ── Process per-rule ──
    rule_dirs = sorted([
        p for p in input_dir.iterdir()
        if p.is_dir() and not p.name.startswith(".")
    ])

    if not rule_dirs:
        sys.exit(f"No rule subdirectories found in {input_dir}")

    random.seed(args.seed)

    total_in = 0
    total_train = 0
    total_valid = 0
    total_test = 0
    skipped_rules = []
    processed_rules = 0

    for rule_dir in rule_dirs:
        json_files = sorted([f for f in rule_dir.glob("*.json")])
        n = len(json_files)
        total_in += n

        if n < args.min_events:
            skipped_rules.append((rule_dir.name, n))
            continue

        # Shuffle deterministically per-rule with rule-specific seed offset
        # (so changing one rule's content doesn't affect other rules' splits)
        rule_rng = random.Random(args.seed + hash(rule_dir.name) % 100000)
        shuffled = json_files[:]
        rule_rng.shuffle(shuffled)

        n_train = int(n * train_r)
        n_valid = int(n * valid_r)
        # test gets the remainder
        train_files = shuffled[:n_train]
        valid_files = shuffled[n_train:n_train + n_valid]
        test_files = shuffled[n_train + n_valid:]

        # Edge case: if valid_r > 0 but n_valid rounded to 0, take at least 1
        if valid_r > 0 and len(valid_files) == 0 and len(test_files) > 1:
            valid_files = [test_files.pop(0)]
        if test_r > 0 and len(test_files) == 0 and len(valid_files) > 1:
            test_files = [valid_files.pop(-1)]

        total_train += len(train_files)
        total_valid += len(valid_files)
        total_test += len(test_files)
        processed_rules += 1

        if not args.dry_run:
            for files, out_dir in [
                (train_files, out_train),
                (valid_files, out_valid),
                (test_files, out_test),
            ]:
                if not files:
                    continue
                dst_dir = out_dir / rule_dir.name
                dst_dir.mkdir(parents=True, exist_ok=True)
                for src in files:
                    dst = dst_dir / src.name
                    if args.copy_mode == "copy":
                        shutil.copy2(src, dst)
                    elif args.copy_mode == "symlink":
                        if dst.exists() or dst.is_symlink():
                            dst.unlink()
                        os.symlink(src, dst)
                    elif args.copy_mode == "hardlink":
                        if dst.exists():
                            dst.unlink()
                        os.link(src, dst)

    # ── Report ──
    print("─" * 70)
    print(f"Input dir:     {input_dir}")
    print(f"Total rules:   {len(rule_dirs)}")
    print(f"Processed:     {processed_rules}")
    print(f"Skipped rules: {len(skipped_rules)} (rules with <{args.min_events} events)")
    if skipped_rules and len(skipped_rules) <= 20:
        for name, n in skipped_rules:
            print(f"  - {name[:60]:<60} ({n} events)")
    elif skipped_rules:
        print(f"  (first 5)")
        for name, n in skipped_rules[:5]:
            print(f"  - {name[:60]:<60} ({n} events)")
    print("─" * 70)
    print(f"Total events:  {total_in}")
    used = total_train + total_valid + total_test
    print(f"Used:          {used} ({used/max(total_in,1)*100:.1f}%)")
    print(f"Train: {total_train:>6} ({total_train/max(used,1)*100:5.1f}%) → {out_train}")
    print(f"Valid: {total_valid:>6} ({total_valid/max(used,1)*100:5.1f}%) → {out_valid}")
    print(f"Test:  {total_test:>6} ({total_test/max(used,1)*100:5.1f}%) → {out_test}")
    if args.dry_run:
        print("(DRY RUN — no files written)")


if __name__ == "__main__":
    main()
