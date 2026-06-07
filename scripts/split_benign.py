#!/usr/bin/env python3
"""Split a benign data file into train/val/test sets via random shuffle.

3-way split (default):
    python scripts/split_benign.py \
        --input ~/data/benign/process_creation/benign_train.txt \
        --train-ratio 0.70 --valid-ratio 0.15 --test-ratio 0.15

Outputs (cùng thư mục với input):
    benign_train_split_train.txt   (70%)
    benign_train_split_valid.txt   (15%)
    benign_train_split_test.txt    (15%)

2-way split (backward compat, khi không truyền --test-ratio):
    python scripts/split_benign.py --input X.txt --train-ratio 0.8
    → X_split_train.txt (80%) + X_split_val.txt (20%)

Cập nhật config sau khi split 3-way:
    data:
      benign_train: ~/data/benign/process_creation/benign_train_split_train.txt
      benign_valid: ~/data/benign/process_creation/benign_train_split_valid.txt
      benign_test:  ~/data/benign/process_creation/benign_train_split_test.txt
"""

import argparse
import os
import random
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Split benign data → train/val/test")
    parser.add_argument("--input", required=True,
                        help="Path to benign data file (txt/jsonl/csv)")
    parser.add_argument("--train-ratio", type=float, default=0.70,
                        help="Tỉ lệ train (default 0.70)")
    parser.add_argument("--valid-ratio", type=float, default=None,
                        help="Tỉ lệ validation (default None — fallback 2-way)")
    parser.add_argument("--test-ratio", type=float, default=None,
                        help="Tỉ lệ test (default None — fallback 2-way)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out-train", default=None)
    parser.add_argument("--out-valid", default=None)
    parser.add_argument("--out-test", default=None)
    # Backward compat alias
    parser.add_argument("--out-val", default=None,
                        help="Alias of --out-valid (backward compat)")
    args = parser.parse_args()

    input_path = Path(os.path.expanduser(args.input))
    if not input_path.is_file():
        raise SystemExit(f"File not found: {input_path}")

    # ── Determine split mode ──
    # 3-way if any of --valid-ratio or --test-ratio is provided
    three_way = (args.valid_ratio is not None) or (args.test_ratio is not None)

    if three_way:
        # Both must be provided for 3-way
        if args.valid_ratio is None or args.test_ratio is None:
            parser.error("3-way split requires both --valid-ratio and --test-ratio")
        total = args.train_ratio + args.valid_ratio + args.test_ratio
        if abs(total - 1.0) > 1e-6:
            parser.error(f"train + valid + test must equal 1.0 (got {total})")
    else:
        # Legacy 2-way: train + (1 - train)
        if args.train_ratio <= 0 or args.train_ratio >= 1:
            parser.error("--train-ratio must be in (0, 1) for 2-way split")

    # ── Resolve output paths ──
    if three_way:
        train_path = Path(os.path.expanduser(args.out_train)) if args.out_train \
            else input_path.parent / f"{input_path.stem}_split_train.txt"
        valid_path = Path(os.path.expanduser(args.out_valid)) if args.out_valid \
            else input_path.parent / f"{input_path.stem}_split_valid.txt"
        test_path = Path(os.path.expanduser(args.out_test)) if args.out_test \
            else input_path.parent / f"{input_path.stem}_split_test.txt"
    else:
        train_path = Path(os.path.expanduser(args.out_train)) if args.out_train \
            else input_path.parent / f"{input_path.stem}_split_train.txt"
        val_path = Path(os.path.expanduser(args.out_valid or args.out_val)) \
            if (args.out_valid or args.out_val) \
            else input_path.parent / f"{input_path.stem}_split_val.txt"

    # ── Read & shuffle ──
    with open(input_path, encoding="utf-8", errors="ignore") as f:
        lines = [ln for ln in f if ln.strip()]

    if len(lines) < 100:
        print(f"WARNING: chỉ có {len(lines)} dòng — quá ít để split có ý nghĩa")

    random.seed(args.seed)
    random.shuffle(lines)

    n = len(lines)

    if three_way:
        n_train = int(n * args.train_ratio)
        n_valid = int(n * args.valid_ratio)
        # test = remaining (avoid rounding loss)
        train_lines = lines[:n_train]
        valid_lines = lines[n_train:n_train + n_valid]
        test_lines = lines[n_train + n_valid:]

        train_path.write_text("".join(train_lines), encoding="utf-8")
        valid_path.write_text("".join(valid_lines), encoding="utf-8")
        test_path.write_text("".join(test_lines), encoding="utf-8")

        print(f"Tổng:  {n} samples (seed={args.seed})")
        print(f"Train: {len(train_lines):>7} ({len(train_lines)/n*100:.1f}%) → {train_path}")
        print(f"Valid: {len(valid_lines):>7} ({len(valid_lines)/n*100:.1f}%) → {valid_path}")
        print(f"Test:  {len(test_lines):>7} ({len(test_lines)/n*100:.1f}%) → {test_path}")
    else:
        split = int(n * args.train_ratio)
        train_lines = lines[:split]
        val_lines = lines[split:]

        train_path.write_text("".join(train_lines), encoding="utf-8")
        val_path.write_text("".join(val_lines), encoding="utf-8")

        print(f"Tổng:  {n} samples (seed={args.seed})")
        print(f"Train: {len(train_lines):>7} → {train_path}")
        print(f"Val:   {len(val_lines):>7} → {val_path}")


if __name__ == "__main__":
    main()
