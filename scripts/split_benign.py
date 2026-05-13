#!/usr/bin/env python3
"""Split a benign data file into train/val sets via random shuffle.

Usage:
    python scripts/split_benign.py \
        --input ~/data/benign/process_creation/benign_train.txt \
        --train-ratio 0.8

Outputs (cùng thư mục với input):
    benign_train_split_train.txt   (80%)
    benign_train_split_val.txt     (20%)

Sau đó cập nhật config:
    data:
      benign_train: ~/data/benign/process_creation/benign_train_split_train.txt
      benign_valid: ~/data/benign/process_creation/benign_train_split_val.txt
"""

import argparse
import os
import random
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Split benign data → train/val")
    parser.add_argument("--input", required=True,
                        help="Path to benign data file (txt/jsonl/csv)")
    parser.add_argument("--train-ratio", type=float, default=0.8,
                        help="Tỉ lệ train (default 0.8)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out-train", default=None)
    parser.add_argument("--out-val", default=None)
    args = parser.parse_args()

    input_path = Path(os.path.expanduser(args.input))
    if not input_path.is_file():
        raise SystemExit(f"File not found: {input_path}")

    if args.out_train:
        train_path = Path(os.path.expanduser(args.out_train))
    else:
        train_path = input_path.parent / f"{input_path.stem}_split_train.txt"
    if args.out_val:
        val_path = Path(os.path.expanduser(args.out_val))
    else:
        val_path = input_path.parent / f"{input_path.stem}_split_val.txt"

    with open(input_path, encoding="utf-8", errors="ignore") as f:
        lines = [ln for ln in f if ln.strip()]

    if len(lines) < 100:
        print(f"WARNING: chỉ có {len(lines)} dòng — quá ít để split có ý nghĩa")

    random.seed(args.seed)
    random.shuffle(lines)

    split = int(len(lines) * args.train_ratio)
    train_lines = lines[:split]
    val_lines = lines[split:]

    train_path.write_text("".join(train_lines), encoding="utf-8")
    val_path.write_text("".join(val_lines), encoding="utf-8")

    print(f"Tổng:  {len(lines)} samples (seed={args.seed})")
    print(f"Train: {len(train_lines):>6} → {train_path}")
    print(f"Val:   {len(val_lines):>6} → {val_path}")


if __name__ == "__main__":
    main()
