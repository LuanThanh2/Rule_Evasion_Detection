#!/usr/bin/env python3
"""Sanity-check that split_events.py produced consistent train/valid/test dirs.

Verifies:
  1. Total events in (train + valid + test) ≤ total in source (skipped rules excluded)
  2. No overlap between train/valid/test for any rule
  3. Each rule appears in at least valid + test (or just valid+test for evasion)
  4. Distribution ratios per rule are close to expected

Usage:
    python scripts/verify_split.py \\
        --source ~/data/sigma/events_hayabusa/windows/process_creation \\
        --train  ~/data/sigma/events_hayabusa/windows/process_creation_train \\
        --valid  ~/data/sigma/events_hayabusa/windows/process_creation_valid \\
        --test   ~/data/sigma/events_hayabusa/windows/process_creation_test \\
        --expect-ratios 0.70 0.15 0.15

    # For evasion (2-way 50/50):
    python scripts/verify_split.py \\
        --source ~/data/sigma/evasions/windows/process_creation \\
        --valid  ~/data/sigma/evasions/windows/process_creation_valid \\
        --test   ~/data/sigma/evasions/windows/process_creation_test \\
        --expect-ratios 0.0 0.5 0.5
"""

import argparse
import os
import sys
from pathlib import Path


def list_rule_files(base_dir):
    """Return dict[rule_name → set[file_basename]]."""
    base = Path(base_dir)
    out = {}
    if not base.is_dir():
        return out
    for rule_dir in base.iterdir():
        if not rule_dir.is_dir():
            continue
        files = {p.name for p in rule_dir.glob("*.json")}
        out[rule_dir.name] = files
    return out


def main():
    parser = argparse.ArgumentParser(description="Verify split quality")
    parser.add_argument("--source", required=True, help="Source dir before split")
    parser.add_argument("--train", default=None, help="Train dir (omit for 2-way)")
    parser.add_argument("--valid", required=True, help="Valid dir")
    parser.add_argument("--test", required=True, help="Test dir")
    parser.add_argument("--expect-ratios", nargs=3, type=float,
                        metavar=("TRAIN", "VALID", "TEST"),
                        default=[0.70, 0.15, 0.15])
    parser.add_argument("--tolerance", type=float, default=0.05,
                        help="Allowed deviation from expected ratio (default ±0.05)")
    parser.add_argument("--min-events", type=int, default=10,
                        help="Rules with <N events in source are excluded (default 10)")
    args = parser.parse_args()

    src = Path(os.path.expanduser(args.source))
    train_dir = Path(os.path.expanduser(args.train)) if args.train else None
    valid_dir = Path(os.path.expanduser(args.valid))
    test_dir = Path(os.path.expanduser(args.test))

    if not src.is_dir():
        sys.exit(f"Source not found: {src}")
    if not valid_dir.is_dir():
        sys.exit(f"Valid dir not found: {valid_dir}")
    if not test_dir.is_dir():
        sys.exit(f"Test dir not found: {test_dir}")

    train_r, valid_r, test_r = args.expect_ratios

    src_files = list_rule_files(src)
    train_files = list_rule_files(train_dir) if train_dir else {}
    valid_files = list_rule_files(valid_dir)
    test_files = list_rule_files(test_dir)

    print("─" * 80)
    print(f"Source:      {src}  ({len(src_files)} rules, {sum(len(v) for v in src_files.values())} events)")
    if train_dir:
        print(f"Train:       {train_dir}  ({len(train_files)} rules, {sum(len(v) for v in train_files.values())} events)")
    print(f"Valid:       {valid_dir}  ({len(valid_files)} rules, {sum(len(v) for v in valid_files.values())} events)")
    print(f"Test:        {test_dir}  ({len(test_files)} rules, {sum(len(v) for v in test_files.values())} events)")
    print(f"Expected:    train={train_r:.2f}, valid={valid_r:.2f}, test={test_r:.2f} (tolerance ±{args.tolerance})")
    print("─" * 80)

    issues = []
    rules_below_min = []
    rules_with_bad_ratio = []
    rules_with_overlap = []
    rules_missing_in_split = []

    for rule_name, src_set in src_files.items():
        n_src = len(src_set)
        if n_src < args.min_events:
            rules_below_min.append((rule_name, n_src))
            continue

        n_train = len(train_files.get(rule_name, set()))
        n_valid = len(valid_files.get(rule_name, set()))
        n_test = len(test_files.get(rule_name, set()))

        total_split = n_train + n_valid + n_test
        # Allow small loss (rounding); tolerate up to 1 missing file
        if total_split < n_src - 1 or total_split > n_src:
            issues.append(
                f"  Rule {rule_name[:60]:<60}: src={n_src} split={total_split} "
                f"(train={n_train} valid={n_valid} test={n_test})"
            )

        # Overlap check
        train_set = train_files.get(rule_name, set())
        valid_set = valid_files.get(rule_name, set())
        test_set = test_files.get(rule_name, set())
        tv = train_set & valid_set
        tt = train_set & test_set
        vt = valid_set & test_set
        if tv or tt or vt:
            rules_with_overlap.append((rule_name, len(tv), len(tt), len(vt)))

        # Ratio check (only for the non-zero expected ratios)
        if valid_r > 0 and n_src >= 20:
            ratio_v = n_valid / n_src
            if abs(ratio_v - valid_r) > args.tolerance:
                rules_with_bad_ratio.append(
                    (rule_name, "valid", ratio_v, valid_r, n_src)
                )
        if test_r > 0 and n_src >= 20:
            ratio_t = n_test / n_src
            if abs(ratio_t - test_r) > args.tolerance:
                rules_with_bad_ratio.append(
                    (rule_name, "test", ratio_t, test_r, n_src)
                )

        # Missing-in-split check (rule should appear in valid AND test if both expected)
        if valid_r > 0 and n_valid == 0 and n_src >= args.min_events:
            rules_missing_in_split.append((rule_name, "valid", n_src))
        if test_r > 0 and n_test == 0 and n_src >= args.min_events:
            rules_missing_in_split.append((rule_name, "test", n_src))

    # ── Report ──
    print(f"\n✓ Rules below min ({args.min_events}): {len(rules_below_min)} (expected to be skipped)")
    if rules_below_min and len(rules_below_min) <= 10:
        for name, n in rules_below_min:
            print(f"    {name[:60]:<60} ({n} events)")

    print(f"\n{'✓' if not issues else '✗'} Total counts consistent: {len(issues)} issue(s)")
    for issue in issues[:10]:
        print(issue)
    if len(issues) > 10:
        print(f"    ... and {len(issues)-10} more")

    print(f"\n{'✓' if not rules_with_overlap else '✗'} No overlap: {len(rules_with_overlap)} rule(s) with overlap")
    for name, tv, tt, vt in rules_with_overlap[:10]:
        print(f"    {name[:50]:<50}: train∩valid={tv} train∩test={tt} valid∩test={vt}")

    print(f"\n{'✓' if not rules_missing_in_split else '⚠'} Rules missing from split: {len(rules_missing_in_split)}")
    for name, where, n in rules_missing_in_split[:10]:
        print(f"    {name[:50]:<50}: missing from {where} (source had {n})")

    print(f"\n{'✓' if not rules_with_bad_ratio else '⚠'} Rules with out-of-tolerance ratios: {len(rules_with_bad_ratio)}")
    for name, where, actual, expected, n in rules_with_bad_ratio[:10]:
        print(f"    {name[:40]:<40}: {where}_ratio={actual:.2f} expected={expected:.2f} (n_src={n})")

    print("\n" + "─" * 80)
    n_critical = len(issues) + len(rules_with_overlap)
    if n_critical == 0:
        print(f"✓ SPLIT OK (warnings: {len(rules_missing_in_split) + len(rules_with_bad_ratio)})")
        return 0
    else:
        print(f"✗ SPLIT HAS ISSUES: {n_critical} critical, {len(rules_missing_in_split) + len(rules_with_bad_ratio)} warnings")
        return 1


if __name__ == "__main__":
    sys.exit(main())
