#!/usr/bin/env python3
"""
Verify evasion candidates with Zircolite's own detections.

A candidate is a TRUE evasion of its origin rule iff, after re-running Zircolite
on the transformed command line, the ORIGIN rule no longer matches it. (It may
still trip a different rule — that's fine, what matters is the targeted rule was
bypassed.)

Reads:
    --meta         : evasion_meta.json (evid -> origin rule + transformed cmd)
    --detections   : Zircolite output on the candidate JSONL
Writes true evasions to:
    <out-dir>/<rule_name>/<rule_name>_Evasion_<technique>_N.json
each carrying process.command_line (transformed), origin rule metadata, technique.

Usage:
    python3 linux_evasion_verify.py \
        --meta  /home/luanthanh/data/red_linux/work/evasion_meta.json \
        --detections /home/luanthanh/data/red_linux/work/detections_evasion.json \
        --out-dir /home/luanthanh/data/red_linux/evasions/linux/process_creation
"""

import argparse
import json
import os
import re
from collections import defaultdict
from pathlib import Path


def normalize_rule_name(title: str, max_len: int = 60) -> str:
    name = re.sub(r"[^\w]", "_", title).lower().strip("_")
    return re.sub(r"_+", "_", name)[:max_len].rstrip("_")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--meta", required=True)
    ap.add_argument("--detections", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    meta = json.load(open(os.path.expanduser(args.meta), encoding="utf-8"))
    detections = json.load(open(os.path.expanduser(args.detections), encoding="utf-8"))

    # evid -> set of rule_ids that still matched it
    evid_hits = defaultdict(set)
    for rule in detections:
        rid = rule.get("id", "")
        for m in rule.get("matches", []):
            evid = m.get("evid")
            if evid:
                evid_hits[evid].add(rid)

    out_dir = Path(os.path.expanduser(args.out_dir))
    out_dir.mkdir(parents=True, exist_ok=True)

    counters = defaultdict(int)
    n_true = n_still = 0
    per_rule_total = defaultdict(int)

    for evid, info in meta.items():
        origin = info["origin_rule_id"]
        per_rule_total[info["origin_rule_title"]] += 1
        if origin in evid_hits.get(evid, set()):
            n_still += 1          # origin rule still fires -> NOT an evasion
            continue
        n_true += 1

        rule_name = normalize_rule_name(info["origin_rule_title"])
        rule_dir = out_dir / rule_name
        rule_dir.mkdir(exist_ok=True)
        counters[rule_name] += 1
        ev = {
            "process": {"command_line": info["transformed_cmd"]},
            "rule_title": info["origin_rule_title"],
            "rule_id": origin,
            "sigmafile": info.get("origin_sigmafile", ""),
            "evasion_technique": info["technique"],
            "original_command_line": info["original_cmd"],
            "still_matched_other_rules": sorted(evid_hits.get(evid, set())),
        }
        fn = rule_dir / f"{rule_name}_Evasion_{info['technique']}_{counters[rule_name]:02d}.json"
        json.dump(ev, open(fn, "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    total = n_true + n_still
    print(f"candidates: {total} | TRUE evasions: {n_true} | still matched origin: {n_still}")
    print(f"true-evasion files -> {out_dir}\n")
    print(f"{'rule':52} {'evade':>6} {'/ total':>8}")
    for title in sorted(per_rule_total):
        rn = normalize_rule_name(title)
        print(f"{title[:52]:52} {counters.get(rn,0):6} {per_rule_total[title]:8}")


if __name__ == "__main__":
    main()
