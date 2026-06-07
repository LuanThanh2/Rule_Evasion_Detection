#!/usr/bin/env python3
"""
ART malicious corpus → event-JSON theo split (cho pipeline production train/validate).

`train.py`/`validate.py` nạp malicious từ event-dir (get_all_matches), không từ file
phẳng. Script này chia atomic_malicious.jsonl thành train/valid/test (70/15/15, seed 42
— giống stage1_atomic.py để số liệu nhất quán) và ghi mỗi lệnh thành 1 event JSON có
`process.command_line` (đúng field config đọc), gom dưới 1 pseudo-rule dir `atomic_misuse`.

Xuất: data/red_linux/split_atomic/match_{train,valid,test}/atomic_misuse/atomic_Match_*.json

Chạy: ~/venvs/rule_evasion_env/bin/python red_linux/scripts/atomic_to_events.py
"""

import argparse
import json
import os
import re
import shutil
from pathlib import Path

import numpy as np

DATA = Path("/home/luanthanh/data/red_linux")
ART = DATA / "benign/process_creation/atomic_malicious.jsonl"
OUT = DATA / "split_atomic"
ASSIGN = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*=")


def is_proc(c):
    return not (ASSIGN.match(c) or re.match(r"^\s*(if|for|while|case|echo \$|\)|\{|\}|exit\b)", c))


def event(cmd, tech):
    prog = cmd.split(" ", 1)[0]
    exe = prog if prog.startswith("/") else f"/usr/bin/{os.path.basename(prog)}"
    return {
        "process": {"command_line": cmd, "executable": exe},
        "CommandLine": cmd, "Image": exe,
        "rule_id": "atomic_misuse", "rule_title": "Atomic Red Team misuse",
        "technique": tech,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(ART)]
    rows = [r for r in rows if is_proc(r["command_line"])]
    # dedup theo command_line
    seen, uniq = set(), []
    for r in rows:
        c = r["command_line"]
        if c not in seen:
            seen.add(c)
            uniq.append(r)

    rng = np.random.default_rng(args.seed)
    idx = rng.permutation(len(uniq))
    n = len(uniq)
    a, b = int(.7 * n), int(.85 * n)
    splits = {"train": idx[:a], "valid": idx[a:b], "test": idx[b:]}

    if OUT.exists():
        shutil.rmtree(OUT)
    counts = {}
    for split, ii in splits.items():
        d = OUT / f"match_{split}" / "atomic_misuse"
        d.mkdir(parents=True, exist_ok=True)
        for k, i in enumerate(ii):
            r = uniq[i]
            ev = event(r["command_line"], r["technique"])
            (d / f"atomic_Match_{k:04d}.json").write_text(
                json.dumps(ev, ensure_ascii=False, indent=2), encoding="utf-8")
        counts[split] = len(ii)
    print(f"unique ART malicious: {n} → train {counts['train']} / "
          f"valid {counts['valid']} / test {counts['test']}")
    print(f"wrote {OUT}/match_{{train,valid,test}}/atomic_misuse/")


if __name__ == "__main__":
    main()
