#!/usr/bin/env python3
"""
GTFOBins malicious corpus -> event-JSON splits for production Stage 1.

The root train/validate scripts load malicious samples from event directories.
This converter mirrors atomic_to_events.py but keeps GTFOBins metadata.

Run:
  ~/venvs/rule_evasion_env/bin/python red_linux/scripts/gtfobins_to_events.py
"""

import argparse
import json
import os
import shutil
from pathlib import Path

import numpy as np

DATA = Path("/home/luanthanh/data/red_linux")
SRC = DATA / "benign/process_creation/gtfobins_malicious.jsonl"
OUT = DATA / "split_gtfobins"


def event(row):
    cmd = row["command_line"]
    binary = row.get("binary") or cmd.split(" ", 1)[0]
    exe = binary if binary.startswith("/") else f"/usr/bin/{os.path.basename(binary)}"
    return {
        "process": {"command_line": cmd, "executable": exe},
        "CommandLine": cmd,
        "Image": exe,
        "rule_id": "gtfobins_lolbin_misuse",
        "rule_title": "GTFOBins LOLBin misuse",
        "technique": row.get("technique"),
        "techniques": row.get("techniques", [row.get("technique")]),
        "gtfobin_binary": row.get("binary"),
        "gtfobin_function": row.get("function"),
        "gtfobin_context": row.get("context"),
        "source": "GTFOBins",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(SRC))
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    src = Path(args.src).expanduser()
    out = Path(args.out).expanduser()
    rows = [json.loads(l) for l in open(src, encoding="utf-8")]

    seen, uniq = set(), []
    for row in rows:
        cmd = row["command_line"]
        if cmd not in seen:
            seen.add(cmd)
            uniq.append(row)

    rng = np.random.default_rng(args.seed)
    idx = rng.permutation(len(uniq))
    n = len(uniq)
    a, b = int(0.7 * n), int(0.85 * n)
    splits = {"train": idx[:a], "valid": idx[a:b], "test": idx[b:]}

    if out.exists():
        shutil.rmtree(out)
    counts = {}
    for split, ii in splits.items():
        d = out / f"match_{split}" / "gtfobins_lolbin_misuse"
        d.mkdir(parents=True, exist_ok=True)
        for k, i in enumerate(ii):
            (d / f"gtfobins_Match_{k:04d}.json").write_text(
                json.dumps(event(uniq[i]), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        counts[split] = len(ii)

    print(
        f"unique GTFOBins malicious: {n} -> train {counts['train']} / "
        f"valid {counts['valid']} / test {counts['test']}"
    )
    print(f"wrote {out}/match_{{train,valid,test}}/gtfobins_lolbin_misuse/")


if __name__ == "__main__":
    main()
