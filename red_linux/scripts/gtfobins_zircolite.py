#!/usr/bin/env python3
"""
Run Zircolite on GTFOBins commands to measure Sigma coverage.

This script does not execute GTFOBins commands. It builds synthetic
process_creation/auditd-like JSON rows and feeds them to Zircolite, matching the
offline ART coverage workflow.

Output:
  work/gtfobins_zircolite_input.jsonl
  work/detections_gtfobins.json
  benign/process_creation/gtfobins_fired.jsonl

Run:
  ~/venvs/rule_evasion_env/bin/python red_linux/scripts/gtfobins_zircolite.py
"""

import argparse
import json
import os
import shlex
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ZIRC = Path(os.path.expanduser("~/tools/Zircolite"))
RULES = Path("/home/luanthanh/data/sigma/rules/linux")
DATA = Path("/home/luanthanh/data/red_linux")
SRC = DATA / "benign/process_creation/gtfobins_malicious.jsonl"
WORK = DATA / "work"
OUT_FIRED = DATA / "benign/process_creation/gtfobins_fired.jsonl"
VENV_PY = os.path.expanduser("~/venvs/rule_evasion_env/bin/python")


def build_rows(cmd, evid, binary=None):
    try:
        args = shlex.split(cmd)
    except ValueError:
        args = cmd.split(" ")
    if not args:
        return []
    prog = binary or args[0]
    exe = prog if prog.startswith("/") else f"/usr/bin/{os.path.basename(prog)}"
    comm = os.path.basename(prog)
    common = {
        "Image": exe,
        "CommandLine": cmd,
        "exe": exe,
        "comm": comm,
        "User": "root",
        "CurrentDirectory": "/tmp",
        "key": "audit-wazuh-c",
        "evid": evid,
    }
    syscall = {**common, "type": "SYSCALL"}
    execve = {**common, "type": "EXECVE"}
    for i, a in enumerate(args):
        execve[f"a{i}"] = a
    return [syscall, execve]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(SRC))
    args = ap.parse_args()

    WORK.mkdir(parents=True, exist_ok=True)
    rows = [json.loads(l) for l in open(Path(args.src).expanduser(), encoding="utf-8")]

    meta = {}
    inp = WORK / "gtfobins_zircolite_input.jsonl"
    with open(inp, "w", encoding="utf-8") as f:
        for i, row in enumerate(rows):
            evid = f"gt{i:06d}"
            meta[evid] = row
            for zrow in build_rows(row["command_line"], evid, row.get("binary")):
                f.write(json.dumps(zrow, ensure_ascii=False) + "\n")
    print(f"built {len(rows)} commands -> {inp}")

    det = WORK / "detections_gtfobins.json"
    cmd = [
        VENV_PY,
        "zircolite.py",
        "-e",
        str(inp),
        "-j",
        "-r",
        str(RULES / "process_creation"),
        str(RULES / "auditd"),
        "-o",
        str(det),
        "--keepflat",
        "-q",
    ]
    print("running:", " ".join(cmd))
    p = subprocess.run(cmd, cwd=str(ZIRC), capture_output=True, text=True)
    if not det.exists():
        print("ZIRCOLITE FAILED\n", p.stdout[-2000:], p.stderr[-2000:])
        sys.exit(1)

    detections = json.load(open(det, encoding="utf-8"))
    evid_fired = defaultdict(list)
    rule_meta = {}
    for rule in detections:
        rid = rule.get("id", "")
        rule_meta[rid] = {"title": rule.get("title", ""), "level": rule.get("level", "")}
        for match in rule.get("matches", []):
            ev = match.get("evid")
            if ev:
                evid_fired[ev].append(rid)

    n_fire = 0
    function_total = Counter(r.get("function", "?") for r in meta.values())
    function_fire = Counter()
    tech_total = Counter(r.get("technique", "?") for r in meta.values())
    tech_fire = Counter()
    level_ct = Counter()

    with open(OUT_FIRED, "w", encoding="utf-8") as f:
        for evid, row in meta.items():
            rids = sorted(set(evid_fired.get(evid, [])))
            if rids:
                n_fire += 1
                function_fire[row.get("function", "?")] += 1
                tech_fire[row.get("technique", "?")] += 1
                for rid in rids:
                    level_ct[rule_meta.get(rid, {}).get("level", "?")] += 1
            out = dict(row)
            out["fired"] = [{"id": rid, **rule_meta.get(rid, {})} for rid in rids]
            f.write(json.dumps(out, ensure_ascii=False) + "\n")

    n = len(meta)
    print("\n=== RESULT ===")
    print(
        f"GTFOBins commands: {n} | fire >=1 Sigma rule: {n_fire} ({100*n_fire/max(n,1):.1f}%) | "
        f"miss all rules: {n-n_fire} ({100*(n-n_fire)/max(n,1):.1f}%)"
    )
    print(f"rule fire levels: {dict(level_ct)}")
    print(f"functions with >=1 fired command: {len(function_fire)}/{len(function_total)}")
    print(f"techniques with >=1 fired command: {len(tech_fire)}/{len(tech_total)}")
    print("top functions fire:", [(k, f"{v}/{function_total[k]}") for k, v in function_fire.most_common(8)])
    print("top techniques fire:", [(k, f"{v}/{tech_total[k]}") for k, v in tech_fire.most_common(8)])
    print(f"-> {OUT_FIRED}")


if __name__ == "__main__":
    main()
