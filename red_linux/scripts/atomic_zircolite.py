#!/usr/bin/env python3
"""
Chạy Zircolite (engine Sigma thật) trên lệnh Atomic Red Team → rule-linkage THẬT.

Mục tiêu (hợp nhất 2 pipeline):
  - Nhãn malicious của ART độc lập-Sigma (MITRE) — đã có.
  - Bổ sung: rule Sigma nào THỰC SỰ fire trên từng lệnh ART (chạy Zircolite y như
    pipeline match/evasion). → ground-truth attribution = "rule fire thật", không phải
    gom theo tag technique. Đồng thời biết lệnh ART nào ĐÃ né được mọi rule (= evasion thật).

Quy trình: build Zircolite input (2 row/cmd: SYSCALL+EXECVE, mang evid) → zircolite -j
-r <linux process_creation+auditd> --keepflat → parse detections → evid→rule fired.

Xuất:
  work/atomic_zircolite_input.jsonl, work/detections_atomic.json
  benign/process_creation/atomic_fired.jsonl   {command_line, technique, fired:[{id,title,level}]}

Chạy: ~/venvs/rule_evasion_env/bin/python red_linux/scripts/atomic_zircolite.py
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ZIRC = Path(os.path.expanduser("~/tools/Zircolite"))
RULES = Path("/home/luanthanh/data/sigma/rules/linux")
DATA = Path("/home/luanthanh/data/red_linux")
ART = DATA / "benign/process_creation/atomic_malicious.jsonl"
WORK = DATA / "work"
OUT_FIRED = DATA / "benign/process_creation/atomic_fired.jsonl"
VENV_PY = os.path.expanduser("~/venvs/rule_evasion_env/bin/python")

ASSIGN = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*=")


def is_proc(c):
    return not (ASSIGN.match(c) or re.match(r"^\s*(if|for|while|case|echo \$|\)|\{|\}|exit\b)", c))


def build_rows(cmd, evid):
    """SYSCALL + EXECVE row cho 1 lệnh (giống linux_evasion_generate.build_rows)."""
    try:
        args = shlex.split(cmd)
    except ValueError:
        args = cmd.split(" ")
    if not args:
        return []
    prog = args[0]
    exe = prog if prog.startswith("/") else f"/usr/bin/{os.path.basename(prog)}"
    comm = os.path.basename(prog)
    common = {"Image": exe, "CommandLine": cmd, "exe": exe, "comm": comm,
              "User": "root", "CurrentDirectory": "/tmp", "key": "audit-wazuh-c",
              "evid": evid}
    syscall = {**common, "type": "SYSCALL"}
    execve = {**common, "type": "EXECVE"}
    for i, a in enumerate(args):
        execve[f"a{i}"] = a
    return [syscall, execve]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--art", default=str(ART))
    args = ap.parse_args()
    WORK.mkdir(parents=True, exist_ok=True)

    # 1) build Zircolite input + meta evid->(cmd,technique)
    rows = [json.loads(l) for l in open(args.art)]
    rows = [r for r in rows if is_proc(r["command_line"])]
    meta = {}
    inp = WORK / "atomic_zircolite_input.jsonl"
    with open(inp, "w", encoding="utf-8") as f:
        for i, r in enumerate(rows):
            evid = f"at{i:06d}"
            meta[evid] = {"command_line": r["command_line"],
                          "technique": r["technique"], "test_name": r.get("test_name", "")}
            for row in build_rows(r["command_line"], evid):
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"built {len(rows)} commands → {inp}")

    # 2) run Zircolite (y như pipeline match/evasion)
    det = WORK / "detections_atomic.json"
    cmd = [VENV_PY, "zircolite.py", "-e", str(inp), "-j",
           "-r", str(RULES / "process_creation"), str(RULES / "auditd"),
           "-o", str(det), "--keepflat", "-q"]
    print("running:", " ".join(cmd))
    p = subprocess.run(cmd, cwd=str(ZIRC), capture_output=True, text=True)
    if not det.exists():
        print("ZIRCOLITE FAILED\n", p.stdout[-2000:], p.stderr[-2000:])
        sys.exit(1)

    # 3) parse detections → evid -> fired rules
    detections = json.load(open(det))
    evid_fired = defaultdict(list)
    rule_meta = {}
    for rule in detections:
        rid = rule.get("id", "")
        rule_meta[rid] = {"title": rule.get("title", ""), "level": rule.get("level", "")}
        for m in rule.get("matches", []):
            ev = m.get("evid")
            if ev:
                evid_fired[ev].append(rid)

    # 4) write per-command fired mapping
    n_fire = 0
    fired_per_tech = defaultdict(int)
    tech_total = Counter(m["technique"] for m in meta.values())
    level_ct = Counter()
    with open(OUT_FIRED, "w", encoding="utf-8") as f:
        for evid, info in meta.items():
            rids = sorted(set(evid_fired.get(evid, [])))
            if rids:
                n_fire += 1
                fired_per_tech[info["technique"]] += 1
                for rid in rids:
                    level_ct[rule_meta.get(rid, {}).get("level", "?")] += 1
            f.write(json.dumps({
                "command_line": info["command_line"],
                "technique": info["technique"],
                "test_name": info["test_name"],
                "fired": [{"id": r, **rule_meta.get(r, {})} for r in rids],
            }, ensure_ascii=False) + "\n")

    n = len(meta)
    print(f"\n=== KẾT QUẢ ===")
    print(f"lệnh ART: {n} | fire ≥1 rule Sigma: {n_fire} ({100*n_fire/n:.1f}%) | "
          f"né hết (evasion thật): {n-n_fire} ({100*(n-n_fire)/n:.1f}%)")
    print(f"rule fire (theo level): {dict(level_ct)}")
    print(f"technique có ≥1 lệnh fire: {len(fired_per_tech)}/{len(tech_total)}")
    print(f"→ {OUT_FIRED}")
    # top techniques fire nhiều nhất
    top = sorted(fired_per_tech.items(), key=lambda x: -x[1])[:8]
    print("top technique fire:", [(t, f"{c}/{tech_total[t]}") for t, c in top])


if __name__ == "__main__":
    main()
