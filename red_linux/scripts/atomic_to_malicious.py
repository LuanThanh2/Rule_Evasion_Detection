#!/usr/bin/env python3
"""
Atomic Red Team (Linux) → malicious command corpus cho RED-Linux.

Vì sao: Linux-APT-Dataset-2024 gán nhãn malicious THEO Sigma match → V2 (task vòng
tròn) + V1 (nhiễm nhãn benign). ART định nghĩa lệnh tấn công THẬT gắn nhãn theo
MITRE technique — **độc lập hoàn toàn với Sigma**. RED Stage 1 ăn `command_line` nên
ta chỉ cần trích `executor.command` của các atomic Linux (resolve input args mặc định).
Giữ được Stage 2 vì technique→Sigma rule map qua tag MITRE.

Đọc:  <art>/atomics/*/T*.yaml   (clone: redcanaryco/atomic-red-team, sparse atomics)
Xuất: JSONL {command_line, technique, test_name, guid, executor} — 1 dòng / process.

Chạy: ~/venvs/rule_evasion_env/bin/python red_linux/scripts/atomic_to_malicious.py \
        --art ~/tools/atomic-red-team \
        --out /home/luanthanh/data/red_linux/benign/process_creation/atomic_malicious.jsonl
"""

import argparse
import json
import re
from pathlib import Path

import yaml

ARG_RE = re.compile(r"#\{([^}]+)\}")
# bỏ dòng comment / rỗng / chỉ là control-flow shell thuần
SKIP_LINE = re.compile(r"^\s*(#|$|fi\b|done\b|else\b|then\b|do\b|esac\b)")


def resolve_args(cmd, input_arguments):
    """Thay #{name} bằng default (nếu có), giữ nguyên nếu thiếu."""
    defaults = {k: str(v.get("default", f"#{{{k}}}"))
                for k, v in (input_arguments or {}).items()}
    return ARG_RE.sub(lambda m: defaults.get(m.group(1), m.group(0)), cmd)


def split_lines(cmd):
    """Multi-line command → từng process-line (lọc comment/flow rỗng)."""
    out = []
    for ln in cmd.splitlines():
        ln = ln.strip()
        if not ln or SKIP_LINE.match(ln):
            continue
        out.append(ln)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--art", default="/home/luanthanh/tools/atomic-red-team")
    ap.add_argument("--out", required=True)
    ap.add_argument("--executors", nargs="+", default=["sh", "bash", "command_prompt"],
                    help="executor.name chấp nhận (mặc định shell)")
    args = ap.parse_args()

    atomics = sorted(Path(args.art, "atomics").glob("*/T*.yaml"))
    rows, seen = [], set()
    n_tests = 0
    techniques = set()
    for af in atomics:
        try:
            doc = yaml.safe_load(open(af, encoding="utf-8"))
        except Exception:
            continue
        tech = doc.get("attack_technique", af.stem)
        for t in doc.get("atomic_tests", []) or []:
            plats = [p.lower() for p in t.get("supported_platforms", [])]
            if "linux" not in plats:
                continue
            ex = t.get("executor", {}) or {}
            if ex.get("name") not in args.executors:
                continue
            cmd = ex.get("command")
            if not cmd:
                continue
            n_tests += 1
            techniques.add(tech)
            resolved = resolve_args(cmd, t.get("input_arguments"))
            for line in split_lines(resolved):
                if line in seen:
                    continue
                seen.add(line)
                rows.append({
                    "command_line": line,
                    "technique": tech,
                    "test_name": t.get("name", ""),
                    "guid": t.get("auto_generated_guid", ""),
                    "executor": ex.get("name"),
                })

    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    with open(outp, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"linux atomic tests: {n_tests} | techniques: {len(techniques)} | "
          f"unique command lines: {len(rows)}")
    print(f"wrote {outp}")


if __name__ == "__main__":
    main()
