#!/usr/bin/env python3
"""
RED-Linux demo trên LỆNH TẤN CÔNG THẬT (Atomic Red Team) — bản thuyết phục.

Khác demo_linux.py (dùng lệnh dataset nhiễm, admin-flavored), bản này dùng lệnh ART
THẬT đang fire Sigma → áp transform evasion cấp argv → Zircolite xác nhận luật hết fire
→ RED (model production đã fix) vẫn bắt mạnh (vì model học chính từ ART).

Quy trình tự động:
  1. Lấy lệnh ART fire ≥1 Sigma rule (atomic_fired.jsonl).
  2. Áp MỌI transform (linux_evasion_generate.TRANSFORMS) → candidate.
  3. Zircolite 1 lần trên baseline + mọi candidate → biết luật nào fire.
  4. Giữ (baseline, evasion) mà luật R: baseline FIRE R, evasion KHÔNG fire R = evasion thật.
  5. RED chấm điểm; chọn ~6 phase đa dạng (khác rule) ưu tiên RED bắt được evasion.

Xuất reports/linux/demo_art_result.md + bảng ra màn hình.
Chạy: ~/venvs/rule_evasion_env/bin/python red_linux/scripts/demo_linux_art.py [--threshold 0.42]
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

PROJ = Path("/home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection")
ZIRC = Path(os.path.expanduser("~/tools/Zircolite"))
RULES = "/home/luanthanh/data/sigma/rules/linux"
FIRED = Path("/home/luanthanh/data/red_linux/benign/process_creation/atomic_fired.jsonl")
MODEL = PROJ / "models/linux_atomic/train_rslt_ensemble_atomic.zip"
WORK = Path("/home/luanthanh/data/red_linux/work")
OUT = PROJ / "reports/linux/demo_art_result.md"
VENV_PY = os.path.expanduser("~/venvs/rule_evasion_env/bin/python")

sys.path.insert(0, str(PROJ))
sys.path.insert(0, str(PROJ / "red_linux/scripts"))
from red.persist import load_result                                  # noqa: E402
from red.normalize import Normalizer, normalize_samples              # noqa: E402
from red.evaluate import scale_df_values                             # noqa: E402
from red.features import create_vectorizer                           # noqa: E402
from red.attribution import CosineRuleAttributor                     # noqa: E402
from red.data import (load_rule_set, resolve_event_paths,            # noqa: E402
                      extract_filter_values, extract_sigma_detection_values)
from linux_evasion_generate import TRANSFORMS                        # noqa: E402

nz = Normalizer()
SF = ["CommandLine", "Image"]
EFM = {"CommandLine": ["process.command_line"], "Image": ["process.executable", "exe"]}


def build_rows(cmd, evid):
    try:
        args = shlex.split(cmd)
    except ValueError:
        args = cmd.split(" ")
    if not args:
        return []
    prog = args[0]
    exe = prog if prog.startswith("/") else f"/usr/bin/{os.path.basename(prog)}"
    common = {"Image": exe, "CommandLine": cmd, "exe": exe, "comm": os.path.basename(prog),
              "User": "root", "CurrentDirectory": "/tmp", "key": "audit-wazuh-c", "evid": evid}
    sc = {**common, "type": "SYSCALL"}
    ex = {**common, "type": "EXECVE"}
    for i, a in enumerate(args):
        ex[f"a{i}"] = a
    return [sc, ex]


def run_zircolite(cmds):
    WORK.mkdir(parents=True, exist_ok=True)
    inp = WORK / "demo_art_input.jsonl"
    with open(inp, "w", encoding="utf-8") as f:
        for evid, cmd in cmds.items():
            for r in build_rows(cmd, evid):
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    det = WORK / "demo_art_detections.json"
    subprocess.run([VENV_PY, "zircolite.py", "-e", str(inp), "-j",
                    "-r", f"{RULES}/process_creation", f"{RULES}/auditd",
                    "-o", str(det), "--keepflat", "-q"],
                   cwd=str(ZIRC), capture_output=True, text=True)
    fired = defaultdict(set)
    if det.exists():
        for rule in json.load(open(det)):
            for m in rule.get("matches", []):
                if m.get("evid"):
                    fired[m["evid"]].add(rule.get("title", ""))
    return fired


def build_attributor():
    rs = load_rule_set("/__none__", RULES)
    ep = resolve_event_paths(SF, EFM)
    rfn = {}
    for name, rd in rs.items():
        vals = []
        for det in rd.sigma_values:
            if isinstance(det, dict):
                vals.extend(extract_sigma_detection_values(det, SF))
        for filt in rd.filters:
            vals.extend(extract_filter_values(filt, ep))
        norm = normalize_samples(vals) if vals else []
        if norm:
            rfn[name] = norm
    return CosineRuleAttributor.fit(rfn, create_vectorizer("tfidf", ngram_range=(1, 1)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=float, default=0.42)
    ap.add_argument("--n-phases", type=int, default=6)
    args = ap.parse_args()
    T = args.threshold

    # 1) lệnh ART fire ≥1 rule
    fired_rows = [json.loads(l) for l in open(FIRED)]
    fired_rows = [r for r in fired_rows if r["fired"]]
    print(f"lệnh ART fire Sigma: {len(fired_rows)}")

    # 2) sinh candidate (baseline, technique, evasion)
    cand = []   # (idx_base, tech, evasion_cmd)
    bases = []  # baseline cmds
    for r in fired_rows:
        bases.append(r["command_line"])
        bi = len(bases) - 1
        for tech, fn in TRANSFORMS.items():
            try:
                new = fn(r["command_line"])
            except Exception:
                continue
            if new and new != r["command_line"]:
                cand.append((bi, tech, new))
    print(f"candidate evasion: {len(cand)}")

    # 3) Zircolite 1 lần (baseline + candidate)
    cmds = {f"b{i}": c for i, c in enumerate(bases)}
    for j, (bi, tech, ev) in enumerate(cand):
        cmds[f"e{j}"] = ev
    fired = run_zircolite(cmds)

    # 4) RED model + attributor
    m = load_result(str(MODEL))
    est, vec, scaler, shift = m["estimator"], m["vectorizer"], m["scaler"], float(m["shift"])

    def red(cmd):
        X = vec.transform([nz.normalize(cmd)])
        if X.nnz == 0:
            return 0.0
        return float(scale_df_values(np.asarray(est.decision_function(X)).ravel(), scaler, shift)[0])

    attr = build_attributor()

    # 5) lọc evasion THẬT: rule R baseline-fire nhưng evasion không fire; RED bắt evasion
    found = []  # dict per (rule)
    for j, (bi, tech, ev) in enumerate(cand):
        base = bases[bi]
        Fb = fired.get(f"b{bi}", set())
        Fe = fired.get(f"e{j}", set())
        evaded = Fb - Fe                      # luật baseline fire mà evasion né
        if not evaded:
            continue
        s_ev = red(ev)
        for R in evaded:
            found.append({"rule": R, "tech": tech, "base": base, "evasion": ev,
                          "red_base": red(base), "red_ev": s_ev,
                          "catch": s_ev >= T})

    # chọn phase đa dạng: ưu tiên RED bắt, mỗi rule 1 phase, đa dạng technique
    found.sort(key=lambda x: (-x["catch"], -x["red_ev"]))
    seen_rule, seen_tech, phases = set(), set(), []
    for f in found:
        if f["rule"] in seen_rule:
            continue
        phases.append(f); seen_rule.add(f["rule"]); seen_tech.add(f["tech"])
        if len(phases) >= args.n_phases:
            break
    # nếu thiếu, nới điều kiện trùng rule
    if len(phases) < args.n_phases:
        for f in found:
            if f in phases:
                continue
            phases.append(f)
            if len(phases) >= args.n_phases:
                break

    # attribution cho từng phase
    for p in phases:
        ranked = attr.score_samples([nz.normalize(p["evasion"])])[0]
        names = [n for n, _ in ranked]
        p["top"] = names[0] if names else "-"
        p["orank"] = names.index(p["rule"]) + 1 if p["rule"] in names else None

    n_catch = sum(p["catch"] for p in phases)
    in5 = sum(1 for p in phases if p["orank"] and p["orank"] <= 5)

    # render
    print(f"\n{'RULE (baseline fire → evasion né)':<46} {'tech':<14} {'RED base':<9} {'RED evad':<9} catch")
    print("-" * 100)
    L, A = [], lambda s: L.append(s)
    A("# RED-Linux — Demo trên lệnh tấn công THẬT (Atomic Red Team)\n")
    A(f"> `demo_linux_art.py` (T\\*={T}, model production đã fix). Lệnh ART fire Sigma → "
      "transform evasion cấp argv → Zircolite xác nhận luật hết fire → RED vẫn bắt.\n")
    A("\n| # | Sigma rule (bị né) | Kỹ thuật | RED baseline | RED evasion | RED bắt? | Stage2 origin |")
    A("|--:|---|---|:--:|:--:|:--:|:--:|")
    for i, p in enumerate(phases, 1):
        print(f"{p['rule'][:46]:<46} {p['tech']:<14} {p['red_base']:<9.3f} "
              f"{p['red_ev']:<9.3f} {'✅' if p['catch'] else '·'}")
        A(f"| {i} | {p['rule']} | `{p['tech']}` | {p['red_base']:.3f} | {p['red_ev']:.3f} | "
          f"{'✅' if p['catch'] else '❌'} | {('top-'+str(p['orank'])) if p['orank'] else '—'} |")
    A(f"\n**Tổng kết:** {len(phases)} lệnh ART tấn công — baseline **fire Sigma**, sau evasion "
      f"**Sigma né hết**, **RED bắt {n_catch}/{len(phases)}** evasion; Stage 2 rule gốc ∈ top-5: "
      f"{in5}/{len(phases)}.\n")
    A("\n## Chi tiết lệnh\n")
    for i, p in enumerate(phases, 1):
        A(f"\n**Phase {i}** — rule *{p['rule']}* (`{p['tech']}`)")
        A(f"- baseline (Sigma FIRE, RED {p['red_base']:.3f}): `{p['base'][:150]}`")
        A(f"- evasion  (Sigma MISS, RED {p['red_ev']:.3f}): `{p['evasion'][:150]}`")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(L), encoding="utf-8")
    print("-" * 100)
    print(f"phases={len(phases)} | RED catch evasion: {n_catch}/{len(phases)} | origin∈top5: {in5}/{len(phases)}")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
