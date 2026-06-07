#!/usr/bin/env python3
"""
RED-Linux demo driver — Sigma fire (baseline) vs Sigma miss (evasion) vs RED catch.

Song song test_apt_demo_v2.py của Windows, nhưng cho Linux/auditd/Zircolite (offline).
Mỗi phase dùng 1 cặp lệnh ĐÃ VERIFY (lệnh gốc fire 1 Sigma Linux rule → lệnh evasion
đổi representation cấp argv nên rule gốc hết fire), rồi:
  1. Chạy Zircolite (engine Sigma thật) trên cả baseline + evasion → rule nào fire.
  2. RED Stage 1 (model production models/linux_atomic) chấm điểm evasion → vẫn cờ malicious.
  3. RED Stage 2 (CosineRuleAttributor) quy evasion về Sigma rule họ hàng gần nhất.

In bảng kết quả + lưu reports/linux/demo_result.md.

Chạy: ~/venvs/rule_evasion_env/bin/python red_linux/scripts/demo_linux.py
       [--threshold 0.46]   # T* model production
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
EVADIR = Path("/home/luanthanh/data/red_linux/evasions/linux/process_creation")
MODEL = PROJ / "models/linux_atomic/train_rslt_ensemble_atomic.zip"
WORK = Path("/home/luanthanh/data/red_linux/work")
OUT = PROJ / "reports/linux/demo_result.md"
VENV_PY = os.path.expanduser("~/venvs/rule_evasion_env/bin/python")

sys.path.insert(0, str(PROJ))
from red.persist import load_result                                  # noqa: E402
from red.normalize import Normalizer, normalize_samples              # noqa: E402
from red.evaluate import scale_df_values                             # noqa: E402
from red.features import create_vectorizer                           # noqa: E402
from red.attribution import CosineRuleAttributor                     # noqa: E402
from red.data import (load_rule_set, resolve_event_paths,            # noqa: E402
                      extract_filter_values, extract_sigma_detection_values)

nz = Normalizer()
SF = ["CommandLine", "Image"]
EFM = {"CommandLine": ["process.command_line"], "Image": ["process.executable", "exe"]}

# Phase = (tên, rule_title chứa, technique, lệnh BENIGN read-only) → driver tìm file evasion khớp.
PHASES = [
    ("1. curl upload → wget", "Curl File Upload", "tool_swap",
     "curl -s -o /tmp/index.html https://example.com"),
    ("2. systemctl stop → mask", "Disable Or Stop Services", "alt_subcommand",
     "systemctl status snapd.service"),
    ("3. chmod thư mục hệ thống → busybox", "Chmod Suspicious Directory", "busybox_applet",
     "ls -la /var/tmp"),
    ("4. chmod thư mục hệ thống → relative", "Chmod Suspicious Directory", "relative_path",
     "stat /var/tmp"),
    ("5. useradd → adduser", "Creation Of An User Account", "tool_swap",
     "getent passwd root"),
]


def find_pair(rule_sub, tech):
    """Tìm 1 file evasion khớp (rule_title chứa rule_sub, đúng technique)."""
    for f in sorted(EVADIR.glob("*/*_Evasion_*.json")):
        d = json.load(open(f))
        if rule_sub.lower() in d.get("rule_title", "").lower() and d.get("evasion_technique") == tech:
            return d
    return None


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
    """cmds: {evid: cmd} → {evid: set(rule_title fired)}."""
    WORK.mkdir(parents=True, exist_ok=True)
    inp = WORK / "demo_zircolite_input.jsonl"
    with open(inp, "w", encoding="utf-8") as f:
        for evid, cmd in cmds.items():
            for r in build_rows(cmd, evid):
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    det = WORK / "demo_detections.json"
    cmd = [VENV_PY, "zircolite.py", "-e", str(inp), "-j",
           "-r", f"{RULES}/process_creation", f"{RULES}/auditd",
           "-o", str(det), "--keepflat", "-q"]
    subprocess.run(cmd, cwd=str(ZIRC), capture_output=True, text=True)
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


MODE_DESC = {
    "benign":   "lệnh quản trị read-only → kỳ vọng Sigma 0 fire, RED không cờ (sanity check)",
    "baseline": "lệnh canonical Sigma biết → kỳ vọng Sigma FIRE",
    "evasion":  "đổi representation cấp argv → kỳ vọng Sigma MISS nhưng RED catch",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["benign", "baseline", "evasion", "all"], default="all")
    ap.add_argument("--threshold", type=float, default=0.46)
    args = ap.parse_args()

    # load phases (benign từ PHASES; baseline+evasion từ file đã verify)
    phases = []
    for title, rule_sub, tech, benign in PHASES:
        d = find_pair(rule_sub, tech)
        if d:
            phases.append({"title": title, "tech": tech, "rule": d["rule_title"],
                           "benign": benign, "baseline": d["original_command_line"],
                           "evasion": d.get("process", {}).get("command_line", "")})
    if not phases:
        sys.exit("Không tìm thấy evasion verified — chạy pipeline data (RUN_NOTE) trước.")

    # 1) Zircolite trên TẤT CẢ biến thể (1 lần) → fired theo evid
    PFX = {"benign": "n", "baseline": "b", "evasion": "e"}   # 'benign'≠'baseline' (cùng 'b')
    cmds = {}
    for i, p in enumerate(phases):
        for v in ("benign", "baseline", "evasion"):
            cmds[f"{PFX[v]}{i}"] = p[v]
    fired = run_zircolite(cmds)

    # 2) RED Stage 1 model
    m = load_result(str(MODEL))
    est, vec, scaler, shift = m["estimator"], m["vectorizer"], m["scaler"], float(m["shift"])

    def red_score(cmd):
        X = vec.transform([nz.normalize(cmd)])
        if X.nnz == 0:                       # OOV hoàn toàn → không tín hiệu → benign
            return 0.0
        df = np.asarray(est.decision_function(X)).ravel()
        return float(scale_df_values(df, scaler, shift)[0])

    # 3) RED Stage 2 attributor
    attr = build_attributor()

    # tính sẵn mọi biến thể cho từng phase
    for i, p in enumerate(phases):
        for v in ("benign", "baseline", "evasion"):
            p[f"{v}_fire"] = p["rule"] in fired.get(f"{PFX[v]}{i}", set())
            p[f"{v}_score"] = red_score(p[v])
        ranked = attr.score_samples([nz.normalize(p["evasion"])])[0]
        names = [n for n, _ in ranked]
        p["top"] = names[0] if names else "-"
        p["origin_rank"] = names.index(p["rule"]) + 1 if p["rule"] in names else None

    T = args.threshold
    modes = ["benign", "baseline", "evasion"] if args.mode == "all" else [args.mode]

    L, A = [], lambda s: L.append(s)
    A("# RED-Linux — Kết quả Demo (Sigma vs RED)\n")
    A(f"> Sinh bởi `demo_linux.py --mode {args.mode}` (T\\*={T}). Zircolite = engine Sigma "
      "thật; RED = model production `models/linux_atomic`.\n")

    for mode in modes:
        A(f"\n## Mode `{mode}` — {MODE_DESC[mode]}\n")
        print(f"\n=== MODE: {mode} === ({MODE_DESC[mode]})")
        print(f"{'PHASE':<40} {'Sigma':<8} {'RED':<9} {'cờ?':<5} "
              f"{'Stage2' if mode=='evasion' else ''}")
        print("-" * 92)
        A("| Phase | Kỹ thuật | Sigma rule | Sigma | RED score | RED cờ? |"
          + (" Stage2 origin-rank |" if mode == "evasion" else ""))
        A("|---|---|---|:--:|:--:|:--:|" + (":--:|" if mode == "evasion" else ""))
        n_fire = n_flag = 0
        for p in phases:
            fire = p[f"{mode}_fire"]; score = p[f"{mode}_score"]; flag = score >= T
            n_fire += fire; n_flag += flag
            sg = "🔴FIRE" if fire else "—"
            extra = ""
            md_extra = ""
            if mode == "evasion":
                orank = p["origin_rank"]
                extra = f"origin@{('#'+str(orank)) if orank else '—'}"
                md_extra = f" {('top-'+str(orank)) if orank else '—'} |"
            print(f"{p['title']:<40} {sg:<8} {score:<9.3f} "
                  f"{'✅' if flag else '·':<5} {extra}")
            A(f"| {p['title']} | `{p['tech']}` | {p['rule']} | "
              f"{'🔴 FIRE' if fire else '🟢 MISS' if mode=='evasion' else '—'} | "
              f"{score:.3f} | {'✅' if flag else '❌'} |" + md_extra)
        # tổng kết theo mode
        if mode == "benign":
            print(f"  → Sigma fire {n_fire}/{len(phases)} (kỳ vọng 0) | "
                  f"RED cờ {n_flag}/{len(phases)} (kỳ vọng thấp)")
            A(f"\n**Tổng kết benign:** Sigma fire **{n_fire}/{len(phases)}** (kỳ vọng 0); "
              f"RED cờ **{n_flag}/{len(phases)}** → kiểm chứng RED không cờ bừa.\n")
        elif mode == "baseline":
            print(f"  → Sigma FIRE {n_fire}/{len(phases)} (kỳ vọng đủ)")
            A(f"\n**Tổng kết baseline:** Sigma **FIRE {n_fire}/{len(phases)}** — chữ ký hoạt "
              f"động tốt khi lệnh đúng khuôn.\n")
        else:  # evasion
            in5 = sum(1 for p in phases if p["origin_rank"] and p["origin_rank"] <= 5)
            print(f"  → Sigma né {len(phases)-n_fire}/{len(phases)} | RED catch {n_flag}/{len(phases)} | origin∈top5 {in5}/{len(phases)}")
            A(f"\n**Tổng kết evasion:** Sigma **né {len(phases)-n_fire}/{len(phases)}** rule mục "
              f"tiêu; **RED Stage 1 bắt {n_flag}/{len(phases)}**; Stage 2 rule gốc ∈ **top-5: "
              f"{in5}/{len(phases)}**.\n")
            A("\n> Stage 2 quy về rule gốc khó vì evasion **cố tình xoá token chữ ký** của chính "
              "rule đó (top-1 có thể là rule họ hàng) → giới hạn token-similarity, động lực "
              "Layer-3 Sigma-logic validator.\n")

    # phụ lục: lệnh từng phase
    A("\n## Phụ lục — lệnh mỗi phase\n")
    for p in phases:
        A(f"\n**{p['title']}** → rule *{p['rule']}* (`{p['tech']}`)")
        A(f"- benign  : `{p['benign'][:95]}`")
        A(f"- baseline: `{p['baseline'][:95]}`")
        A(f"- evasion : `{p['evasion'][:95]}`")

    out = OUT if args.mode == "all" else OUT.with_name(f"demo_result_{args.mode}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(L), encoding="utf-8")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
