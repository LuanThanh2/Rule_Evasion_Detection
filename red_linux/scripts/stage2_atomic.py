#!/usr/bin/env python3
"""
Stage 2 — Rule Attribution trên malicious ART (technique-level), độc lập-Sigma.

Khác attribution cũ (evasion → đúng origin-rule của nó): ART không có 1 origin-rule,
nên ground-truth = **mọi Sigma Linux rule mang tag MITRE cùng base-technique** với lệnh.
Đo top-k hit rate: rule đúng-technique có nằm trong top-k rule do CosineRuleAttributor
xếp hạng không.

Tái dùng nguyên pipeline Stage 2: load_rule_set + extract_sigma_detection_values +
extract_filter_values + normalize_samples + CosineRuleAttributor (production method).

Xuất: red_linux/RESULT_LINUX_ATOMIC_STAGE2.md
Chạy: ~/venvs/rule_evasion_env/bin/python red_linux/scripts/stage2_atomic.py
"""

import glob
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

PROJ = Path("/home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection")
RULES = "/home/luanthanh/data/sigma/rules/linux"
DATA_BENIGN = Path("/home/luanthanh/data/red_linux/benign/process_creation")
ART = str(DATA_BENIGN / "atomic_malicious.jsonl")
OUT = PROJ / "red_linux/RESULT_LINUX_ATOMIC_STAGE2.md"
SEARCH_FIELDS = ["CommandLine", "Image"]
EVENT_FIELD_MAP = {"CommandLine": ["process.command_line"],
                   "Image": ["process.executable", "exe"]}

sys.path.insert(0, str(PROJ))
from red.data import (load_rule_set, resolve_event_paths,          # noqa: E402
                      extract_filter_values, extract_sigma_detection_values)
from red.normalize import normalize_samples, Normalizer            # noqa: E402
from red.features import create_vectorizer                         # noqa: E402
from red.attribution import CosineRuleAttributor                   # noqa: E402

nz = Normalizer()
ASSIGN = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*=")
TAG_RE = re.compile(r"attack\.(t\d+)", re.I)


def is_proc(c):
    return not (ASSIGN.match(c) or re.match(r"^\s*(if|for|while|case|echo \$|\)|\{|\}|exit\b)", c))


def rule_techniques():
    """rule TITLE (= RuleData.name) -> set base-technique (Txxxx) từ tag MITRE."""
    out = defaultdict(set)
    for f in glob.glob(f"{RULES}/**/*.yml", recursive=True):
        try:
            d = yaml.safe_load(open(f))
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        key = d.get("title") or Path(f).stem      # load_rule_set keys rule theo title
        for t in (d.get("tags") or []):
            m = TAG_RE.match(str(t))
            if m:
                out[key].add(m.group(1).upper())
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--ground-truth", choices=["technique", "fired"], default="technique",
                    help="technique = rule cùng tag MITRE; fired = rule THỰC SỰ fire (Zircolite)")
    args = ap.parse_args()

    # 1) Rule filters (giống train_attribution) — rule_filters-only mode
    rule_set = load_rule_set("/__nonexistent_events__", RULES)
    event_paths = resolve_event_paths(SEARCH_FIELDS, EVENT_FIELD_MAP)
    rule_filters_normalized = {}
    for rule_name, rd in rule_set.items():
        vals = []
        for det in rd.sigma_values:
            if isinstance(det, dict):
                vals.extend(extract_sigma_detection_values(det, SEARCH_FIELDS))
        for filt in rd.filters:
            vals.extend(extract_filter_values(filt, event_paths))
        norm = normalize_samples(vals) if vals else []
        if norm:
            rule_filters_normalized[rule_name] = norm

    attributor = CosineRuleAttributor.fit(rule_filters_normalized,
                                          create_vectorizer("tfidf", ngram_range=(1, 1)))
    rule_tech = rule_techniques()
    # base-technique -> rules CÓ trong attributor
    tech_to_rules = defaultdict(set)
    for r in rule_filters_normalized:
        for t in rule_tech.get(r, ()):
            tech_to_rules[t].add(r)

    # 2) ART commands + ground-truth rules
    items = []
    if args.ground_truth == "fired":
        # ground-truth = rule THỰC SỰ fire (từ atomic_zircolite.py). Khớp theo title.
        fired_path = DATA_BENIGN / "atomic_fired.jsonl"
        if not fired_path.exists():
            sys.exit("Thiếu atomic_fired.jsonl — chạy atomic_zircolite.py trước.")
        valid_titles = set(rule_filters_normalized)
        for a in (json.loads(l) for l in open(fired_path)):
            gt = {f["title"] for f in a["fired"] if f.get("title") in valid_titles}
            if gt:
                items.append((a["command_line"], a["technique"].split(".")[0].upper(), gt))
    else:
        # ground-truth = mọi rule cùng base-technique tag MITRE
        for a in (json.loads(l) for l in open(ART)):
            c = a["command_line"]
            if not is_proc(c):
                continue
            gt = tech_to_rules.get(a["technique"].split(".")[0].upper(), set())
            if gt:
                items.append((c, a["technique"].split(".")[0].upper(), gt))
    # dedup theo (cmd, bt)
    seen, uniq = set(), []
    for c, bt, gt in items:
        if (c, bt) in seen:
            continue
        seen.add((c, bt))
        uniq.append((c, bt, gt))

    norm_cmds = [nz.normalize(c) for c, _, _ in uniq]
    ranked = attributor.score_samples(norm_cmds)

    # 3) top-k hit rate
    KS = [1, 3, 5, 10]
    N = len(rule_filters_normalized)
    hits = {k: 0 for k in KS}
    base = {k: 0.0 for k in KS}      # kỳ vọng hit nếu xếp hạng NGẪU NHIÊN
    for (c, bt, gt), rk in zip(uniq, ranked):
        names = [name for name, _ in rk]
        g = len(gt)
        for k in KS:
            if gt & set(names[:k]):
                hits[k] += 1
            # P(random top-k chứa ≥1 trong g rule đúng) = 1 - Π (N-g-i)/(N-i)
            p, ok = 1.0, True
            for i in range(k):
                if N - i <= 0:
                    ok = False
                    break
                p *= max(N - g - i, 0) / (N - i)
            base[k] += (1 - p) if ok else 0.0
    n = len(uniq)

    # render
    out_path = (PROJ / "red_linux/RESULT_LINUX_ATOMIC_STAGE2_FIRED.md"
                if args.ground_truth == "fired" else OUT)
    gt_desc = ("rule **THỰC SỰ fire** trên lệnh (Zircolite, atomic_zircolite.py) — "
               "ground-truth chặt, đúng nghĩa attribution"
               if args.ground_truth == "fired"
               else "Sigma rule mang **tag MITRE cùng base-technique** (nới lỏng)")
    L, A = [], lambda s: L.append(s)
    A(f"# RED-Linux — Stage 2 Attribution trên ART ({args.ground_truth}-ground-truth)\n")
    A(f"> `stage2_atomic.py --ground-truth {args.ground_truth}`. Malicious = lệnh ART; "
      f"ground-truth = {gt_desc}. CosineRuleAttributor (production), độc lập-Sigma.\n")
    A("\n## I. Thiết lập\n")
    A(f"\n- Rules trong attributor: **{len(rule_filters_normalized)}** "
      f"(có filter values, /{len(rule_set)} rule Linux nạp).\n")
    A(f"- Lệnh ART đánh giá (có ground-truth rule): **{n}**.\n")
    if args.ground_truth == "fired":
        A("- Ground-truth = rule fire thật → chỉ gồm lệnh ART mà SigmaHQ phát hiện được "
          "(phần né hết rule không có ground-truth, không đánh giá attribution ở đây).\n")
    else:
        A(f"- Technique được phủ bởi ≥1 rule: **{len(tech_to_rules)}**. Ground-truth nới ở "
          "mức base-technique (Txxxx) vì ART không có origin-rule đơn lẻ.\n")
    A("\n## II. Top-k hit rate\n")
    A("\n| Method | Top-1 | Top-3 | Top-5 | Top-10 |")
    A("|:--|--:|--:|--:|--:|")
    A("| **Cosine** | " + " | ".join(f"**{100*hits[k]/max(n,1):.1f}%**" for k in KS) + " |")
    A("| Random baseline | " + " | ".join(f"{100*base[k]/max(n,1):.1f}%" for k in KS) + " |")
    lift1 = (hits[1] / max(n, 1)) / max(base[1] / max(n, 1), 1e-9)
    A(f"\n> Cosine top-1 cao hơn baseline ngẫu nhiên **~{lift1:.0f}×** → token similarity "
      "có tín hiệu thật, dù thấp hơn bộ evasion cũ (token chia sẻ sẵn với rule).\n")
    A("\n## III. Đọc kết quả\n")
    A("\n- Đây là attribution **đứng độc lập-Sigma**: lệnh ART (nhãn MITRE) được quy về "
      "đúng rule-technique chỉ bằng token similarity — KHÔNG dùng Sigma match logic.\n")
    A("- So với attribution cũ (origin-rule, top-1 68.8% trên evasion Sigma-derived): "
      "task này KHÁC & khó hơn (technique có thể nhiều rule, lệnh ART đa dạng hơn).\n")
    A("- Hạn chế: chỉ phủ technique có rule Sigma Linux (coverage ~69% lệnh); rule không "
      "tag MITRE bị loại khỏi ground-truth.\n")

    out_path.write_text("\n".join(L), encoding="utf-8")
    print(f"wrote {out_path}")
    print(f"  gt={args.ground_truth} rules={len(rule_filters_normalized)} n={n}")
    print("  " + " ".join(f"top{k}={100*hits[k]/max(n,1):.1f}%" for k in KS))


if __name__ == "__main__":
    main()
