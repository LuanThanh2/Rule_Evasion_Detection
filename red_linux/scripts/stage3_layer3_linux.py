#!/usr/bin/env python3
"""
Stage 2 — Layer-3 Sigma-logic validator (rerank) để nâng top-1.

Vấn đề: cosine attribution top-1 chỉ ~45% (token-similarity, dễ chọn nhầm rule họ hàng).
Ý tưởng Layer 3: cosine LỌC NHANH ra top-N ứng viên (top-10 đạt ~90% recall), rồi dùng
ENGINE SIGMA THẬT (Zircolite) XÁC NHẬN trong N ứng viên đó rule nào thực sự khớp lệnh →
đẩy lên #1. Cosine lo recall, Sigma-logic lo precision — bù điểm yếu của nhau.

Oracle Sigma-logic = `atomic_fired.jsonl` (rule thực fire mỗi lệnh, sinh bởi atomic_zircolite.py
chạy Zircolite). Trong sản xuất, bước này = chạy Sigma engine trên N rule ứng viên.

Đánh giá trên ground-truth "fired" (rule thật fire). So sánh:
  - Cosine đơn (baseline)
  - Cosine + Layer-3 rerank @ N ∈ {3,5,10}

Xuất red_linux/RESULT_LINUX_LAYER3.md
Chạy: ~/venvs/rule_evasion_env/bin/python red_linux/scripts/stage2_layer3.py
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

PROJ = Path("/home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection")
RULES = "/home/luanthanh/data/sigma/rules/linux"
FIRED = "/home/luanthanh/data/red_linux/benign/process_creation/atomic_fired.jsonl"
OUT = PROJ / "reports/linux/layer3_result.md"   # output regenerate; số chính ở RESULT_LINUX_COMBINED §5.1
SF = ["CommandLine", "Image"]
EFM = {"CommandLine": ["process.command_line"], "Image": ["process.executable", "exe"]}

sys.path.insert(0, str(PROJ))
from red.data import (load_rule_set, resolve_event_paths,            # noqa: E402
                      extract_filter_values, extract_sigma_detection_values)
from red.normalize import normalize_samples, Normalizer             # noqa: E402
from red.features import create_vectorizer                          # noqa: E402
from red.attribution import CosineRuleAttributor                    # noqa: E402

nz = Normalizer()
KS = [1, 3, 5, 10]
NS = [3, 5, 10]   # độ sâu cosine cho Layer-3 xác nhận


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
    return CosineRuleAttributor.fit(rfn, create_vectorizer("tfidf", ngram_range=(1, 1))), set(rfn)


def layer3_rerank(names, fired_set, n):
    """Đẩy các rule THỰC FIRE (Sigma-logic) trong top-N cosine lên đầu, giữ thứ tự cosine."""
    head = [r for r in names[:n] if r in fired_set]      # Sigma xác nhận khớp
    rest = [r for r in names if r not in head]
    return head + rest


def topk_hits(items, rankings):
    hit = {k: 0 for k in KS}
    for (_, gt), names in zip(items, rankings):
        for k in KS:
            if gt & set(names[:k]):
                hit[k] += 1
    n = len(items)
    return {k: 100 * hit[k] / n for k in KS}


def main():
    attr, rule_set = build_attributor()
    # oracle: command -> set rule fire thật (∩ rule trong attributor)
    fired_oracle = {}
    items = []   # (cmd, gt) với gt = rule fire ∈ attributor
    for a in (json.loads(l) for l in open(FIRED)):
        fset = {f["title"] for f in a["fired"] if f["title"] in rule_set}
        if fset:
            fired_oracle[a["command_line"]] = fset
            items.append((a["command_line"], fset))

    norm = [nz.normalize(c) for c, _ in items]
    ranked = attr.score_samples(norm)
    names_list = [[n for n, _ in rk] for rk in ranked]

    cosine = topk_hits(items, names_list)
    layer3 = {}
    for N in NS:
        rer = [layer3_rerank(names_list[i], fired_oracle[items[i][0]], N)
               for i in range(len(items))]
        layer3[N] = topk_hits(items, rer)

    # render
    L, A = [], lambda s: L.append(s)
    A("# RED-Linux — Stage 2 Layer-3 Sigma-logic validator\n")
    A("> `stage2_layer3.py`. Cosine lọc top-N ứng viên → Zircolite (Sigma engine thật) xác "
      "nhận rule nào khớp → đẩy #1. Đánh giá trên ground-truth *fired* (n="
      f"{len(items)} lệnh ART có rule fire).\n")
    A("\n## So sánh top-k hit rate\n")
    A("\n| Phương pháp | Top-1 | Top-3 | Top-5 | Top-10 |")
    A("|---|--:|--:|--:|--:|")
    A("| Cosine (baseline) | " + " | ".join(f"{cosine[k]:.1f}%" for k in KS) + " |")
    for N in NS:
        A(f"| **Cosine + Layer-3 @top-{N}** | "
          + " | ".join(f"**{layer3[N][k]:.1f}%**" if k == 1 else f"{layer3[N][k]:.1f}%" for k in KS)
          + " |")
    A(f"\n→ Layer-3 nâng **top-1 từ {cosine[1]:.1f}% lên {layer3[10][1]:.1f}%** (xác nhận trong "
      "top-10 cosine). Top-1 sau Layer-3 = đúng bằng **recall top-N của cosine**: Sigma-logic "
      "chọn chính xác rule khớp trong số ứng viên cosine đưa ra.\n")
    A("\n## Đọc kết quả (trung thực)\n")
    A(f"\n- **Cơ chế đúng đắn**: cosine một mình hay nhầm rule họ-hàng (top-1 {cosine[1]:.0f}%); "
      "thêm bước chạy logic Sigma thật để **xác nhận** thì loại được nhầm lẫn → top-1 ≈ "
      f"{layer3[10][1]:.0f}%.\n")
    A("- **Giới hạn**: Layer-3 chỉ giúp lệnh mà **có rule thật khớp** (đã/đang fire). Với "
      "**evasion thuần** (không rule nào fire — attacker xoá hết chữ ký) thì Sigma-logic không "
      "xác nhận được gì → rơi về cosine. Đây là ranh giới bản chất: token bị xoá thì không "
      "phương pháp nào (kể cả Sigma-logic) quy về đúng rule đã bị né.\n")
    A("- **Chi phí**: chỉ chạy Sigma-logic trên **N rule ứng viên** (không phải toàn catalog) "
      "→ rẻ. Cosine làm phần nặng (lọc), Sigma-logic làm phần chính xác (chốt).\n")
    A(f"- Top-N nhỏ hơn → trần thấp hơn: @top-3 {layer3[3][1]:.0f}% / @top-5 {layer3[5][1]:.0f}% "
      f"/ @top-10 {layer3[10][1]:.0f}% (đánh đổi số rule phải kiểm tra vs độ chính xác).\n")

    OUT.write_text("\n".join(L), encoding="utf-8")
    print(f"wrote {OUT}")
    print(f"  cosine top-1={cosine[1]:.1f}%  →  +Layer3@10 top-1={layer3[10][1]:.1f}% "
          f"(@5={layer3[5][1]:.1f} @3={layer3[3][1]:.1f}) | n={len(items)}")


if __name__ == "__main__":
    main()
