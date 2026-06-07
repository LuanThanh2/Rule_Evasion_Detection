#!/usr/bin/env python3
"""
Stage 1 trên malicious ĐỘC LẬP-SIGMA (Atomic Red Team) — fix gốc V1+V2.

Khác bộ Linux-APT-Dataset-2024 (malicious = Sigma match → vòng tròn + nhiễm nhãn),
ở đây malicious = lệnh ART gắn nhãn theo MITRE technique (overlap benign chỉ ~1.6%
vs 68% của match cũ). Đây là phép thử để Linux ĐỨNG ĐỘC LẬP, không mượn Windows.

Tái dùng đúng code pipeline: red.normalize + red.features + red.models + red.evaluate.
Quy trình mirror ablation: fit vectorizer trên train → train model → chốt T* trên
VALID (sweep F1) → báo cáo trên TEST với T* cố định.

Split:
  benign  : dùng sẵn benign_split_{train,valid,test}.txt
  malicious (ART): chia 70/15/15 (khớp benign Linux + bộ Windows). Mặc định ngẫu nhiên; --holdout-technique =
                   chia theo MITRE technique (train-tech ∩ test-tech = ∅) để đo
                   TỔNG QUÁT HOÁ sang kỹ thuật tấn công CHƯA TỪNG THẤY (khắt khe hơn).

Xuất: red_linux/RESULT_LINUX_ATOMIC.md
Chạy: ~/venvs/rule_evasion_env/bin/python red_linux/scripts/stage1_atomic.py
        [--holdout-technique] [--models svm lr cnb ensemble]
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

PROJ = Path("/home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection")
BEN = Path("/home/luanthanh/data/red_linux/benign/process_creation")
ART = BEN / "atomic_malicious.jsonl"
OUT = PROJ / "red_linux/RESULT_LINUX_ATOMIC.md"

sys.path.insert(0, str(PROJ))
from red.normalize import Normalizer                      # noqa: E402
from red.features import create_vectorizer                # noqa: E402
from red.models import (train_svc_gridsearch, train_lr_gridsearch,   # noqa: E402
                        train_cnb, train_ensemble)
from red.evaluate import create_mcc_scaler, scale_df_values          # noqa: E402

nz = Normalizer()
ASSIGN = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*=")


def is_proc(c):
    """Bỏ dòng gán biến thuần / control-flow (không phải process_creation)."""
    if ASSIGN.match(c):
        return False
    if re.match(r"^\s*(if|for|while|case|echo \$|\)|\{|\}|exit\b)", c):
        return False
    return True


def load_benign(split):
    p = BEN / f"benign_split_{split}.txt"
    return [l.rstrip("\n") for l in open(p) if l.strip()]


def load_art():
    rows = [json.loads(l) for l in open(ART)]
    return [r for r in rows if is_proc(r["command_line"])]


def split_art(rows, holdout_technique, seed=42):
    rng = np.random.default_rng(seed)
    if holdout_technique:
        techs = sorted({r["technique"] for r in rows})
        rng.shuffle(techs)
        n = len(techs)
        tr = set(techs[: int(.7 * n)])
        va = set(techs[int(.7 * n): int(.85 * n)])
        buckets = {"train": [], "valid": [], "test": []}
        for r in rows:
            t = r["technique"]
            k = "train" if t in tr else ("valid" if t in va else "test")
            buckets[k].append(r["command_line"])
        return buckets["train"], buckets["valid"], buckets["test"]
    cmds = [r["command_line"] for r in rows]
    idx = rng.permutation(len(cmds))
    n = len(cmds)
    a, b = int(.7 * n), int(.85 * n)
    g = lambda s: [cmds[i] for i in s]
    return g(idx[:a]), g(idx[a:b]), g(idx[b:])


def f1_at(labels, scaled, thr):
    pred = (scaled >= thr).astype(int)
    tp = int(np.sum((pred == 1) & (labels == 1)))
    fp = int(np.sum((pred == 1) & (labels == 0)))
    tn = int(np.sum((pred == 0) & (labels == 0)))
    fn = int(np.sum((pred == 0) & (labels == 1)))
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    # macro F1
    pn = tn / (tn + fn) if tn + fn else 0.0
    rn = tn / (tn + fp) if tn + fp else 0.0
    fn_ = 2 * pn * rn / (pn + rn) if pn + rn else 0.0
    return dict(p=p, r=r, f1=f, f1_macro=(f + fn_) / 2, tp=tp, fp=fp, tn=tn, fn=fn)


def fit_predict(name, Xtr, ytr, Xva, Xte):
    if name == "svm":
        est, *_ = train_svc_gridsearch(Xtr, ytr, n_jobs=3)
    elif name == "lr":
        est, *_ = train_lr_gridsearch(Xtr, ytr, n_jobs=3)
    elif name == "cnb":
        est = train_cnb(Xtr, ytr)
    elif name == "ensemble":
        est, *_ = train_ensemble(Xtr, ytr, n_jobs=3, members=("svm", "lr", "cnb"))
    else:
        raise ValueError(name)
    df = lambda X: (est.decision_function(X) if hasattr(est, "decision_function")
                    else est.predict_proba(X)[:, 1])
    return np.asarray(df(Xtr)).ravel(), np.asarray(df(Xva)).ravel(), np.asarray(df(Xte)).ravel()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--holdout-technique", action="store_true")
    ap.add_argument("--models", nargs="+", default=["svm", "lr", "cnb", "ensemble"])
    ap.add_argument("--max-benign", type=int, default=12000)
    args = ap.parse_args()

    out_path = (PROJ / "red_linux/RESULT_LINUX_ATOMIC_HOLDOUT.md"
                if args.holdout_technique else OUT)
    art = load_art()
    m_tr, m_va, m_te = split_art(art, args.holdout_technique)
    b_tr = load_benign("train")[: args.max_benign]
    b_va, b_te = load_benign("valid"), load_benign("test")

    # contamination (normform malicious ∩ benign-all)
    bset = set(nz.normalize(c) for c in (b_tr + b_va + b_te))
    cont = sum(1 for c in (m_tr + m_va + m_te) if nz.normalize(c) in bset)
    n_mal_all = len(m_tr) + len(m_va) + len(m_te)

    def build(bcmds, mcmds):
        samples = [nz.normalize(c) for c in bcmds] + [nz.normalize(c) for c in mcmds]
        y = np.array([0] * len(bcmds) + [1] * len(mcmds))
        return samples, y

    s_tr, y_tr = build(b_tr, m_tr)
    s_va, y_va = build(b_va, m_va)
    s_te, y_te = build(b_te, m_te)

    vec = create_vectorizer("tfidf", ngram_range=(1, 1))
    Xtr = vec.fit_transform(s_tr)
    Xva, Xte = vec.transform(s_va), vec.transform(s_te)

    results = {}
    for name in args.models:
        dtr, dva, dte = fit_predict(name, Xtr, y_tr, Xva, Xte)
        scaler, shift = create_mcc_scaler(dtr, y_tr)
        sva = scale_df_values(dva, scaler, shift)
        ste = scale_df_values(dte, scaler, shift)
        # chốt T* trên VALID (sweep 50)
        ths = np.linspace(0, 1, 51)
        best = max(ths, key=lambda t: f1_at(y_va, sva, t)["f1"])
        results[name] = f1_at(y_te, ste, best) | {"tstar": float(best)}

    # render
    LAB = {"svm": "SVM", "lr": "LR", "cnb": "CNB", "ensemble": "Ensemble"}
    L, A = [], lambda s: L.append(s)
    mode = "HOLD-OUT technique (test = kỹ thuật CHƯA thấy)" if args.holdout_technique \
        else "random 70/15/15"
    A("# RED-Linux — Stage 1 trên malicious độc lập-Sigma (Atomic Red Team)\n")
    A(f"> Sinh bởi `red_linux/scripts/stage1_atomic.py`. Malicious = lệnh ART (MITRE), "
      f"split **{mode}**. Tái dùng red.normalize/features/models/evaluate (cùng pipeline). "
      "T\\* chốt trên valid, báo cáo trên test.\n")
    A("\n## I. Vì sao bộ này\n")
    A(f"\n- Malicious ART overlap benign chỉ **{cont}/{n_mal_all} "
      f"({100*cont/max(n_mal_all,1):.1f}%)** — so với **68%** của match Sigma cũ → "
      "fix V1 (nhiễm nhãn) + V2 (vòng tròn: nhãn theo MITRE, KHÔNG theo Sigma).\n")
    A(f"- Quy mô: {n_mal_all} lệnh tấn công, {len({r['technique'] for r in art})} "
      "MITRE technique. Benign giữ nguyên 3-way split.\n")
    A(f"- Split: train {len(m_tr)} / valid {len(m_va)} / test {len(m_te)} malicious; "
      f"benign {len(b_tr)}/{len(b_va)}/{len(b_te)}.\n")
    A("\n## II. Kết quả Stage 1 (test, T* cố định từ valid)\n")
    A("\n| Model | Precision | Recall | F1 | Macro F1 | T* | TP | FP | TN | FN |")
    A("|:--|--:|--:|--:|--:|--:|--:|--:|--:|--:|")
    for name in args.models:
        m = results[name]
        A(f"| {LAB.get(name,name)} | {m['p']:.3f} | {m['r']:.3f} | {m['f1']:.3f} | "
          f"{m['f1_macro']:.3f} | {m['tstar']:.2f} | {m['tp']} | {m['fp']} | "
          f"{m['tn']} | {m['fn']} |")
    A("\n## III. Đọc kết quả\n")
    A("\n- Đây là phép đo **đứng độc lập cho Linux**: malicious không phải pattern Sigma "
      "nên F1 ở đây phản ánh năng lực phát hiện **lệnh tấn công thật vs benign**, KHÔNG "
      "phải 'nhận lại pattern đã học' (V2).\n")
    A("- Nếu F1 < 1.0 (khác bộ cũ đụng trần): tốt — chứng tỏ task có độ khó thật, có thể "
      "**xếp hạng model trên Linux** mà không cần mượn kết luận Windows.\n")
    if args.holdout_technique:
        A("- **Hold-out technique**: test toàn kỹ thuật chưa thấy khi train → đo tổng quát "
          "hoá sang biến thể tấn công mới (gần với 'evasion' đúng nghĩa).\n")

    out_path.write_text("\n".join(L), encoding="utf-8")
    print(f"wrote {out_path}")
    for name in args.models:
        m = results[name]
        print(f"  {name}: F1={m['f1']:.3f} macroF1={m['f1_macro']:.3f} "
              f"P={m['p']:.3f} R={m['r']:.3f} (FP={m['fp']} FN={m['fn']})")


if __name__ == "__main__":
    main()
