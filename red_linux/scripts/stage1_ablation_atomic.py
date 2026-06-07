#!/usr/bin/env python3
"""
stage1_ablation_atomic.py — 7-config Stage 1 ablation trên bộ ART (Linux), song song REPORT.md
(Windows). 3 đơn (SVM/LR/CNB) + 3 ablation (SVM+LR/SVM+CNB/LR+CNB) + 1 Ensemble đầy đủ.

Hai kịch bản (song song test_match / test_evasion của Windows):
  - random  : split ngẫu nhiên 70/15/15  (~ test_match: phát hiện lệnh tấn công đã thấy phân phối)
  - holdout : hold-out technique (test = kỹ thuật MITRE CHƯA thấy ~ test_evasion: tổng quát hoá)

Mỗi config: train trên train, chốt T* trên valid (F1), báo cáo trên test. Đo P/R/F1 + Macro-F1
+ thời gian train. Tái dùng red.normalize/features/models/evaluate (cùng pipeline Windows).

⚠️ Số F1 ở đây bị CONFOUND NGUỒN (xem RESULT_CAMLDS_ARTCLEAN.md / Chương 5 §3.5): chỉ dùng để
SO SÁNH TƯƠNG ĐỐI giữa 7 cấu hình, KHÔNG đọc độ lớn tuyệt đối là năng lực. Thước đo năng lực =
OOD (camlds_ood_probe.py).

Out: red_linux/RESULT_LINUX_ABLATION.md (+ in JSON số liệu)
Run: ~/venvs/rule_evasion_env/bin/python red_linux/scripts/stage1_ablation_atomic.py
"""
import argparse, json, re, sys, time
from pathlib import Path
import numpy as np

PROJ = Path("/home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection")
BEN = Path("/home/luanthanh/data/red_linux/benign/process_creation")
ART = BEN / "atomic_malicious.jsonl"
OUT = PROJ / "red_linux/RESULT_LINUX_ABLATION.md"

sys.path.insert(0, str(PROJ))
from red.normalize import Normalizer
from red.features import create_vectorizer
from red.models import (train_svc_gridsearch, train_lr_gridsearch, train_cnb, train_ensemble)
from red.evaluate import create_mcc_scaler, scale_df_values

nz = Normalizer()
ASSIGN = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*=")

CONFIGS = [
    ("SVM", ("svm",)), ("LR", ("lr",)), ("CNB", ("cnb",)),
    ("SVM+LR", ("svm", "lr")), ("SVM+CNB", ("svm", "cnb")), ("LR+CNB", ("lr", "cnb")),
    ("Ensemble", ("svm", "lr", "cnb")),
]


def is_proc(c):
    return not (ASSIGN.match(c) or re.match(r"^\s*(if|for|while|case|echo \$|\)|\{|\}|exit\b)", c))


def load_art():
    rows = [json.loads(l) for l in open(ART)]
    return [r for r in rows if is_proc(r["command_line"])]


def split_art(rows, holdout, seed=42):
    rng = np.random.default_rng(seed)
    if holdout:
        techs = sorted({r["technique"] for r in rows}); rng.shuffle(techs)
        n = len(techs); tr = set(techs[:int(.7*n)]); va = set(techs[int(.7*n):int(.85*n)])
        b = {"train": [], "valid": [], "test": []}
        for r in rows:
            k = "train" if r["technique"] in tr else ("valid" if r["technique"] in va else "test")
            b[k].append(r["command_line"])
        return b["train"], b["valid"], b["test"]
    cmds = [r["command_line"] for r in rows]; idx = rng.permutation(len(cmds))
    a, bb = int(.7*len(cmds)), int(.85*len(cmds))
    g = lambda s: [cmds[i] for i in s]
    return g(idx[:a]), g(idx[a:bb]), g(idx[bb:])


def load_benign(split):
    return [l.rstrip("\n") for l in open(BEN / f"benign_split_{split}.txt") if l.strip()]


def stats(y, scaled, thr):
    pred = (scaled >= thr).astype(int)
    tp = int(np.sum((pred==1)&(y==1))); fp = int(np.sum((pred==1)&(y==0)))
    tn = int(np.sum((pred==0)&(y==0))); fn = int(np.sum((pred==0)&(y==1)))
    p = tp/(tp+fp) if tp+fp else 0.0; r = tp/(tp+fn) if tp+fn else 0.0
    f = 2*p*r/(p+r) if p+r else 0.0
    pn = tn/(tn+fn) if tn+fn else 0.0; rn = tn/(tn+fp) if tn+fp else 0.0
    fnb = 2*pn*rn/(pn+rn) if pn+rn else 0.0
    return dict(p=p, r=r, f1=f, f1_macro=(f+fnb)/2, tp=tp, fp=fp, tn=tn, fn=fn)


def fit_members(members, Xtr, ytr):
    if members == ("svm",): est, *_ = train_svc_gridsearch(Xtr, ytr, n_jobs=3)
    elif members == ("lr",): est, *_ = train_lr_gridsearch(Xtr, ytr, n_jobs=3)
    elif members == ("cnb",): est = train_cnb(Xtr, ytr)
    else: est, *_ = train_ensemble(Xtr, ytr, n_jobs=3, members=members)
    return est


def run_split(holdout, max_benign):
    art = load_art(); m_tr, m_va, m_te = split_art(art, holdout)
    b_tr = load_benign("train")[:max_benign]; b_va = load_benign("valid"); b_te = load_benign("test")
    build = lambda b, m: ([nz.normalize(c) for c in b]+[nz.normalize(c) for c in m],
                          np.array([0]*len(b)+[1]*len(m)))
    s_tr, y_tr = build(b_tr, m_tr); s_va, y_va = build(b_va, m_va); s_te, y_te = build(b_te, m_te)
    vec = create_vectorizer("tfidf", ngram_range=(1, 1))
    Xtr = vec.fit_transform(s_tr); Xva = vec.transform(s_va); Xte = vec.transform(s_te)
    res = {}
    for name, members in CONFIGS:
        t0 = time.time()
        est = fit_members(members, Xtr, y_tr)
        dt = time.time() - t0
        df = lambda X: (est.decision_function(X) if hasattr(est, "decision_function")
                        else est.predict_proba(X)[:, 1])
        dtr = np.asarray(df(Xtr)).ravel()
        sc, sh = create_mcc_scaler(dtr, y_tr)
        sva = scale_df_values(np.asarray(df(Xva)).ravel(), sc, sh)
        ste = scale_df_values(np.asarray(df(Xte)).ravel(), sc, sh)
        ths = np.linspace(0, 1, 51)
        tstar = max(ths, key=lambda t: stats(y_va, sva, t)["f1"])
        m = stats(y_te, ste, tstar); m["train_s"] = dt; m["tstar"] = float(tstar)
        res[name] = m
        print(f"  [{ 'holdout' if holdout else 'random'}] {name:9s} "
              f"F1={m['f1']:.3f} MacroF1={m['f1_macro']:.3f} P={m['p']:.3f} R={m['r']:.3f} ({dt:.0f}s)")
    return res, dict(m_tr=len(m_tr), m_va=len(m_va), m_te=len(m_te),
                     b_tr=len(b_tr), b_va=len(b_va), b_te=len(b_te), techs=len({r['technique'] for r in art}))


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--max-benign", type=int, default=12000)
    args = ap.parse_args()
    print("[random split]"); rnd, meta = run_split(False, args.max_benign)
    print("[holdout technique]"); hld, _ = run_split(True, args.max_benign)

    # ranking theo trung bình Macro F1 hai kịch bản
    rank = sorted(CONFIGS, key=lambda c: -(rnd[c[0]]["f1_macro"] + hld[c[0]]["f1_macro"]) / 2)

    L = []; A = L.append
    A("# RED-Linux — Stage 1 Ablation 7 cấu hình trên bộ ART (song song REPORT.md Windows)\n")
    A("> Sinh bởi `stage1_ablation_atomic.py`. 7 cấu hình: 3 đơn + 3 ablation + Ensemble. Hai "
      "kịch bản: **random** (~test_match) và **holdout technique** (~test_evasion). T\\* chốt "
      "trên valid, báo cáo trên test.\n")
    A("\n> ⚠️ **F1 dưới đây bị CONFOUND NGUỒN** (Chương 5 §3.5 / RESULT_CAMLDS_ARTCLEAN.md): "
      "malicious ART (lệnh mẫu tổng hợp) vs benign Linux-APT (log thật) khác phân phối → độ lớn "
      "tuyệt đối KHÔNG là năng lực. Bảng này chỉ để **so sánh tương đối 7 cấu hình**; năng lực "
      "thật đo bằng **OOD 8/9** (RESULT_CAMLDS_OOD.md).\n")
    A(f"\n- Dữ liệu: ART {meta['m_tr']}/{meta['m_va']}/{meta['m_te']} (train/valid/test malicious, "
      f"{meta['techs']} technique) · benign {meta['b_tr']}/{meta['b_va']}/{meta['b_te']}.\n")

    def table(res, title):
        A(f"\n## {title}\n")
        A("\n| Model | Precision | Recall | F1 | Macro F1 | T* | TP | FP | TN | FN | Train(s) |")
        A("|:--|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|")
        for name, _ in CONFIGS:
            m = res[name]
            A(f"| {name} | {m['p']:.3f} | {m['r']:.3f} | {m['f1']:.3f} | {m['f1_macro']:.3f} | "
              f"{m['tstar']:.2f} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | {m['train_s']:.1f} |")

    table(rnd, "I. Kịch bản random split (~ test_match)")
    table(hld, "II. Kịch bản hold-out technique (~ test_evasion, kỹ thuật chưa thấy)")

    A("\n## III. Ranking theo Macro F1 trung bình hai kịch bản\n")
    A("\n| Rank | Model | MacroF1 avg | MacroF1 random | MacroF1 holdout | Train(s) |")
    A("|--:|:--|--:|--:|--:|--:|")
    top = (rnd[rank[0][0]]["f1_macro"] + hld[rank[0][0]]["f1_macro"]) / 2
    for i, (name, _) in enumerate(rank, 1):
        avg = (rnd[name]["f1_macro"] + hld[name]["f1_macro"]) / 2
        A(f"| {i} | {name} | {avg:.3f} | {rnd[name]['f1_macro']:.3f} | {hld[name]['f1_macro']:.3f} "
          f"| {rnd[name]['train_s']:.1f} |")

    A("\n## IV. Đọc kết quả (trung thực)\n")
    A("\n- Đây là **so sánh tương đối** 7 cấu hình trên cùng điều kiện — KHÔNG đọc F1 tuyệt đối "
      "là năng lực phát hiện (confound nguồn).\n")
    A("- Hold-out technique (kỹ thuật chưa thấy) khắt khe hơn random; chênh lệch nhỏ giữa các "
      "cấu hình sau top nằm trong nhiễu lấy mẫu (test ART nhỏ) → KHÔNG kết luận thứ hạng tuyệt "
      "đối chỉ từ Linux; giữ lựa chọn **Ensemble** nhất quán với Windows + độ bền.\n")
    A("- Thước đo năng lực thật: **OOD recall 8/9** trên tấn công thật CAM-LDS (§3.5).\n")

    OUT.write_text("\n".join(L), encoding="utf-8")
    print(f"\nwrote {OUT}")
    print("ranking:", [n for n, _ in rank])


if __name__ == "__main__":
    main()
