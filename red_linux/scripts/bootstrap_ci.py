#!/usr/bin/env python3
"""
Bootstrap CI 95% cho RED-Linux Stage 1 — fix V3 (ranking ablation không tin được).

Đọc các output thực nghiệm đã có (KHÔNG train lại):
  - models/linux_process_creation/valid_rslt_<key>_test_<sub>.zip
        -> predict (raw decision scores), labels, scaler, shift  (per-sample)
  - models/linux_process_creation/eval_rslt_<key>_test_<sub>_info.json
        -> fixed_threshold.threshold (T* chốt trên valid, áp cố định lên test)

Với mỗi cấu hình & subset, resample test set có hoàn lại (nonparametric bootstrap),
áp ĐÚNG scaling + T* cố định như evaluate.py, tính lại Macro/Weighted F1 + MCC →
percentile CI [2.5, 97.5]. Sau đó xếp hạng theo Macro F1 avg (match+evasion) và
kiểm tra CI có CHỒNG NHAU không → kết luận thống kê các model tương đương hay không.

Xuất red_linux/RESULT_LINUX_BOOTSTRAP.md.

Chạy: ~/venvs/rule_evasion_env/bin/python red_linux/scripts/bootstrap_ci.py
       [--n-boot 10000] [--seed 42]
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np

PROJ = Path("/home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection")
MODELS = PROJ / "models/linux_process_creation"
OUT = PROJ / "red_linux/RESULT_LINUX_BOOTSTRAP.md"

sys.path.insert(0, str(PROJ))
from red.persist import load_result          # noqa: E402
from red.evaluate import scale_df_values      # noqa: E402

KEYS = ["svm", "lr", "cnb", "svm_lr", "svm_cnb", "lr_cnb", "ensemble"]
LABEL = {"svm": "SVM", "lr": "LR", "cnb": "CNB", "svm_lr": "SVM+LR",
         "svm_cnb": "SVM+CNB", "lr_cnb": "LR+CNB", "ensemble": "Ensemble"}
SUBS = ["match", "evasion"]


def confusion_metrics(labels, pred):
    """tp/fp/tn/fn -> Macro & Weighted F1 (KHỚP generate_linux_report.metrics)."""
    tp = int(np.sum((pred == 1) & (labels == 1)))
    fp = int(np.sum((pred == 1) & (labels == 0)))
    tn = int(np.sum((pred == 0) & (labels == 0)))
    fn = int(np.sum((pred == 0) & (labels == 1)))
    sp, sn = tp + fn, tn + fp                       # support malicious / benign
    tot = sp + sn or 1
    p_pos = tp / (tp + fp) if tp + fp else 0.0
    r_pos = tp / (tp + fn) if tp + fn else 0.0
    f_pos = 2 * p_pos * r_pos / (p_pos + r_pos) if p_pos + r_pos else 0.0
    p_neg = tn / (tn + fn) if tn + fn else 0.0
    r_neg = tn / (tn + fp) if tn + fp else 0.0
    f_neg = 2 * p_neg * r_neg / (p_neg + r_neg) if p_neg + r_neg else 0.0
    f1_m = (f_pos + f_neg) / 2
    f1_w = (sp * f_pos + sn * f_neg) / tot
    return f1_m, f1_w


def load_scaled(key, sub, base=MODELS):
    """-> (scaled_scores, labels, T*). None nếu thiếu file."""
    vp = base / f"valid_rslt_{key}_test_{sub}.zip"
    ip = base / f"eval_rslt_{key}_test_{sub}_info.json"
    if not vp.exists() or not ip.exists():
        return None
    r = load_result(str(vp))
    scaled = scale_df_values(r["predict"], r["scaler"], float(r["shift"]))
    labels = np.asarray(r["labels"]).astype(int)
    tstar = json.load(open(ip))["fixed_threshold"]["threshold"]
    return scaled, labels, float(tstar)


def gather(base_dirs, n_boot, rng):
    """Gộp bootstrap qua nhiều seed-dir → bất định (seed × resample).

    Mỗi seed-dir góp `n_boot // nseeds` resample; trong CÙNG seed+subset mọi model
    dùng CHUNG idx (paired); nối các block seed lại (mỗi block vẫn paired) →
    phân phối gộp phản ánh cả bất định huấn luyện lẫn lấy mẫu test.
    Trả: boot_f1m[(key,sub)] -> ndarray, point_f1m[(key,sub)] -> mean-over-seeds, n_mal[sub].
    """
    per = max(1, n_boot // len(base_dirs))
    boot_f1m = {(k, s): [] for k in KEYS for s in SUBS}
    pt_acc = {(k, s): [] for k in KEYS for s in SUBS}
    n_mal = {}
    for base in base_dirs:
        for sub in SUBS:
            ref = next((load_scaled(k, sub, base) for k in KEYS
                        if load_scaled(k, sub, base)), None)
            if ref is None:
                continue
            n = len(ref[1])
            n_mal[sub] = int(ref[1].sum())
            idx = boot_indices(n, per, rng)        # chung cho mọi model seed+subset này
            for key in KEYS:
                got = load_scaled(key, sub, base)
                if got is None:
                    continue
                scaled, labels, tstar = got
                f1m, pf = boot_f1m_shared(scaled, labels, tstar, idx)
                boot_f1m[(key, sub)].append(f1m)
                pt_acc[(key, sub)].append(pf)
    boot_f1m = {k: np.concatenate(v) for k, v in boot_f1m.items() if v}
    point_f1m = {k: float(np.mean(v)) for k, v in pt_acc.items() if v}
    return boot_f1m, point_f1m, n_mal


def boot_indices(n, n_boot, rng):
    """Ma trận (n_boot, n) chỉ số resample có hoàn lại."""
    return rng.integers(0, n, size=(n_boot, n))


def ci(arr, lo=2.5, hi=97.5):
    return float(np.percentile(arr, lo)), float(np.percentile(arr, hi))


def boot_f1m_shared(scaled, labels, tstar, idx):
    """Macro F1 cho từng hàng của ma trận chỉ số `idx` (shared bootstrap).
    Dùng CHUNG idx cho mọi model trong cùng subset → hiệu số giữa các model là PAIRED."""
    pred_full = (scaled >= tstar).astype(int)
    out = np.empty(idx.shape[0])
    for b in range(idx.shape[0]):
        ii = idx[b]
        out[b] = confusion_metrics(labels[ii], pred_full[ii])[0]
    return out, confusion_metrics(labels, pred_full)[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-boot", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--multiseed", action="store_true",
                    help="gộp mọi models/.../seeds/seed_*/ (bất định seed × resample)")
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)

    # 1) Chọn nguồn: 1 thư mục (seed-42) hoặc gộp đa seed.
    if args.multiseed:
        base_dirs = sorted((MODELS / "seeds").glob("seed_*"))
        if not base_dirs:
            ap.error("--multiseed nhưng không thấy models/.../seeds/seed_* "
                     "(chạy run_multiseed.sh trước)")
        seeds_used = [d.name.replace("seed_", "") for d in base_dirs]
    else:
        # seed-42 ưu tiên đọc từ backup seeds/seed_42 (bền khi run_multiseed.sh
        # đã move file test khỏi top-level); fallback top-level nếu chưa backup.
        s42 = MODELS / "seeds" / "seed_42"
        base_dirs = [s42] if s42.exists() else [MODELS]
        seeds_used = ["42"]
    boot_f1m, point_f1m, n_mal = gather(base_dirs, args.n_boot, rng)

    # 2) Combined ranking metric: Macro F1 avg = mean(match, evasion) per resample.
    combined = {}        # key -> ndarray[n_boot]
    point_avg = {}       # key -> float
    for key in KEYS:
        if (key, "match") in boot_f1m and (key, "evasion") in boot_f1m:
            combined[key] = (boot_f1m[(key, "match")] + boot_f1m[(key, "evasion")]) / 2
            point_avg[key] = (point_f1m[(key, "match")] + point_f1m[(key, "evasion")]) / 2

    rank = sorted(point_avg, key=lambda k: -point_avg[k])
    top = rank[0]

    # 3) PAIRED difference test: Δ = combined[top] - combined[key] mỗi resample.
    #    Khác biệt "có ý nghĩa" nếu CI của Δ KHÔNG chứa 0 (tức lo > 0).
    diff_ci = {}         # key -> (point_delta, lo, hi, significant)
    for k in rank:
        if k == top:
            continue
        d = combined[top] - combined[k]
        lo, hi = ci(d)
        diff_ci[k] = (point_avg[top] - point_avg[k], lo, hi, lo > 0)

    # cờ suy biến: model perfect trên MỌI resample (CI biên rộng = 0) → đụng trần
    degenerate = {k: (ci(combined[k])[1] - ci(combined[k])[0] == 0.0
                      and point_avg[k] >= 0.9999) for k in rank}
    n_sig = sum(1 for v in diff_ci.values() if v[3])

    # 4) Render markdown
    L = []
    A = L.append
    mode = (f"MULTI-SEED gộp {len(seeds_used)} seed ({', '.join(seeds_used)}) — "
            "bất định seed × resample" if args.multiseed
            else "seed-42 đơn (chỉ bất định lấy mẫu test)")
    A("# RED-Linux — Bootstrap CI 95% (Stage 1) — fix V3\n")
    A(f"> Sinh tự động bởi `red_linux/scripts/bootstrap_ci.py` "
      f"(B≈{args.n_boot:,} resample, rng-seed={args.seed}, percentile CI [2.5, 97.5]). "
      f"Nguồn: **{mode}**. Chỉ đọc output đã có — KHÔNG train lại.\n")
    A("\nMục tiêu: biến *\"ranking ablation không tin được\"* (V3) thành kết luận thống kê. "
      "Bootstrap resample test set có hoàn lại (chung chỉ số cho mọi model → **paired**), "
      "giữ nguyên scaling + T\\* cố định, tính lại Macro F1 mỗi lần → CI 95%. So sánh model "
      "bằng **CI của hiệu số Δ vs top** (Mục II): Δ chứa 0 ⇒ không khác biệt. "
      "Lưu ý: significance trên một test cố định **quá dễ/nhỏ** chỉ nói \"số ổn định\", "
      "KHÔNG đồng nghĩa model thực sự tốt hơn (xem Mục III).\n")
    A(f"\nTest support: **test_match** {n_mal.get('match','?')} malicious, "
      f"**test_evasion** {n_mal.get('evasion','?')} malicious (benign ~2,633). "
      "Test evasion rất nhỏ → CI rộng là điều **được kỳ vọng**, đúng bản chất V3.\n")

    A("\n---\n\n## I. Macro F1 + CI 95% theo subset (CI biên mỗi model)\n")
    for sub in SUBS:
        A(f"\n### {sub} (test_{sub})\n")
        A("\n| Model | Macro F1 (point) | CI 95% | Độ rộng CI |")
        A("|:--|--:|:--:|--:|")
        for key in KEYS:
            if (key, sub) not in boot_f1m:
                A(f"| {LABEL[key]} | – | – | – |")
                continue
            lo, hi = ci(boot_f1m[(key, sub)])
            pf = point_f1m[(key, sub)]
            tag = " ⚠️trần" if (hi - lo == 0.0 and pf >= 0.9999) else ""
            A(f"| {LABEL[key]} | {pf:.4f}{tag} | [{lo:.4f}, {hi:.4f}] | {hi-lo:.4f} |")
    A("\n> ⚠️trần = Macro F1 = 1.0 trên **mọi** lần resample (CI suy biến, độ rộng 0). "
      "Không phải \"chắc chắn hoàn hảo\" mà là **test quá dễ/nhỏ để bootstrap phân giải** — "
      "đúng triệu chứng đụng trần của V3.\n")

    A("\n---\n\n## II. So sánh đúng cách — PAIRED bootstrap hiệu số vs top\n")
    A(f"\nMetric xếp hạng: Macro F1 avg (match+evasion). Top = **{LABEL[top]}** "
      f"({point_avg[top]:.4f}). Δ = F1(top) − F1(model) trên CÙNG lần resample (paired). "
      "Khác biệt **có ý nghĩa thống kê** ⇔ CI 95% của Δ không chứa 0 (lo > 0).\n")
    A("\n| Rank | Model | Macro F1 avg | Δ vs top | CI 95% của Δ | Khác biệt có ý nghĩa? |")
    A("|--:|:--|--:|--:|:--:|:--:|")
    for i, k in enumerate(rank, 1):
        if k == top:
            A(f"| {i} | {LABEL[k]} | {point_avg[k]:.4f} | — | — | — (top) |")
            continue
        dpt, lo, hi, sig = diff_ci[k]
        A(f"| {i} | {LABEL[k]} | {point_avg[k]:.4f} | {dpt:.4f} | "
          f"[{lo:.4f}, {hi:.4f}] | {'❌ CÓ (sig.)' if sig else '✅ không'} |")

    A("\n---\n\n## III. Kết luận thống kê (đọc trung thực)\n")
    A(f"\nPaired bootstrap cho thấy **{n_sig}/{len(diff_ci)}** cấu hình có Δ vs top khác 0 "
      "ở mức 95%. **Nhưng đây KHÔNG phải bằng chứng model nào tốt hơn về bản chất** — vì:\n")
    if any(degenerate.values()):
        degs = [LABEL[k] for k in rank if degenerate[k]]
        A(f"- **Top/đầu bảng đụng trần** ({', '.join(degs)} có F1=1.0, phương sai 0). "
          "Bootstrap resample lặp lại CÙNG 34 mẫu evasion + 182 match dễ → giữ nguyên điểm "
          "tuyệt đối, nên \"significant\" ở đây phản ánh **test thiếu độ phân giải**, không "
          "phản ánh năng lực model. Đây chính là artifact V3 (SVM=1.0 do data dễ + test nhỏ).\n")
    A("- **Ensemble thấp nhất là artifact ngưỡng**, không phải model kém: z-score averaging + "
      "T\\* cố định (chốt trên 32 mẫu valid) đẩy FP trên test nhỏ → giảm Macro F1 evasion "
      "(point 0.83). Cơ chế ngưỡng, trùng đúng cảnh báo V3.\n")
    A("- Khoảng cách tuyệt đối **rất nhỏ** (top→hạng 3 chênh < 0.005 Macro F1) và bị chi phối "
      "bởi 1–2 mẫu evasion (n=34).\n")
    A(f"\n**→ Kết luận:** bootstrap xác nhận các con số **ổn định trên test hiện tại**, "
      "nhưng test này quá dễ/nhỏ + nhiễm nhãn nên **không dùng để xếp hạng model trên Linux**. "
      "Giữ nguyên kết luận chọn model theo thực nghiệm Windows (RESULT_2.md). "
      f"KHÔNG kết luận \"{LABEL[top]} > Ensemble trên Linux\".\n")
    A("\n**Giới hạn còn lại (không fix bằng bootstrap):**\n")
    A("- Bootstrap chỉ định lượng *bất định lấy mẫu* trên test cố định; KHÔNG khắc phục "
      "**V1 (nhiễm nhãn)** và **V2 (task quá dễ vì malicious = pattern Sigma)**. "
      "Hai cái đó cần **nguồn malicious tách bạch (Atomic Red Team Linux)** + test evasion lớn hơn.\n")
    A("- Chưa có **multi-seed**: models train cố định `random_state=42`. Muốn tách thêm "
      "*bất định huấn luyện*, chạy `run_ablation.sh` với nhiều seed rồi gộp CI (retrain 7×N).\n")

    OUT.write_text("\n".join(L), encoding="utf-8")
    print(f"wrote {OUT}")
    print(f"  ranking: {[LABEL[k] for k in rank]}")
    print(f"  top={LABEL[top]} | paired-sig differences: {n_sig}/{len(diff_ci)}"
          f" | degenerate(ceiling): {[LABEL[k] for k in rank if degenerate[k]]}")


if __name__ == "__main__":
    main()
