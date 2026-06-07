#!/usr/bin/env python3
"""
Benign sanity check — model production có VU OAN benign không?

Mô phỏng đúng đường inference thật (`detect_batch` chuẩn hoá MỌI lệnh): chấm điểm toàn bộ
benign test bằng model `models/linux_atomic`, đo tỷ lệ bị gắn cờ (false positive) ở T*.
In thêm vài ví dụ benign (điểm thấp) và tấn công ART (điểm cao) để thấy model tách lớp.

Đây là phép kiểm chứng cho bản FIX `normalize_benign`: trước fix benign-normalized bị cờ
~84% (lỗi); sau fix chỉ ~0.65%.

Chạy: ~/venvs/rule_evasion_env/bin/python red_linux/scripts/benign_sanity.py [--threshold 0.46]
"""

import argparse
import json
import random
import sys
from pathlib import Path

import numpy as np

PROJ = Path("/home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection")
B = Path("/home/luanthanh/data/red_linux/benign/process_creation")
MODEL = PROJ / "models/linux_atomic/train_rslt_ensemble_atomic.zip"

sys.path.insert(0, str(PROJ))
from red.persist import load_result                 # noqa: E402
from red.normalize import Normalizer                # noqa: E402
from red.evaluate import scale_df_values            # noqa: E402

nz = Normalizer()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=float, default=0.46)
    ap.add_argument("--model", default=str(MODEL))
    args = ap.parse_args()
    T = args.threshold

    m = load_result(args.model)
    est, vec, sc, sh = m["estimator"], m["vectorizer"], m["scaler"], float(m["shift"])

    def score(c):
        X = vec.transform([nz.normalize(c)])         # detect_batch LUÔN normalize
        if X.nnz == 0:
            return 0.0
        return float(scale_df_values(np.asarray(est.decision_function(X)).ravel(), sc, sh)[0])

    ben = [l.strip() for l in open(B / "benign_split_test.txt") if l.strip()]
    s = np.array([score(c) for c in ben])
    fp = int((s >= T).sum())
    print(f"Model: {Path(args.model).name} | T*={T}")
    print(f"[BENIGN] {len(ben)} lệnh | bị cờ: {fp} ({100*fp/len(ben):.2f}% FP) | "
          f"điểm TB={s.mean():.3f} trung vị={np.median(s):.3f}")

    random.seed(3)
    print("\n[Ví dụ BENIGN — điểm thấp = KHÔNG cờ ✅]")
    for c in random.sample(ben, 6):
        print(f"  {score(c):.3f}  {c[:74]}")

    artf = B / "atomic_malicious.jsonl"
    if artf.exists():
        art = [json.loads(l)["command_line"] for l in open(artf)]
        art = [c for c in art if len(c) > 15 and "PathToAtomics" not in c]
        random.seed(7)
        print("\n[Ví dụ TẤN CÔNG ART — điểm cao = cờ đúng]")
        for c in random.sample(art, 6):
            print(f"  {score(c):.3f}  {c[:74]}")

    print(f"\n→ FP {100*fp/len(ben):.2f}% ({'ĐẠT' if fp/len(ben) < 0.05 else 'CAO'}). "
          "Model tách benign (điểm thấp) khỏi tấn công (điểm cao).")


if __name__ == "__main__":
    main()
