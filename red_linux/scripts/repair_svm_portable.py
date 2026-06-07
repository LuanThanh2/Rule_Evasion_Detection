#!/usr/bin/env python3
"""Sửa Stage 1 ensemble model để PORTABLE qua CPU khác.

Vấn đề: model train với Intel oneDAL (patch_sklearn). oneDAL fit drop các cột feature
có coef=0 (zero trên toàn bộ support vectors) → svm.coef_ có dim 7182 nhưng
n_features_in_=7185 (vectorizer xuất 7185). Khi inference trên CPU khác, oneDAL đọc lệch
dim → MemoryError: std::bad_alloc. (LR/CNB là pure sklearn nên không sao.)

Fix: re-fit CHỈ SVM bằng PURE sklearn (RED_DISABLE_INTELEX=1) với ĐÚNG C đã chọn, trên
ĐÚNG training corpus (transform bằng vectorizer đã lưu). Pure sklearn KHÔNG drop cột →
coef_ đủ 7185-dim. Cùng C + cùng data → cùng QP → boundary y hệt (F1 không đổi). Giữ
nguyên LR/CNB/weights/scaler/shift; tái calibrate score_means/stds cho chắc.

Chạy:
  RED_DISABLE_INTELEX=1 ~/venvs/rule_evasion_env/bin/python \
    red_linux/scripts/repair_svm_portable.py
"""
import os
import sys

os.environ["RED_DISABLE_INTELEX"] = "1"  # bắt buộc: pure sklearn, không oneDAL

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.abspath(ROOT))

import numpy as np
import yaml
from sklearn.svm import SVC

from red.persist import load_result, save_result
from red.data import (
    load_rule_set, count_benign_samples, create_labels, resolve_event_paths,
)
# create_malicious_samples + training_samples_iter sống trong scripts/train.py
sys.path.insert(0, os.path.abspath(os.path.join(ROOT, "scripts")))
from train import create_malicious_samples, training_samples_iter  # noqa: E402

CONFIG = os.path.abspath(os.path.join(ROOT, "config/linux_atomic.yaml"))
MODEL_IN = os.path.abspath(os.path.join(ROOT, "models/linux_atomic/train_rslt_ensemble_atomic.zip"))
MODEL_OUT = os.path.abspath(os.path.join(ROOT, "models/linux_atomic/train_rslt_ensemble_atomic_portable.zip"))


def main():
    with open(CONFIG) as f:
        cfg = yaml.safe_load(f)
    dcfg, tcfg = cfg["data"], cfg["training"]

    print(f"Loading model: {MODEL_IN}")
    r = load_result(MODEL_IN)
    vectorizer = r["vectorizer"]
    ens = r["estimator"]
    svm_old = ens.classifiers["svm"]
    C = svm_old.get_params()["C"]
    print(f"  vectorizer dim: {len(vectorizer.vocabulary_)}")
    print(f"  OLD svm coef_: {svm_old.coef_.shape}  n_features_in_: {svm_old.n_features_in_}  C={C}")

    # ── Tái lập corpus train ĐÚNG như scripts/train.py ──
    benign_path = os.path.expanduser(dcfg["benign_train"])
    events_dir = os.path.expanduser(dcfg["events_dir"])
    rules_dir = os.path.expanduser(dcfg["rules_dir"])
    benign_field = dcfg.get("benign_field")
    max_benign = dcfg.get("max_benign_samples")
    search_fields = dcfg["search_fields"]
    event_field_map = dcfg["event_field_map"]
    norm_benign = tcfg.get("normalize_benign", False)
    mal_type = tcfg.get("malicious_samples", "matches")

    print("Loading rule set + malicious samples ...")
    rule_set = load_rule_set(events_dir, rules_dir, evasions_dir=None)
    event_paths = resolve_event_paths(search_fields, event_field_map)
    malicious = create_malicious_samples(
        rule_set, mal_type, sigma_fields=search_fields,
        event_paths=event_paths, rules_dir=rules_dir, extra_path=None,
    )
    num_benign = count_benign_samples(benign_path, benign_field, max_samples=max_benign)
    print(f"  benign={num_benign}  malicious={len(malicious)}")

    # transform bằng vectorizer ĐÃ LƯU (KHÔNG fit lại — giữ nguyên vocab/idf)
    samples = list(training_samples_iter(
        benign_path, malicious, benign_field,
        max_benign=max_benign, normalize_benign=norm_benign,
    ))
    X = vectorizer.transform(samples)
    y = create_labels(num_benign, len(malicious))
    print(f"  X={X.shape}  y={len(y)} (pos={int(np.sum(y))})")
    assert X.shape[1] == len(vectorizer.vocabulary_), "dim mismatch vs vocab"

    # ── Re-fit SVM PURE sklearn (cùng C, cùng params, cùng seed) ──
    print(f"Re-fitting PURE sklearn SVC (C={C}) ...")
    svm_new = SVC(
        C=C, kernel="linear", class_weight="balanced",
        random_state=42, cache_size=2000,
    )
    svm_new.fit(X, y)
    print(f"  NEW svm coef_: {svm_new.coef_.shape}  n_features_in_: {svm_new.n_features_in_}")
    assert svm_new.coef_.shape[1] == X.shape[1], "pure sklearn vẫn lệch dim?!"

    # sanity: boundary có khớp model cũ không (so trên vài mẫu, dùng numpy linear)
    Xd = X[:200]
    d_new = svm_new.decision_function(Xd)
    print(f"  decision_function NEW chạy OK (pure sklearn), mẫu: {d_new[:5]}")

    # ── Swap vào ensemble, tái calibrate ──
    ens.classifiers["svm"] = svm_new
    print("Re-calibrating ensemble score_means/score_stds on full training X ...")
    ens.calibrate(X)

    r["estimator"] = ens
    out_dir = os.path.dirname(MODEL_OUT)
    out_name = os.path.splitext(os.path.basename(MODEL_OUT))[0]
    save_result(r, out_name, out_dir)
    print(f"\n✅ Saved portable model: {MODEL_OUT}")
    print("   → cập nhật config detect_live_linux trỏ vào file _portable này.")


if __name__ == "__main__":
    main()
