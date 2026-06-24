#!/usr/bin/env python3
"""Sửa Stage 1 ensemble model bất kỳ → PORTABLE qua CPU khác (tổng quát hoá).

Giống red_linux/scripts/repair_svm_portable.py (hardcode linux_atomic) nhưng nhận
--config / --model-in / --model-out để dùng cho mọi event type (process_creation,
registry_event, powershell, ...).

Vấn đề: model train với Intel oneDAL (patch_sklearn). Khi load bằng pure sklearn trên
máy KHÔNG có sklearnex, SVC thiếu các fitted attr (`_dual_coef_`, `_intercept_`) →
decision_function ném AttributeError.

Fix: re-fit CHỈ SVM bằng PURE sklearn (RED_DISABLE_INTELEX=1) với ĐÚNG C đã chọn, trên
ĐÚNG training corpus (tái lập y hệt scripts/train.py: load_rule_set với evasions_dir,
create_malicious_samples, transform bằng vectorizer ĐÃ LƯU). Cùng C + cùng data → cùng
QP → boundary y hệt (F1 không đổi). Giữ nguyên LR/CNB/weights/scaler/shift; tái calibrate.

Chạy (ví dụ process_creation):
  RED_DISABLE_INTELEX=1 ~/venvs/rule_evasion_env/bin/python \
    red_linux/scripts/repair_svm_portable_generic.py \
    --config config/process_creation.yaml \
    --model-in  models/process_creation/train_rslt_ensemble.zip \
    --model-out models/process_creation/train_rslt_ensemble_portable.zip
"""
import argparse
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


def build_corpus(dcfg, tcfg, vectorizer):
    """Tái lập corpus train ĐÚNG như scripts/train.py main() rồi transform bằng
    vectorizer ĐÃ LƯU (KHÔNG fit lại — giữ nguyên vocab/idf)."""
    benign_path = os.path.expanduser(dcfg["benign_train"])
    events_dir = os.path.expanduser(dcfg["events_dir"])
    rules_dir = os.path.expanduser(dcfg["rules_dir"])
    benign_field = dcfg.get("benign_field")
    max_benign = dcfg.get("max_benign_samples")
    search_fields = dcfg["search_fields"]
    event_field_map = dcfg.get("event_field_map", {})
    norm_benign = tcfg.get("normalize_benign", False)
    mal_type = tcfg.get("malicious_samples", "matches")

    # evasions_dir: resolve y hệt train.py (dùng nếu là thư mục, ngược lại None)
    evasions_dir = os.path.expanduser(dcfg.get("evasions_dir") or "")
    evasions_dir = evasions_dir if os.path.isdir(evasions_dir) else None

    # malicious_extra: resolve y hệt train.py
    extra_path = os.path.expanduser(dcfg.get("malicious_extra") or "")
    extra_path = extra_path if os.path.isfile(extra_path) else None

    print(f"  benign_train  : {benign_path}")
    print(f"  events_dir    : {events_dir}")
    print(f"  rules_dir     : {rules_dir}")
    print(f"  evasions_dir  : {evasions_dir}")
    print(f"  malicious     : {mal_type}   normalize_benign={norm_benign}")

    rule_set = load_rule_set(events_dir, rules_dir, evasions_dir=evasions_dir)
    event_paths = resolve_event_paths(search_fields, event_field_map)
    malicious = create_malicious_samples(
        rule_set, mal_type, sigma_fields=search_fields,
        event_paths=event_paths, rules_dir=rules_dir, extra_path=extra_path,
    )
    num_benign = count_benign_samples(benign_path, benign_field, max_samples=max_benign)
    print(f"  benign={num_benign}  malicious={len(malicious)}")

    samples = list(training_samples_iter(
        benign_path, malicious, benign_field,
        max_benign=max_benign, normalize_benign=norm_benign,
    ))
    X = vectorizer.transform(samples)
    y = create_labels(num_benign, len(malicious))
    print(f"  X={X.shape}  y={len(y)} (pos={int(np.sum(y))})")
    assert X.shape[1] == len(vectorizer.vocabulary_), "dim mismatch vs vocab"
    return X, y


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", required=True)
    ap.add_argument("--model-in", required=True)
    ap.add_argument("--model-out", required=True)
    args = ap.parse_args()

    config = os.path.abspath(os.path.join(ROOT, args.config)) if not os.path.isabs(args.config) else args.config
    model_in = os.path.abspath(os.path.join(ROOT, args.model_in)) if not os.path.isabs(args.model_in) else args.model_in
    model_out = os.path.abspath(os.path.join(ROOT, args.model_out)) if not os.path.isabs(args.model_out) else args.model_out

    with open(config) as f:
        cfg = yaml.safe_load(f)
    dcfg, tcfg = cfg["data"], cfg["training"]

    print(f"Loading model: {model_in}")
    r = load_result(model_in)
    vectorizer = r["vectorizer"]
    ens = r["estimator"]
    if "svm" not in getattr(ens, "classifiers", {}):
        sys.exit(f"ERROR: estimator không có member 'svm' (members={list(getattr(ens,'classifiers',{}))})")
    svm_old = ens.classifiers["svm"]
    old_params = svm_old.get_params()
    C = old_params["C"]
    kernel = old_params.get("kernel", "linear")
    class_weight = old_params.get("class_weight", "balanced")
    random_state = old_params.get("random_state", 42)
    print(f"  vectorizer dim: {len(vectorizer.vocabulary_)}")
    try:
        print(f"  OLD svm coef_: {svm_old.coef_.shape}  n_features_in_: {svm_old.n_features_in_}")
    except Exception as e:
        print(f"  (không đọc được coef_ của model cũ: {e})")
    print(f"  C={C}  kernel={kernel}  class_weight={class_weight}  random_state={random_state}")

    print("Tái lập corpus train ...")
    X, y = build_corpus(dcfg, tcfg, vectorizer)

    print(f"Re-fitting PURE sklearn SVC (C={C}) ...")
    svm_new = SVC(
        C=C, kernel=kernel, class_weight=class_weight,
        random_state=random_state, cache_size=2000,
    )
    svm_new.fit(X, y)
    print(f"  NEW svm coef_: {svm_new.coef_.shape}  n_features_in_: {svm_new.n_features_in_}")
    assert svm_new.coef_.shape[1] == X.shape[1], "pure sklearn vẫn lệch dim?!"

    d_new = svm_new.decision_function(X[:200])
    print(f"  decision_function NEW chạy OK (pure sklearn), mẫu: {d_new[:5]}")

    ens.classifiers["svm"] = svm_new
    print("Re-calibrating ensemble score_means/score_stds on full training X ...")
    ens.calibrate(X)
    r["estimator"] = ens

    out_dir = os.path.dirname(model_out)
    out_name = os.path.splitext(os.path.basename(model_out))[0]
    save_result(r, out_name, out_dir)
    print(f"\n✅ Saved portable model: {model_out}")
    print("   → cập nhật config train_result_path trỏ vào file _portable này, rồi restart detect_live.")


if __name__ == "__main__":
    main()
