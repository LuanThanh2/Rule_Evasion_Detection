#!/usr/bin/env bash
# RED-Linux ablation: 7 cấu hình × {test_match, test_evasion}.
# Quy trình (giống RESULT_2): train -> validate(valid) chốt T* -> test với T* cố định.
set -u
VENV=~/venvs/rule_evasion_env
PROJ=/home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection
CFG=config/linux_process_creation.yaml
OUT=models/linux_process_creation
TIMES=$OUT/ablation_train_times.csv
cd "$PROJ"
mkdir -p "$OUT"
echo "key,train_seconds" > "$TIMES"

# key -> train.py ensemble flags
declare -A MEMBERS=(
  [svm]=""                       # single SVM (no --ensemble)
  [lr]="--ensemble --ensemble-members lr"
  [cnb]="--ensemble --ensemble-members cnb"
  [svm_lr]="--ensemble --ensemble-members svm lr"
  [svm_cnb]="--ensemble --ensemble-members svm cnb"
  [lr_cnb]="--ensemble --ensemble-members lr cnb"
  [ensemble]="--ensemble --ensemble-members svm lr cnb"
)
ORDER=(svm lr cnb svm_lr svm_cnb lr_cnb ensemble)

for key in "${ORDER[@]}"; do
  echo "================= CONFIG: $key ================="
  # 1) TRAIN (time it)
  t0=$(date +%s.%N)
  $VENV/bin/python scripts/train.py --config "$CFG" --result-name "$key" \
      --search-params ${MEMBERS[$key]} >/dev/null 2>&1
  t1=$(date +%s.%N)
  dt=$(echo "$t1 - $t0" | bc)
  echo "$key,$dt" >> "$TIMES"
  echo "  trained in ${dt}s -> train_rslt_${key}.zip"

  # 2) VALIDATE on valid (benign_valid + evasion_valid) -> sweep -> T*
  $VENV/bin/python scripts/validate.py --config "$CFG" \
      --result-path "$OUT/train_rslt_${key}.zip" \
      --data-split valid --malicious-type evasions \
      --result-name "${key}_valid" >/dev/null 2>&1
  $VENV/bin/python scripts/evaluate.py --config "$CFG" \
      --result-path "$OUT/valid_rslt_${key}_valid.zip" >/dev/null 2>&1
  TSTAR=$($VENV/bin/python -c "import json;print(json.load(open('$OUT/eval_rslt_${key}_valid_info.json'))['optimal']['threshold'])")
  echo "  T* (from valid) = $TSTAR"

  # 3) TEST match + evasion with FIXED T*
  declare -A MT=([match]=matches [evasion]=evasions)
  for sub in match evasion; do
    $VENV/bin/python scripts/validate.py --config "$CFG" \
        --result-path "$OUT/train_rslt_${key}.zip" \
        --data-split test --malicious-type "${MT[$sub]}" \
        --result-name "${key}_test_${sub}" >/dev/null 2>&1
    $VENV/bin/python scripts/evaluate.py --config "$CFG" \
        --result-path "$OUT/valid_rslt_${key}_test_${sub}.zip" \
        --use-threshold "$TSTAR" >/dev/null 2>&1
    echo "  eval_rslt_${key}_test_${sub}_info.json done"
  done
done
echo "===== ABLATION DONE ====="
