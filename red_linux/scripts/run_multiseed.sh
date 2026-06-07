#!/usr/bin/env bash
# RED-Linux multi-seed ablation (fix V3 — thêm bất định HUẤN LUYỆN vào CI).
# Additive & non-destructive: KHÔNG đụng file kết quả seed-42 đã công bố ở top-level.
#   - Backup output seed-42 hiện có -> seeds/seed_42/ (giữ nguyên report cũ tái lập được).
#   - Mỗi seed mới: train (RED_SEED=s) -> validate(valid)->T* -> test match+evasion @T*,
#     rồi MOVE valid_rslt_*_test_* + eval_rslt_*_test_*_info.json -> seeds/seed_<s>/.
# bootstrap_ci.py --multiseed sẽ gộp mọi seeds/seed_*/.
#
# Usage: bash red_linux/scripts/run_multiseed.sh "1 2 3 4"   # seeds thêm (42 đã backup)
set -u
VENV=~/venvs/rule_evasion_env
PROJ=/home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection
CFG=config/linux_process_creation.yaml
OUT=models/linux_process_creation
SEEDS="${1:-1 2 3 4}"
cd "$PROJ"

declare -A MEMBERS=(
  [svm]=""
  [lr]="--ensemble --ensemble-members lr"
  [cnb]="--ensemble --ensemble-members cnb"
  [svm_lr]="--ensemble --ensemble-members svm lr"
  [svm_cnb]="--ensemble --ensemble-members svm cnb"
  [lr_cnb]="--ensemble --ensemble-members lr cnb"
  [ensemble]="--ensemble --ensemble-members svm lr cnb"
)
ORDER=(svm lr cnb svm_lr svm_cnb lr_cnb ensemble)
declare -A MT=([match]=matches [evasion]=evasions)

# 0) Backup seed-42 published outputs (chỉ làm 1 lần)
S42="$OUT/seeds/seed_42"
if [ ! -d "$S42" ]; then
  mkdir -p "$S42"
  cp "$OUT"/valid_rslt_*_test_*.zip "$S42"/ 2>/dev/null
  cp "$OUT"/eval_rslt_*_test_*_info.json "$S42"/ 2>/dev/null
  echo "backed up seed-42 published outputs -> $S42"
fi

for s in $SEEDS; do
  SD="$OUT/seeds/seed_$s"; mkdir -p "$SD"
  echo "################# SEED $s #################"
  export RED_SEED=$s
  for key in "${ORDER[@]}"; do
    echo "  [seed $s] config $key"
    $VENV/bin/python scripts/train.py --config "$CFG" --result-name "$key" \
        --search-params ${MEMBERS[$key]} >/dev/null 2>&1
    $VENV/bin/python scripts/validate.py --config "$CFG" \
        --result-path "$OUT/train_rslt_${key}.zip" \
        --data-split valid --malicious-type evasions \
        --result-name "${key}_valid" >/dev/null 2>&1
    $VENV/bin/python scripts/evaluate.py --config "$CFG" \
        --result-path "$OUT/valid_rslt_${key}_valid.zip" >/dev/null 2>&1
    TSTAR=$($VENV/bin/python -c "import json;print(json.load(open('$OUT/eval_rslt_${key}_valid_info.json'))['optimal']['threshold'])")
    for sub in match evasion; do
      $VENV/bin/python scripts/validate.py --config "$CFG" \
          --result-path "$OUT/train_rslt_${key}.zip" \
          --data-split test --malicious-type "${MT[$sub]}" \
          --result-name "${key}_test_${sub}" >/dev/null 2>&1
      $VENV/bin/python scripts/evaluate.py --config "$CFG" \
          --result-path "$OUT/valid_rslt_${key}_test_${sub}.zip" \
          --use-threshold "$TSTAR" >/dev/null 2>&1
      # isolate per-seed
      mv -f "$OUT/valid_rslt_${key}_test_${sub}.zip" "$SD/" 2>/dev/null
      mv -f "$OUT/eval_rslt_${key}_test_${sub}_info.json" "$SD/" 2>/dev/null
    done
  done
  echo "  seed $s done -> $SD"
done
unset RED_SEED
echo "===== MULTISEED DONE (seeds: 42 $SEEDS) ====="
