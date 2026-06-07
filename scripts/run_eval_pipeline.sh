#!/bin/bash
# Run full evaluation pipeline for one (model, event_type) combination.
#
# Pipeline:
#   1. train.py → train_rslt
#   2. validate.py --data-split valid --malicious-type both → for threshold tuning
#   3. evaluate.py sweep → optimal threshold T*
#   4. validate.py --data-split test --malicious-type matches → match test set
#   5. validate.py --data-split test --malicious-type evasions → evasion test set
#   6. evaluate.py --use-threshold T* on each → final test metrics
#
# Usage:
#   ./scripts/run_eval_pipeline.sh <event_type> <model> [<extra-train-args>]
#
# Examples:
#   ./scripts/run_eval_pipeline.sh process_creation svm
#   ./scripts/run_eval_pipeline.sh process_creation lr
#   ./scripts/run_eval_pipeline.sh process_creation cnb
#   ./scripts/run_eval_pipeline.sh process_creation ensemble

set -e

EVENT_TYPE="$1"
MODEL="$2"

if [ -z "$EVENT_TYPE" ] || [ -z "$MODEL" ]; then
    echo "Usage: $0 <event_type> <model>"
    exit 1
fi

CONFIG="config/${EVENT_TYPE}.yaml"
LOG_DIR="logs"
mkdir -p "$LOG_DIR"

case "$MODEL" in
    svm)        TRAIN_ARGS="" ;;                                # train.py mặc định SVM solo (không pass --ensemble)
    lr)         TRAIN_ARGS="--ensemble --ensemble-members lr" ;;
    cnb)        TRAIN_ARGS="--ensemble --ensemble-members cnb" ;;
    ensemble)   TRAIN_ARGS="--ensemble" ;;
    svm_lr)     TRAIN_ARGS="--ensemble --ensemble-members svm lr" ;;
    svm_cnb)    TRAIN_ARGS="--ensemble --ensemble-members svm cnb" ;;
    lr_cnb)     TRAIN_ARGS="--ensemble --ensemble-members lr cnb" ;;
    *) echo "Unknown model: $MODEL"; exit 1 ;;
esac

PREFIX="${MODEL}"

echo "═══════════════════════════════════════════════════════════════"
echo " Pipeline: event_type=$EVENT_TYPE, model=$MODEL"
echo " Train args: $TRAIN_ARGS"
echo "═══════════════════════════════════════════════════════════════"

# ── Step 1: Train ──
echo "[1/7] Training $MODEL on $EVENT_TYPE..."
python3 scripts/train.py --config "$CONFIG" $TRAIN_ARGS \
    --result-name "${PREFIX}" \
    2>&1 | tee "$LOG_DIR/${EVENT_TYPE}_${MODEL}_train.log" | tail -5

# ── Step 2: Validate on VALID set with EVASION for threshold tuning ──
# Note: dùng evasion-only (KHÔNG dùng rule_filters synthetic) để tune threshold
# trên distribution thực tế. "both" hoặc "rule_filters" sẽ làm threshold lệch.
echo ""
echo "[2/7] Validating on VALID (evasion) for threshold..."
python3 scripts/validate.py --config "$CONFIG" \
    --data-split valid --malicious-type evasions \
    --result-path "models/${EVENT_TYPE}/train_rslt_${PREFIX}.zip" \
    --result-name "${PREFIX}_valid_evasion" \
    2>&1 | tee "$LOG_DIR/${EVENT_TYPE}_${MODEL}_valid_evasion.log" | tail -3

# ── Step 3: Evaluate sweep → optimal T ──
echo ""
echo "[3/7] Evaluate sweep on VALID (evasion) → pick optimal threshold..."
python3 scripts/evaluate.py --config "$CONFIG" \
    --result-name "${PREFIX}_valid_evasion" \
    2>&1 | tee "$LOG_DIR/${EVENT_TYPE}_${MODEL}_eval_valid.log" | tail -3

# Extract optimal threshold
OPT_T=$(python3 -c "
import json
with open('models/${EVENT_TYPE}/eval_rslt_${PREFIX}_valid_evasion_info.json') as f:
    d = json.load(f)
print(d['optimal']['threshold'])
")
echo "  → Optimal threshold T* = $OPT_T  (tuned on evasion valid)"

# ── Step 4: Validate on TEST set with MATCH events only ──
echo ""
echo "[4/7] Validating on TEST (match events)..."
python3 scripts/validate.py --config "$CONFIG" \
    --data-split test --malicious-type matches \
    --result-path "models/${EVENT_TYPE}/train_rslt_${PREFIX}.zip" \
    --result-name "${PREFIX}_test_match" \
    2>&1 | tee "$LOG_DIR/${EVENT_TYPE}_${MODEL}_test_match.log" | tail -3

# ── Step 5: Validate on TEST set with EVASION only ──
echo ""
echo "[5/7] Validating on TEST (evasion variants)..."
python3 scripts/validate.py --config "$CONFIG" \
    --data-split test --malicious-type evasions \
    --result-path "models/${EVENT_TYPE}/train_rslt_${PREFIX}.zip" \
    --result-name "${PREFIX}_test_evasion" \
    2>&1 | tee "$LOG_DIR/${EVENT_TYPE}_${MODEL}_test_evasion.log" | tail -3

# ── Step 6: Evaluate at fixed threshold on TEST match ──
echo ""
echo "[6/7] Evaluate at T*=$OPT_T on TEST match..."
python3 scripts/evaluate.py --config "$CONFIG" \
    --result-name "${PREFIX}_test_match" \
    --use-threshold "$OPT_T" \
    2>&1 | tee "$LOG_DIR/${EVENT_TYPE}_${MODEL}_eval_test_match.log" | tail -3

# ── Step 7: Evaluate at fixed threshold on TEST evasion ──
echo ""
echo "[7/7] Evaluate at T*=$OPT_T on TEST evasion..."
python3 scripts/evaluate.py --config "$CONFIG" \
    --result-name "${PREFIX}_test_evasion" \
    --use-threshold "$OPT_T" \
    2>&1 | tee "$LOG_DIR/${EVENT_TYPE}_${MODEL}_eval_test_evasion.log" | tail -3

echo ""
echo "✓ Pipeline complete for $EVENT_TYPE / $MODEL"
echo "  Outputs:"
echo "    models/${EVENT_TYPE}/eval_rslt_${PREFIX}_valid_both_info.json     (threshold sweep)"
echo "    models/${EVENT_TYPE}/eval_rslt_${PREFIX}_test_match_info.json     (test on match, T=$OPT_T)"
echo "    models/${EVENT_TYPE}/eval_rslt_${PREFIX}_test_evasion_info.json   (test on evasion, T=$OPT_T)"
