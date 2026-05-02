# Rule Evasion Detection (RED)

Extension của AMIDES pipeline (Uetz et al., USENIX Security 2024) — phát hiện và quy kết evasion của luật Sigma bằng SVM Ensemble + Cosine Similarity.

## Pipeline tổng quan

```
Train → Validate → Evaluate → Attribution
```

**Stage 1 — Misuse Detection** (`train.py` → `validate.py` → `evaluate.py`):
- Phân loại nhị phân: benign vs. malicious
- Input: command line / ScriptBlockText / TargetObject / URL strings
- Output: score ∈ [0,1] sau MCC scaling, threshold sweep để ra P/R/F1/MCC

**Stage 2 — Rule Attribution** (`train_attribution.py` → `eval_attribution.py`):
- Với mỗi event bị đánh dấu suspicious, xác định rule Sigma nào bị evasion
- Đánh giá: top-k hit rate

## Cấu trúc thư mục

```
red/                  # Core library
  normalize.py        # 6-step text normalization → comma-separated tokens
  features.py         # TF-IDF / Count / Hashing vectorizers, comma_tokenizer
  models.py           # SVC + LR + CNB training, EnsembleClassifier
  evaluate.py         # BinaryEvaluation, create_mcc_scaler, scale_df_values
  attribution.py      # RuleAttributionEvaluation, CosineRuleAttributor, RRF
  data.py             # Benign loader (txt/jsonl/json/csv), load_rule_set, extract_filter_values
  persist.py          # save_result / load_result (pickle + ZIP)
  visualize.py        # plot_pr_threshold, plot_attribution

scripts/              # Entry points
  train.py            # Stage 1 training (SVM solo or Ensemble)
  validate.py         # Transform + decision_function → df_values
  evaluate.py         # MCC scale + threshold sweep → eval result
  train_attribution.py # Stage 2: per-rule SVM + CosineRuleAttributor
  eval_attribution.py  # Stage 2 eval: --method svm|cosine|hybrid
  generate_evasions.py # Tạo evasion variants từ match events
  run_pipeline.py     # Chạy toàn bộ pipeline qua config
  hayabusa_to_matches.py  # Hayabusa JSONL → per-rule JSON
  lmd_to_benign.py        # LMD CSV → benign_train.txt
  mpsd_to_benign.py       # MPSD .ps1 → benign_train.txt
  secrepo_to_benign.py    # Squid access.log → benign_train.txt

config/               # YAML config per event type
  process_creation.yaml
  registry_event.yaml
  powershell.yaml
  proxy_web.yaml

data/                 # Dữ liệu thực (không commit lên git)
  sigma/events_hayabusa/  # Match events theo rule
  sigma/evasions/         # Evasion events
  sigma/rules/            # Sigma rule YAMLs
  benign/                 # benign_train.txt files

models/               # Output .zip từ train/validate/evaluate
```

## Key design decisions

### Normalization → TF-IDF
- `Normalizer.normalize()`: lowercase → tokenize `\w+` → filter hex/long → sort → join ","
- `comma_tokenizer`: split on "," — **không phải** whitespace splitter mặc định của sklearn
- TF-IDF dùng smoothed formula: `log((1+N)/(1+DF(t))) + 1`

### MCC Scaler
- Tạo ra trong `train.py` (trên training data), lưu trong `train_rslt_*.zip`
- Áp dụng trong `evaluate.py`: shift → MinMaxScale → clip[0,1]
- `decision_function` raw → scaled score ∈ [0,1]

### EnsembleClassifier (models.py)
- Thành viên: SVM (GridSearch) + LR (GridSearch) + ComplementNB
- Z-score normalize mỗi thành viên trên training data (calibrate())
- `.decision_function(X)` → weighted average → tương thích hoàn toàn với pipeline cũ
- `validate.py` và `evaluate.py` không cần sửa gì khi dùng ensemble

### CosineRuleAttributor (attribution.py)
- Shared TF-IDF vectorizer fitted trên UNION filter values của tất cả rules
- Per-rule: ma trận TF-IDF của filter values (sparse)
- Score = max(cosine_similarity(evasion_vec, rule_matrix))
- `reciprocal_rank_fusion()` gộp SVM ranking + Cosine ranking (k=60)

### Data format cho match events
- Directory: `events_dir/<rule_name>/<rule_name>_Match_NN.json`
- Evasion: `evasions_dir/<rule_name>/<rule_name>_Evasion_*_NN.json`
- Mỗi file = 1 event dict với field `process.command_line` hoặc `winlog.event_data.CommandLine`

### Benign data field mapping
- `process_creation`: `process.command_line` hoặc `winlog.event_data.CommandLine`
- `registry_event`: `winlog.event_data.TargetObject`
- `powershell`: `winlog.event_data.ScriptBlockText`
- `proxy_web`: plain text URL (1 per line)

## Commands hay dùng

```bash
# Chạy toàn bộ Stage 1
python scripts/train.py --config config/process_creation.yaml --search-params
python scripts/validate.py --config config/process_creation.yaml
python scripts/evaluate.py --config config/process_creation.yaml

# Chạy với Ensemble
python scripts/train.py --config config/process_creation.yaml --ensemble

# Stage 2
python scripts/train_attribution.py --config config/process_creation.yaml
python scripts/eval_attribution.py --config config/process_creation.yaml --method hybrid

# Chạy tất cả event types
bash run_all.sh
```

## Nguồn dữ liệu benign

| Event type | Nguồn | Script converter |
|---|---|---|
| process_creation | LMD Collections (LMD-2022, LMD-2023) | `lmd_to_benign.py` |
| registry_event | LMD Collections (Sysmon EID 12/13/14) | `lmd_to_benign.py` |
| powershell | MPSD (das-lab/mpsd) | `mpsd_to_benign.py` |
| proxy_web | SecRepo Squid access.log | `secrepo_to_benign.py` |

## Dependencies

```
scikit-learn, numpy, pyyaml, luqum, tqdm, matplotlib, seaborn
Optional: cuml (NVIDIA GPU), sklearnex (Intel CPU acceleration)
```
