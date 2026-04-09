# Rule Evasion Detection (RED)

Reimplementation of the AMIDES pipeline for detecting SIEM rule evasion using SVM-based misuse classification and rule attribution.

## Project Structure

```
rule_evasion_detection/
├── README.md                          # This file
├── requirements.txt                   # Python dependencies
├── run_all.sh                         # Run complete pipeline
├── config/
│   └── process_creation.yaml          # Config for process creation experiments
├── red/                               # Core library (package)
│   ├── __init__.py                    # Package init
│   ├── data.py                        # Data loading (benign, Sigma rules, events)
│   ├── normalize.py                   # Text normalization pipeline
│   ├── features.py                    # TF-IDF feature extraction
│   ├── models.py                      # SVC training with GridSearchCV
│   ├── evaluate.py                    # Threshold sweep & MCC scaling
│   ├── attribution.py                 # Per-rule attribution evaluation
│   ├── visualize.py                   # PR curves & attribution plots
│   └── persist.py                     # Save/load models (pickle + zip)
└── scripts/                           # CLI entry points
    ├── train.py                       # Train misuse classifier (C1/C2)
    ├── validate.py                    # Validate with evasions
    ├── evaluate.py                    # MCC scaling + threshold sweep
    ├── train_attribution.py           # Train per-rule models (C3)
    ├── eval_attribution.py            # Evaluate rule attribution
    ├── plot.py                        # Generate figures
    └── run_pipeline.py                # Run all steps end-to-end
```

---

## Installation

```bash
cd rule_evasion_detection
pip install -r requirements.txt
```

Dependencies: `numpy`, `scikit-learn`, `matplotlib`, `seaborn`, `pyyaml`, `luqum`

---

## Quick Start

```bash
# Run complete pipeline with config
python scripts/run_pipeline.py --config config/process_creation.yaml

# Or step by step:
bash run_all.sh
```

---

## Pipeline Overview

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Benign      │    │ Sigma Rules  │    │   Events     │
│  Samples     │    │  (YAML)      │    │ Match/Evasion│
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       └──────────┬────────┴───────────────────┘
                  ▼
        ┌─────────────────┐
        │  1. Data Loading │  ← red/data.py
        └────────┬────────┘
                 ▼
        ┌─────────────────┐
        │  2. Normalize    │  ← red/normalize.py
        │  FilterDummy→    │    (filter " ^ ` ' → lowercase
        │  Lower→Token→    │     → tokenize → filter numeric
        │  Filter→Sort     │     → filter strings → sort,join)
        └────────┬────────┘
                 ▼
        ┌─────────────────┐
        │  3. TF-IDF      │  ← red/features.py
        │  Vectorization   │    (comma tokenizer → TfidfVectorizer)
        └────────┬────────┘
                 ▼
    ┌────────────┴────────────┐
    ▼                         ▼
┌───────────────┐    ┌────────────────┐
│ 4A. Misuse    │    │ 4B. Rule       │
│ Classification│    │ Attribution    │
│ (C1/C2)       │    │ (C3)           │
│               │    │                │
│ GridSearchCV  │    │ Per-rule SVC   │
│ + SVC(linear) │───>│ (fixed params) │
│               │    │                │
│ Validate →    │    │ Rank by df →   │
│ decision_func │    │ Top-k hit rate │
│               │    │                │
│ MCC Scaling → │    └────────────────┘
│ Threshold     │
│ Sweep P/R/F1  │
└───────────────┘
```

---

## File Descriptions

### Core Library (`red/`)

#### `red/data.py` — Data Loading
- **`load_benign_samples(path)`**: Load benign samples from text file (1 per line)
- **`load_rule_set(events_dir, rules_dir)`**: Load all Sigma rules with matches/evasions
- **`extract_commandlines(events)`**: Extract CommandLine from event dicts
- **`extract_filter_values(filter_str, fields)`**: Parse Sigma filter via luqum
- **`get_all_filter_values(rule_set, fields)`**: Get all filter values across rules
- **`create_labels(num_benign, num_malicious)`**: Create [0...0, 1...1] label array

#### `red/normalize.py` — Text Normalization
- **`Normalizer`** class with 5-step pipeline:
  1. `FilterDummyCharacters`: Remove `"`, `^`, `` ` ``, `'`
  2. `Lowercase`: Convert to lowercase
  3. `Tokenize`: Split on word boundaries (`\w+`)
  4. `FilterNumeric`: Remove hex/numeric tokens > 3 chars
  5. `FilterStrings`: Remove tokens > 30 chars
  6. Sort + comma-join
- **`normalize_samples(samples)`**: Batch normalize, drop empties

#### `red/features.py` — Feature Extraction
- **`create_vectorizer(method, ngram_range)`**: Create TF-IDF/Count/Hashing vectorizer
- **`comma_tokenizer(text)`**: Split normalized sample on commas
- Supported methods: `tfidf`, `count`, `binary_count`, `hashing`, `scaled_count`

#### `red/models.py` — SVM Training
- **`train_svc_gridsearch(X, y, ...)`**: GridSearchCV over C ∈ [0.01, 10], class_weight
  - Returns: `(best_estimator, best_params, best_score)`
- **`train_svc_fixed(X, y, C, kernel, class_weight)`**: Train with fixed params

#### `red/evaluate.py` — Evaluation & MCC Scaling
- **`create_mcc_scaler(df_values, labels, ...)`**: Build symmetric MinMaxScaler
  - Finds df range where MCC > threshold → makes symmetric → maps to [0,1]
- **`scale_df_values(df_values, scaler, shift)`**: Apply scaling
- **`BinaryEvaluation`** class:
  - `.evaluate(labels, scaled_scores)`: Sweep thresholds, compute P/R/F1/MCC
  - `.optimal_threshold_idx()`: Index of max F1
  - `.default_threshold_idx()`: Index of threshold 0.5
  - `.summary()`: Dict with optimal & default metrics

#### `red/attribution.py` — Rule Attribution
- **`RuleAttributionEvaluation`**: Track top-k hit rates
  - `.evaluate_single(true_rule, ranked_attributions)`: Score one evasion
  - `.calculate_hit_rates()`: Convert counts to rates
  - `.summary()`: Top-1/5/10 cumulative hit rates
- **`score_evasion(sample_vector, rule_models)`**: Score against all models
- **`process_evasions_batch(...)`**: Batch evaluation

#### `red/visualize.py` — Plotting
- **`plot_pr_threshold(evaluations, labels, output_path)`**: 2×2 subplot (P/R/F1/MCC vs threshold)
- **`plot_attribution(top_n_hits, output_path)`**: Bar distribution + CDF line

#### `red/persist.py` — Persistence
- **`save_result(obj, name, output_dir, info)`**: Pickle → ZIP archive + JSON sidecar
- **`load_result(path)`**: Load from ZIP archive

### Scripts (`scripts/`)

#### `scripts/train.py` — Train Misuse Classifier
```bash
# With config file:
python scripts/train.py --config config/process_creation.yaml

# With CLI args:
python scripts/train.py \
  --benign-samples ../amides/data/socbed/process_creation/train \
  --events-dir ../amides/data/sigma/events/windows/process_creation \
  --rules-dir ../amides/data/sigma/rules/windows/process_creation \
  --model-type misuse \
  --malicious-samples rule_filters \
  --vectorization tfidf \
  --search-params \
  --scoring f1 \
  --cv 5 \
  --mcc-scaling \
  --out-dir models/process_creation \
  --result-name misuse_svc_rules_f1
```
**Output**: `models/process_creation/train_rslt_misuse_svc_rules_f1.zip`

#### `scripts/validate.py` — Validate Model
```bash
python scripts/validate.py \
  --result-path models/process_creation/train_rslt_misuse_svc_rules_f1.zip \
  --benign-samples ../amides/data/socbed/process_creation/validation \
  --events-dir ../amides/data/sigma/events/windows/process_creation \
  --rules-dir ../amides/data/sigma/rules/windows/process_creation \
  --malicious-type evasions \
  --out-dir models/process_creation
```
**Output**: `models/process_creation/valid_rslt_misuse_svc_rules_f1.zip`

#### `scripts/evaluate.py` — Threshold Sweep Evaluation
```bash
python scripts/evaluate.py \
  --result-path models/process_creation/valid_rslt_misuse_svc_rules_f1.zip \
  --num-thresholds 50 \
  --out-dir models/process_creation
```
**Output**: `models/process_creation/eval_rslt_misuse_svc_rules_f1.zip`

#### `scripts/train_attribution.py` — Train Per-Rule Models
```bash
python scripts/train_attribution.py \
  --benign-samples ../amides/data/socbed/process_creation/train \
  --events-dir ../amides/data/sigma/events/windows/process_creation \
  --rules-dir ../amides/data/sigma/rules/windows/process_creation \
  --model-params models/process_creation/train_rslt_misuse_svc_rules_f1.zip \
  --out-dir models/process_creation \
  --result-name attr_svc_rules
```
**Output**: `models/process_creation/train_rslt_attr_svc_rules.zip`

#### `scripts/eval_attribution.py` — Evaluate Rule Attribution
```bash
python scripts/eval_attribution.py \
  --result-path models/process_creation/train_rslt_attr_svc_rules.zip \
  --events-dir ../amides/data/sigma/events/windows/process_creation \
  --rules-dir ../amides/data/sigma/rules/windows/process_creation \
  --out-dir models/process_creation
```
**Output**: `models/process_creation/eval_attr_attr_svc_rules.zip`

#### `scripts/plot.py` — Generate Figures
```bash
# PR-Threshold plot (Figure 3)
python scripts/plot.py pr \
  --result-paths models/process_creation/eval_rslt_misuse_svc_rules_f1.zip \
  --output figures/figure_3_misuse_classification.pdf

# Attribution plot (Figure 4)
python scripts/plot.py attr \
  --result-path models/process_creation/eval_attr_attr_svc_rules.zip \
  --output figures/figure_4_rule_attribution.pdf
```

#### `scripts/run_pipeline.py` — Run Complete Pipeline
```bash
python scripts/run_pipeline.py --config config/process_creation.yaml
python scripts/run_pipeline.py --config config/process_creation.yaml --skip-attribution
python scripts/run_pipeline.py --config config/process_creation.yaml --skip-plots
```
Runs all steps (train → validate → evaluate → attribution → plot) in sequence.

---

## Config File Format (`config/process_creation.yaml`)

```yaml
data:
  benign_train: ../amides/data/socbed/process_creation/train
  benign_valid: ../amides/data/socbed/process_creation/validation
  events_dir: ../amides/data/sigma/events/windows/process_creation
  rules_dir: ../amides/data/sigma/rules/windows/process_creation
  search_fields:
    - process.command_line

training:
  malicious_samples: rule_filters    # rule_filters | matches
  vectorization: tfidf               # tfidf | count | hashing
  ngram_range: [1, 1]
  search_params: true
  scoring: f1                        # f1 | mcc
  cv_folds: 5
  num_jobs: 3

scaling:
  mcc_scaling: true
  mcc_threshold: 0.1

evaluation:
  num_thresholds: 50

output:
  dir: models/process_creation
  result_name: misuse_svc_rules_f1
  attr_result_name: attr_svc_rules
```

---

## Data Format

### Benign Samples
Plain text file, one sample per line:
```
C:\Windows\System32\cmd.exe /c ipconfig
powershell.exe -ExecutionPolicy Bypass -File script.ps1
```

### Sigma Rules (YAML)
```yaml
- filter: 'process.command_line:"powershell" AND process.command_line:"-enc"'
  pre_detector:
    title: "Suspicious PowerShell Encoded Command"
```

### Match/Evasion Events (JSON)
```json
{
  "process": {
    "command_line": "powershell.exe -encodedcommand SQBFAFgA..."
  }
}
```
Files named: `*_Match_1.json`, `*_Evasion_technique_1.json`

---

## Pipeline Mapping to AMIDES Paper

| Paper Section | Experiment | Script                    | Output              |
|---------------|------------|---------------------------|---------------------|
| C1/C2         | Misuse Classification (rule_filters vs matches) | `train.py` → `validate.py` → `evaluate.py` | Figure 3 (PR-Threshold) |
| C3            | Rule Attribution | `train_attribution.py` → `eval_attribution.py` | Figure 4 (Distribution+CDF) |
| C4            | Tainted Training | `train.py --tainted-*` (extend as needed) | Figure 5 |
| Visualization | All plots | `plot.py pr` / `plot.py attr` | PDF figures |
