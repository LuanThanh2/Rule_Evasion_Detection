# Rule Evasion Detection (RED)

Reimplementation and extension of the AMIDES pipeline for detecting SIEM rule evasion.
Uses SVM-based misuse classification and rule attribution across multiple Windows event types.

---

## Project Structure

```
rule_evasion_detection/
├── README.md
├── requirements.txt
├── run_all.sh
├── config/
│   ├── process_creation.yaml     # Process Creation experiments
│   ├── registry_event.yaml       # Registry Event experiments
│   ├── powershell.yaml           # PowerShell ScriptBlock experiments
│   └── proxy_web.yaml            # Proxy/Web URL experiments
├── red/                          # Core library
│   ├── __init__.py
│   ├── data.py                   # Data loading (benign, Sigma rules, events)
│   ├── normalize.py              # Text normalization pipeline
│   ├── features.py               # TF-IDF/Count vectorization
│   ├── models.py                 # SVC training (CPU/GPU/Intel acceleration)
│   ├── evaluate.py               # Threshold sweep & MCC scaling
│   ├── attribution.py            # Per-rule attribution evaluation
│   ├── visualize.py              # PR curves & attribution plots
│   └── persist.py                # Save/load models (pickle + zip)
└── scripts/
    ├── train.py                  # Train misuse classifier (C1/C2)
    ├── validate.py               # Validate model with evasions
    ├── evaluate.py               # MCC scaling + threshold sweep
    ├── train_attribution.py      # Train per-rule models (C3)
    ├── eval_attribution.py       # Evaluate rule attribution
    ├── plot.py                   # Generate figures
    ├── run_pipeline.py           # Run all steps end-to-end
    ├── generate_evasions.py      # Generate evasion events from match events
    ├── hayabusa_to_matches.py    # Convert Hayabusa JSONL → AMIDES match events
    ├── otrf_to_matches.py        # Convert OTRF datasets → AMIDES match events
    ├── lmd_to_benign.py          # Convert LMD Collections CSV → benign samples
    ├── mpsd_to_benign.py         # Convert MPSD .ps1 files → benign PowerShell samples
    ├── mpsd_to_malicious.py      # Filter MPSD malicious .ps1 by Sigma patterns
    ├── secrepo_to_benign.py      # Extract URLs from Squid access.log → benign samples
    └── train_all.sh              # Shell script to train all event types
```

---

## Installation

```bash
cd rule_evasion_detection
pip install -r requirements.txt
```

Dependencies: `numpy`, `scikit-learn`, `matplotlib`, `seaborn`, `pyyaml`, `luqum`,
`scikit-learn-intelex` (Intel CPU acceleration), `tqdm`

### Optional GPU acceleration

```bash
# NVIDIA GPU (RAPIDS cuML — requires CUDA)
pip install cuml-cu12
```

The training code auto-detects the best available backend:
NVIDIA GPU (cuML) > Intel CPU (scikit-learn-intelex) > plain scikit-learn CPU.

---

## Supported Event Types

| Event Type        | Field extracted                   | Config file              |
|-------------------|-----------------------------------|--------------------------|
| `process_creation`| `process.command_line`            | `config/process_creation.yaml` |
| `registry_event`  | `winlog.event_data.TargetObject`  | `config/registry_event.yaml`   |
| `powershell`      | `winlog.event_data.ScriptBlockText` | `config/powershell.yaml`     |
| `proxy_web`       | `url` / `c-uri` / `cs-uri-stem`  | `config/proxy_web.yaml`        |

---

## Quick Start

```bash
# Run complete pipeline for process creation events
python scripts/run_pipeline.py --config config/process_creation.yaml

# Skip attribution (faster)
python scripts/run_pipeline.py --config config/process_creation.yaml --skip-attribution

# Skip plots
python scripts/run_pipeline.py --config config/process_creation.yaml --skip-plots
```

---

## Pipeline Overview

```
┌──────────────────────────────────────────────────────────────┐
│                     DATA PREPARATION                         │
│                                                              │
│  Benign data sources:                                        │
│    LMD Collections (CSV) ──→ lmd_to_benign.py               │
│    MPSD PowerShell .ps1   ──→ mpsd_to_benign.py             │
│    SecRepo Squid log      ──→ secrepo_to_benign.py          │
│                                                              │
│  Match event sources:                                        │
│    Hayabusa JSONL         ──→ hayabusa_to_matches.py         │
│    OTRF Security-Datasets ──→ otrf_to_matches.py            │
│                                                              │
│  Evasion generation:                                         │
│    Match events           ──→ generate_evasions.py           │
│      (remove_exe, double_space, backtick_insert, ...)        │
└──────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                   TRAINING PIPELINE                          │
│                                                              │
│  1. Load data (data.py)                                      │
│     ├── Benign: txt / jsonl / json / csv (multi-format)      │
│     ├── Rule filters: AMIDES YAML or raw Sigma detection     │
│     └── Match/Evasion events: per-rule JSON files            │
│                                                              │
│  2. Normalize (normalize.py)                                 │
│     Filter dummy → lowercase → tokenize → filter            │
│     numeric/long tokens → sort → comma-join                  │
│                                                              │
│  3. Vectorize (features.py)                                  │
│     TF-IDF / Count / Binary / Hashing / Scaled Count         │
│                                                              │
│  4A. Misuse Classification C1/C2 (train.py)                  │
│      GridSearchCV over C ∈ logspace(-2,1,50), class_weight   │
│      → best SVC + MCC-based scaler                           │
│                                                              │
│  4B. Rule Attribution C3 (train_attribution.py)              │
│      Per-rule binary SVC (benign vs rule_i) → rank by df     │
│                                                              │
│  5. Evaluate & Plot                                          │
│     Threshold sweep P/R/F1/MCC → PR-Threshold plot           │
│     Top-k hit rates → Attribution distribution + CDF plot    │
└──────────────────────────────────────────────────────────────┘
```

---

## Core Library (`red/`)

### `red/data.py` — Data Loading

**Benign sample loading** (multi-format, memory-efficient):
- `load_benign_samples(path, field)` — Load all at once into list
- `benign_samples_iter(path, field, max_samples)` — Yield one at a time (avoids OOM for large datasets)
- `count_benign_samples(path, field, max_samples)` — Count without loading
- Supported formats: `.txt` (plain text), `.jsonl`/`.ndjson`, `.json`, `.csv`
- `field`: dot-separated path e.g. `"process.command_line"`, `"winlog.event_data.TargetObject"`

**Rule set loading**:
- `load_rule_set(events_dir, rules_dir, evasions_dir)` — Load rules with matches and evasions
  - Supports separate `evasions_dir` (generated evasions separate from match events)
  - Falls back to rules-only mode when `events_dir` is absent
- `RuleData` dataclass: `name`, `filters`, `matches`, `evasions`, `sigma_values`

**Sigma filter/detection extraction**:
- `extract_filter_values(filter_str, search_fields)` — Parse AMIDES Lucene filter via luqum
- `get_all_filter_values(rule_set, search_fields)` — Across all rules (AMIDES + raw Sigma)
- `get_all_yaml_filter_values(rules_dir, search_fields)` — Scan all YAMLs directly (handles mismatched filenames)
- `_extract_sigma_detection_values(detection, search_fields)` — From raw Sigma detection blocks

**Helpers**: `extract_commandlines()`, `get_all_matches()`, `get_all_evasions()`, `create_labels()`

---

### `red/normalize.py` — Text Normalization

`Normalizer` class performs a 6-step pipeline:
1. `FilterDummyCharacters`: Remove `"`, `^`, `` ` ``, `'`
2. `Lowercase`
3. `Tokenize`: Split on `\w+` word boundaries
4. `FilterNumeric`: Remove hex/numeric tokens > `max_num_len` (default 3) chars
5. `FilterStrings`: Remove tokens > `max_str_len` (default 30) chars
6. Sort alphabetically + comma-join

`normalize_samples(samples)` — Batch normalize, drop empties.

---

### `red/features.py` — Feature Extraction

`create_vectorizer(method, ngram_range, analyzer)` — Create sklearn vectorizer:

| Method         | Description                                      |
|----------------|--------------------------------------------------|
| `tfidf`        | TF-IDF (default)                                 |
| `count`        | Raw token counts                                 |
| `binary_count` | Binary presence/absence                          |
| `hashing`      | HashingVectorizer (memory-efficient)             |
| `scaled_count` | CountVectorizer + MaxAbsScaler pipeline          |

`comma_tokenizer(text)` — Split normalized sample on commas.

---

### `red/models.py` — SVM Training

Auto-detects acceleration backend at import:
- **NVIDIA GPU**: RAPIDS cuML SVC (fastest for large datasets)
- **Intel CPU**: scikit-learn-intelex patched SVC
- **Plain CPU**: standard scikit-learn SVC

`train_svc_gridsearch(X, y, param_grid, scoring, cv, n_jobs)`:
- Default grid: `C ∈ logspace(-2, 1, 50)`, `kernel=linear`, `class_weight ∈ [balanced, None]`
- tqdm progress bar during grid search
- GPU mode: grid search on CPU → final fit on GPU
- Returns: `(estimator, best_params, best_score)`

`train_svc_fixed(X, y, C, kernel, class_weight)` — Train with fixed parameters.

---

### `red/evaluate.py` — Evaluation & MCC Scaling

`create_mcc_scaler(df_values, labels, num_samples, mcc_threshold)`:
- Two-pass scan: coarse → refine within MCC > threshold range
- Makes range symmetric around 0
- Calculates shift to center MCC optimum at 0.5
- Returns `(MinMaxScaler, shift)`

`scale_df_values(df_values, scaler, shift)` — Apply shift + scale, clip to [0, 1].

`BinaryEvaluation(num_thresholds)`:
- `.evaluate(labels, scaled_scores)` — Sweep `num_thresholds+1` thresholds, compute P/R/F1/MCC/TP/FP/TN/FN
- `.optimal_threshold_idx()` — Index of max F1
- `.default_threshold_idx()` — Index of threshold 0.5
- `.summary()` — Dict with metrics at optimal and default thresholds

---

### `red/attribution.py` — Rule Attribution

`RuleAttributionEvaluation(num_rules)`:
- `.evaluate_single(true_rule, ranked_attributions)` — Score one evasion
- `.calculate_hit_rates()` — Convert counts to rates
- `.summary()` — Top-1/5/10 cumulative hit rates + TP/FP/TN/FN

`score_evasion(sample_vector, rule_models)` — Score one sample against all rule models, return sorted list.

`process_evasions_batch(normalized_samples, evasion_to_rule, rule_models)` — Batch evaluation with per-rule transform.

---

### `red/visualize.py` — Plotting

`plot_pr_threshold(evaluations, labels, output_path, title)`:
- 2×2 subplot: Precision / Recall / F1-Score / MCC vs. threshold
- Marks optimal threshold (per evaluation) and default 0.5

`plot_attribution(top_n_hits, output_path, title)`:
- Bar chart: distribution of attribution ranks
- Line: cumulative distribution (CDF)

---

### `red/persist.py` — Persistence

`save_result(obj, name, output_dir, info)` — Pickle → ZIP (max compression) + JSON sidecar.

`load_result(path)` — Load from ZIP archive.

File naming convention:
- `train_rslt_<name>.zip` — TrainingResult
- `valid_rslt_<name>.zip` — ValidationResult
- `eval_rslt_<name>.zip` — EvaluationResult
- `<name>_info.json` — Human-readable metadata sidecar

---

## Scripts (`scripts/`)

### `scripts/train.py` — Train Misuse Classifier

```bash
python scripts/train.py --config config/process_creation.yaml

# CLI args (override config):
python scripts/train.py \
  --benign-samples ~/data/benign/process_creation/benign_train.txt \
  --events-dir ~/data/sigma/events_hayabusa/windows/process_creation \
  --rules-dir ~/data/sigma/rules/windows/process_creation \
  --malicious-samples both \       # rule_filters | matches | both
  --vectorization tfidf \
  --search-params \
  --scoring f1 \
  --cv 5 \
  --mcc-scaling \
  --max-benign-samples 50000 \     # cap benign count (avoids OOM)
  --out-dir models/process_creation \
  --result-name misuse_svc_rules_f1
```

**Output**: `models/process_creation/train_rslt_misuse_svc_rules_f1.zip`

---

### `scripts/validate.py` — Validate Model

```bash
python scripts/validate.py \
  --config config/process_creation.yaml \
  --result-path models/process_creation/train_rslt_misuse_svc_rules_f1.zip
```

**Output**: `models/process_creation/valid_rslt_misuse_svc_rules_f1.zip`

---

### `scripts/evaluate.py` — Threshold Sweep Evaluation

```bash
python scripts/evaluate.py \
  --config config/process_creation.yaml \
  --result-path models/process_creation/valid_rslt_misuse_svc_rules_f1.zip \
  --num-thresholds 50
```

**Output**: `models/process_creation/eval_rslt_misuse_svc_rules_f1.zip`

---

### `scripts/train_attribution.py` — Train Per-Rule Models

```bash
python scripts/train_attribution.py \
  --config config/process_creation.yaml \
  --model-params models/process_creation/train_rslt_misuse_svc_rules_f1.zip
```

**Output**: `models/process_creation/train_rslt_attr_svc_rules.zip`

---

### `scripts/eval_attribution.py` — Evaluate Rule Attribution

```bash
python scripts/eval_attribution.py \
  --config config/process_creation.yaml \
  --result-path models/process_creation/train_rslt_attr_svc_rules.zip
```

**Output**: `models/process_creation/eval_attr_attr_svc_rules.zip`

---

### `scripts/plot.py` — Generate Figures

```bash
# PR-Threshold plot
python scripts/plot.py pr \
  --result-paths models/process_creation/eval_rslt_misuse_svc_rules_f1.zip \
  --output figures/figure_3_misuse_classification.pdf

# Attribution plot
python scripts/plot.py attr \
  --result-path models/process_creation/eval_attr_attr_svc_rules.zip \
  --output figures/figure_4_rule_attribution.pdf
```

---

### `scripts/run_pipeline.py` — Run Complete Pipeline

```bash
python scripts/run_pipeline.py --config config/process_creation.yaml
python scripts/run_pipeline.py --config config/process_creation.yaml --skip-attribution
python scripts/run_pipeline.py --config config/process_creation.yaml --skip-plots
```

Runs all steps sequentially: train → validate → evaluate → attribution → plot.

---

## Data Preparation Scripts

### `scripts/generate_evasions.py` — Generate Evasion Events

Generates evasion variants of match events by applying transformation techniques that bypass Sigma rule patterns.

```bash
python scripts/generate_evasions.py --config config/process_creation.yaml
python scripts/generate_evasions.py --config config/registry_event.yaml
python scripts/generate_evasions.py --config config/powershell.yaml
python scripts/generate_evasions.py --config config/process_creation.yaml --dry-run
```

Supported transformations by event type:

| Event Type        | Techniques                                                                          |
|-------------------|-------------------------------------------------------------------------------------|
| `process_creation`| `remove_exe`, `double_space`, `quote_wrap_flags`, `case_upper`, `case_lower`, `env_systemroot`, `env_temp`, `long_flag_o` |
| `registry_event`  | `hklm_expand`, `hklm_abbrev`, `hku_expand`, `hku_abbrev`, `case_lower`, `case_upper`, `trailing_backslash` |
| `powershell`      | `backtick_insert`, `case_mix`, `concat_keywords`, `double_space`, `env_comspec`     |

Each technique is verified to actually bypass the rule (evasion discarded if it still matches any rule pattern).
Output: `evasions_dir/<rule_name>/<rule>_Evasion_<technique>_<n>.json`

---

### `scripts/hayabusa_to_matches.py` — Hayabusa JSONL → Match Events

Converts Hayabusa security scanner JSONL output to AMIDES-format per-rule match JSON files.

```bash
python scripts/hayabusa_to_matches.py \
  --input hayabusa_matches.jsonl \
  --output-dir ~/data/sigma/events_hayabusa/windows/process_creation \
  --event-type process_creation

python scripts/hayabusa_to_matches.py \
  --input hayabusa_registry.jsonl \
  --output-dir ~/data/sigma/events_hayabusa/windows/registry_event \
  --event-type registry_event

python scripts/hayabusa_to_matches.py \
  --input hayabusa_powershell.jsonl \
  --output-dir ~/data/sigma/events_hayabusa/windows/powershell \
  --event-type powershell
```

Enriches events with AMIDES-compatible fields (`process.command_line`, `winlog.event_data.TargetObject`, etc.).
Groups by `RuleTitle`, normalizes to snake_case dir name, writes `<rule>_Match_<n>.json`.

---

### `scripts/otrf_to_matches.py` — OTRF Datasets → Match Events

Converts OTRF Security-Datasets JSON files to AMIDES-format match events by matching CommandLine values against Sigma rule patterns.

```bash
python scripts/otrf_to_matches.py \
  --otrf-dir ~/data/Security-Datasets/datasets/atomic/windows \
  --rules-dir ~/data/sigma/rules/windows/process_creation \
  --output-dir ~/data/sigma/events_otrf/windows/process_creation
```

Handles multiple OTRF JSON formats (Winlogbeat ECS, raw WEL, simplified Sysmon).
Supports wildcard matching (`*`) in Sigma patterns.

---

### `scripts/lmd_to_benign.py` — LMD Collections → Benign Samples

Converts Lateral Movement Dataset (LMD) Collections CSV files to per-event-type benign sample text files.

```bash
python scripts/lmd_to_benign.py \
  --lmd-dir ~/datasets/benign_data/Lateral-Movement-Dataset--LMD_Collections \
  --output-dir ~/data/benign
```

Maps EventID → event type: `1 → process_creation`, `12/13/14 → registry_event`.
Deduplicates samples automatically. Processes both LMD-2022 and LMD-2023 subsets.

---

### `scripts/mpsd_to_benign.py` — MPSD PowerShell → Benign Samples

Converts das-lab/mpsd PowerShell benign `.ps1` files to `benign_train.txt`.
Each file becomes one line (newlines collapsed to spaces).

```bash
python scripts/mpsd_to_benign.py \
  --mpsd-dir ~/datasets/benign_data/mpsd/powershell_benign_dataset \
  --output-dir ~/data/benign/powershell
```

---

### `scripts/mpsd_to_malicious.py` — MPSD PowerShell → Malicious Samples

Filters das-lab/mpsd malicious `.ps1` files by Sigma rule patterns for `ScriptBlockText`.
Only keeps files that would have triggered at least one Sigma rule.

```bash
python scripts/mpsd_to_malicious.py \
  --mpsd-dir ~/datasets/malicious_data/mpsd/malicious_pure \
  --rules-dir ~/data/sigma/rules/windows/powershell \
  --output ~/data/benign/powershell/malicious_extra.txt
```

---

### `scripts/secrepo_to_benign.py` — SecRepo Squid Log → Benign URLs

Extracts HTTP/HTTPS URLs from Squid `access.log` format for proxy/web experiments.
Skips `CONNECT` (HTTPS tunnels) and non-HTTP entries.

```bash
python scripts/secrepo_to_benign.py \
  --input ~/datasets/benign_data/access.log/access.log \
  --output-dir ~/data/benign/proxy_web
```

---

## Config File Format

```yaml
data:
  benign_train: ~/data/benign/process_creation/benign_train.txt
  benign_valid: ~/data/benign/process_creation/benign_train.txt
  benign_field: process.command_line          # dot-path to extract from JSON/CSV
  events_dir: ~/data/sigma/events_hayabusa/windows/process_creation
  evasions_dir: ~/data/sigma/evasions/windows/process_creation   # separate evasions dir
  rules_dir: ~/data/sigma/rules/windows/process_creation
  search_fields:
    - process.command_line
  max_benign_samples: 50000                  # optional cap (proxy_web has 1.5M URLs)
  malicious_extra: ~/data/benign/powershell/malicious_extra.txt  # extra malicious samples

training:
  malicious_samples: both       # rule_filters | matches | both
  vectorization: tfidf           # tfidf | count | binary_count | hashing | scaled_count
  ngram_range: [1, 1]
  search_params: true            # GridSearchCV (false = fixed default params)
  scoring: f1                    # f1 | mcc
  cv_folds: 5
  num_jobs: 3

scaling:
  mcc_scaling: true
  mcc_threshold: 0.1
  num_mcc_samples: 50

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

Supports multiple formats (auto-detected by file extension):

```
# .txt — one value per line
C:\Windows\System32\cmd.exe /c ipconfig
powershell.exe -ExecutionPolicy Bypass -File script.ps1

# .jsonl — one JSON object per line
{"process": {"command_line": "cmd.exe /c whoami"}}

# .csv — header required, column found by benign_field name
CommandLine,User,Host
"cmd.exe /c dir",SYSTEM,WORKSTATION
```

### Match/Evasion Events (JSON)

```json
{
  "process": {
    "command_line": "cscript.exe //nologo malicious.vbs"
  },
  "winlog": {
    "event_data": {
      "CommandLine": "cscript.exe //nologo malicious.vbs",
      "Image": "C:\\Windows\\System32\\cscript.exe"
    }
  }
}
```

Files named: `<rule>_Match_<n>.json`, `<rule>_Evasion_<technique>_<n>.json`

### Sigma Rules (AMIDES YAML format)

```yaml
- filter: 'process.command_line:"cscript" AND process.command_line:"malicious"'
  pre_detector:
    title: "Suspicious CScript Execution"
```

Also supports standard Sigma HQ YAML format (with `detection:` blocks).

---

## Pipeline Mapping to AMIDES Paper

| Paper Section | Experiment                                     | Scripts                                              | Output                     |
|---------------|------------------------------------------------|------------------------------------------------------|----------------------------|
| C1            | Misuse Classification (rule_filters)           | `train.py` → `validate.py` → `evaluate.py`          | Figure 3 (PR-Threshold)    |
| C2            | Misuse Classification (matches)                | `train.py --malicious-samples matches` → ...         | Figure 3                   |
| C3            | Rule Attribution                               | `train_attribution.py` → `eval_attribution.py`       | Figure 4 (Distribution+CDF)|
| —             | Evasion generation (own extension)             | `generate_evasions.py`                               | Evasion JSON files         |
| —             | Data preparation (own extension)               | `hayabusa_to_matches.py`, `lmd_to_benign.py`, etc.   | Benign/match datasets      |
| Visualization | All plots                                      | `plot.py pr` / `plot.py attr`                        | PDF figures                |
