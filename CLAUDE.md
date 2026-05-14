# Rule Evasion Detection (RED)

RED là hệ thống hỗ trợ phát hiện các hành vi né tránh luật Sigma và quy kết event đáng ngờ về rule Sigma tương ứng trên Windows Event Logs.

Project mở rộng pipeline AMIDES (Uetz et al., USENIX Security 2024) bằng Stage 1 Ensemble Classifier và Stage 2 Cosine Similarity.

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
  attribution.py      # RuleAttributionEvaluation, CosineRuleAttributor, RRF baseline
  data.py             # Benign loader (txt/jsonl/json/csv), load_rule_set, extract_filter_values
  persist.py          # save_result / load_result (pickle + ZIP)
  visualize.py        # plot_pr_threshold, plot_attribution

scripts/              # Entry points
  run_stage1.py       # Gộp train + validate + evaluate (khuyến nghị — 2026-05-14)
  train.py            # Stage 1 training (SVM solo or Ensemble)
  validate.py         # Transform + decision_function → df_values
  evaluate.py         # MCC scale + threshold sweep → eval result
  train_attribution.py # Stage 2: CosineRuleAttributor + per-rule SVM baseline
  eval_attribution.py  # Stage 2 eval: production --method cosine; baseline svm|hybrid
  generate_evasions.py # Tạo evasion variants từ match events
  run_pipeline.py     # Chạy toàn bộ pipeline (Stage 1+2) qua config
  hayabusa_to_matches.py  # Hayabusa JSONL → per-rule JSON
  lmd_to_benign.py        # LMD CSV → benign_train.txt
  mpsd_to_benign.py       # MPSD .ps1 → benign_train.txt
  secrepo_to_benign.py    # Squid access.log → benign_train.txt
  diagnose_stage1.py      # Analyze Stage 1 model F1=1.0 issue, token analysis
  # ELK Integration (2026-05-11)
  elk_export.py       # Export events từ Elasticsearch → JSONL
  detect_batch.py     # Batch detection: JSONL → alerts JSONL (offline verify)
  detect_live.py      # Live daemon: poll ES → Stage1+2 → index alerts về ES
  push_alerts.py      # Bulk index alerts.jsonl → Elasticsearch

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

### GridSearch (models.py) — đã tối ưu
- Dùng **sklearn GridSearchCV** thay manual loop → chạy parallel `n_jobs=3`
- Grid C: **20 giá trị** (giảm từ 50) ∈ [0.01, 10], `class_weight=["balanced"]` (bỏ None)
- LR grid: **10 giá trị** C; cùng GridSearchCV parallel
- `random_state=42` cho SVC, LR, StratifiedKFold → kết quả reproducible
- Tổng fits: SVM 20×5=100, LR 10×5=50 — giảm ~80% so với trước

### CosineRuleAttributor (attribution.py)
- Shared TF-IDF vectorizer fitted trên UNION filter values của tất cả rules
- Per-rule: ma trận TF-IDF của filter values (sparse)
- Score = max(cosine_similarity(evasion_vec, rule_matrix))
- `reciprocal_rank_fusion()` gộp SVM ranking + Cosine ranking (k=60)

### train_attribution.py — tránh crash mất công
- Cap benign per-rule: `max_attribution_benign` (default 15000) — tránh fit TF-IDF full benign cho mỗi rule
- `benign_field` được truyền đúng vào Stage 2 (trước bị bỏ qua)
- Checkpoint mỗi 20 rules → file `train_rslt_{name}_ckpt_20.zip`, `_ckpt_40.zip`, ...
- `try/except` per rule → 1 rule fail không kill cả run
- tqdm progress bar

### Pre-flight validation (train.py + train_attribution.py)
- Kiểm tra file/thư mục tồn tại trước khi bắt đầu normalize/train
- Đọc 10 sample đầu để xác nhận `benign_field` đúng format
- `os.makedirs(out_dir, exist_ok=True)` tự tạo thư mục output

### Config fields mới (tất cả configs)
- `data.max_benign_samples`: cap Stage 1 benign (process/registry/powershell=30000, proxy=10000)
- `data.max_attribution_benign`: cap Stage 2 per-rule benign (process/registry/powershell=15000, proxy=8000)

### Data format cho match events
- Directory: `events_dir/<rule_name>/<rule_name>_Match_NN.json`
- Evasion: `evasions_dir/<rule_name>/<rule_name>_Evasion_*_NN.json`
- Mỗi file = 1 event dict với field `process.command_line` hoặc `winlog.event_data.CommandLine`

### Benign data field mapping
- `process_creation`: `process.command_line` hoặc `winlog.event_data.CommandLine`
- `registry_event`: `winlog.event_data.TargetObject`
- `powershell`: `winlog.event_data.ScriptBlockText`
- `proxy_web`: plain text URL (1 per line)

### Config: benign_train vs benign_valid (2026-05-14)
- **Production (default)**: `benign_valid` → `benign_train` (100% benign → F1=1.0 trên validation)
  - Đây là deployment setup: dùng 100% data sẵn có, không holdout
  - Metric "thật" chỉ có ý nghĩa khi đo trên real ELK events (bằng diagnose_stage1.py)
- **Debug/Thesis (80/20)**: đổi `benign_valid` → `benign_train_split_val.txt` (20% holdout)
  - Honest evaluation: train 80%, validate 20% không giao nhau

## Commands hay dùng

> **Activate venv trước**: `source ~/venvs/rule_evasion_env/bin/activate`

```bash
# Smoke test TRƯỚC KHI chạy full (2-3 phút — xác nhận data/config OK)
python3 scripts/train.py --config config/process_creation.yaml --max-benign-samples 1000
python3 scripts/train_attribution.py --config config/process_creation.yaml --max-attribution-benign 1000

# Stage 1 — Production (Ensemble SVM+LR+CNB, 100% benign)
python3 scripts/run_stage1.py --config config/process_creation.yaml

# Stage 1 — SVM baseline để so sánh
python3 scripts/run_stage1.py --config config/process_creation.yaml --no-ensemble --result-name svm_baseline

# Stage 1 — Từng bước nếu debug (vẫn dùng 100% benign → F1=1.0)
python3 scripts/train.py --config config/process_creation.yaml --ensemble
python3 scripts/validate.py --config config/process_creation.yaml
python3 scripts/evaluate.py --config config/process_creation.yaml

# Diagnose Stage 1 model (F1=1.0, token analysis, real ELK events)
python3 scripts/diagnose_stage1.py --valid-result models/process_creation/valid_rslt_ensemble_f1.zip

# Stage 2 — attribution (checkpoint tự động mỗi 20 rules)
python3 scripts/train_attribution.py --config config/process_creation.yaml
python3 scripts/eval_attribution.py --config config/process_creation.yaml --method cosine

# ELK Integration — phát hiện trên hệ thống thật
# Bước 1: Export events từ Elasticsearch ra JSONL (15 phút qua)
python3 scripts/elk_export.py --es-host http://10.10.20.100:9200 --es-user elastic --es-password ... \
  --es-index "logs-winlog*" --since 15m --out ~/detect_logs/events.jsonl
# Index names: "winlogbeat-*" (Winlogbeat) | "logs-winlog*" (Elastic Agent)

# Bước 2: Batch detection (offline verify)
python3 scripts/detect_batch.py --config config/process_creation.yaml \
  --events ~/detect_logs/events.jsonl --threshold 0.0 --method cosine --out ~/detect_logs/alerts.jsonl

# Bước 3: Live polling daemon (real-time detection)
python3 scripts/detect_live.py --config config/process_creation.yaml \
  --es-host "http://elastic:PASSWORD@10.10.20.100:9200" --es-index "logs-winlog*" \
  --out-index red-alerts --threshold 0.0 --method cosine --interval 60

# Linux/Mac — Stage 1 cho cả 3 event types
for cfg in process_creation registry_event powershell; do
    python3 scripts/run_stage1.py --config config/$cfg.yaml
done

# Windows PowerShell — chạy cả Stage 1 + Stage 2
foreach ($cfg in @("process_creation","registry_event","powershell")) {
    python scripts/run_stage1.py --config "config/$cfg.yaml"
    python scripts/train_attribution.py --config "config/$cfg.yaml"
    python scripts/eval_attribution.py --config "config/$cfg.yaml" --method cosine
}
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

---

## Roadmap luận văn (KLTN)

Đề tài: *"Xây dựng hệ thống phát hiện xâm nhập và hành vi né tránh luật dựa trên mô hình học máy và AI-Agent"*

### Hiện trạng (2026-05-14)

| Event type | Benign | Evasion | Stage 1 | Stage 2 |
|---|---|---|---|---|
| process_creation | 1828 (split 1462/366) | 446 → 298 unique | ✅ Ensemble F1=1.0 | ✅ Cosine top-1=68.8% |
| powershell | 4266 (split 3413/853) | 25 subdirs load **0** | ✅ Done | ⚠️ Debug evasion format |
| registry_event | 11776 (split 9420/2356) | **không có** | ✅ Done | ❌ Cần generate_evasions.py |
| proxy_web | ? | ? | ❓ Chưa kiểm tra | ❓ Chưa kiểm tra |

### Bằng chứng Ensemble vượt SVM (process_creation, raw threshold=0)

| Metric | SVM đơn | **Ensemble** |
|---|---|---|
| Recall | 94.3% | **100%** |
| F1 | 0.9706 | **1.0000** |
| FN | 17 | **0** |
| → CNB cứu 17 evasion mà SVM bỏ sót | | |

Sau MCC scaling, cả 2 đều F1=1.0 (data dễ tách). **Raw metrics mới phơi bày sự khác biệt** → dùng làm bằng chứng chính trong luận văn.

### Các phase chưa làm

#### Phase B — Stage 2: Rule Attribution ✅ DONE (process_creation)

**Kết quả (83 rules, 298 evasion samples, 2026-05-10):**

| Method | Top-1 | Top-3 | Top-5 | Top-10 |
|--------|-------|-------|-------|--------|
| SVM    | 23.5% | 53.7% | 73.2% | 87.2%  |
| Cosine | **68.8%** | **92.6%** | **97.3%** | **99.7%** |
| Hybrid | 48.7% | 85.9% | 91.9% | 96.0%  |

**Nhận xét:** Cosine > Hybrid > SVM (ngược kỳ vọng). SVM underfitted vì fallback dùng match events (1-15 samples/rule). Cosine trên shared TF-IDF (330 filter values) mạnh hơn. Cần chạy thêm cho powershell/registry_event/proxy_web.

**Còn lại:** Chạy Stage 2 cho 3 event types khác.

#### Phase C — AI Agent SOC Triage (NOVELTY CHÍNH)

Architecture:
```
SOC Triage Agent (ReAct loop, LiteLLM-based)
├── Tools:
│   ├── classify_event(event) → score
│   ├── attribute_rule(event) → top-k rules
│   ├── enrich_mitre(rule) → ATT&CK technique
│   ├── lookup_ioc(hash/ip) → VirusTotal/AbuseIPDB
│   ├── query_history(host) → previous alerts
│   ├── generate_response() → Sigma patch suggestion
│   └── escalate(severity) → TheHive/Slack
└── LLM: Claude/GPT/Llama via LiteLLM
```

Multi-Agent (advanced): Triage → Investigation → Response → Report.

Đánh giá:
- Time-to-decision (vs analyst người)
- Token cost/alert
- Hallucination rate (agent có bịa rule không tồn tại?)
- Accuracy vs ground truth

#### Phase D — Adversarial Robustness
- LLM-based evasion: dùng Claude/GPT sinh command tránh rule
- Encoding obfuscation: base64, hex, ROT13, padding
- Concept drift: train LMD-2022, test LMD-2023
- Robustness curve: F1 vs noise level

#### Phase E — System Engineering & Production Deploy (✅ SIGNIFICANT PROGRESS)
**Stage 1 (2026-05-14):**
- ✅ `run_stage1.py` — gộp train+validate+evaluate 1 lệnh (khuyến nghị dùng)
- ✅ Config updated: `benign_valid` = `benign_train` (100% production setup)
- ✅ Virtual environment setup docs (~/venvs/rule_evasion_env)
- ✅ `diagnose_stage1.py` — analyze F1=1.0, token analysis, real events distribution

**ELK Integration (2026-05-11):**
- ✅ `elk_export.py` — export events từ ES → JSONL (với auth)
- ✅ `detect_batch.py` — batch detection offline (verify pipeline, fixed MinMaxScaler & batch vectorize)
- ✅ `detect_live.py` — live daemon poll ES, index alerts về `red-alerts`
- ✅ `push_alerts.py` — bulk index alerts.jsonl → Elasticsearch
- ✅ Compatible cả Winlogbeat (`winlogbeat-*`) và Elastic Agent (`logs-windows.*`)
- ❌ FastAPI server: `/predict`, `/attribute`, `/agent/triage`
- ❌ React/Vue dashboard: real-time alert feed
- ❌ Wazuh/TheHive/Cortex Analyzer integration
- ❌ Docker compose deployment

#### Phase F — Explainability + Active Learning
- SHAP/LIME: token nào trigger detection
- Counterfactual: "đổi token X có còn detect không?"
- Analyst feedback loop → uncertainty sampling → retrain

#### Phase G — Statistical Rigor
- Bootstrap confidence intervals cho mọi metric
- Wilcoxon signed-rank: Ensemble vs SVM có significant?
- McNemar's test (paired comparison)

### Timeline đề xuất

| Tuần | Mục tiêu | Deliverable |
|---|---|---|
| 1 | Debug powershell evasion + Stage 2 process_creation | top-k bảng |
| 2 | proxy_web + Stage 2 powershell | 4 event types |
| 3 | Visualization + adversarial robustness | Biểu đồ |
| 4-5 | AI Agent core (ReAct, tools, LiteLLM) | CLI demo |
| 6 | API server + dashboard | Web UI |
| 7 | Integration (Wazuh/TheHive nếu kịp) | E2E demo |
| 8 | Viết luận văn nháp | Draft |
| 9 | Polish + slide + demo video | Final |

### Đóng góp khoa học (claims cho luận văn)

1. Mở rộng AMIDES với **multi-event-type** (4 loại) thay vì chỉ process creation
2. **Cosine Similarity** trong không gian TF-IDF chung cho attribution → nhanh, ổn định; SVM/Hybrid-RRF giữ làm baseline so sánh
3. **AI Agent SOC Triage** tự động hóa workflow analyst — novelty chính
4. **Adversarial robustness analysis** với LLM-generated evasions
5. **End-to-end system** từ event → detection → attribution → response → report
6. **Bằng chứng Ensemble robust hơn SVM ở raw boundary** (5.7% recall improvement, ý nghĩa thống kê cần verify)

### Vietnamese context (điểm cộng KLTN)

- Vietnamese language report từ agent
- VNCERT/Cybersecurity compliance mentions (NĐ 13/2023, NĐ 53/2022)
- PII redaction trong logs
- Local threat actor case study (APT32...)

### Cost-Benefit Analysis (nên có trong luận văn)

| Metric | Manual analyst | Pipeline + Agent |
|---|---|---|
| Time/alert | 5-15 phút | 5-30 giây |
| Cost/alert | $X | token + compute |
| FN risk | Cao (mệt) | Thấp (consistent) |
| Scale | Linear | Auto |

ROI calc cho SOC trung (1000 alerts/ngày).
