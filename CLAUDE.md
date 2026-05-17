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

**Phase C — AI Agent SOC Triage**: ✅ Implemented (8 agents incl. Forensic, end-to-end OK).
**Phase E — ELK Integration**: ✅ Done (RED detect_live + Elastic SIEM 1,624 Sigma rules imported + agent daemon).

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

#### Phase C — AI Agent SOC Triage (✅ IMPLEMENTED 2026-05-14)

**Status**: Multi-agent pipeline đã hoạt động end-to-end với LLM DeepSeek V3, deploy thông qua `agent/daemon.py`.

**Architecture — 8 agents hierarchical** (Forensic added 2026-05-17):

```
Supervisor (no tools) → Triage (3 tools)
                            │
                            ├──► is_false_positive → skip rest
                            ▼
                  🔬 Forensic (3 VR tools)  ← NEW: host-level evidence
                            │
                            ├──► verdict=likely_benign → close case
                            ▼
            parallel(Hunt, RED Analyst, MITRE)  ← asyncio.gather
                            │
                            ▼
                       Response (3 tools, grounded by forensic)
                            │
                            ▼
                       Report (no tools, forensic timeline)
                            │
                            ▼
                  ai-investigations (ES)
```

**Module structure** (`agent/`):
- `orchestrator.py` — Workflow runner async
- `_loop.py` — Generic ReAct loop với local token tracking (parallel-safe)
- `llm.py` — Async DeepSeek/OpenAI client (OpenAI-compat)
- `schemas.py` — Pydantic models cho mọi output types
- `tools.py` — 12 shared tools (9 mock/ES + 3 Velociraptor wrappers)
- `vr_client.py` — Velociraptor gRPC wrapper + mock data + host→client_id resolver
- `vr_client_map.yaml` — Map hostname → Velociraptor client_id (điền sau khi cài VR)
- `es_io.py` — Read red-alerts, write ai-investigations + state mgmt
- `daemon.py` — Polling daemon với `--since`, `--no-state`, `--query-string`
- `inject_test_alert.py` — Helper inject mock alert
- `agents/` — 8 agent implementations (mỗi cái ~80 dòng)
- `prompts/` — 8 system prompts markdown

**8 agents chi tiết**:

| Agent | Tools | Output schema | Vai trò |
|---|---|---|---|
| **Supervisor** | (none) | `WorkflowPlan` | Router decide skip_fp/quick/full |
| **Triage** | query_es_history, get_process_tree, lookup_mitre | `TriageOutput` | Severity + FP filter (~60-80% alerts) |
| **Forensic** ⭐ | vr_process_tree_deep, vr_file_artifacts, vr_network_connections | `ForensicOutput` | Host-level evidence từ Velociraptor — ground hết downstream |
| **Hunt** | + get_network_connections, search_threat_intel | `HuntOutput` | Timeline + IOCs + threat intel |
| **RED Analyst** ⭐ | get_sigma_rule_text, get_evasion_tokens | `RedAnalystOutput` | Explain WHY this is evasion (interpretability) |
| **MITRE** | lookup_mitre | `MitreOutput` | TTP chain mapping |
| **Response** ⭐ | get_sigma_rule_text, suggest_containment, send_telegram | `ResponseOutput` | Sigma patch (grounded bởi forensic) + containment + notify |
| **Report** | (none) | `ReportOutput` | Vietnamese markdown report kèm forensic timeline |

**Performance** (per investigation, DeepSeek V3, 2026-05-17 — REAL Velociraptor verified):
- 7-agent (no Forensic): ~67-77s, ~30-50k tokens, ~$0.015
- **8-agent mock VR: ~98s, ~67k tokens, ~$0.020** (+27s, +$0.005)
- **8-agent REAL VR: ~210s, ~67k tokens, ~$0.018** (Forensic Agent ~150s vì 3 query × 25-30s)
- Forensic Agent mock: ~22s; real: ~150s
- Parallel block (Hunt+RED+MITRE) vẫn tiết kiệm ~13-16s

**Forensic Agent rationale** (Phase C v2):
- Vấn đề pipeline cũ: triage + analysis chỉ dựa trên LOG → "LLM bịa Sigma patch" là rủi ro chính
- Forensic gọi Velociraptor query trực tiếp host nạn nhân → bằng chứng cứng (process tree, file hash, registry persistence, network active)
- Downstream agents (Response, Report) nhận `ForensicOutput` qua optional kwarg `forensic=` → backward compatible
- Mock mode (default): trả mock data có shape giống VQL thật → agent code không đổi giữa dev/prod
- Real mode: `export VR_USE_REAL=1 VR_API_CONFIG=...` + `pip install pyvelociraptor grpcio pyyaml` + điền `vr_client_map.yaml`
- **Verified 2026-05-17**: pipeline 8-agent chạy với REAL Velociraptor query Windows VM (DESKTOP-2UQB61H, C.1b622eacffe8b75d), scan 166 real processes, agent honest verdict `inconclusive` khi không tìm thấy alert PID → **kháng hallucination measurable**

**Velociraptor lab setup** (đã verify hoạt động):
- Server binary: `/usr/local/bin/velociraptor` (chạy systemd `velociraptor_server.service`)
- Server config (root): `/etc/velociraptor/server.config.yaml`
- User-owned configs: `~/velociraptor/{server,client,api}.config.yaml`
- Datastore: `/var/lib/velociraptor` (owned by `velociraptor` user, 0750)
- Server IP: `10.10.20.20`, frontend `:8000`, GUI `:8889`, API gRPC `:8001`
- GUI admin: user `admin` / pass `tzxr` (lab only, đổi cho prod)
- API user (cho agent): `agent` (role administrator) — phải tạo qua `user add` + restart server
- Cần restart `velociraptor_server` sau khi `user add` để pick up user mới
- API config required field `name` = API user (vd `agent`), NOT TLS hostname (TLS hardcoded `VelociraptorServer`)

**VQL pattern dùng trong vr_client.py**:
- `collect_client(artifacts=['X'], timeout=60)` → flow_id
- `watch_monitoring(artifact='System.Flow.Completion') WHERE FlowId = flow.flow_id LIMIT 1` → đợi flow xong
- `source(client_id, flow_id, artifact='X')` → đọc kết quả
- VQL của Velociraptor KHÔNG hỗ trợ subquery `IN { SELECT ... }` → filter trong Python
- Artifacts dùng: `Windows.System.Pslist`, `Windows.Registry.NTUser`, `Windows.Network.NetstatEnriched`

**Time synchronization** (quan trọng cho thesis evaluation):
- Pipeline correlate event giữa Windows VM, ELK, Velociraptor server, lab agent
- Lệch giờ > 30s gây: Forensic kết luận sai live/dead, `since_minutes` méo window, timeline đảo thứ tự
- Bằng chứng **cấu trúc** (process tree, hash, path, IP, registry) KHÔNG bị ảnh hưởng
- Bằng chứng **thời gian** (timeline tuyệt đối, decision live/dead) BỊ ảnh hưởng
- Khuyến nghị: `chrony` trên Ubuntu + `w32tm /resync` trên Windows VM về cùng NTP source
- Velociraptor server tự gán `_ts` (server-received timestamp) — dùng để cross-host correlation

**Sigma patch generation — quan trọng cần ghi rõ**:
- Hiện tại: LLM generation, **grounded bởi ForensicOutput** từ 2026-05-17 (giảm hallucination)
- Limitation: vô hạn evasion variants → patch là tactical band-aid, KHÔNG silver bullet
- Real defense: RED ML model generalize + feedback loop retrain
- Trong luận văn KHÔNG claim "auto-Sigma patch solves evasion" — chỉ claim tactical mitigation + feedback loop strategic
- Forensic evidence giờ là **input ground truth** cho LLM thay vì để LLM tự đoán
- Future work (Layer 3 validator): YAML parse + Sigma schema + functional test với evasion command

**LLM choice**:
- Production: DeepSeek-V3 (cheap, decent tool use, OpenAI-compat API)
- API key trong `.env` (KHÔNG commit)
- Subscription Claude Pro / ChatGPT Plus KHÔNG cho API access → phải có key riêng
- Future: benchmark Claude / GPT trong evaluation chapter

**Đánh giá luận văn** (cần làm):
- Time-to-decision (~70s) vs analyst người (5-15 phút) → 4-12× faster
- Token cost/alert (~$0.015) vs analyst hour ($25-50)
- Accuracy vs ground truth — CẦN build labeled dataset 100-200 alerts
- Hallucination rate — cần count cases LLM bịa rule/IOC
- FP filter coverage — ~60-80% expected

**Limitations cần thừa nhận trong luận văn**:
- LLM hallucinate có thể sinh Sigma patch invalid YAML
- Sigma patch không thay thế được generalization của ML model
- Latency 70s không real-time (acceptable cho SOC triage)
- Phụ thuộc DeepSeek API uptime + rate limits

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

### Đóng góp khoa học (claims cho luận văn — refraine 2026-05-14)

⚠️ **Tránh claim**: "Auto-Sigma patch giải quyết evasion vĩnh viễn" (cat-and-mouse vô hạn — bạn đúng).
✅ **Claim đúng**: Multi-layer adversarial-aware detection với AI orchestration.

1. **ML model generalize over evasion variants tốt hơn Sigma exact-match**
   - Ensemble F1=1.0 vs SVM 0.97 (raw threshold=0)
   - 1 model bắt cả họ variants, không cần enumerate
   - Bằng chứng: process_creation 17 evasion mà SVM miss được CNB catch

2. **Cosine Similarity attribution accuracy cao**
   - Top-1 68.8% so với SVM 23.5%, Hybrid 48.7%
   - Đơn giản, ổn định, scalable

3. **Multi-Agent SOC orchestration tự động hóa workflow analyst**
   - 8 specialized agents (incl. Forensic), ~98s/alert vs 5-15 phút analyst
   - Cost $0.020/alert vs $25-50 analyst hour

3b. **Evidence-grounded Sigma patch (Forensic Agent)** ⭐ NEW 2026-05-17
   - Velociraptor query host nạn nhân → bằng chứng cứng (process tree, file hash, registry, network)
   - LLM Response Agent ground patch + containment trên evidence cứng thay vì log-level guess
   - Giảm hallucination Sigma patch — measurable: % patches reference real file paths Velociraptor saw
   - Trade-off mock: +27s latency, +$0.005/alert
   - Trade-off real VR: +112s latency (mỗi VR query ~25-30s × 3)
   - **Hallucination resistance measurable**: với alert PID=0 (Idle Process), Forensic Agent scan 166 real processes, trả verdict `inconclusive` thay vì bịa evidence → claim defensible trong luận văn

4. **Explainable ML detection (RED Analyst Agent)** ⭐ NOVELTY
   - LLM dịch ML score (black-box) → human reasoning với evidence
   - Bridge gap giữa ML output và SOC analyst
   - Không có trong Elastic AI Assistant / Splunk / Sentinel

5. **Cross-source signal correlation (Hunt Agent)**
   - Fuse SIEM exact-match alerts + RED evasion findings + Threat intel
   - 1 incident view thay vì N separated alerts

6. **Vietnamese-language SOC automation**
   - Report tiếng Việt cho VN SOC teams
   - VNCERT/NĐ 13/2023 compliance ready

7. **Tactical Sigma patch generation + Feedback loop**
   - LLM sinh patch SHORT-TERM cho variant cụ thể (band-aid)
   - Evasion samples → retrain RED → long-term defense
   - Honest framing: patch không thay thế ML model

**Bằng chứng cần measure cho luận văn**:
- Time-to-decision: agent vs analyst người
- Accuracy: agent severity vs ground truth (cần build labeled 100-200 alerts)
- Hallucination rate: % cases LLM bịa rule/IOC
- FP filter coverage: % FP eliminated trước SOC
- Sigma patch quality: % patches valid YAML, % catches re-run evasion

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
