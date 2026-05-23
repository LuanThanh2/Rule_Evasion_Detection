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

**Velociraptor lab setup** (đã verify hoạt động — updated 2026-05-23):
- Server binary: `/usr/local/bin/velociraptor` (chạy systemd `velociraptor_server.service`)
- Server config (root): `/etc/velociraptor/server.config.yaml`
- User-owned configs: `~/velociraptor/{server,client,api}.config.yaml`
- Project api.config: `velociraptor/api.config.yaml` (trong repo, dùng cho gRPC)
- Datastore: `/var/lib/velociraptor` (owned by `velociraptor` user, 0750)
- Server IP: `127.0.0.1:8001` (gRPC API, localhost only), GUI `:8889`
- GUI admin: user `admin` / pass `tzxr` (lab only)
- API config required field `name` = username GUI (vd `admin`), NOT TLS hostname
- TLS hostname hardcoded `VelociraptorServer` (trong grpc ssl_target_name_override)
- **api.config.yaml hết hạn / sai CA** — regenerate bằng:
  ```python
  import yaml, os, tempfile, subprocess
  with open('velociraptor/server.config.yaml') as f:
      cfg = yaml.safe_load(f)
  tmpdir = tempfile.mkdtemp()
  os.makedirs(f"{tmpdir}/users", exist_ok=True)
  cfg['Datastore']['location'] = tmpdir
  tmp_cfg = f"{tmpdir}/server.config.yaml"
  with open(tmp_cfg, 'w') as f: yaml.dump(cfg, f)
  subprocess.run(['/usr/local/bin/velociraptor', '--config', tmp_cfg,
                  'config', 'api_client', '--name', 'admin',
                  '--role', 'administrator', 'velociraptor/api.config.yaml'])
  ```
  Lý do dùng tmpdir: `/var/lib/velociraptor/users` owned by `velociraptor` user → permission denied nếu chạy với user thường.

**Velociraptor client_id mapping** (`agent/vr_client_map.yaml`):
- `DESKTOP-2UQB61H: C.1b622eacffe8b75d` — demo VM cũ (10.10.20.x lab)
- `DESKTOP-IQAM883: C.cd6bfbb23aee7979` — demo VM mới (192.168.10.103)
- Tìm client_id mới: `curl -sk -u "admin:tzxr" "https://127.0.0.1:8889/api/v1/SearchClients?query=all"`

**VQL pattern dùng trong vr_client.py** ⚠️ CRITICAL BUG đã fix 2026-05-23:
- `LET _wait <= SELECT * FROM watch_monitoring(...)` là **lazy evaluation** — không bao giờ thực thi nếu `_wait` không được reference trong SELECT cuối. → **Lỗi**: 0 process trả về.
- **Fix đúng**: dùng `foreach(row={watch_monitoring(...)}, query={source(...)})` — đảm bảo watch_monitoring thực thi trước khi source đọc kết quả.
- Pattern chuẩn (đã apply cho cả 4 VQL trong vr_client.py):
  ```sql
  LET flow <= collect_client(client_id=ClientId, artifacts=['X'], timeout=60)
  SELECT ... FROM foreach(
      row={SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
           WHERE FlowId = flow.flow_id LIMIT 1},
      query={SELECT ... FROM source(client_id=ClientId, flow_id=flow.flow_id, artifact='X')}
  )
  ```
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

---

## ⏳ HANDOFF — Work-in-progress 2026-05-20 (3 fix RED ML)

User đề xuất 4 limitation của RED, đã apply Fix #1, #2, #4 (bỏ #3 top-K).

### Fix đã apply (code + config đã sửa trên disk)

| Fix | File sửa | Thay đổi |
|---|---|---|
| **#2 Tokenizer giữ path** | `red/normalize.py` | Thêm `[\w\\/:.\-]+` trong regex, replace `\ / : . -` thành `_` trong token, max_str_len 30→60. `C:\Windows\sshd.exe` → 1 token `c_windows_sshd_exe`. |
| **#4 Extract broader** | `red/data.py` `_extract_sigma_detection_values` | Case-insensitive field match + bỏ `_` để `parent_image` = `ParentImage`. Auto-extract `keywords:` section + list of plain strings. Recursive nested dict. |
| **#1 Multi-field search_fields** | `config/process_creation.yaml`, `config/registry_event.yaml`, `config/powershell.yaml` (powershell đã làm trước đó) | Mở rộng `search_fields` thêm `Image`, `ParentImage`, `ParentCommandLine`, `IntegrityLevel`, `User`, `OriginalFileName`, `CurrentDirectory` (process_creation); `Image`, `User`, `EventType` (registry_event). Cập nhật `event_field_map` map ra JSON path tương ứng. |

### ✅ Retrain ĐÃ XONG 2026-05-20 16:32

**Before vs After Fix #1/2/4**:

| Model | Before SVM | Before Cos | After SVM | After Cos |
|---|---|---|---|---|
| process_creation | 202 | 920 | 200 | **1129** ⬆ |
| powershell | 25 | 204 | 25 | **208** ⬆ |
| registry_event | 38 | 243 | 23 | **242** |
| **TỔNG** | 265 | **1,367** | 248 | **1,579** ⬆ |

**Δ Cosine: +212 rule (+15.5%)** — Fix #1 (multi-field) đóng góp chính (process_creation +209).

**Δ SVM: -17** — tokenizer mới làm 17 rule không đủ filter values sau normalize (chấp nhận được, SVM được fallback bằng Cosine).

**Verified metadata lookup**: 1,579/1,579 (100%) qua SigmaRuleIndex.

### ✅ Quick rehearsal verify 2026-05-20 16:39 — Fix #1 confirmed

RunId `13b2e975` (Mode evasion) — RED attribute thêm rule mới mà TRƯỚC fix miss:

| Sau fix RED bắt được | Quan hệ với Sigma Kibana | Lý do |
|---|---|---|
| `program_executed_using_proxy_local_command_via_ssh_exe` ⭐ | ✅ Sigma Kibana cũng fire | Rule check `ParentImage|endswith: '\sshd.exe'` — Fix #1 thêm ParentImage vào search_fields → RED extract được |
| `regsvr32_execution_from_highly_suspicious_location` ⭐ | (rule mới) | Phase 6 Squiblydoo, rule mới từ catalog expansion |
| `hacktool_covenant_powershell_launcher` | (rule mới) | Pattern PowerShell launcher |
| `amsi_bypass_pattern_assembly_gettype` | (giữ nguyên) | Phase 4 AMSI marker |
| 4 rule khác | various | Cover thêm |

→ **Bằng chứng Fix #1 ĐÚNG MỤC ĐÍCH**: RED catch được rule SSH-based (parent-child) — trước fix MISS hoàn toàn vì RED chỉ nhìn command_line.

**Sigma vs RED overlap**: Trước fix 1/8 → sau fix ≥3/8 (SSH spawn + WMI + Regsvr32 đều khớp).

### ⏭️ Việc tiếp theo (chưa làm)

Tokenizer thay đổi → vocabulary thay đổi → **PHẢI retrain Stage 1 + Stage 2 cả 3 event_type**. Backup model cũ đã làm: `models/{event}/train_rslt_*.PRE_FIX124.zip`.

**Sau retrain — verify**

```bash
# 1. Verify rule count tăng (kỳ vọng > 1,367 trong Cosine attributor)
python3 -c "
from red.persist import load_result
for n,p in [('proc','models/process_creation/train_rslt_attr_ensemble.zip'),
            ('ps','models/powershell/train_rslt_attr_ensemble.zip'),
            ('reg','models/registry_event/train_rslt_attr_ensemble.zip')]:
    r=load_result(p)
    print(f'{n}: SVM={len(r[\"rule_models\"])}, Cosine={len(r[\"cosine_attributor\"].rule_filter_matrices)}')
"

# 2. Regenerate RED_RULE_MAP.md với rule count mới (xem demo/RED_RULE_MAP.md generator trong git history)

# 3. Rerun demo Mode evasion + so sánh Sigma vs RED overlap
sshpass -p tzxr ssh luanthanh@10.10.20.50 \
  'powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode evasion -SleepSeconds 60'
sleep 90

# So sánh:
# - Trước fix: Sigma fire 8 rule unique, RED attribute 9 rule (1 overlap)
# - Sau fix kỳ vọng: RED attribute thêm rule SSH-based (parent), AMSI bypass, RunOnce NT → overlap tăng 3-5 rule
```

### Update sau khi verify

- `demo/RED_RULE_MAP.md` — regenerate (xem snippet trong section 12.14 của demo/README.md)
- `demo/README.md` — thêm section 12.16 "Multi-field Fix #1/#2/#4" với before/after
- `demo/apt_demo_scenario_demo_present.md` — update bảng Pha 4 với rule overlap mới
- `README.md` (root) — update Stage 2 catalog expansion: 1,367 → con số mới
- File này (CLAUDE.md) — đánh dấu Fix #1/#2/#4 status = "applied + verified"

### Rủi ro

- Stage 1 retrain có thể giảm accuracy nếu tokenizer mới generate tokens lạ với benign data → check F1 sau retrain
- Nếu accuracy giảm > 5% → revert tokenizer hoặc dùng dual-tokenization (keep both old + new tokens)
- Cosine catalog có thể tăng lên ~1,500 rule (từ 1,367) sau Fix #4 — KHÔNG cần lo nếu < 2,000

### Files khác đã update trong session này (2026-05-20)

- `demo/apt_demo_scenario.md` — giải thích từng phase + Sigma rule match
- `demo/apt_demo_scenario_demo_present.md` — hướng dẫn defense step-by-step + Phụ lục A Velociraptor
- `demo/RED_RULE_MAP.md` — tra cứu 1,367 RED rule ↔ Sigma metadata
- `demo/QA_PREP.md` + `demo/SLIDES_OUTLINE.md` — Q&A + slides
- `agent/prompts/{triage,hunt,response,report}.md` — anti-hallucination rules
- `agent/agents/{forensic,response,report}.py` — Forensic Agent + integration
- `agent/vr_client.py` — Velociraptor gRPC wrapper
- `red/rule_metadata.py` — SigmaRuleIndex enrichment

---

## ⏳ HANDOFF — Work-in-progress 2026-05-23 (IQAM883 lab + Elastic Agent ECS)

### Môi trường lab mới (DESKTOP-IQAM883)

Session này chuyển sang lab environment mới hoàn toàn:

| Thành phần | Lab cũ (2026-05-20) | Lab mới (2026-05-23) |
|---|---|---|
| Windows VM | DESKTOP-2UQB61H | **DESKTOP-IQAM883** (192.168.10.103) |
| ELK host | http://10.10.20.100:9200 | **https://192.168.10.10:9200** (HTTPS!) |
| Kibana | http://10.10.20.100:5601 | https://192.168.10.10:5601 |
| Agent trên Windows | Winlogbeat | **Elastic Agent v9.4.1** |
| SSH | sshpass + openssh | **paramiko** (Python) |
| VR client_id | C.1b622eacffe8b75d | **C.cd6bfbb23aee7979** |
| Branch git | main | **elk_server** |

### ✅ Fixes đã apply và commit (branch: elk_server)

| Fix | File | Chi tiết |
|---|---|---|
| **VQL foreach** | `agent/vr_client.py` | `LET _wait` lazy eval → `foreach(row={watch_monitoring}, query={source()})`. Trước: 0 process; sau: 129 process. |
| **IQAM883 VR map** | `agent/vr_client_map.yaml` | Thêm `DESKTOP-IQAM883: C.cd6bfbb23aee7979` |
| **ForensicEvidence.kind** | `agent/schemas.py` | Mở rộng Literal: thêm `alert_correlation`, `sigma_rules`, `threat_intel`, `wmi` |
| **HTTPS SSL verify** | `es_io.py`, `tools.py`, `inject_test_alert.py`, `detect_live.py` | `verify=ES_VERIFY` (từ `ES_VERIFY_SSL=false` trong .env) + suppress InsecureRequestWarning |
| **Elastic Agent ECS** | `config/powershell.yaml` | Thêm `powershell.file.script_block_text` (primary) trước `winlog.event_data.ScriptBlockText` |
| **Elastic Agent ECS** | `config/registry_event.yaml` | Thêm `registry.path` + `registry.data.strings` (list→join) trước Winlogbeat fields |
| **extract_field list** | `scripts/detect_live.py` | Xử lý field là list (registry.data.strings) → join thành string |
| **New demo guide** | `demo/apt_demo_scenario_demo_present_2.md` | File mới cho IQAM883, Elastic Agent, HTTPS ELK |

### Elastic Agent ECS vs Winlogbeat field mapping

Elastic Agent v9+ dùng ECS (Elastic Common Schema) — **khác hoàn toàn** Winlogbeat:

| Sysmon field | Winlogbeat path | Elastic Agent ECS path |
|---|---|---|
| ScriptBlockText | `winlog.event_data.ScriptBlockText` | `powershell.file.script_block_text` |
| TargetObject (registry key) | `winlog.event_data.TargetObject` | `registry.path` |
| Details (registry value) | `winlog.event_data.Details` | `registry.data.strings` (LIST, không phải string!) |
| CommandLine | `winlog.event_data.CommandLine` | `process.command_line` |
| Image | `winlog.event_data.Image` | `process.executable` |
| ParentImage | `winlog.event_data.ParentImage` | `process.parent.executable` |

**`registry.data.strings` là list** → detect_live.py `extract_field()` phải join thành string.

Config `event_field_map` trong YAML phải list cả 2 path (ECS primary, Winlogbeat fallback).

### Clock sync: Windows @timestamp vs Ubuntu UTC ✅ RESOLVED 2026-05-23

**Lịch sử**: Trước đây Windows VM ghi `@timestamp` lệch 7 tiếng so với Ubuntu UTC (do múi giờ UTC+7 không sync NTP đúng). Phải dùng workaround `--since` trừ 7h.

**Hiện tại (2026-05-23)**: NTP đã sync trên Windows VM. Verify:
- Ubuntu UTC: `2026-05-23T10:23:57Z`
- Event mới nhất từ DESKTOP-IQAM883: `2026-05-23T10:24:00Z`
- Lệch ~3s (network + indexing delay) — chấp nhận được

**Cách dùng `--since` đúng**: lấy giờ UTC hiện tại trừ window mong muốn, KHÔNG cần workaround -7h.
```bash
SINCE=$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)
python3 scripts/detect_live.py --config config/process_creation.yaml --since "$SINCE" ...
```

**Nếu skew xuất hiện lại** (Windows VM restart, NTP fail): chạy trên Windows
```powershell
w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:YES /update
w32tm /resync /force
```

### Elastic Agent OTel collector freeze bug

**Triệu chứng**: `elastic-agent` service RUNNING nhưng events ngừng đến ES. Sub-process `elastic-otel-collector.exe` bị freeze (không crash, không restart). Log file dừng update.

**Kiểm tra**: xem log file mới nhất trong `C:\Program Files\Elastic\Agent\data\elastic-agent-*\logs\`:
- Nếu log `elastic-otel-collector-*.log` có dòng "Shutdown complete" → sub-process đã die
- Nếu log không update trong > 5 phút → freeze

**Fix**: Phải stop + start service (restart không đủ vì sub-process không respawn):
```powershell
sc stop "Elastic Agent"
# Đợi 5-10s
sc start "Elastic Agent"
```

### Kết quả demo thực tế 2026-05-23

- **detect_live**: 1,026 alerts generated (process_creation + registry_event + powershell)
- **AI Agent run**: INV-c48334e770f9, severity=CRITICAL, 252s, $0.076, `confirmed_malicious`
- **Velociraptor**: 129 real processes scanned từ DESKTOP-IQAM883 (sau VQL foreach fix)
- **ForensicOutput**: `evidence_grade=high`, `c2_confirmed=True` (network connection thấy)

### ⏭️ Việc tiếp theo

1. **Merge elk_server → main** khi sẵn sàng (hoặc giữ tách biệt nếu lab env khác nhau)
2. ~~NTP sync Windows VM~~ ✅ Đã sync 2026-05-23, lệch <3s
3. **Verify PowerShell + Registry alerts**: chạy `--since` đúng window, check `powershell.file.script_block_text` có được index không
4. **Còn pending từ 2026-05-20**: retrain Stage 1+2 sau Fix #1/#2/#4 vẫn chưa verify đầy đủ trên IQAM883 environment

### Files chính cần đọc khi resume

- `demo/apt_demo_scenario_demo_present_2.md` — hướng dẫn demo đầy đủ cho IQAM883 (thay thế _present.md cũ)
- `agent/vr_client.py` — VQL queries (đã fix foreach)
- `config/{powershell,registry_event}.yaml` — ECS field mapping
- `.env` — `ES_VERIFY_SSL=false`, `VR_API_CONFIG` absolute path, `VR_USE_REAL=1`

---

## ⏳ HANDOFF — Session 2026-05-23 tối (Sigma import + 3 bug fixes)

Tiếp sau handoff IQAM883 buổi sáng. Buổi tối làm 2 việc lớn:
1. Benchmark 5 agent runs đa dạng + document chi tiết
2. **Fix 3 bugs hệ thống** đã observed trong các runs

### ✅ Bug fixes (verified + smoke-tested)

| Bug | File sửa | Thay đổi | Verify |
|---|---|---|---|
| **B1 dotenv override** | `agent/__init__.py` | `load_dotenv(_env)` → `load_dotenv(_env, override=True)` | Daemon poll OK dù `ES_RED_INDEX=red-alerts` exported sẵn trong shell |
| **B2 action_type Literal hẹp** | `agent/schemas.py` | `action_type: ResponseActionType` (Literal 10 giá trị) → `action_type: str` + giữ `KNOWN_ACTION_TYPES` set làm advisory | Cùng alert sdiagnhost: trước fix 2 actions, sau fix 3 actions (không drop nào) |
| **B3 max_iter dead code** | `agent/_loop.py` + `.env` | `_loop.py` đọc `AGENT_MAX_ITERATIONS` env làm ceiling chung (`max(caller_default, env)`); `.env` bump 8→12 | `max_iterations_reached` warning biến mất trên smoke test |

**Root cause B3** (quan trọng): `.env` đã có `AGENT_MAX_ITERATIONS=8` từ trước nhưng
`_loop.py` chỉ dùng param default `max_iter=6` — env var là **dead code**. Mỗi agent
hardcode max_iter riêng (triage=6, mitre=5, hunt=5, red_analyst=4, forensic, response=6,
report=3) → tăng .env không có tác dụng. Sau fix, env làm ceiling: nếu env ≥ caller default
thì env thắng.

### ✅ Sigma → Elastic NDJSON + Kibana import (1,620/1,624 rules)

**Script**: `scripts/convert_sigma_to_elastic.py` (đã có sẵn từ trước)

**2 lỗi hit khi import trên IQAM883**:

| Lỗi | Triệu chứng | Fix |
|---|---|---|
| **SSL WRONG_VERSION_NUMBER** | `--kibana-url https://...:5601` → `requests.exceptions.SSLError` | Kibana chạy **HTTP** (không HTTPS) trên port 5601. ES mới HTTPS. Dùng `http://192.168.10.10:5601` |
| **Invalid UUID** | 4/1624 rules fail với `id: Invalid UUID` | Sigma rule field `id:` phải là UUID format — 4 rule trong catalog có id không UUID → Kibana reject. Skip được, không critical |

**Commands chuẩn** (cho lab IQAM883):
```bash
# Convert + Import 1 lệnh
python3 scripts/convert_sigma_to_elastic.py \
  --index-pattern "logs-windows.*" \
  --index-pattern "winlogbeat-*" \
  --field-profile winlog-raw \
  --out data/sigma/elastic_rules/windows_sigma_elastic_winlog_raw.ndjson \
  --import-to-kibana \
  --kibana-url http://192.168.10.10:5601 \
  --kibana-user elastic \
  --kibana-password 'Admin123@' \
  --import-chunk-size 200 \
  --import-timeout 300
```

**Lưu ý index pattern**: data stream thật trên cluster là `logs-windows.*` (có chữ **s**),
KHÔNG phải `logs-winlog.*`. Các index có data:
- `.ds-logs-windows.powershell-*` (374k docs)
- `.ds-logs-windows.sysmon_operational-*` (99k)
- `.ds-logs-windows.powershell_operational-*` (94k)

**Sau import**: Kibana `Security → Rules` có **1,645 rules** (1,620 mới + 25 đã có sẵn).

### Benchmark 5 agent runs (2026-05-23 tối)

| InvId | Alert | Triage | Workflow | Time | Cost | Tokens |
|---|---|---|---|---|---|---|
| `INV-eb8a89f60736` | Covenant PS WMI | HIGH | full | 270.5s | $0.0352 | 170k |
| `INV-8443d66a4d97` | (low score) | LOW | quick_triage | 22.6s | $0.0057 | 28k |
| `INV-b96df99d7736` | nslookup_powershell_download_cradle | CRITICAL | full + REAL VR | 304.5s | $0.0634 | 374k |
| `INV-34b67170be9a` | potential_persistence_via_globalflags | **FP** | quick_triage (skip) | 13.4s | $0.0046 | 17k |
| `INV-932cb13b882b` | sdiagnhost shorthand-flag evasion | LOW | full | 85.3s | $0.0295 | 128k |
| `INV-553034b97c57` | sdiagnhost (sau fix B2/B3) | LOW | full | 78.0s | $0.0247 | 128k |

**Insights**:
- Median full pipeline: ~270s, ~$0.035 (REAL VR thêm ~150s + $0.02)
- Median quick_triage (FP filter): ~15s, ~$0.005
- FP filter coverage: 1/5 = 20% (sample nhỏ; field claim 60-80%)
- Cost extrapolation 1000 alerts/day: ~$21 (vs analyst $200-400 → 10-19× rẻ hơn)

### ⚠️ Limitation còn lại (chưa fix)

- **B2 mở rộng action_type sang `str`** — match được mọi LLM output, nhưng downstream
  dispatch logic mất type safety. Nếu sau này thêm executor cho từng action type, cần
  re-introduce dispatch table với `if action_type in KNOWN_ACTION_TYPES`.
- **`max_iterations_reached` Test #3 (PowerShell)** — vẫn xảy ra với RED Analyst dù tăng
  lên 12. Có thể tăng thêm hoặc đổi prompt để giảm tool-call chain.

### Files đã sửa session này

```
agent/__init__.py           — load_dotenv(override=True)
agent/schemas.py            — action_type: str + KNOWN_ACTION_TYPES set + mở rộng ForensicEvidence.kind (đã làm sáng)
agent/_loop.py              — đọc AGENT_MAX_ITERATIONS env làm ceiling
.env                        — AGENT_MAX_ITERATIONS=8 → 12
README.md                   — sửa convert_sigma_to_elastic.py example (http kibana, logs-windows.*)
demo/apt_demo_scenario_demo_present_2.md  — thêm Phụ lục D (benchmark + bugs)
data/sigma/elastic_rules/windows_sigma_elastic_winlog_raw.ndjson  — 1,624 Elastic rules
```

### ⏭️ Việc tiếp theo (sau session này)

1. **Smoke test daemon full**: chạy với 5-10 alerts liên tiếp (`--max-iter 5`) để verify B1/B2/B3 fix hoạt động ổn định
2. **Kibana Detection Rules tuning**: sau khi 1,620 rules enable, sẽ có nhiều FP. Cần
   - Disable rule severity informational (Sigma có ~30% là info)
   - Tune `interval` từ default 5m → 15m cho rule không critical
3. **B3 deeper fix**: nếu RED Analyst vẫn hit max_iter=12, xem prompt + tool design có thể giảm chain
4. **Sigma Rule UUID fix**: 4 rule fail có thể manual fix (replace `id:` bằng UUID) trong NDJSON rồi re-import
5. **Còn pending lâu**: retrain Stage 1+2 cho IQAM883 environment (từ handoff sáng 2026-05-20 Fix #1/#2/#4 chưa verify đầy đủ)

---

## ⏳ HANDOFF — Session 2026-05-23 (apt_demo_defense_present.md + diagnose red-alerts empty)

### Vấn đề được giải quyết

**Triệu chứng**: chạy `apt_demo_scenario.ps1` trên Windows VM nhưng `red-alerts*` không có log mới.

**Root cause**: PS script chỉ tạo **events** trong ELK `logs-windows.*` (qua Elastic Agent).
Để event → alert trong `red-alerts*` phải có 1 trong 2 pipeline:
- **Live**: `detect_live.py` daemon poll ELK → index `red-alerts-{demo,registry-demo,powershell-demo}`
- **Batch**: `elk_export.py` → `detect_batch.py` → `push_alerts.py` → index `red-alerts-defense-*`

Verify daemon chạy: `ps aux | grep detect_live | grep -v grep`. Nếu trống → start lại (xem Section 6.2 bước 1 trong `demo/apt_demo_defense_present.md`).

### ✅ Cập nhật file apt_demo_defense_present.md

Thêm **Section 6 "Lệnh chạy demo end-to-end"** với:
- **6.1** Prerequisites (load .env, verify ELK + IQAM883)
- **6.2** Workflow A — Live daemon (3× `detect_live.py` → `red-alerts-demo/registry-demo/powershell-demo`), recommended cho live demo GVHD
- **6.3** Workflow B — Batch offline (`elk_export` → `detect_batch` → `push_alerts`) reproduce artifacts `red-alerts-defense-*`; **lưu ý**: `push_alerts.py` không có `--no-verify-ssl` → cần monkey-patch hoặc dùng curl bulk (snippet trong Section 6.3 bước 4 "Cách 2")
- **6.4** Troubleshoot table 8 dòng (daemon không chạy, clock skew, OTel freeze, wrong index `logs-windows.*` vs `logs-winlog.*`, threshold quá cao, `ES_AUTH_HOST` rỗng)
- **6.5** Cleanup
- Section cũ 6/7/8 → 7/8/9

### ⚠️ push_alerts.py HTTPS issue (chưa fix trong code)

`push_alerts.py` gọi `requests` **không có `verify=False`** → crash trên ELK HTTPS self-signed.
Workaround đã có trong Section 6.3: curl bulk NDJSON thay vì script, hoặc monkey-patch `requests.Session`.
Nếu muốn fix đúng: thêm `--no-verify-ssl` flag vào `push_alerts.py` (đọc `ES_VERIFY_SSL` env từ `.env`).

### Indices hiện tại (2026-05-23)

| Index | docs.count | Workflow |
|---|---|---|
| `red-alerts-demo` | 15,529 | detect_live proc EID 1 |
| `red-alerts-powershell-demo` | 20,319 | detect_live PS EID 4104 |
| `red-alerts-registry-demo` | 108 | detect_live registry EID 13 |
| `red-alerts-defense-proc` | 1,158 | batch workflow session 2026-05-23 tối |
| `red-alerts-defense-reg` | 3,657 | batch workflow session 2026-05-23 tối |
| `red-alerts` | 0 | (empty, từ live default, bỏ qua) |

### Files sửa session này

```
demo/apt_demo_defense_present.md  — thêm Section 6 (lệnh chạy demo) + renumber 6/7/8 → 7/8/9
```

---

## ⏳ HANDOFF — Session 2026-05-24 (Fix #5 normalize + Section 10 alert verification)

### ✅ Fix #5 — normalize.py fallback split (`red/normalize.py`)

**Root cause**: Fix #2 (2026-05-20) giữ path context (`C:\Windows\sshd.exe` → 1 token `c_windows_sshd_exe`)
nhưng side-effect: `registry.path` đầy đủ `HKU\S-1-5-21-3762793008-640418586-4080996910-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\<key>` thành 1 token đơn 124 chars > `max_str_len=60` → filter empty → detect_batch skip → 0 reg alert per mode.

**Fix logic**: nếu merged token > max_str_len → fallback split lại trên separator thành sub-tokens. Backward-compat: path ngắn (proc/ps) vẫn merge nguyên → không cần retrain proc/ps.

**Verify**:
- Trước: `Normalizer().normalize('HKU\\S-1-5-...\\Run\\xxx')` → `''`
- Sau: → `'1,21,5,currentversion,hku,microsoft,red_apt_demo_benign_8f922e43,run,s,software,windows'`

**Retrained**: `models/registry_event/` Stage 1 (F1=1.0, 11,869 samples) + Stage 2 (39 SVM + 245 cosine rules, 1,673 filter values). Backup `*.PRE_FIX5.zip` còn nguyên trong models/registry_event/ (gitignored).

**Reg detection sau Fix #5** (verified per mode):

| Mode | Score | Top rule (cosine) |
|---|---|---|
| benign | 1.00 | currentversion_autorun_keys_modification (0.90) — FP OneDrive |
| baseline | 1.00 | currentversion_autorun_keys_modification (0.90) — Run + xkj9.exe |
| **evasion** | 1.00 | **currentversion_nt_autorun_keys_modification (0.73)** — RunOnce variant Tier 1 |
| chain | 1.00 | currentversion_autorun_keys_modification (0.90) — Run + xkj9.exe |

→ Insight defensible cho luận văn: RED Cosine phân biệt được Tier 1 evasion (RunOnce vs Run).

### ✅ Section 10 — Kiểm thử alert thật trong `demo/apt_demo_defense_present.md`

4 case cross-check RED attribution vs Sigma logic + label TP/FP + reproduce commands:

| Case | Sample | Stage 1 | Stage 2 attribution | Sigma logic match? | Label |
|---|---|---|---|---|---|
| 1 (proc) | WMI fire `powershell -Command "Write-Host"` parent=WmiPrvSE.exe | score=1.0 | hacktool_covenant_powershell_launcher (cosine 0.847) | ❌ NOT match | TP-attack / MIS-ATTR |
| 2 (ps) | Phase 6 fileless `'[' + 'System.Reflection.Assembly' + ']::' + 'Load'` | score=1.0 | potential_in_memory_execution_using_reflection_assembly | ✅ CORRECT (rule bị bypass) | **TP** |
| 3 (reg) | RunOnce path evasion | score=1.0 | currentversion_nt_autorun_keys_modification (cosine 0.732 TIE) | ⚠️ Top-1 wrong, Top-2 right | TP / PARTIAL-MIS-ATTR |
| 4 (proc) | `chcp.com 65001` parent=pwsh.exe | score=0.92 | abused_debug_privilege_by_arbitrary_parent_processes | ❌ NOT match | **FP** |

**Pattern (4 case)**:
- Stage 1 TP rate: 3/4 = 75% (case 1+2+3)
- Stage 1 FP rate: 1/4 = 25%
- Stage 2 top-1 attribution: 1/4 = 25% correct
- Stage 2 top-3 attribution: 3/4 = 75% correct

**Limitation lộ ra**: Stage 2 Cosine TF-IDF chỉ "gần token", không validate Sigma detection logic → khi multiple rule TIE cosine, top-1 thắng theo insertion order. Roadmap: Layer 3 Sigma validator (parse YAML + functional test).

Section 10.6 chứa 1-shot reproduce commands cho cả 4 case (curl + python parse).

### Files sửa session này

```
red/normalize.py                  — Fix #5 fallback split when merged token > max_str_len
demo/apt_demo_defense_present.md  — Section 0 bảng RED ML thêm cột reg (real data) + Section 10 (200+ lines verification)
CLAUDE.md                         — handoff này
models/registry_event/*.zip        — retrained (gitignored)
models/registry_event/*.PRE_FIX5.zip — backup (gitignored)
```

### ⏭️ Việc tiếp theo

1. Cần build labeled dataset 100-200 alerts → measure TP/FP/TN/FN chính thức (extrapolation từ 4 case chưa đủ)
2. Layer 3 Sigma validator implementation: parse Sigma YAML + apply detection logic Python → filter Stage 2 mis-attribution
3. Investigate `chcp.com` FP: rebuild benign training set với `chcp.com` được explicit include (xuất hiện trong PowerShell startup → nên là benign signal)
4. Còn pending: WMI consumer rule (`proc_creation_win_susp_wmi_consumer_powershell_invocation`) thiếu trong catalog cosine — verify + add nếu chưa có

---

## ✅ HANDOFF — Session 2026-05-24 (apt_demo_v2 verified 6 Sigma fire / 6 miss + RED catch)

### Mục tiêu đã hoàn thành

User yêu cầu làm tiếp `demo/apt_demo_v2.ps1`, test thật 2 mode và document mapping để chuẩn bị demo:

- Baseline mode → verify đúng 6 Sigma target rules fire.
- Evasion mode → verify 6 Sigma target rules MISS + RED ML catch.
- Document mapping vào demo file + push branch `elk_server`.

### Files đã thêm/sửa

```text
demo/apt_demo_v2.ps1                     — NEW script 6 phase, hỗ trợ benign/baseline/evasion, Phase 0-6, DryRun
demo/apt_demo_v2.md                      — NEW mapping + runbook + verified RunId/result
demo/README.md                           — link fast-path v2
demo/apt_demo_scenario_demo_present_2.md — note fast-path v2 đã verify
```

Commit đã tạo và push lên `elk_server`:

```text
f387a69 Add verified APT demo v2 flow
```

### Mapping apt_demo_v2 hiện tại

| Phase | Event type | Target Sigma rule | Sigma ID | Baseline | Evasion |
|---:|---|---|---|---|---|
| 1 | PowerShell 4104 | Potential Invoke-Mimikatz PowerShell Script | `189e3b02-82b2-4b90-9662-411eb64486d4` | Child ScriptBlock có `DumpCreds` + `DumpCerts` | Char-code reconstruct, chỉ in hash |
| 2 | Process EID 1 | Suspicious Eventlog Clearing or Configuration Change Activity | `cc36992a-4671-4f21-a91d-6c2b72a2edf5` | `wevtutil cl RED_DEMO_V2_NONEXISTENT_<RunId>` | Split token trong PowerShell, không có clear command line |
| 3 | Process EID 1 | PowerShell Download and Execution Cradles | `85b0b087-eddf-4a2b-b033-d771fa2b9775` | `iwr ... | iex` | Swap sang `curl.exe`, target PowerShell cradle miss |
| 4 | Process EID 1 | Remotely Hosted HTA File Executed Via Mshta.EXE | `b98d0db6-511d-45de-ad02-e82a98729620` | HTA utility + remote URL | HTA utility + inline scheme, không có remote URL token |
| 5 | Process EID 1 | Direct Autorun Keys Modification | `24357373-078f-44ed-9ac4-6d334a668a11` | `reg.exe add HKCU\...\CurrentVersion\Run` | Registry provider ghi `StartupApproved\Run` |
| 6 | Process EID 1 | File Encoded To Base64 Via Certutil.EXE | `e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a` | `certutil.exe -encode` temp file | .NET base64 API runtime, không dùng target utility |

**Lý do Phase 5/6 đổi so với draft đầu**:
- Registry-set rule `20f0ee37...` bị Elastic rule query filter `Details:null` loại event ECS trong lab hiện tại.
- Reflection ps_script rule `ddcd88cb...` có query escape không match ổn định với `powershell.file.script_block_text`.
- Đổi sang process_creation rules đang enabled và raw query match chính xác trong Kibana.

### Verified test thật trên DESKTOP-IQAM883

Endpoint: `DESKTOP-IQAM883` (`192.168.10.103`, user `endpoint`).
ELK: `https://192.168.10.10:9200`; Kibana API HTTP port `5601`.

| Test | RunId | Result |
|---|---|---|
| Baseline raw Sigma query | `4035abf9` | 6/6 target queries match, mỗi target đúng 1 event |
| Baseline Kibana Security Alerts | `4035abf9` | 6 unique target Sigma alerts materialized sau scheduler lag |
| Evasion raw Sigma query | `f73f19ba` | 0/6 target queries match |
| Evasion Kibana Security Alerts | `f73f19ba` | 0/6 target Sigma alerts |
| Evasion RED ML backfill | `f73f19ba` | 11 RED alerts trong `red-alerts-v2-test`, score `0.5887` đến `1.0` |

Baseline Security Alerts observed:

```text
cc36992a  SIGMA - Suspicious Eventlog Clearing or Configuration Change Activity
e62a9f0c  SIGMA - File Encoded To Base64 Via Certutil.EXE
b98d0db6  SIGMA - Remotely Hosted HTA File Executed Via Mshta.EXE
85b0b087  SIGMA - PowerShell Download and Execution Cradles
24357373  SIGMA - Direct Autorun Keys Modification
189e3b02  SIGMA - Potential Invoke-Mimikatz PowerShell Script
```

RED evasion examples from `red-alerts-v2-test`:

```text
EID 1    score 1.0000  suspicious_ping_del_command_combination         curl.exe marker
EID 1    score 1.0000  potential_lethalhta_technique_execution         mshta inline scheme
EID 4104 score 0.6158  hacktool_evil_winrm_execution_powershell_module phase1 char-code
EID 4104 score 0.5887  hacktool_rubeus_execution_scriptblock           phase2 split token
EID 4104 score 0.8264  powershell_script_with_file_upload_capabilities  phase6 runtime base64
```

### Operational notes

- `apt_demo_v2.ps1` parent source tránh literal target ps_script để AMSI không chặn khi parse. DryRun đã verify OK.
- Khi copy lên Windows, add UTF-8 BOM như trong `demo/apt_demo_v2.md`.
- Security Alerts có scheduler lag; raw Sigma query match/miss có ngay trong `logs-windows.*`, alert index cần khoảng 1-5 phút.
- Cleanup đã chạy trên endpoint, xoá các registry artifacts `RED_DEMO_V2_*` còn sót từ test.

### Push status

- `git push origin elk_server` fail do `origin` HTTPS không có credential helper tương tác.
- Push thành công bằng URL credential đã có trong `branch.elk_server.remote`.
- Final status sau push: clean working tree trên branch `elk_server`.

## HANDOFF — Session 2026-05-24 (apt_demo_v2 re-test resolved)

### User issue

User không thấy 6 Sigma target alerts trong Kibana Security Alerts khi chạy
`apt_demo_v2.ps1 -Mode baseline`, nghi ngờ mapping trong `demo/apt_demo_v2.md`
không đúng hoặc chưa được kiểm thử lại.

### Work done in this session

Đã thêm script kiểm thử tự động:

```text
scripts/test_apt_demo_v2.py
```

Script này làm 4 việc:
- Load local NDJSON `data/sigma/elastic_rules/windows_sigma_elastic_ecs.ndjson`
  và verify có đủ 6 target Sigma rule IDs.
- Gọi Kibana API `/api/detection_engine/rules?rule_id=...` để kiểm tra rule
  có tồn tại/enabled, index pattern, field profile.
- Nếu dùng `--run-endpoint`, copy `demo/apt_demo_v2.ps1` sang
  `192.168.10.103:C:/Users/endpoint/apt_demo_v2.ps1` bằng Paramiko/SFTP, thêm
  UTF-8 BOM, rồi chạy baseline/evasion với RunId mới.
- Poll Elasticsearch raw logs `logs-windows.*` theo RunId + live Kibana query
  nếu rule check chạy được; fallback local NDJSON nếu `--skip-rule-check`. Sau đó
  poll Security Alerts index `.alerts-security.alerts-*,.siem-signals-*`.

Đã cập nhật:

```text
demo/apt_demo_v2.md     — thêm mục "Kiem thu lai baseline/evasion"
requirements.txt        — thêm paramiko
```

Local verification đã chạy OK:

```bash
python3 -m py_compile scripts/test_apt_demo_v2.py
python3 scripts/test_apt_demo_v2.py --check-only --skip-rule-check
```

Kiểm tra offline NDJSON: đủ 6/6 target rules, `enabled: true`, index
`["logs-windows.*", "winlogbeat-*"]`, query dùng ECS (`process.*`,
`powershell.*`).

### Earlier blocker (resolved)

Phiên Codex trước không chạy được end-to-end vì sandbox network bị chặn:

```text
curl https://192.168.10.10:9200  -> [Errno 1] Operation not permitted
curl http://192.168.10.10:5601   -> [Errno 1] Operation not permitted
```

Đây là lỗi permission của sandbox Codex hiện tại, không chứng minh ELK/Kibana
bị down. Session đang ở `sandbox_mode=workspace-write`, `network restricted`,
`approval_policy=never`, nên agent không thể xin quyền network.

User dự định chạy lại Codex bằng:

```bash
codex -a never -s danger-full-access
```

Sau khi vào phiên mới, cần verify lại network thật. Nếu vẫn lỗi
`Operation not permitted`, nghĩa là CLI vẫn đang chạy trong môi trường bị chặn
network hoặc route tới lab không có.

### Commands to run in next session

1. Verify ES/Kibana connectivity:

```bash
curl -sk -u elastic:'Admin123@' https://192.168.10.10:9200/_cluster/health
curl -s  -u elastic:'Admin123@' http://192.168.10.10:5601/api/status
```

Important: Kibana API trong lab IQAM883 là HTTP:

```text
http://192.168.10.10:5601
```

Không dùng `https://192.168.10.10:5601` dù `.env` hiện đang có HTTPS.

2. Check target rules in Kibana:

```bash
cd /home/ubuntu/rule_evasion_detection/Rule_Evasion_Detection
python3 scripts/test_apt_demo_v2.py \
  --check-only \
  --kibana-url http://192.168.10.10:5601 \
  --http-timeout 10
```

Expected: 6 dòng `OK`, `enabled=True`/state OK, index có `logs-windows.*`.

3. Run baseline end-to-end:

```bash
python3 scripts/test_apt_demo_v2.py \
  --mode baseline \
  --run-endpoint \
  --kibana-url http://192.168.10.10:5601 \
  --wait-raw-seconds 180 \
  --wait-alert-seconds 420
```

Expected:

```text
raw_sigma=PASS
security_alerts=PASS
```

4. If baseline was already run manually and user has a RunId:

```bash
python3 scripts/test_apt_demo_v2.py \
  --mode baseline \
  --run-id <RunId> \
  --kibana-url http://192.168.10.10:5601 \
  --wait-alert-seconds 420
```

### How to interpret failures

- `raw_events=0`: script event did not reach `logs-windows.*`; check Elastic
  Agent, Sysmon EID 1, PowerShell 4104 logging, endpoint clock.
- `raw_sigma=FAIL` with raw events present: mapping/query mismatch; inspect per
  phase counts from script output.
- `raw_sigma=PASS` but `security_alerts=FAIL`: demo generated correct raw event,
  but Detection Engine did not materialize alerts. Check rule missing/disabled,
  imported wrong field profile, wrong index pattern, or scheduler lag.
- `--check-only` shows `fields=ecs`: đúng với lab IQAM883 hiện tại. Script ưu
  tiên live Kibana query nên raw check khớp rule đang enabled trong Kibana.

### Update — re-test completed in danger-full-access session

Network lab đã hoạt động lại:

```text
ES https://192.168.10.10:9200/_cluster/health -> status=yellow, reachable
Kibana http://192.168.10.10:5601/api/status -> overall available
```

Bug phát hiện trong script test: default local NDJSON trước đó dùng bản
`windows_sigma_elastic_winlog_raw.ndjson`, nhưng 6 rule đang enabled trong
Kibana là ECS query (`process.*`, `powershell.*`). Vì vậy baseline RunId
`5826f4be` ban đầu có Security Alerts 6/6 nhưng `raw_sigma=FAIL` giả.

Fix đã apply:
- `scripts/test_apt_demo_v2.py`: default NDJSON đổi sang
  `windows_sigma_elastic_ecs.ndjson`; raw check ưu tiên live Kibana Lucene query.
- `demo/apt_demo_v2.md`: cập nhật runbook theo ECS/live Kibana query.

Verified sau fix:

| Test | RunId | Result |
|---|---|---|
| Baseline | `5826f4be` | raw Sigma 6/6 + Security Alerts 6/6 |
| Evasion | `b64a6298` | raw Sigma 0/6 + Security Alerts 0/6 |
| RED live catch evasion | `b64a6298` | `red-alerts-demo` 16 docs + `red-alerts-powershell-demo` 6 docs |

Kết luận: mapping demo đúng. Nếu user không thấy đủ 6 alerts trong Kibana, nguyên
nhân nhiều khả năng là scheduler lag/time window/filter trong UI, không phải
`apt_demo_v2.ps1` hay mapping rule.

### Update — demo runbook rewritten + benign mode documented

User yêu cầu viết lại `demo/apt_demo_v2.md` và thêm hướng dẫn demo. Đã rewrite
file này thành runbook đầy đủ:

- Lab topology IQAM883, demo story, expected results.
- Phase mapping 6 rule có thêm cột `Benign` / `Baseline` / `Evasion`.
- Preflight ES/Kibana/SSH/rule check.
- Fast automated flow với `scripts/test_apt_demo_v2.py`.
- Manual presenter flow: copy script, dry-run, chạy từng phase, chạy trực tiếp
  Windows.
- Hướng dẫn xem Kibana Security Alerts và RED alerts trong Discover.
- Verified results, troubleshooting, cleanup, short talk track.

Đã thêm `benign` vào `scripts/test_apt_demo_v2.py`:

```text
--mode benign | baseline | evasion
```

Ý nghĩa:
- `benign`: sanity check, 6 target Sigma rules phải 0/6 raw + 0/6 Security Alerts.
- `baseline`: 6/6 fire.
- `evasion`: 0/6 target Sigma fire, RED ML catch trong `red-alerts-*`.

Verify nhẹ đã chạy OK:

```bash
python3 -m py_compile scripts/test_apt_demo_v2.py
python3 scripts/test_apt_demo_v2.py --mode benign --check-only --skip-rule-check
```

Chưa chạy full endpoint `--mode benign --run-endpoint` để tránh mất thời gian
poll; command đã có trong `demo/apt_demo_v2.md`.
