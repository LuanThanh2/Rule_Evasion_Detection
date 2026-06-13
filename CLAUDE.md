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
- Output: score ∈ [0,1] sau MCC scaling, threshold sweep → P/R/F1/MCC

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
  run_stage1.py       # Gộp train + validate + evaluate (khuyến nghị)
  train.py            # Stage 1 training (SVM solo or Ensemble)
  validate.py         # Transform + decision_function → df_values
  evaluate.py         # MCC scale + threshold sweep → eval result
  train_attribution.py # Stage 2: CosineRuleAttributor + per-rule SVM baseline
  eval_attribution.py  # Stage 2 eval: production --method cosine; baseline svm|hybrid
  generate_evasions.py # Tạo evasion variants từ match events
  run_pipeline.py     # Chạy toàn bộ pipeline (Stage 1+2) qua config
  diagnose_stage1.py  # Analyze Stage 1 model, token analysis, real ELK events
  # ELK Integration
  elk_export.py       # Export events từ Elasticsearch → JSONL
  detect_batch.py     # Batch detection: JSONL → alerts JSONL (offline verify)
  detect_live.py      # Live daemon: poll ES → Stage1+2 → index alerts về ES
  push_alerts.py      # Bulk index alerts.jsonl → Elasticsearch (⚠️ xem HTTPS issue bên dưới)
  test_apt_demo_v2.py # Tự động verify baseline/evasion/benign vs Kibana + Sigma
  convert_sigma_to_elastic.py  # Sigma YAML → Elastic NDJSON + Kibana import
  # Data converters
  hayabusa_to_matches.py / lmd_to_benign.py / mpsd_to_benign.py / secrepo_to_benign.py

config/               # YAML config per event type
  process_creation.yaml / registry_event.yaml / powershell.yaml / proxy_web.yaml

agent/                # AI Agent SOC Triage
  orchestrator.py / _loop.py / llm.py / schemas.py / tools.py
  vr_client.py / vr_client_map.yaml / es_io.py / daemon.py
  agents/  (8 agents) / prompts/  (8 system prompts)

demo/                 # Demo scripts + runbooks
  apt_demo_v2.ps1     # APT demo v2 — 6 phases, baseline/evasion/benign modes
  apt_demo_v2.md      # Runbook đầy đủ cho IQAM883 (ĐỌC ĐÂY TRƯỚC KHI DEMO)
  apt_demo_defense_present.md  # Defense demo + Section 10 alert verification
  apt_demo_scenario_demo_present_2.md  # Full guide IQAM883 lab
  RED_RULE_MAP.md / QA_PREP.md / SLIDES_OUTLINE.md

data/                 # Dữ liệu thực (không commit)
  sigma/events_hayabusa/ sigma/evasions/ sigma/rules/ benign/
  sigma/elastic_rules/windows_sigma_elastic_ecs.ndjson   # ECS profile (dùng cho IQAM883)
  sigma/elastic_rules/windows_sigma_elastic_winlog_raw.ndjson

models/               # Output .zip từ train (gitignored)
```

## Key design decisions

### Normalization → TF-IDF (Fix #2 + Fix #5 đã apply)
- `Normalizer.normalize()`: lowercase → tokenize `[\w\\/:.\-]+` → replace separators `\_` → filter hex/long → sort → join ","
- Path ngắn: `C:\Windows\sshd.exe` → 1 token `c_windows_sshd_exe`
- Path dài > `max_str_len=60`: fallback split lại trên separators thành sub-tokens (Fix #5 — giải quyết registry.path dài bị filter empty)
- `comma_tokenizer`: split on "," — **không phải** whitespace splitter mặc định của sklearn
- TF-IDF dùng smoothed formula: `log((1+N)/(1+DF(t))) + 1`

### MCC Scaler
- Tạo trong `train.py`, lưu trong `train_rslt_*.zip`; áp dụng trong `evaluate.py`: shift → MinMaxScale → clip[0,1]

### EnsembleClassifier (models.py)
- Thành viên: SVM (GridSearch, 20 C values) + LR (GridSearch, 10 C values) + ComplementNB
- Z-score normalize mỗi thành viên; `.decision_function(X)` → weighted average
- GridSearchCV parallel `n_jobs=3`, `random_state=42` → reproducible

### CosineRuleAttributor (attribution.py)
- Shared TF-IDF vectorizer fitted trên UNION filter values của tất cả rules
- Score = max(cosine_similarity(evasion_vec, rule_matrix)); `reciprocal_rank_fusion()` k=60

### Config: benign_train vs benign_valid
- **Production**: `benign_valid` = `benign_train` (100% benign → F1=1.0 validation — deployment setup)
- **Debug/Thesis 80/20**: đổi `benign_valid` → `benign_train_split_val.txt` (20% holdout)

### Multi-field search_fields (Fix #1 đã apply)
- `process_creation`: search_fields gồm `CommandLine`, `Image`, `ParentImage`, `ParentCommandLine`, `IntegrityLevel`, `User`, `OriginalFileName`, `CurrentDirectory`
- `registry_event`: thêm `Image`, `User`, `EventType`
- Cần thiết để catch rule check `ParentImage` (e.g., SSH-based parent-child rules)

### Stage 2 extract_filter_values (Fix #4 đã apply)
- Case-insensitive field match, bỏ `_` → `parent_image` = `ParentImage`
- Auto-extract `keywords:` section + list of plain strings; recursive nested dict

### Elastic Agent ECS vs Winlogbeat field mapping
| Sysmon field | Winlogbeat path | Elastic Agent ECS path |
|---|---|---|
| ScriptBlockText | `winlog.event_data.ScriptBlockText` | `powershell.file.script_block_text` |
| TargetObject | `winlog.event_data.TargetObject` | `registry.path` |
| Details (registry) | `winlog.event_data.Details` | `registry.data.strings` (**LIST** → join!) |
| CommandLine | `winlog.event_data.CommandLine` | `process.command_line` |
| Image | `winlog.event_data.Image` | `process.executable` |
| ParentImage | `winlog.event_data.ParentImage` | `process.parent.executable` |

Config `event_field_map` trong YAML phải list cả 2 path (ECS primary, Winlogbeat fallback).

### Velociraptor VQL pattern (Critical — bug đã fix)
`LET _wait <= SELECT * FROM watch_monitoring(...)` là lazy evaluation — KHÔNG dùng. Pattern chuẩn:
```sql
LET flow <= collect_client(client_id=ClientId, artifacts=['X'], timeout=60)
SELECT ... FROM foreach(
    row={SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
         WHERE FlowId = flow.flow_id LIMIT 1},
    query={SELECT ... FROM source(client_id=ClientId, flow_id=flow.flow_id, artifact='X')}
)
```
Artifacts: `Windows.System.Pslist`, `Windows.Registry.NTUser`, `Windows.Network.NetstatEnriched`. VQL không hỗ trợ subquery `IN { SELECT ... }` → filter trong Python.

## Commands hay dùng

> **Activate venv trước**: `source ~/venvs/rule_evasion_env/bin/activate`

```bash
# Smoke test (2-3 phút — xác nhận data/config OK)
python3 scripts/train.py --config config/process_creation.yaml --max-benign-samples 1000

# Stage 1 — Production (Ensemble SVM+LR+CNB)
python3 scripts/run_stage1.py --config config/process_creation.yaml

# Stage 1 cho cả 3 event types
for cfg in process_creation registry_event powershell; do
    python3 scripts/run_stage1.py --config config/$cfg.yaml
done

# Stage 2 — attribution
python3 scripts/train_attribution.py --config config/process_creation.yaml
python3 scripts/eval_attribution.py --config config/process_creation.yaml --method cosine

# Stage 3 — Layer-3 Sigma-logic validator (Windows)
# Đánh giá offline trên match events EVTX (ground-truth fired thật, không dùng evasion-sinh-từ-match)
python3 scripts/stage3_layer3_windows.py                              # tất cả 3 event type
python3 scripts/stage3_layer3_windows.py --event-type process_creation  # chỉ proc
# Output: reports/windows/layer3_result.md + layer3_result.json + *_details.jsonl

# Verify model rule counts
python3 -c "
from red.persist import load_result
for n,p in [('proc','models/process_creation/train_rslt_attr_ensemble.zip'),
            ('ps','models/powershell/train_rslt_attr_ensemble.zip'),
            ('reg','models/registry_event/train_rslt_attr_ensemble.zip')]:
    r=load_result(p)
    print(f'{n}: SVM={len(r[\"rule_models\"])}, Cosine={len(r[\"cosine_attributor\"].rule_filter_matrices)}')
"

# ELK — Live daemon (index mới cho demo)
source .env
SINCE=$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)
python3 scripts/detect_live.py --config config/process_creation.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-demo --threshold 0.0 --method cosine --interval 60 --since "$SINCE"

# ELK — Batch detection
python3 scripts/elk_export.py --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" --since 15m \
  --out /tmp/events.jsonl
python3 scripts/detect_batch.py --config config/process_creation.yaml \
  --events /tmp/events.jsonl --threshold 0.0 --method cosine --out /tmp/alerts.jsonl

# Demo v2 — verify (check-only, không cần network)
python3 scripts/test_apt_demo_v2.py --check-only --skip-rule-check
# Demo v2 — run full (cần lab network)
python3 scripts/test_apt_demo_v2.py --mode baseline --run-endpoint \
  --kibana-url http://192.168.10.10:5601 --wait-raw-seconds 180 --wait-alert-seconds 420

# Sigma → Kibana import (IQAM883)
python3 scripts/convert_sigma_to_elastic.py \
  --index-pattern "logs-windows.*" --field-profile winlog-raw \
  --out data/sigma/elastic_rules/windows_sigma_elastic_winlog_raw.ndjson \
  --import-to-kibana --kibana-url http://192.168.10.10:5601 \
  --kibana-user elastic --kibana-password 'Admin123@' \
  --import-chunk-size 200 --import-timeout 300

# Regenerate Velociraptor api.config.yaml (nếu cert hết hạn)
python3 - <<'EOF'
import yaml, os, tempfile, subprocess
with open('velociraptor/server.config.yaml') as f: cfg = yaml.safe_load(f)
tmpdir = tempfile.mkdtemp()
os.makedirs(f"{tmpdir}/users", exist_ok=True)
cfg['Datastore']['location'] = tmpdir
tmp_cfg = f"{tmpdir}/server.config.yaml"
with open(tmp_cfg, 'w') as f: yaml.dump(cfg, f)
subprocess.run(['/usr/local/bin/velociraptor', '--config', tmp_cfg,
                'config', 'api_client', '--name', 'admin',
                '--role', 'administrator', 'velociraptor/api.config.yaml'])
EOF
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
scikit-learn, numpy, pyyaml, luqum, tqdm, matplotlib, seaborn, paramiko
Optional: cuml (NVIDIA GPU), sklearnex (Intel CPU acceleration)
```

---

## Roadmap KLTN

Đề tài: *"Xây dựng hệ thống phát hiện xâm nhập và hành vi né tránh luật dựa trên mô hình học máy và AI-Agent"*

### Trạng thái các phase

| Phase | Status | Ghi chú |
|---|---|---|
| **A — Stage 1 Ensemble** | ✅ Done | Ensemble F1=1.0; SVM raw recall 94.3% vs Ensemble 100% → bằng chứng CNB cứu 17 FN |
| **B — Stage 2 Attribution** | ✅ process_creation; ⚠️ ps/reg partial | Cosine top-1=**38.2%** (fired/trung thực) hay 68.8% (evasion-inflated); Layer-3 nâng lên 79.4% |
| **C — AI Agent SOC** | ✅ Done (8 agents + Forensic + real VR) | ~98s mock / ~210s real VR; $0.020/alert; IQAM883 verified |
| **D — Adversarial Robustness** | ❌ Chưa làm | LLM-based evasion, concept drift |
| **E — ELK Integration** | ✅ Done | detect_live + 1,620 Sigma rules Kibana + daemon |
| **F — Explainability** | ❌ Chưa làm | SHAP/LIME, counterfactual |
| **G — Statistical Rigor** | ❌ Chưa làm | Bootstrap CI, Wilcoxon, McNemar |

### Stage 2 Attribution results (process_creation)

⚠️ Số 68.8% là **lạm phát** (evasion sinh từ match → chia sẻ token sẵn). Số trung thực đo trên **fired ground-truth** (match events EVTX, Hayabusa xác nhận):

| Ground-truth | Method | Top-1 | Top-3 | Top-5 | Top-10 |
|---|---|---|---|---|---|
| evasion-inflated (cũ) | Cosine | 68.8% | 92.6% | 97.3% | 99.7% |
| **fired/trung thực (mới)** | Cosine | **38.2%** | 64.7% | 75.0% | 79.4% |
| **fired/trung thực (mới)** | **+Layer-3 @top-10** | **79.4%** | — | — | — |
| fired | SVM (cũ, inflated) | 23.5% | 53.7% | 73.2% | 87.2% |

→ Cosine fired top-1 thấp hơn tưởng vì catalog Windows lớn (1,119 rule) → nhiều rule họ hàng. Layer-3 cứu 41pp (41.2% sample có gt ∈ top2–10), nâng top-1 38.2%→79.4%.
Script: `scripts/stage3_layer3_windows.py` | Output: `reports/windows/layer3_result.md`

### AI Agent architecture (8 agents hierarchical)

```
Supervisor → Triage → Forensic (VR) → parallel(Hunt, RED Analyst, MITRE) → Response → Report → ES
```

| Agent | Tools | Vai trò |
|---|---|---|
| Supervisor | (none) | Router: skip_fp / quick / full |
| Triage | query_es_history, get_process_tree, lookup_mitre | Severity + FP filter |
| **Forensic** | vr_process_tree_deep, vr_file_artifacts, vr_network_connections | Host-level evidence từ Velociraptor |
| Hunt | get_network_connections, search_threat_intel | Timeline + IOCs |
| **RED Analyst** | get_sigma_rule_text, get_evasion_tokens | Giải thích WHY là evasion |
| MITRE | lookup_mitre | TTP chain |
| **Response** | get_sigma_rule_text, suggest_containment, send_telegram | Sigma patch + containment |
| Report | (none) | Vietnamese markdown report |

LLM: DeepSeek-V3 (OpenAI-compat API), key trong `.env`.

### Đóng góp khoa học (claims cho luận văn)

⚠️ **KHÔNG claim**: "Auto-Sigma patch giải quyết evasion vĩnh viễn".
✅ **Claim đúng**: Multi-layer adversarial-aware detection với AI orchestration.

1. **ML generalize over evasion variants** — Ensemble F1=1.0 vs SVM 0.97 (raw); CNB cứu 17 FN
2. **Cosine attribution accuracy** — Top-1 38.2% (fired/trung thực); Layer-3 Sigma-logic nâng lên 79.4% (+41pp, đối xứng kiến trúc Linux)
3. **Multi-Agent SOC automation** — 8 agents, ~98s/alert vs 5-15 phút analyst, $0.020 vs $25-50
4. **Evidence-grounded Sigma patch** — Velociraptor bằng chứng cứng → giảm hallucination (measurable: `inconclusive` khi PID không tìm thấy)
5. **Explainable ML** (RED Analyst) — LLM dịch ML score → human reasoning; không có trong Elastic AI / Splunk / Sentinel
6. **Vietnamese SOC automation** — báo cáo tiếng Việt, VNCERT/NĐ 13/2023

**Cần đo cho luận văn**: time-to-decision, accuracy vs ground truth (cần 100-200 labeled alerts), hallucination rate, FP filter coverage (~60-80% expected), Sigma patch YAML validity.

---

## Trạng thái hiện tại (2026-05-24)

### Lab environment (IQAM883)

| Thành phần | Giá trị |
|---|---|
| Windows VM | DESKTOP-IQAM883 (192.168.10.103, user `endpoint`) |
| ELK | **https**://192.168.10.10:9200 (`ES_VERIFY_SSL=false` trong .env) |
| Kibana | **http**://192.168.10.10:5601 (HTTP! không phải HTTPS) |
| Agent trên Windows | Elastic Agent v9.4.1 (ECS fields) |
| SSH từ Ubuntu | `paramiko` (Python) |
| Velociraptor gRPC | `127.0.0.1:8001`, GUI `:8889` (admin/tzxr) |
| VR client_id IQAM883 | `C.cd6bfbb23aee7979` (trong `agent/vr_client_map.yaml`) |
| Datastream thật | `logs-windows.*` (không phải `logs-winlog.*`) |
| Branch git | `elk_server` |

**NTP**: Windows VM đã sync, lệch <3s so với Ubuntu UTC. Nếu skew lại: `w32tm /resync /force` trên Windows.

**Elastic Agent OTel freeze**: nếu events ngừng đến ES (service RUNNING nhưng log dừng update) → `sc stop "Elastic Agent"` rồi `sc start` (restart không đủ).

### Model state hiện tại (sau Fix #1/#2/#4/#5)

| Event type | Stage 1 | Stage 2 SVM rules | Stage 2 Cosine rules |
|---|---|---|---|
| process_creation | F1=1.0 | 200 | 1,129 |
| powershell | F1=1.0 | 25 | 208 |
| registry_event | F1=1.0 | 39 | 245 |
| **TỔNG** | | **264** | **1,582** |

Models backup: `*.PRE_FIX124.zip` và `*.PRE_FIX5.zip` trong `models/registry_event/` (gitignored).

### apt_demo_v2 — Phase mapping (verified IQAM883)

| Phase | Event | Target Sigma rule | Sigma ID | Evasion technique |
|---:|---|---|---|---|
| 1 | PS 4104 | Potential Invoke-Mimikatz | `189e3b02` | Char-code reconstruct |
| 2 | EID 1 | Suspicious Eventlog Clearing | `cc36992a` | Split token trong PS |
| 3 | EID 1 | PowerShell Download Cradles | `85b0b087` | Swap sang `curl.exe` |
| 4 | EID 1 | Remotely Hosted HTA via Mshta | `b98d0db6` | Inline scheme thay remote URL |
| 5 | EID 1 | Direct Autorun Keys Modification | `24357373` | Registry provider → `StartupApproved\Run` |
| 6 | EID 1 | File Encoded via Certutil | `e62a9f0c` | .NET base64 API runtime |

**Verified** (RunId `4035abf9` baseline: 6/6 Sigma fire; RunId `f73f19ba` evasion: 0/6 Sigma + 11 RED alerts).

Kibana Security Alerts dùng **ECS** queries (`process.*`, `powershell.*`) — NDJSON đúng: `windows_sigma_elastic_ecs.ndjson`. Kibana có **1,645 rules** (1,620 import + 25 sẵn).

### Verified 4-case alert analysis (từ `demo/apt_demo_defense_present.md` Section 10)

| Case | Stage 1 | Stage 2 top-1 | Label |
|---|---|---|---|
| WMI → PS `Write-Host` | score=1.0 | hacktool_covenant (cosine 0.847) | TP-attack / MIS-ATTR |
| Fileless Assembly Load | score=1.0 | potential_in_memory_reflection ✅ | **TP** correct |
| RunOnce path evasion | score=1.0 | nt_autorun (cosine 0.732 TIE) | TP / PARTIAL-MIS-ATTR |
| `chcp.com 65001` | score=0.92 | abused_debug_privilege | **FP** |

Stage 2 Limitation: TF-IDF chỉ "gần token", không validate Sigma detection logic → TIE thắng theo insertion order. Roadmap: Layer 3 Sigma validator.

### Issues chưa fix trong code

- **`push_alerts.py` HTTPS**: không có `verify=False` → crash trên self-signed ELK. Workaround: dùng `curl` bulk NDJSON (xem Section 6.3 trong `apt_demo_defense_present.md`). Fix đúng: thêm `--no-verify-ssl` flag đọc `ES_VERIFY_SSL` env.
- **RED Analyst max_iter**: vẫn có thể hit ceiling=12 với PowerShell alerts phức tạp. Tăng `AGENT_MAX_ITERATIONS` trong `.env` hoặc tối ưu prompt.
- **`chcp.com` FP**: xuất hiện trong PowerShell startup → nên là benign signal. Cần rebuild benign set explicit include.

### ⏭️ Việc tiếp theo

1. **Build labeled dataset 100-200 alerts** → measure TP/FP/TN/FN chính thức cho luận văn
2. **Layer 3 Sigma validator**: parse Sigma YAML + apply detection logic → filter Stage 2 mis-attribution
3. **Stage 2 cho powershell/proxy_web**: chạy `train_attribution.py` + `eval_attribution.py` → hoàn thiện bảng top-k
4. **Fix `push_alerts.py` HTTPS** (xem Issues bên trên)
5. **Merge elk_server → main** khi sẵn sàng

### Velociraptor lab setup

- Server: `/usr/local/bin/velociraptor`, systemd `velociraptor_server.service`
- Config (root): `/etc/velociraptor/server.config.yaml`; project api.config: `velociraptor/api.config.yaml`
- Datastore: `/var/lib/velociraptor` (owned by `velociraptor` user, 0750)
- API `name` field = Velociraptor GUI username (e.g., `admin`), NOT TLS hostname
- TLS hostname hardcoded `VelociraptorServer` (grpc ssl_target_name_override)
- Tìm client_id mới: `curl -sk -u "admin:tzxr" "https://127.0.0.1:8889/api/v1/SearchClients?query=all"`
- Real mode: `export VR_USE_REAL=1 VR_API_CONFIG=velociraptor/api.config.yaml`
