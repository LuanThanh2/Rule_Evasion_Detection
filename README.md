# Rule Evasion Detection (RED)

RED là hệ thống phát hiện hành vi né tránh luật Sigma trên Windows Event Logs.
Pipeline chính gồm:

- Stage 1: phát hiện event đáng ngờ bằng mô hình ML trên đặc trưng text.
- Stage 2: quy kết event đáng ngờ về Sigma rule có khả năng bị né.
- Phase C: AI Agent SOC Triage đọc alert RED, điều tra thêm bằng evidence và sinh báo cáo tiếng Việt.

Repo này phục vụ nghiên cứu, demo lab và thử nghiệm phòng thủ. Các script demo chỉ nên chạy trong môi trường kiểm thử có kiểm soát.

## Mục Lục

- [Tổng Quan](#tổng-quan)
- [Kết Quả Hiện Có](#kết-quả-hiện-có)
- [Yêu Cầu](#yêu-cầu)
- [Cài Đặt](#cài-đặt)
- [Cấu Trúc Repo](#cấu-trúc-repo)
- [Chạy Pipeline ML](#chạy-pipeline-ml)
- [ELK Integration](#elk-integration)
- [AI Agent SOC Triage](#ai-agent-soc-triage)
- [Demo Windows Lab](#demo-windows-lab)
- [Chuẩn Bị Dữ Liệu](#chuẩn-bị-dữ-liệu)
- [Config](#config)
- [Script Thường Dùng](#script-thường-dùng)
- [Troubleshooting](#troubleshooting)

## Tổng Quan

| Thành phần | Vai trò | Output chính |
|---|---|---|
| Stage 1 - Misuse Detection | Phân loại benign vs suspicious bằng SVM hoặc Ensemble SVM + Logistic Regression + ComplementNB | `detection_score` trong khoảng `[0, 1]` |
| Stage 2 - Rule Attribution | Xếp hạng Sigma rule gần nhất bằng per-rule SVM, cosine similarity hoặc hybrid RRF | `top_rules`, `top_rule_sigma_*` |
| ELK Integration | Đọc log từ Elasticsearch, chạy RED, ghi alert về index `red-alerts` | Alert dùng được trong Kibana |
| Phase C - AI Agent | Multi-agent triage, hunt, MITRE mapping, forensic, response và report | Document trong `ai-investigations` |

Điểm chính của RED:

- Chuẩn hóa command line, ScriptBlockText, registry path và URL thành token ổn định hơn trước các biến thể né rule.
- Stage 1 hỗ trợ EnsembleClassifier gồm SVM, Logistic Regression và Complement Naive Bayes.
- Stage 2 có `CosineRuleAttributor` dùng cùng không gian TF-IDF cho rule filter values, phù hợp khi mở rộng catalog Sigma.
- Alert được enrich metadata Sigma: filename, Sigma ID, title.
- AI Agent có 8 module: Supervisor, Triage, Forensic, Hunt, RED Analyst, MITRE, Response, Report.

## Kết Quả Hiện Có

Các số liệu dưới đây lấy từ các file `models/*/*_info.json` hiện có trong repo. Khi train lại, hãy ưu tiên số liệu mới trong chính các file output.

### Stage 1 - Misuse Detection

| Event type | Threshold | Precision | Recall | F1 | MCC | Ghi chú |
|---|---:|---:|---:|---:|---:|---|
| `process_creation` | 0.50 | 99.67% | 100.00% | 99.83% | 99.81% | `models/process_creation/eval_rslt_ensemble_f1_info.json` |
| `powershell` | 0.46 | 99.05% | 100.00% | 99.52% | 99.51% | optimal threshold; default 0.50 có precision 100.00%, recall 99.04% |
| `registry_event` | 0.50 | 100.00% | 100.00% | 100.00% | 100.00% | `models/registry_event/eval_rslt_ensemble_f1_info.json` |

### Stage 2 - Rule Attribution

| Event type | Method | Top-1 | Top-3 | Top-5 | File |
|---|---|---:|---:|---:|---|
| `process_creation` | cosine | 68.79% | 92.62% | 97.32% | `models/process_creation/eval_attr_cosine_attr_ensemble_info.json` |
| `powershell` | cosine | 84.62% | 100.00% | 100.00% | `models/powershell/eval_attr_cosine_attr_ensemble_info.json` |
| `registry_event` | cosine | 78.89% | 100.00% | 100.00% | `models/registry_event/eval_attr_cosine_attr_ensemble_info.json` |

Catalog cosine hiện có trong model attribution:

| Event type | Per-rule SVM rules | Cosine rules |
|---|---:|---:|
| `process_creation` | 200 | 1129 |
| `powershell` | 25 | 208 |
| `registry_event` | 23 | 242 |

## Yêu Cầu

- Python 3.10+.
- Linux/macOS cho pipeline train/evaluate. Repo hiện đang dùng đường dẫn kiểu Linux.
- Windows VM có Sysmon, PowerShell logging và Elastic Agent nếu chạy demo live.
- Elasticsearch/Kibana nếu dùng ELK integration hoặc AI Agent daemon.
- DeepSeek API key nếu dùng AI Agent.
- Tùy chọn: Velociraptor nếu muốn Forensic Agent lấy evidence thật từ host.

## Cài Đặt

```bash
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection

python3 -m venv ~/venvs/rule_evasion_env
source ~/venvs/rule_evasion_env/bin/activate

pip install -r requirements.txt
```

Tùy chọn tăng tốc:

```bash
# NVIDIA GPU, cần CUDA phù hợp
pip install cuml-cu12

# Intel CPU acceleration đã có trong requirements.txt
pip install scikit-learn-intelex
```

RED tự ưu tiên backend theo thứ tự: NVIDIA GPU, Intel oneDAL, scikit-learn CPU thường.

Nếu dùng AI Agent:

```bash
cp .env.example .env
nano .env
```

Các biến tối thiểu:

```text
DEEPSEEK_API_KEY=sk-your-deepseek-key
ES_HOST=https://192.168.10.10:9200      # ES có thể HTTPS — set ES_VERIFY_SSL=false nếu self-signed
ES_USER=elastic
ES_PASSWORD=your-es-password
ES_VERIFY_SSL=false                      # cho self-signed cert
ES_RED_INDEX=red-alerts*                 # wildcard match cả live + replay indices
ES_AI_INDEX=ai-investigations
AGENT_MAX_ITERATIONS=12                  # ceiling chung cho mọi ReAct agent
```

Lưu ý:
- Module `agent` tự load `.env` với `override=True` → giá trị trong `.env` thắng biến shell (fix 2026-05-23).
- `detect_live.py` không tự load `.env` và cũng không có option `--es-user` / `--es-password`; khi cần xác thực, hãy đặt credential trong `--es-host`, ví dụ `http://elastic:PASSWORD@10.10.20.100:9200`.
- Nếu shell có biến `ES_RED_INDEX` cũ (ví dụ `red-alerts`), `unset ES_RED_INDEX` trước khi chạy. Từ 2026-05-23 `agent/__init__.py` đã dùng `override=True` nên .env thắng, nhưng cẩn thận với script không qua module `agent`.

## Cấu Trúc Repo

```text
rule_evasion_detection/
├── agent/                 # Multi-agent SOC triage
├── config/                # YAML config cho từng event type
├── data/                  # Dữ liệu nhỏ hoặc placeholder trong repo
├── demo/                  # Script và tài liệu demo Windows lab
├── models/                # Model/result đã train
├── red/                   # Core RED: normalize, data, model, attribution, evaluate
├── scripts/               # CLI train/evaluate/ELK/data prep
├── .env.example           # Template cấu hình agent/ELK
├── requirements.txt
└── README.md
```

Phần lớn dataset và Sigma catalog được cấu hình ở `~/data/...`, không nằm trực tiếp trong repo.

## Chạy Pipeline ML

Luôn activate virtualenv trước:

```bash
source ~/venvs/rule_evasion_env/bin/activate
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
```

### Stage 1 - Train, Validate, Evaluate

Lệnh khuyến nghị cho Ensemble SVM + LR + CNB:

```bash
python3 scripts/run_stage1.py --config config/process_creation.yaml
python3 scripts/run_stage1.py --config config/powershell.yaml
python3 scripts/run_stage1.py --config config/registry_event.yaml
```

Chạy baseline SVM đơn để so sánh:

```bash
python3 scripts/run_stage1.py --config config/process_creation.yaml --no-ensemble --result-name svm_baseline
```

Output chính:

```text
models/<event_type>/train_rslt_<name>.zip
models/<event_type>/valid_rslt_<name>.zip
models/<event_type>/eval_rslt_<name>.zip
models/<event_type>/eval_rslt_<name>_info.json
```

### Stage 2 - Train Và Evaluate Attribution

```bash
python3 scripts/train_attribution.py --config config/process_creation.yaml
python3 scripts/eval_attribution.py --config config/process_creation.yaml --method cosine
```

Chạy cho các event type còn lại:

```bash
python3 scripts/train_attribution.py --config config/powershell.yaml
python3 scripts/eval_attribution.py --config config/powershell.yaml --method cosine

python3 scripts/train_attribution.py --config config/registry_event.yaml
python3 scripts/eval_attribution.py --config config/registry_event.yaml --method cosine
```

Các method hỗ trợ:

| Method | Ý nghĩa | Khi dùng |
|---|---|---|
| `svm` | Xếp hạng bằng per-rule SVM | So sánh baseline hoặc rule có đủ match/evasion data |
| `cosine` | Xếp hạng bằng cosine similarity trên TF-IDF chung | Khuyến nghị cho catalog Sigma mở rộng |
| `hybrid` | Reciprocal Rank Fusion giữa SVM và cosine | Thử nghiệm khi muốn kết hợp hai tín hiệu |

### Full Pipeline Helper

Repo có `scripts/run_pipeline.py` để chạy train, validate, evaluate, train attribution, eval attribution và plot:

```bash
python3 scripts/run_pipeline.py --config config/process_creation.yaml
```

Lưu ý: `run_pipeline.py` không đảm bảo Ensemble và không chạy `eval_attribution.py --method cosine`. Khuyến nghị dùng `run_stage1.py` + các lệnh Stage 2 riêng như hai phần trên.

## ELK Integration

### Export Log Từ Elasticsearch

```bash
python3 scripts/elk_export.py \
  --es-host http://elastic:PASSWORD@10.10.20.100:9200 \
  --es-index "logs-winlog.*" \
  --event-id 1 \
  --since 24h \
  --out exported_process_creation.jsonl
```

Event ID thường dùng:

| Event type | Event ID | Ghi chú |
|---|---:|---|
| `process_creation` | 1 | Sysmon Process Create |
| `powershell` | 4104 | PowerShell Script Block Logging |
| `registry_event` | 12, 13, 14 | Sysmon registry create/set/rename; chạy live riêng cho từng ID nếu cần |

### Batch Detection

```bash
python3 scripts/detect_batch.py \
  --config config/process_creation.yaml \
  --events exported_process_creation.jsonl \
  --threshold 0.5 \
  --method cosine \
  --top-k 5 \
  --out red_alerts.jsonl
```

Đẩy alert JSONL lên Elasticsearch:

```bash
python3 scripts/push_alerts.py \
  --alerts red_alerts.jsonl \
  --es-host http://10.10.20.100:9200 \
  --es-user elastic \
  --es-password "$ES_PASSWORD" \
  --es-index red-alerts
```

### Live Detection

```bash
python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host http://elastic:PASSWORD@10.10.20.100:9200 \
  --es-index "logs-winlog.*" \
  --out-index red-alerts \
  --event-id 1 \
  --threshold 0.5 \
  --method cosine \
  --interval 60
```

Backfill một khoảng thời gian cụ thể:

```bash
python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host http://elastic:PASSWORD@10.10.20.100:9200 \
  --es-index "logs-winlog.*" \
  --out-index red-alerts \
  --event-id 1 \
  --since 30m \
  --until now \
  --no-state \
  --max-iter 1 \
  --threshold 0.5 \
  --method cosine
```

State file mặc định là `.detect_live_state.json`. Dùng `--reset-state` khi muốn quét lại từ đầu.

### Convert Sigma Sang Elastic Rules

Nếu Kibana chưa có Detection Rules, chuyển Sigma YAML sang Elastic NDJSON. Đường dẫn
dưới đây dùng `~/data/sigma/...` — sửa lại theo môi trường của bạn nếu khác.

```bash
python3 scripts/convert_sigma_to_elastic.py \
  --index-pattern "logs-windows.*" \
  --index-pattern "winlogbeat-*" \
  --field-profile winlog-raw \
  --out data/sigma/elastic_rules/windows_sigma_elastic_winlog_raw.ndjson
```

> ⚠️ Index pattern phải khớp với data stream thật. Trên lab IQAM883 (Elastic Agent v9)
> là `logs-windows.*` (có chữ **s**), KHÔNG phải `logs-winlog.*`.

Import qua Kibana UI:

```text
Kibana -> Security -> Rules -> Import rules
```

Hoặc import bằng API. Lưu ý Kibana chạy **HTTP** trên port 5601 (chỉ Elasticsearch
là HTTPS), nên `--kibana-url` phải dùng `http://`:

```bash
python3 scripts/convert_sigma_to_elastic.py \
  --skip-convert \
  --out data/sigma/elastic_rules/windows_sigma_elastic_winlog_raw.ndjson \
  --import-to-kibana \
  --kibana-url http://192.168.10.10:5601 \
  --kibana-user elastic \
  --kibana-password "$KIBANA_PASSWORD" \
  --import-chunk-size 200 \
  --import-timeout 300
```

Dùng `--field-profile winlog-raw` khi log còn ở field gốc như `winlog.event_data.CommandLine`. Nếu log đã chuẩn ECS, có thể bỏ option này.

**Kết quả thực tế trên lab IQAM883 (2026-05-23)**: import 1,620/1,624 rules thành công
qua 9 chunks × 200 (mất ~3 phút). 4 rule fail vì `Invalid UUID` (Sigma rule id không
phải UUID format — Kibana reject).

## AI Agent SOC Triage

AI Agent nhận alert từ `red-alerts`, chạy workflow điều tra và ghi kết quả vào `ai-investigations`.

### Chạy Một Alert

```bash
python3 -m agent.run --quiet --save /tmp/red_investigation.json
```

Dùng alert JSON riêng:

```bash
python3 -m agent.run --alert-file red_alert.json --quiet --save /tmp/red_investigation.json
```

Cho tool query Elasticsearch thật:

```bash
python3 -m agent.run --es-real --alert-file red_alert.json --quiet
```

### Daemon

Dry-run một vòng, không ghi Elasticsearch:

```bash
python3 -m agent.daemon \
  --dry-run \
  --max-iter 1 \
  --score-threshold 0.5
```

Chạy daemon thật:

```bash
python3 -m agent.daemon \
  --interval 60 \
  --score-threshold 0.5 \
  --batch-limit 20
```

Các option hữu ích:

| Option | Ý nghĩa |
|---|---|
| `--reset-state` | Xóa `.agent_daemon_state.json`, cho phép process lại alert cũ |
| `--since <ISO>` | Override timestamp bắt đầu, ví dụ `2026-05-20T08:00:00Z` |
| `--no-state` | Không lưu state, tiện cho demo one-shot |
| `--query-string` | Lọc alert bằng Elasticsearch query string |
| `--skip-health-check` | Bỏ kiểm tra Elasticsearch ban đầu |

### Velociraptor Forensic Mode

Mặc định Forensic Agent dùng mock evidence. Để query Velociraptor thật:

```text
VR_USE_REAL=1
VR_API_CONFIG=/etc/velociraptor/api.config.yaml
VR_CLIENT_MAP_FILE=agent/vr_client_map.yaml
```

Cài thêm package:

```bash
pip install pyvelociraptor grpcio pyyaml
```

Cập nhật `agent/vr_client_map.yaml` để map `host.name` trong alert sang Velociraptor `client_id`.

## Demo Windows Lab

Các script Windows chính:

| Script | Log tạo ra | Config RED |
|---|---|---|
| `demo/process_creation_scenarios.ps1` | Sysmon Event ID 1 | `config/process_creation.yaml` |
| `demo/powershell_scenarios.ps1` | PowerShell Event ID 4104 | `config/powershell.yaml` |
| `demo/registry_scenarios.ps1` | Sysmon Event ID 12/13/14 | `config/registry_event.yaml` |
| `demo/apt_demo_scenario.ps1` | EID 1, 4104, 12/13/14, 4624 | nhiều event type — xem bên dưới |

Ví dụ trên Windows VM:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\process_creation_scenarios.ps1 -Scenario benign
.\process_creation_scenarios.ps1 -Scenario baseline
.\process_creation_scenarios.ps1 -Scenario evasion -SleepSeconds 20
.\process_creation_scenarios.ps1 -Scenario chain
```

Chạy thử không tạo tiến trình thật:

```powershell
.\process_creation_scenarios.ps1 -Scenario evasion -DryRun
```

Tài liệu hỗ trợ:

- `demo/README.md`: hướng dẫn demo end-to-end.
- `demo/apt_demo_scenario.md`: giải thích từng phase và Sigma rule match.
- `demo/apt_demo_scenario_demo_present.md`: lời thoại, kết quả kiểm thử, Q&A cho buổi bảo vệ (KLTN).
- `demo/RED_RULE_MAP.md`: mapping RED rule ↔ Sigma metadata.
- `demo/QA_PREP.md`: câu hỏi thường gặp khi bảo vệ/demo.
- `demo/SLIDES_OUTLINE.md`: outline slide.

## Chuẩn Bị Dữ Liệu

Các config mặc định trỏ về `~/data/...`. Tạo dữ liệu theo cấu trúc sau:

```text
~/data/
├── benign/
│   ├── process_creation/benign_train.txt
│   ├── powershell/benign_train.txt
│   └── registry_event/benign_train.txt
└── sigma/
    ├── rules/windows/process_creation/
    ├── rules/windows/powershell/
    ├── rules/windows/registry/
    ├── events_hayabusa/windows/process_creation/
    ├── events_hayabusa/windows/powershell/
    └── events_hayabusa/windows/registry_event/
```

Script chuyển đổi dữ liệu:

```bash
# LMD -> benign process_creation / registry_event
python3 scripts/lmd_to_benign.py --lmd-dir /path/to/lmd --output-dir ~/data/benign

# MPSD benign PowerShell -> benign_train.txt
python3 scripts/mpsd_to_benign.py --mpsd-dir /path/to/powershell_benign_dataset --output-dir ~/data/benign/powershell

# SecRepo Squid access.log -> benign proxy URLs
python3 scripts/secrepo_to_benign.py --input /path/to/access.log --output-dir ~/data/benign/proxy_web

# Hayabusa JSONL -> match events
python3 scripts/hayabusa_to_matches.py \
  --input hayabusa_output.jsonl \
  --output-dir ~/data/sigma/events_hayabusa/windows/process_creation \
  --event-type process_creation

# Sinh evasion variants từ match events
python3 scripts/generate_evasions.py --config config/process_creation.yaml
```

Nếu cần split benign 80/20:

```bash
python3 scripts/split_benign.py \
  --input ~/data/benign/process_creation/benign_train.txt \
  --train-ratio 0.8
```

## Config

Mỗi file trong `config/` mô tả một event type.

| Config | Trạng thái | Ghi chú |
|---|---|---|
| `config/process_creation.yaml` | chính | Sysmon process creation, nhiều field command/process/parent |
| `config/powershell.yaml` | chính | ScriptBlockText, ContextInfo, Payload, Data, HostApplication |
| `config/registry_event.yaml` | chính | TargetObject, Details, Image, User, EventType |
| `config/proxy_web.yaml` | thử nghiệm | URL/proxy web, chưa phải luồng demo chính |

Các block quan trọng:

| Block | Ý nghĩa |
|---|---|
| `data.benign_train` | file benign train |
| `data.benign_valid` | file benign validation; hiện thường trỏ cùng file train cho deployment-style evaluation |
| `data.rules_dir` | thư mục Sigma YAML |
| `data.events_dir` | match events đã convert |
| `data.evasions_dir` | evasion variants |
| `data.search_fields` | tên field trong Sigma rule |
| `data.event_field_map` | mapping Sigma field sang JSON path trong log thật |
| `training` | vectorizer, CV, scoring, malicious sample source |
| `scaling` | MCC scaler để đưa decision score về `[0, 1]` |
| `output` | thư mục và tên artifact model/result |

## Script Thường Dùng

Tất cả script CLI đều hỗ trợ `--help`:

```bash
python3 scripts/run_stage1.py --help
python3 scripts/train_attribution.py --help
python3 scripts/detect_live.py --help
python3 -m agent.daemon --help
```

| Mục đích | Lệnh |
|---|---|
| Stage 1 gộp train/validate/evaluate | `python3 scripts/run_stage1.py --config config/process_creation.yaml` |
| Train Stage 1 riêng | `python3 scripts/train.py --config config/process_creation.yaml --ensemble` |
| Validate Stage 1 riêng | `python3 scripts/validate.py --config config/process_creation.yaml` |
| Evaluate Stage 1 riêng | `python3 scripts/evaluate.py --config config/process_creation.yaml` |
| Train Stage 2 | `python3 scripts/train_attribution.py --config config/process_creation.yaml` |
| Evaluate Stage 2 cosine | `python3 scripts/eval_attribution.py --config config/process_creation.yaml --method cosine` |
| Batch detect JSONL | `python3 scripts/detect_batch.py --config config/process_creation.yaml --events exported.jsonl --method cosine` |
| Live detect Elasticsearch | `python3 scripts/detect_live.py --config config/process_creation.yaml --es-host http://host:9200` |
| Convert Sigma sang Elastic | `python3 scripts/convert_sigma_to_elastic.py --field-profile winlog-raw --out rules.ndjson` |
| AI Agent một alert | `python3 -m agent.run --alert-file alert.json --quiet` |
| AI Agent daemon | `python3 -m agent.daemon --interval 60 --score-threshold 0.5` |

## Troubleshooting

### `Benign file not found`

Kiểm tra đường dẫn trong config, ví dụ:

```bash
ls ~/data/benign/process_creation/benign_train.txt
```

Nếu dữ liệu nằm nơi khác, sửa `data.benign_train` trong file YAML hoặc truyền tham số trực tiếp cho script.

### `Events dir not found`

Stage 1 có thể fallback sang `rule_filters` nếu thiếu match events, nhưng Stage 2 cần `events_dir`. Hãy chạy converter Hayabusa/OTRF hoặc cập nhật `data.events_dir`.

### `DEEPSEEK_API_KEY chưa set`

Tạo `.env` từ `.env.example` và điền API key:

```bash
cp .env.example .env
nano .env
```

Sau đó chạy agent từ thư mục repo để module `agent` load đúng `.env`.

### Không thấy alert trong Kibana

- Kiểm tra index nguồn: `logs-winlog.*`, `winlogbeat-*` hoặc index lab đang dùng.
- Kiểm tra Event ID đúng với config.
- Với `detect_live.py`, kiểm tra `.detect_live_state.json`; dùng `--reset-state` hoặc `--no-state --since ... --until now` khi backfill.
- Với Elastic Detection Rules, rule chạy theo lịch nên alert Sigma có thể xuất hiện muộn hơn alert RED.

### Registry event có nhiều Event ID

`detect_live.py` nhận một `--event-id` mỗi tiến trình. Với registry, chạy riêng cho 12, 13 và 14 nếu cần cover đầy đủ.

## Ghi Chú An Toàn

- Chỉ chạy các script demo trong lab hoặc VM đã chuẩn bị.
- Không dùng `export_evasion_scripts.py --mode execute` ngoài môi trường kiểm thử.
- AI Agent chỉ đề xuất containment; các action có tác động thật vẫn cần phê duyệt của người vận hành.
