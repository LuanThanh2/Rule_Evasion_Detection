# RED-AI SOC Demo Runbook

Tài liệu này dùng để chạy demo end-to-end cho **Rule Evasion Detection (RED)**:
Windows sinh log Sysmon -> Elastic/Sigma baseline tạo alert -> RED ML phát hiện
biến thể né luật -> AI Agent điều tra và ghi báo cáo vào Elasticsearch.

> Demo chỉ dành cho lab. Script Windows tạo command line, ScriptBlockText và
> registry event đáng ngờ để sinh log, nhưng không tải payload thật và không
> thực thi mã độc từ xa.

## 1. Sơ đồ demo

| Lớp | Input | Logic | Output | Nơi xem |
|---|---|---|---|---|
| Elastic/Sigma baseline | `logs-winlog.*` | Sigma -> Elastic Custom Query rules | Security alerts | `Security -> Rules`, `Security -> Alerts` |
| RED ML | `logs-winlog.*` | Stage 1 score + Stage 2 rule attribution | `red-alerts` | `Discover -> RED Alerts` |
| AI Agent | `red-alerts` | Multi-agent SOC investigation | `ai-investigations` | `Discover -> AI Investigations` |

Điểm cần nhấn khi thuyết trình:

- **Elastic/Sigma** là baseline exact-match, mạnh với mẫu đã biết như
  `-EncodedCommand`.
- **RED** bắt các biến thể gần nghĩa như `-e`, `-Ec`, đổi hoa/thường, thêm tab,
  hoặc rút gọn flag.
- **AI Agent** biến RED alert thành báo cáo điều tra tiếng Việt, mapping MITRE,
  giải thích kỹ thuật evasion và đề xuất Sigma patch/containment.

## 2. Chuẩn bị nhanh

Chạy trên Linux demo box:

```bash
source ~/venvs/rule_evasion_env/bin/activate
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
pip install -r requirements.txt
```

Kiểm tra model RED đã có:

```bash
ls models/process_creation/train_rslt_ensemble_f1.zip
ls models/process_creation/train_rslt_attr_ensemble.zip
ls models/powershell/train_rslt_ensemble_f1.zip
ls models/powershell/train_rslt_attr_ensemble.zip
ls models/registry_event/train_rslt_ensemble_f1.zip
ls models/registry_event/train_rslt_attr_ensemble.zip
```

Chuẩn bị `.env` cho monitor và AI Agent:

```bash
cp .env.example .env
nano .env
```

Các biến tối thiểu:

```text
ES_HOST=http://10.10.20.100:9200
ES_USER=elastic
ES_PASSWORD=your-es-password
ES_RED_INDEX=red-alerts
ES_AI_INDEX=ai-investigations
DEEPSEEK_API_KEY=sk-your-deepseek-key
```

`detect_live.py` không tự đọc `.env`, nên với lệnh RED backfill bên dưới hãy
truyền credential trong URL Elasticsearch, ví dụ
`http://elastic:PASSWORD@10.10.20.100:9200`.

## 3. Elastic/Sigma baseline

Kibana không import trực tiếp Sigma YAML. Nếu chưa có Detection Rules, convert
và import bằng script.

Trong lab hiện tại, Sysmon process fields đang nằm ở raw Winlog fields:

```text
winlog.event_data.CommandLine
winlog.event_data.Image
winlog.event_data.ParentCommandLine
winlog.event_data.ParentImage
```

Vì vậy khi convert Sigma cần dùng profile `winlog-raw` để rewrite query từ ECS
fields như `process.command_line` sang raw fields ở trên:

```bash
source ~/venvs/rule_evasion_env/bin/activate
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection

python3 scripts/convert_sigma_to_elastic.py \
  --index-pattern "logs-winlog.*" \
  --field-profile winlog-raw \
  --out /home/luanthanh/data/sigma/elastic_rules/windows_sigma_elastic_winlog_raw.ndjson
```

File NDJSON cho lab raw Sysmon:

```text
/home/luanthanh/data/sigma/elastic_rules/windows_sigma_elastic_winlog_raw.ndjson
```

Import bằng UI:

```text
Kibana -> Security -> Rules -> Import rules
```

Hoặc import bằng API:

```bash
export KIBANA_PASSWORD='your-kibana-password'

python3 scripts/convert_sigma_to_elastic.py \
  --skip-convert \
  --out /home/luanthanh/data/sigma/elastic_rules/windows_sigma_elastic_winlog_raw.ndjson \
  --import-to-kibana \
  --kibana-url http://10.10.20.100:5601 \
  --kibana-user elastic \
  --kibana-password "$KIBANA_PASSWORD" \
  --import-chunk-size 200 \
  --import-timeout 300
```

Hoặc convert và import ngay trong một lệnh:

```bash
python3 scripts/convert_sigma_to_elastic.py \
  --index-pattern "logs-winlog.*" \
  --field-profile winlog-raw \
  --out /home/luanthanh/data/sigma/elastic_rules/windows_sigma_elastic_winlog_raw.ndjson \
  --import-to-kibana \
  --import-chunk-size 200 \
  --import-timeout 300
```

Nếu log đã được ingest chuẩn ECS và có `process.command_line`, bỏ
`--field-profile winlog-raw`.

Sau khi import:

```text
Security -> Rules
```

Tìm rule theo prefix:

```text
SIGMA -
```

Xem alert:

```text
Security -> Alerts
```

Lưu ý quan trọng: Elastic Detection Rules chạy theo lịch, thường kiểu `interval:
5m` và `from: now-5m`. Vì vậy alert baseline có thể xuất hiện muộn hơn raw log
hoặc RED alert.

## 4. Sinh log trên Windows VM

Ba script demo tương ứng ba event type khác nhau:

| Script | Event type RED | Log cần có | Config |
|---|---|---|---|
| `process_creation_scenarios.ps1` | `process_creation` | Sysmon Event ID 1 | `config/process_creation.yaml` |
| `powershell_scenarios.ps1` | `powershell` | PowerShell Event ID 4104 | `config/powershell.yaml` |
| `registry_scenarios.ps1` | `registry_event` | Sysmon Event ID 12/13/14 | `config/registry_event.yaml` |

### 4.1 Process Creation

Đây là demo PowerShell thông qua **process command line**. Copy
`demo/process_creation_scenarios.ps1` sang Windows VM đã bật Sysmon và Elastic Agent,
sau đó mở PowerShell:


```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force

.\process_creation_scenarios.ps1 -Scenario benign
.\process_creation_scenarios.ps1 -Scenario baseline
.\process_creation_scenarios.ps1 -Scenario evasion -SleepSeconds 20
.\process_creation_scenarios.ps1 -Scenario chain
```

Có thể chạy toàn bộ:

```powershell
.\process_creation_scenarios.ps1 -Scenario all -SleepSeconds 20
```

Các kịch bản:

| Scenario | Mục đích |
|---|---|
| `benign` | Sinh hoạt động admin bình thường như `whoami`, `ipconfig`, maintenance script |
| `baseline` | Sinh mẫu PowerShell `-EncodedCommand` đầy đủ, baseline Sigma thường bắt được |
| `evasion` | Sinh biến thể `-e`, `-Ec`, đổi hoa/thường, tab whitespace, `-en` |
| `chain` | Discovery + PowerShell evasion + curl marker dạng exfil |
| `all` | Chạy tất cả kịch bản trên |

Chạy thử không thực thi process:

```powershell
.\process_creation_scenarios.ps1 -Scenario evasion -DryRun
```

### 4.2 PowerShell ScriptBlock

Đây là demo đúng cho `config/powershell.yaml`, đọc field
`winlog.event_data.ScriptBlockText`. Trên Windows VM cần bật PowerShell Script
Block Logging để có Event ID 4104. Chạy PowerShell bằng quyền Administrator
khi bật policy này:

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force
```

Copy `demo/powershell_scenarios.ps1` sang Windows VM, rồi chạy:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force

.\powershell_scenarios.ps1 -Scenario benign
.\powershell_scenarios.ps1 -Scenario baseline
.\powershell_scenarios.ps1 -Scenario evasion -SleepSeconds 20
.\powershell_scenarios.ps1 -Scenario chain
```

Script này chỉ ghi/print marker đáng ngờ như `Invoke-Expression`,
`DownloadString`, `IEX`, `FromBase64String` vào ScriptBlockText; không tải hay
execute payload từ xa.

### 4.3 Registry Event

Đây là demo đúng cho `config/registry_event.yaml`, đọc
`winlog.event_data.TargetObject` và `winlog.event_data.Details`. Windows VM cần
Sysmon config có bật registry events, tối thiểu SetValue Event ID 13.

Copy `demo/registry_scenarios.ps1` sang Windows VM, rồi chạy:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force

.\registry_scenarios.ps1 -Scenario benign
.\registry_scenarios.ps1 -Scenario baseline
.\registry_scenarios.ps1 -Scenario evasion -SleepSeconds 20
.\registry_scenarios.ps1 -Scenario chain
```

Script này tạo các value lab-safe dưới `HKCU`, ví dụ Run/RunOnce/Policy Run
marker, rồi tự xóa value sau khi sinh log. Nếu cần giữ lại để kiểm tra bằng
Registry Editor, thêm `-KeepArtifacts`.

## 5. RED backfill log Windows

Chạy trên Linux demo box sau khi Windows đã gửi log vào Elasticsearch.

### 5.1 Process Creation

Nếu clock Windows, Linux và ELK đồng bộ, dùng `@timestamp`:

```bash
python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "http://elastic:PASSWORD@10.10.20.100:9200" \
  --es-index "logs-winlog.*" \
  --out-index red-alerts \
  --threshold 0.5 \
  --method cosine \
  --since "2026-05-15T10:00:00Z" \
  --until "2026-05-15T10:20:00Z" \
  --max-iter 1 \
  --no-state
```

Nếu clock Windows lệch nhưng thời gian ingest trên ELK đúng, dùng
`event.ingested`:

```bash
python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "http://elastic:PASSWORD@10.10.20.100:9200" \
  --es-index "logs-winlog.*" \
  --out-index red-alerts \
  --threshold 0.5 \
  --method cosine \
  --timestamp-field event.ingested \
  --since "30m" \
  --until "now" \
  --max-iter 1 \
  --no-state
```

Demo sạch chỉ lấy PowerShell qua **process_creation**:

```bash
python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "http://elastic:PASSWORD@10.10.20.100:9200" \
  --es-index "logs-winlog.*" \
  --out-index red-alerts \
  --threshold 0.5 \
  --method cosine \
  --timestamp-field event.ingested \
  --since "20m" \
  --until "now" \
  --max-iter 1 \
  --no-state \
  --batch-size 100 \
  --query-string 'winlog.event_data.CommandLine:*powershell* OR process.command_line:*powershell*'
```

Chạy liên tục cho demo sạch, chỉ lấy rộng family PowerShell process và ghi vào
index riêng `red-alerts-demo` để không lẫn noise Docker/Chrome/conhost cũ.
Query này chỉ giảm nhiễu nguồn vào, không lọc sẵn `-EncodedCommand`, `-e` hay
các token evasion:

```bash
python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "http://elastic:PASSWORD@10.10.20.100:9200" \
  --es-index "logs-winlog.*" \
  --out-index red-alerts-demo \
  --threshold 0.5 \
  --method cosine \
  --interval 60 \
  --lookback 5m \
  --reset-state \
  --batch-size 500 \
  --query-string 'winlog.event_data.Image:*powershell* OR process.name:*powershell* OR winlog.event_data.CommandLine:*powershell* OR process.command_line:*powershell*'
```

Trong Discover, tạo data view:

```text
Name: RED Alerts Demo
Index pattern: red-alerts-demo
Timestamp field: @timestamp
```

Ghi nhớ:

- `--no-state` không đọc/ghi `.detect_live_state.json`, phù hợp demo replay.
- `--interval 60` là chu kỳ poll liên tục; nó không quyết định cửa sổ thời gian.
- `--lookback 5m` chỉ dùng lúc daemon khởi động khi state rỗng hoặc reset.
- `--reset-state` giúp demo bắt đầu từ `now-5m`, tránh kẹt state cũ.
- `@timestamp` là thời gian event từ Windows log/agent.
- `event.ingested` là thời gian ingest của Elastic/ingest node.
- `--since 30m` được tính theo clock Linux đang chạy script.
- Lab hiện dùng data stream Windows `logs-winlog.winlog-default`, nên index
  pattern khuyến nghị là `logs-winlog.*`.

Kiểm tra RED alert mới nhất:

```bash
curl -s -u elastic:PASSWORD \
  "http://10.10.20.100:9200/red-alerts/_search?size=10&sort=@timestamp:desc" \
  | jq '.hits.hits[]._source | {ts: ."@timestamp", score: ."red.detection_score", top_rule: ."red.top_rule", cmd: ."red.command_line"}'
```

Kết quả kỳ vọng:

| Variant | RED expected |
|---|---|
| `-EncodedCommand` | `score ~= 1.0` |
| `-e` | `score ~= 1.0` |
| `-Ec` | `score ~= 1.0` |
| tab whitespace + `-e` | `score ~= 1.0` |
| case manipulation | `score ~= 1.0` |

### 5.2 PowerShell ScriptBlock

Backfill Event ID 4104 bằng `config/powershell.yaml`:

```bash
python3 scripts/detect_live.py \
  --config config/powershell.yaml \
  --es-host "http://elastic:PASSWORD@10.10.20.100:9200" \
  --es-index "logs-winlog.*" \
  --out-index red-alerts-powershell-demo \
  --event-id 4104 \
  --threshold 0.5 \
  --method cosine \
  --timestamp-field event.ingested \
  --since "20m" \
  --until "now" \
  --max-iter 1 \
  --no-state \
  --batch-size 100 \
  --query-string 'winlog.event_data.ScriptBlockText:*RED_DEMO_PS* OR winlog.event_data.ScriptBlockText:*DownloadString* OR winlog.event_data.ScriptBlockText:*FromBase64String*'
```

Kiểm tra alert:

```bash
curl -s -u elastic:PASSWORD \
  "http://10.10.20.100:9200/red-alerts-powershell-demo/_search?size=10&sort=@timestamp:desc" \
  | jq '.hits.hits[]._source | {ts: ."@timestamp", score: ."red.detection_score", top_rule: ."red.top_rule", text: ."red.command_line"}'
```

### 5.3 Registry Event

Backfill Sysmon SetValue Event ID 13 bằng `config/registry_event.yaml`:

```bash
python3 scripts/detect_live.py \
  --config config/registry_event.yaml \
  --es-host "http://elastic:PASSWORD@10.10.20.100:9200" \
  --es-index "logs-winlog.*" \
  --out-index red-alerts-registry-demo \
  --event-id 13 \
  --threshold 0.5 \
  --method cosine \
  --timestamp-field event.ingested \
  --since "20m" \
  --until "now" \
  --max-iter 1 \
  --no-state \
  --batch-size 100 \
  --query-string 'winlog.event_data.TargetObject:*RED_Demo* OR winlog.event_data.TargetObject:*red_demo*'
```

Nếu muốn bắt thêm registry key create/delete, chạy lại với `--event-id 12`
hoặc `--event-id 14` tùy Sysmon config. Kịch bản registry chính dùng Event ID
13 vì hành vi trọng tâm là set value.

Kiểm tra alert:

```bash
curl -s -u elastic:PASSWORD \
  "http://10.10.20.100:9200/red-alerts-registry-demo/_search?size=10&sort=@timestamp:desc" \
  | jq '.hits.hits[]._source | {ts: ."@timestamp", score: ."red.detection_score", top_rule: ."red.top_rule", target: ."red.command_line"}'
```

Thông điệp chính: mỗi event type phải dùng đúng config và đúng field log. RED có
thể demo cùng một ý tưởng "rule evasion" trên process command line,
ScriptBlockText và registry target/value events.

## 6. AI Agent investigation

Sau khi `red-alerts` đã có alert PowerShell, chạy AI Agent một lần:

```bash
source ~/venvs/rule_evasion_env/bin/activate
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
source .env

python3 -m agent.daemon \
  --interval 5 \
  --score-threshold 0.5 \
  --max-iter 1 \
  --batch-limit 1 \
  --since "2026-05-15T08:05:40Z" \
  --query-string 'red.command_line:*powershell*' \
  --no-state
```

Chạy này gọi LLM thật và tốn token. Mức thường gặp trong demo:

```text
~60-120 giây
~30k-80k tokens
~$0.01-$0.03 nếu dùng DeepSeek
```

Kiểm tra investigation mới nhất:

```bash
curl -s -u elastic:PASSWORD \
  "http://10.10.20.100:9200/ai-investigations/_search?size=1&sort=timestamp:desc" \
  | jq '.hits.hits[0]._source | {id: .investigation_id, severity: .triage.severity, technique: .red_analyst.evasion_technique, title: .report.title_vi, cost: .estimated_cost_usd, tokens: .total_tokens}'
```

Nơi xem trên Kibana:

```text
Discover -> AI Investigations
```

Nếu chưa có data view:

```text
Name: AI Investigations
Index pattern: ai-investigations
Timestamp field: timestamp
```

Field nên pin trong Discover:

```text
timestamp
triage.severity
triage.confidence
red_analyst.evasion_technique
mitre.primary_technique
response.requires_human_approval
estimated_cost_usd
total_tokens
report.title_vi
report.summary_vi
```

## 7. Terminal monitor

Monitor dùng `.env` để đọc Elasticsearch credential.

```bash
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
./demo/monitor.sh 10
```

Màn hình hiển thị:

- Tổng số document trong `red-alerts` và `ai-investigations`.
- 5 RED alert mới nhất.
- 5 AI investigation mới nhất.

## 8. Checklist trình diễn

1. Mở Kibana `Security -> Rules`, filter `SIGMA -`, cho thấy baseline rules.
2. Chọn event type muốn demo: process creation, PowerShell ScriptBlock hoặc registry event.
3. Chạy `baseline` trên Windows, chờ Elastic Security alert.
4. Chạy `evasion`, giải thích vì sao exact-match baseline có thể bỏ sót biến thể.
5. Chạy RED backfill bằng `detect_live.py` với config tương ứng, mở `red-alerts`.
6. Chỉ ra `red.detection_score`, `red.top_rule`, `red.command_line`.
7. Chạy `agent.daemon --max-iter 1`, mở `ai-investigations`.
8. Kết luận bằng báo cáo tiếng Việt, MITRE mapping, evasion explanation và Sigma patch.

## 9. Troubleshooting

| Lỗi | Cách xử lý |
|---|---|
| `ModuleNotFoundError: numpy` hoặc `openai` | `source ~/venvs/rule_evasion_env/bin/activate` rồi `pip install -r requirements.txt` |
| `ES_PASSWORD is empty` khi chạy monitor | Điền `ES_PASSWORD` trong `.env` |
| Không thấy RED alert | Kiểm tra `--es-index`, `--timestamp-field`, khoảng `--since/--until`, và đúng Event ID: `1` process, `4104` PowerShell, `13` registry SetValue |
| Không thấy PowerShell ScriptBlock log | Bật Script Block Logging và kiểm tra channel `Microsoft-Windows-PowerShell/Operational` có Event ID `4104` |
| Không thấy registry log | Kiểm tra Sysmon config có collect registry set value Event ID `13` |
| Không thấy Security alert baseline | Detection Rules chạy theo lịch; chờ ít nhất một interval hoặc kiểm tra rule đã enable |
| AI Agent không chạy | Kiểm tra `DEEPSEEK_API_KEY`, `ES_HOST`, `ES_USER`, `ES_PASSWORD` trong `.env` |
| Query quá nhiễu | Thêm `--query-string 'winlog.event_data.CommandLine:*powershell* OR process.command_line:*powershell*'` |
