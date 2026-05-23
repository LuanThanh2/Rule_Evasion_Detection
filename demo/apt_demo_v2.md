# APT Demo v2 - 6 Sigma Target Rules

Muc tieu cua `apt_demo_v2.ps1`: demo ro rang 2 trang thai:

- `baseline`: 6 phase map 1:1 vao 6 Sigma target rules va Security Alerts fire du 6 rule.
- `evasion`: cung y do nhung doi bieu dien de 6 Sigma target rules miss, RED ML van catch.

## Mapping

| Phase | Event type | Sigma rule | Sigma ID | Baseline | Evasion |
|---:|---|---|---|---|---|
| 1 | PowerShell 4104 | Potential Invoke-Mimikatz PowerShell Script | `189e3b02-82b2-4b90-9662-411eb64486d4` | Child ScriptBlock co `DumpCreds` + `DumpCerts` | Char-code reconstruct, chi in hash |
| 2 | Process EID 1 | Suspicious Eventlog Clearing or Configuration Change Activity | `cc36992a-4671-4f21-a91d-6c2b72a2edf5` | `wevtutil cl RED_DEMO_V2_NONEXISTENT_<RunId>` | Split token trong PowerShell, khong co clear command line |
| 3 | Process EID 1 | PowerShell Download and Execution Cradles | `85b0b087-eddf-4a2b-b033-d771fa2b9775` | `iwr ... | iex` | Swap sang `curl.exe`, target PowerShell cradle miss |
| 4 | Process EID 1 | Remotely Hosted HTA File Executed Via Mshta.EXE | `b98d0db6-511d-45de-ad02-e82a98729620` | HTA utility + remote URL | HTA utility + inline scheme, khong co remote URL token |
| 5 | Process EID 1 | Direct Autorun Keys Modification | `24357373-078f-44ed-9ac4-6d334a668a11` | `reg.exe add HKCU\...\CurrentVersion\Run` | PowerShell registry provider ghi `StartupApproved\Run` |
| 6 | Process EID 1 | File Encoded To Base64 Via Certutil.EXE | `e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a` | `certutil.exe -encode` tren temp file | .NET base64 API runtime, khong dung target utility |

> Note: Phase 5/6 dung process_creation rules thay cho registry-set/Reflection rules vi Elastic Agent + converter hien tai lam registry-set rule bi filter `Details:null`, va Reflection query escape khong match field text on dinh.

## Run

Copy script len endpoint:

```bash
cd /home/ubuntu/rule_evasion_detection/Rule_Evasion_Detection
python3 - <<'PY'
import codecs, paramiko
from pathlib import Path
src = Path('demo/apt_demo_v2.ps1')
tmp = Path('/tmp/apt_demo_v2_bom.ps1')
data = src.read_bytes()
tmp.write_bytes(data if data.startswith(codecs.BOM_UTF8) else codecs.BOM_UTF8 + data)
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('192.168.10.103', username='endpoint', password='123', timeout=15)
sftp = client.open_sftp()
sftp.put(str(tmp), 'C:/Users/endpoint/apt_demo_v2.ps1')
sftp.close()
client.close()
PY
```

Chay baseline/evasion:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\endpoint\apt_demo_v2.ps1 -Mode baseline -SleepSeconds 1
powershell -ExecutionPolicy Bypass -File C:\Users\endpoint\apt_demo_v2.ps1 -Mode evasion  -SleepSeconds 1
```

Co the test parse truoc:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\endpoint\apt_demo_v2.ps1 -Mode baseline -DryRun
```

## Verified Result

Verified tren `DESKTOP-IQAM883`, ngay `2026-05-24` gio VN.

| Test | RunId | Result |
|---|---|---|
| Baseline raw Sigma query | `4035abf9` | 6/6 target queries match, moi target dung 1 event |
| Baseline Kibana Security Alerts | `4035abf9` | 6 unique target Sigma alerts materialized sau scheduler lag |
| Evasion raw Sigma query | `f73f19ba` | 0/6 target queries match |
| Evasion Kibana Security Alerts | `f73f19ba` | 0/6 target Sigma alerts |
| Evasion RED ML backfill | `f73f19ba` | 11 RED alerts trong `red-alerts-v2-test`, score `0.5887` den `1.0` |

Baseline Security Alerts observed:

```text
cc36992a  SIGMA - Suspicious Eventlog Clearing or Configuration Change Activity
e62a9f0c  SIGMA - File Encoded To Base64 Via Certutil.EXE
b98d0db6  SIGMA - Remotely Hosted HTA File Executed Via Mshta.EXE
85b0b087  SIGMA - PowerShell Download and Execution Cradles
24357373  SIGMA - Direct Autorun Keys Modification
189e3b02  SIGMA - Potential Invoke-Mimikatz PowerShell Script
```

RED evasion examples:

```text
EID 1    score 1.0000  suspicious_ping_del_command_combination        curl.exe marker
EID 1    score 1.0000  potential_lethalhta_technique_execution        mshta inline scheme
EID 4104 score 0.6158  hacktool_evil_winrm_execution_powershell_module phase1 char-code
EID 4104 score 0.5887  hacktool_rubeus_execution_scriptblock          phase2 split token
EID 4104 score 0.8264  powershell_script_with_file_upload_capabilities phase6 runtime base64
```

Security Alerts co scheduler lag. Raw Sigma query match/miss co ngay khi log vao `logs-windows.*`; alert index co the can 1-5 phut tuy interval tung rule.
