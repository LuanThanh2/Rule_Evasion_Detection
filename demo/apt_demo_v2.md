# APT Demo v2 - 6 Sigma Fire, 6 Sigma Miss, RED Catch

`apt_demo_v2.ps1` la demo ngan, de giai thich truc tiep diem manh cua RED:

- `benign`: hoat dong doc/tham do binh thuong, dung de kiem tra sanity truoc
  khi chay demo chinh. 6 Sigma target rules khong duoc fire.
- `baseline`: 6 phase tao 6 event map 1:1 vao 6 Sigma target rules. Kibana
  Security Alerts phai fire du 6 rule.
- `evasion`: cung y do tan cong nhung doi cach bieu dien. 6 Sigma target rules
  phai miss, trong khi RED ML van tao alert tren `red-alerts-*`.

Demo nay khong tai malware that. Script chi tao command line, ScriptBlockText va
registry marker co kiem soat de sinh log trong lab.

## 1. Lab Topology

| Thanh phan | Gia tri lab IQAM883 |
|---|---|
| Endpoint Windows | `DESKTOP-IQAM883` / `192.168.10.103` |
| SSH endpoint | user `endpoint`, password `123` |
| Elasticsearch | `https://192.168.10.10:9200` |
| Kibana API | `http://192.168.10.10:5601` |
| Raw log index | `logs-windows.*` |
| Security alert index | `.alerts-security.alerts-*,.siem-signals-*` |
| RED process alerts | `red-alerts-demo` |
| RED PowerShell alerts | `red-alerts-powershell-demo` |
| RED registry alerts | `red-alerts-registry-demo` |

Kibana trong lab nay la HTTP tren port `5601`. Khong dung
`https://192.168.10.10:5601`.

## 2. Demo Story

Thong diep thuyet trinh:

1. Sigma/Elastic bat rat tot mau da biet khi event giong dung query.
2. Ke tan cong chi can doi cach viet command/script thi rule exact-match co the
   miss.
3. RED dung ML + attribution de bat lai cac event gan voi hanh vi evasion, sau
   do giai thich event giong rule nao.

Ket qua mong doi:

| Mode | Sigma raw query | Kibana Security Alerts | RED ML |
|---|---:|---:|---|
| `benign` | 0/6 target match | 0/6 target alerts | Sanity check, khong phai claim chinh |
| `baseline` | 6/6 match | 6/6 target alerts | Co the co them alerts |
| `evasion` | 0/6 target match | 0/6 target alerts | Co alerts trong `red-alerts-*` |

## 3. Phase Mapping

| Phase | Event type | Target Sigma rule | Sigma ID | Benign | Baseline | Evasion |
|---:|---|---|---|---|---|---|
| 1 | PowerShell 4104 | Potential Invoke-Mimikatz PowerShell Script | `189e3b02-82b2-4b90-9662-411eb64486d4` | Doc local users | Child ScriptBlock co `DumpCreds` + `DumpCerts` | Char-code reconstruct, chi in hash |
| 2 | Process EID 1 | Suspicious Eventlog Clearing or Configuration Change Activity | `cc36992a-4671-4f21-a91d-6c2b72a2edf5` | `wevtutil gl Application` | `wevtutil cl RED_DEMO_V2_NONEXISTENT_<RunId>` | Split token trong PowerShell, khong co clear command line |
| 3 | Process EID 1 | PowerShell Download and Execution Cradles | `85b0b087-eddf-4a2b-b033-d771fa2b9775` | Web request khong execute | `iwr ... \| iex` | Doi sang `curl.exe`, target PowerShell cradle miss |
| 4 | Process EID 1 | Remotely Hosted HTA File Executed Via Mshta.EXE | `b98d0db6-511d-45de-ad02-e82a98729620` | Check path `mshta.exe` | `mshta.exe http://...` | `mshta.exe javascript:close()`, khong co remote URL token |
| 5 | Process EID 1 | Direct Autorun Keys Modification | `24357373-078f-44ed-9ac4-6d334a668a11` | Doc Explorer registry key | `reg.exe add HKCU\...\CurrentVersion\Run` | PowerShell registry provider ghi `StartupApproved\Run` |
| 6 | Process EID 1 | File Encoded To Base64 Via Certutil.EXE | `e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a` | Liet ke temp dir | `certutil.exe -encode` tren temp file | .NET base64 API runtime, khong dung target utility |

Phase 5/6 dung process_creation rules thay cho registry-set/reflection rules vi
Elastic Agent + converter trong lab hien tai lam registry-set rule bi filter
`Details:null`, va reflection query escape khong match field text on dinh.

## 4. Preflight

Chay tren Ubuntu demo box:

```bash
cd /home/ubuntu/rule_evasion_detection/Rule_Evasion_Detection
source ~/venvs/rule_evasion_env/bin/activate
```

Kiem tra ES va Kibana:

```bash
curl -sk -u elastic:'Admin123@' \
  https://192.168.10.10:9200/_cluster/health

curl -s -u elastic:'Admin123@' \
  http://192.168.10.10:5601/api/status | head -c 300
```

Kiem tra endpoint SSH:

```bash
timeout 5 bash -c '</dev/tcp/192.168.10.103/22' && echo SSH_OPEN
```

Kiem tra 6 Sigma rules da co trong Kibana:

```bash
python3 scripts/test_apt_demo_v2.py \
  --check-only \
  --kibana-url http://192.168.10.10:5601 \
  --http-timeout 10
```

Expected:

```text
OK: 6/6 target rule queries found
OK phase=1 ... fields=ecs index=[logs-windows.*,winlogbeat-*]
...
[Raw Sigma query source]
using live Kibana queries for 6/6 target rules
```

Lab IQAM883 dung Elastic Agent ECS query (`process.*`, `powershell.*`). Script
uu tien live Kibana query khi rule check thanh cong; NDJSON local chi la
fallback.

Neu rule bi `MISSING`, import lai ban ECS:

```bash
python3 scripts/convert_sigma_to_elastic.py \
  --skip-convert \
  --out data/sigma/elastic_rules/windows_sigma_elastic_ecs.ndjson \
  --import-to-kibana \
  --kibana-url http://192.168.10.10:5601 \
  --kibana-user elastic \
  --kibana-password 'Admin123@' \
  --import-chunk-size 200 \
  --import-timeout 300
```

## 5. Fast Demo - Automated

Day la cach khuyen nghi khi demo truoc hoi dong vi no copy script len endpoint,
chay PowerShell, poll raw logs, poll Security Alerts va in ket qua PASS/FAIL.

### 5.1 Benign: sanity check 0/6

Chay nhanh truoc demo chinh de chung minh 6 target rules khong fire voi thao tac
binh thuong:

```bash
PYTHONUNBUFFERED=1 python3 scripts/test_apt_demo_v2.py \
  --mode benign \
  --run-endpoint \
  --kibana-url http://192.168.10.10:5601 \
  --wait-raw-seconds 120 \
  --wait-alert-seconds 120
```

Expected:

```text
[Raw Sigma query counts]
phase=1 ... count=0
...
[Result]
raw_sigma=PASS
security_alerts=PASS
```

Voi mode `benign`, PASS nghia la 6 target Sigma rules deu khong fire.

### 5.2 Baseline: Sigma fire 6/6

```bash
PYTHONUNBUFFERED=1 python3 scripts/test_apt_demo_v2.py \
  --mode baseline \
  --run-endpoint \
  --kibana-url http://192.168.10.10:5601 \
  --wait-raw-seconds 180 \
  --wait-alert-seconds 420
```

Expected cuoi lenh:

```text
[Result]
raw_sigma=PASS
security_alerts=PASS
```

Ghi lai `RunId` duoc in o dau phan `[Run]`, vi se dung de loc trong Kibana.

### 5.3 Evasion: Sigma miss 6/6, RED catch

```bash
PYTHONUNBUFFERED=1 python3 scripts/test_apt_demo_v2.py \
  --mode evasion \
  --run-endpoint \
  --kibana-url http://192.168.10.10:5601 \
  --wait-raw-seconds 180 \
  --wait-alert-seconds 180
```

Expected cuoi lenh van la PASS, vi voi mode `evasion` dieu dung la 6 target
Sigma rules deu khong fire:

```text
[Raw Sigma query counts]
phase=1 ... count=0
...
[Result]
raw_sigma=PASS
security_alerts=PASS
```

Sau do kiem tra RED alert cho RunId evasion:

```bash
export RUN_ID="<RunId_evasion>"

python3 - <<'PY'
import os, requests, urllib3
urllib3.disable_warnings()
run_id = os.environ["RUN_ID"]
indices = ["red-alerts-demo", "red-alerts-powershell-demo", "red-alerts-registry-demo"]
for idx in indices:
    body = {
        "size": 5,
        "track_total_hits": True,
        "_source": [
            "@timestamp",
            "winlog.event_id",
            "red.detection_score",
            "red.top_rule",
            "red.top_rule_sigma_title",
            "red.command_line",
        ],
        "query": {
            "query_string": {
                "query": f"*{run_id}*",
                "analyze_wildcard": True,
                "lenient": True,
            }
        },
    }
    r = requests.post(
        f"https://192.168.10.10:9200/{idx}/_search",
        params={"ignore_unavailable": "true"},
        json=body,
        auth=("elastic", "Admin123@"),
        verify=False,
        timeout=20,
    )
    r.raise_for_status()
    data = r.json()
    total = data["hits"]["total"]
    count = total["value"] if isinstance(total, dict) else total
    print(f"{idx}: {count}")
    for hit in data["hits"]["hits"][:3]:
        src = hit["_source"]
        print(
            " ",
            src.get("winlog.event_id"),
            src.get("red.detection_score"),
            src.get("red.top_rule"),
            "-",
            src.get("red.top_rule_sigma_title"),
        )
PY
```

Neu dang co nhieu `detect_live.py` daemon chay song song, RED count co the bi
duplicate. Dieu can demo la co alert RED voi dung RunId.

## 6. Manual Demo - Presenter Flow

Dung phan nay khi muon dieu khien tung buoc tren slide va Kibana UI.

### 6.1 Copy script len endpoint

```bash
cd /home/ubuntu/rule_evasion_detection/Rule_Evasion_Detection

python3 - <<'PY'
import codecs, io, paramiko
from pathlib import Path

src = Path("demo/apt_demo_v2.ps1")
data = src.read_bytes()
if not data.startswith(codecs.BOM_UTF8):
    data = codecs.BOM_UTF8 + data

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("192.168.10.103", username="endpoint", password="123", timeout=15)
with client.open_sftp() as sftp:
    sftp.putfo(io.BytesIO(data), "C:/Users/endpoint/apt_demo_v2.ps1")
client.close()
print("copied")
PY
```

UTF-8 BOM giup PowerShell tren Windows doc file on dinh khi co ky tu dac biet.

### 6.2 Dry run

Chay `-DryRun` de kiem tra script parse duoc tren endpoint ma khong tao event
demo:

```bash
python3 - <<'PY'
import paramiko

command = (
    'powershell -ExecutionPolicy Bypass '
    '-File C:/Users/endpoint/apt_demo_v2.ps1 '
    '-Mode baseline -DryRun'
)

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("192.168.10.103", username="endpoint", password="123", timeout=15)
stdin, stdout, stderr = client.exec_command(command, timeout=120)
del stdin
print(stdout.read().decode("utf-8", errors="replace"))
err = stderr.read().decode("utf-8", errors="replace")
if err:
    print(err)
client.close()
PY
```

Hoac chay truc tiep tren endpoint:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\endpoint\apt_demo_v2.ps1 -Mode baseline -DryRun
```

### 6.3 Chay tung phase

Dung khi muon giai thich tung rule:

```bash
python3 scripts/test_apt_demo_v2.py \
  --mode baseline \
  --phase 1 \
  --run-endpoint \
  --kibana-url http://192.168.10.10:5601 \
  --wait-alert-seconds 300
```

Sau khi xong phase 1, doi `--phase 2`, `--phase 3`, ... `--phase 6`.

### 6.4 Chay manual tren Windows

Tren Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\endpoint\apt_demo_v2.ps1 -Mode benign   -SleepSeconds 1
powershell -ExecutionPolicy Bypass -File C:\Users\endpoint\apt_demo_v2.ps1 -Mode baseline -SleepSeconds 1
powershell -ExecutionPolicy Bypass -File C:\Users\endpoint\apt_demo_v2.ps1 -Mode evasion  -SleepSeconds 1
```

Script se in `RunId`. Neu da chay manual, dung RunId do de poll lai tu Ubuntu:

```bash
python3 scripts/test_apt_demo_v2.py \
  --mode benign \
  --run-id <RunId_benign> \
  --kibana-url http://192.168.10.10:5601 \
  --wait-alert-seconds 120

python3 scripts/test_apt_demo_v2.py \
  --mode baseline \
  --run-id <RunId_baseline> \
  --kibana-url http://192.168.10.10:5601 \
  --wait-alert-seconds 420

python3 scripts/test_apt_demo_v2.py \
  --mode evasion \
  --run-id <RunId_evasion> \
  --kibana-url http://192.168.10.10:5601 \
  --wait-alert-seconds 180
```

## 7. What To Show In Kibana

### 7.1 Benign Sanity Check

Neu co thoi gian, search RunId benign trong `Security -> Alerts`:

```text
<RunId_benign>
```

Ket qua dung: 6 target Sigma rules khong co alert. Neu co alert khac tu catalog
lon, ghi ro day khong phai 6 target rules cua demo.

Dieu can noi:

```text
Benign mode tao cac thao tac doc/list binh thuong. Day la sanity check de tach
khong gian benign voi baseline/evasion truoc khi vao demo chinh.
```

### 7.2 Baseline Security Alerts

Mo:

```text
Kibana -> Security -> Alerts
```

Dat time range rong hon luc chay demo, vi Detection Engine co scheduler lag.
Vi du `Last 30 minutes`.

Search nhanh bang RunId:

```text
<RunId_baseline>
```

Neu UI khong tim du, loc theo 6 rule IDs:

```text
189e3b02-82b2-4b90-9662-411eb64486d4
cc36992a-4671-4f21-a91d-6c2b72a2edf5
85b0b087-eddf-4a2b-b033-d771fa2b9775
b98d0db6-511d-45de-ad02-e82a98729620
24357373-078f-44ed-9ac4-6d334a668a11
e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a
```

Dieu can noi:

```text
Baseline tao dung mau ma Sigma da biet, nen ca raw query va Security Alerts deu 6/6.
```

### 7.3 Evasion Security Alerts

Search RunId evasion trong `Security -> Alerts`:

```text
<RunId_evasion>
```

Ket qua dung: khong co alert nao tu 6 target Sigma rules. Co the van co alert
khac neu rule khac trong catalog bat trung hanh vi phu. Demo claim chi noi 6
target rules da miss.

Dieu can noi:

```text
Cung y do hanh vi, nhung doi representation: split string, char-code, doi utility,
inline scheme, API runtime. Cac exact-match Sigma target khong con match.
```

### 7.4 RED Alerts

Mo Discover, chon cac data view/index:

```text
red-alerts-demo
red-alerts-powershell-demo
red-alerts-registry-demo
```

Search:

```text
<RunId_evasion>
```

Fields nen show:

```text
@timestamp
host.name
winlog.event_id
red.detection_score
red.top_rule
red.top_rule_sigma_title
red.command_line
```

Dieu can noi:

```text
Sigma target miss, nhung RED van cham diem nghi van va gan event ve rule gan nhat.
Day la lop bo sung de bat evasion, khong phai thay the Sigma.
```

## 8. Verified Results

Verified tren `DESKTOP-IQAM883`, ngay `2026-05-24` gio VN.

| Test | RunId | Result |
|---|---|---|
| Baseline raw Sigma query | `4035abf9` | 6/6 target queries match, moi target dung 1 event |
| Baseline Kibana Security Alerts | `4035abf9` | 6 unique target Sigma alerts materialized sau scheduler lag |
| Evasion raw Sigma query | `f73f19ba` | 0/6 target queries match |
| Evasion Kibana Security Alerts | `f73f19ba` | 0/6 target Sigma alerts |
| Evasion RED ML backfill | `f73f19ba` | 11 RED alerts trong `red-alerts-v2-test`, score `0.5887` den `1.0` |
| Re-test baseline | `5826f4be` | raw Sigma 6/6 + Security Alerts 6/6 voi live Kibana ECS query |
| Re-test evasion | `b64a6298` | raw Sigma 0/6 + Security Alerts 0/6; RED live catch 22 alerts |
| Benign sanity end-to-end | `87d05364` | 21 raw events ingested; raw Sigma 0/6 + Security Alerts 0/6 (PASS = expected) |

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
EID 1    score 1.0000  suspicious_runas_like_flag_combination          ssh/cmd parent marker
EID 1    score 1.0000  local_file_read_using_curl_exe                  curl.exe marker
EID 1    score 1.0000  potential_lethalhta_technique_execution         mshta inline scheme
EID 4104 score 0.6158  hacktool_evil_winrm_execution_powershell_module phase1 char-code
EID 4104 score 0.5887  hacktool_rubeus_execution_scriptblock           phase2 split token
EID 4104 score 0.8264  powershell_script_with_file_upload_capabilities phase6 runtime base64
```

## 9. Troubleshooting

| Trieu chung | Nguyen nhan hay gap | Cach xu ly |
|---|---|---|
| `curl ...:5601` fail voi HTTPS | Kibana lab chay HTTP | Dung `http://192.168.10.10:5601` |
| `--check-only` bao `MISSING` | Rule chua import hoac sai space | Import lai `windows_sigma_elastic_ecs.ndjson` |
| `raw_events=0` | Endpoint chua gui log, Elastic Agent freeze, sai time range | Restart Elastic Agent; check `logs-windows.*`; check clock |
| `raw_sigma=PASS`, `security_alerts=FAIL` | Detection Engine scheduler lag | Doi 1-5 phut, tang `--wait-alert-seconds 420` |
| UI Kibana khong thay alert nhung script PASS | Time range/filter trong UI qua hep | Chon `Last 30 minutes`, search RunId |
| Baseline raw query 0/6 nhung alert co | Dung sai NDJSON/profile | Dung script moi: live Kibana query/ECS default |
| Evasion van co Security Alerts khac | Rule khac trong catalog bat trung | Claim demo chi la 6 target Sigma rules miss |
| RED alert bi duplicate | Nhieu `detect_live.py` daemon chay song song | Kiem tra `ps -ef | grep detect_live`; giu 1 daemon moi event type |

Restart Elastic Agent tren Windows neu log dung lai:

```powershell
sc stop "Elastic Agent"
Start-Sleep -Seconds 10
sc start "Elastic Agent"
```

Kiem tra daemon RED tren Ubuntu:

```bash
ps -ef | grep detect_live | grep -v grep
```

## 10. Cleanup

`apt_demo_v2.ps1` tu tao cleanup job sau 60 giay cho registry artifacts neu
khong dung `-KeepArtifacts`.

Neu can cleanup tay tren endpoint:

```powershell
$RunId = "<RunId>"
$Name = "RED_DEMO_V2_$RunId"
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
  -Name $Name -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" `
  -Name $Name -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\red_v2_*_$RunId.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\red_v2_p6_*_$RunId.txt" -Force -ErrorAction SilentlyContinue
```

## 11. Short Talk Track

Dung doan nay khi can noi nhanh trong 1-2 phut:

```text
Demo nay co 3 mode. Benign la sanity check: 6 target rules khong fire voi thao
tac binh thuong. Baseline tao dung 6 mau ma Sigma da biet, nen Elastic Security
fire du 6 alert. Evasion giu cung y do tan cong nhung doi cach bieu dien: split
string, char-code, doi utility, inline scheme va runtime API. Sau khi doi
representation, 6 target Sigma rules khong con match. RED ML van bat lai cac
event nay va gan attribution ve rule/hanh vi gan nhat. Vi vay RED khong thay
Sigma, ma bo sung mot lop adversarial-aware detection khi exact-match rule bi ne
tranh.
```
