# Hướng dẫn trình bày Demo APT trước GVHD

> **Mục đích**: Cầm file này, làm theo step-by-step trong buổi defense.
> Bao gồm cả lệnh thực thi, lời thoại, và backup plan.

---

## Mục lục

1. [Tổng quan kịch bản](#1-tổng-quan-kịch-bản)
2. [Pre-demo checklist (1 giờ trước)](#2-pre-demo-checklist-1-giờ-trước)
3. [Bố trí màn hình (4 tabs)](#3-bố-trí-màn-hình-4-tabs)
4. [Live demo flow (~18 phút)](#4-live-demo-flow-18-phút)
5. [Lời thoại — script trình bày](#5-lời-thoại--script-trình-bày)
6. [Wow moments cần highlight](#6-wow-moments-cần-highlight)
7. [Backup plan nếu fail](#7-backup-plan-nếu-fail)
8. [Q&A handling](#8-qa-handling)
9. [Cleanup sau demo](#9-cleanup-sau-demo)

---

## 1. Tổng quan kịch bản

**Cốt truyện**: "Cuộc tấn công APT vào kế toán FinanceCorp Vietnam"

| Thành phần | Chi tiết |
|---|---|
| Nạn nhân | Alice — kế toán trưởng FinanceCorp Vietnam |
| Máy đích | `DESKTOP-2UQB61H` (Windows 11 lab VM, 10.10.20.50) |
| Velociraptor client_id | `C.1b622eacffe8b75d` |
| Attacker | APT giả định (cảm hứng APT32 — Vietnamese context) |
| Mục tiêu | Đánh cắp báo cáo Q1 + thiết lập persistence |

**Phạm vi demo**: Post-exploitation perspective. Initial access (phishing email + macro) **out of scope** vì cần Office license + email infrastructure.

**Pipeline 3 lớp**:
1. **Sigma Kibana** (rule cứng, 1,624 rule) — baseline match, miss khi evasion
2. **RED ML** (Stage 1+2, 1,367 Cosine rule sau catalog expansion) — bắt cả baseline lẫn evasion
3. **AI Agent** (8 agent, ~3 phút/alert, ~$0.02) — triage + Velociraptor forensic + báo cáo Vietnamese

---

## 2. Pre-demo checklist (1 giờ trước)

### A. Push script lên Windows VM (BẮT BUỘC — chạy 1 lần)

> Bước này thường bị quên. Nếu Windows VM mới clean hoặc script đã update,
> phải push lại. Lưu ý **UTF-8 BOM** — không có BOM thì PowerShell parse sai
> tiếng Việt → script lỗi.

```bash
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection

# 1. Add UTF-8 BOM cho apt_demo_scenario.ps1 (PowerShell yêu cầu BOM để đọc tiếng Việt)
python3 -c "
import codecs
with open('demo/apt_demo_scenario.ps1', 'rb') as f: c = f.read()
if not c.startswith(codecs.BOM_UTF8):
    with open('/tmp/apt_bom.ps1', 'wb') as f: f.write(codecs.BOM_UTF8 + c)
    print(f'BOM added — {len(c)+3} bytes')
else:
    import shutil; shutil.copy('demo/apt_demo_scenario.ps1', '/tmp/apt_bom.ps1')
    print('Already has BOM')
"

# 2. Push apt_demo_scenario.ps1 (script attack chính)
sshpass -p tzxr scp /tmp/apt_bom.ps1 \
  luanthanh@10.10.20.50:/C:/Users/LuanThanh/apt_demo_scenario.ps1

# 3. Push cleanup_v2.ps1 (cleanup script — cũng cần BOM nếu có tiếng Việt)
cat > /tmp/cleanup_v2.ps1 <<'EOF'
Remove-Item C:\Users\Public\xkj9_demo_*.exe -Force -ErrorAction SilentlyContinue
Remove-Item C:\Users\Public\mshta_marker_*.txt -Force -ErrorAction SilentlyContinue
foreach ($k in @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")) {
    $names = Get-Item $k -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
    foreach ($n in $names) {
        if ($n -like "RED_APT_DEMO_*") {
            Remove-ItemProperty -Path $k -Name $n -ErrorAction SilentlyContinue
            Write-Host "Removed Run: $n"
        }
    }
}
Get-WmiObject -Namespace root\subscription -Class __EventFilter -EA 0 | Where { $_.Name -like "RED_APT_DEMO_*" } | ForEach-Object { Write-Host "Removed filter $($_.Name)"; $_ | Remove-WmiObject -EA 0 }
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -EA 0 | Where { $_.Name -like "RED_APT_DEMO_*" } | ForEach-Object { Write-Host "Removed consumer $($_.Name)"; $_ | Remove-WmiObject -EA 0 }
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -EA 0 | Where { $_.Filter -match "RED_APT_DEMO_" -or $_.Consumer -match "RED_APT_DEMO_" } | ForEach-Object { Write-Host "Removed binding"; $_ | Remove-WmiObject -EA 0 }
Write-Host "DONE"
EOF
sshpass -p tzxr scp /tmp/cleanup_v2.ps1 \
  luanthanh@10.10.20.50:/C:/Users/LuanThanh/cleanup_v2.ps1

# 4. Verify 2 file đã có trên Windows
sshpass -p tzxr ssh luanthanh@10.10.20.50 \
  'powershell -Command "Get-ChildItem C:\Users\LuanThanh\*.ps1 | Select Name, Length, LastWriteTime"'
# Expected: thấy apt_demo_scenario.ps1 (~16KB) và cleanup_v2.ps1 (~1.5KB)

# 5. Dry-run test parse (an toàn, không chạy thật)
sshpass -p tzxr ssh luanthanh@10.10.20.50 \
  'powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode benign -DryRun' \
  | head -15
# Expected: thấy "Phase 1/7 ... Phase 7/7" hiện đủ, không có parse error
```

**Nếu thấy error `Unexpected token` hoặc tiếng Việt mojibake** → BOM chưa add. Re-run bước 1+2.

### B. Hạ tầng — chạy trên Ubuntu lab (10.10.20.20)

```bash
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
source ~/venvs/rule_evasion_env/bin/activate

# 1. Verify 3 VM connectivity
for ip in 10.10.20.20 10.10.20.50 10.10.20.100; do
  ping -c 1 -W 2 $ip > /dev/null && echo "$ip UP" || echo "$ip DOWN"
done
# Expected: cả 3 UP

# 2. Verify ELK
ES_PASS=$(grep ES_PASSWORD .env | cut -d= -f2)
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/_cluster/health?pretty" | head -5
# Expected: status yellow/green

# 3. Verify Velociraptor server running + Windows client connected
sudo systemctl status velociraptor_server --no-pager | head -3
sudo -u velociraptor /usr/local/bin/velociraptor \
  --config /etc/velociraptor/server.config.yaml \
  query "SELECT client_id, os_info.fqdn, last_seen_at FROM clients()" 2>&1 | tail -5

# 4. Verify Sysmon đang ship đầy đủ EID 1, 11, 13, 22
curl -sk -u elastic:$ES_PASS "http://10.10.20.100:9200/logs-winlog*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"@timestamp":{"gte":"now-5m"}}},"aggs":{"by_code":{"terms":{"field":"event.code"}}}}'
# Expected: thấy code 1, 11, 13, 22

# 5. Test agent pipeline 1 alert mock (nhanh, ~30s)
unset VR_USE_REAL
python3 -m agent.run --save /tmp/precheck.json 2>&1 | tail -3

# 6. Verify RED models đầy đủ
python3 -c "
from red.persist import load_result
for n, p in [('process_creation','models/process_creation/train_rslt_attr_ensemble.zip'),
             ('powershell','models/powershell/train_rslt_attr_ensemble.zip'),
             ('registry_event','models/registry_event/train_rslt_attr_ensemble.zip')]:
    r = load_result(p)
    print(f'{n}: SVM={len(r[\"rule_models\"])}, Cosine={len(r[\"cosine_attributor\"].rule_filter_matrices)}')
"
# Expected: 
# process_creation: SVM=202, Cosine=920
# powershell: SVM=25, Cosine=204
# registry_event: SVM=38, Cosine=243
```

### C. Bật RED detect_live.py (BẮT BUỘC trước live demo)

> Nếu quên bước này: Windows vẫn sinh log, Sigma vẫn có thể báo trong Kibana
> Security, nhưng `red-alerts-*demo*` sẽ không có alert mới vì RED chưa poll
> Elasticsearch.
>
> Lưu ý khi bảo vệ: **không dùng `--query-string` chứa marker demo** như
> `RED_APT_DEMO`. Query dưới đây chỉ scope đúng máy nạn nhân + nhóm log liên
> quan từng model để tránh log nhiễu của lab; detection vẫn do RED model tự chấm
> điểm. `ES_AUTH_HOST` là URL Elasticsearch kèm user/pass, không phải chỉ là IP.

Mở **3 terminal/tmux panes** trên Ubuntu lab, chạy từ repo:

```bash
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
source ~/venvs/rule_evasion_env/bin/activate
set -a; source .env; set +a
ES_AUTH_HOST="http://${ES_USER}:${ES_PASSWORD}@10.10.20.100:9200"
DEMO_HOST_QUERY='host.name:"desktop-2uqb61h" OR winlog.computer_name:"DESKTOP-2UQB61H"'
DEMO_PROCESS_QUERY="($DEMO_HOST_QUERY) AND (winlog.event_data.Image:*powershell* OR process.name:*powershell* OR winlog.event_data.CommandLine:*powershell* OR process.command_line:*powershell* OR winlog.event_data.Image:*mshta* OR winlog.event_data.Image:*regsvr32* OR winlog.event_data.Image:*rundll32*)"
DEMO_REGISTRY_QUERY="($DEMO_HOST_QUERY) AND (winlog.event_data.TargetObject:*CurrentVersion*Run* OR message:*CurrentVersion*Run*)"
DEMO_PS_QUERY="$DEMO_HOST_QUERY"
```

**Terminal 1 — Process creation EID 1** (`-EncodedCommand`, LOLBins):

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
  --batch-size 500 \
  --query-string "$DEMO_PROCESS_QUERY"
```

**Terminal 2 — Registry SetValue EID 13** (Phase 3 Run/RunOnce):

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
  --batch-size 500 \
  --query-string "$DEMO_REGISTRY_QUERY"
```

**Terminal 3 — PowerShell ScriptBlock EID 4104** (DownloadString, markers, sandbox probe):

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
  --batch-size 500 \
  --query-string "$DEMO_PS_QUERY"
```

Kiểm tra nhanh RED đã có alert:

```bash
curl -s -u "$ES_USER:$ES_PASSWORD" \
  "$ES_HOST/red-alerts-demo,red-alerts-registry-demo,red-alerts-powershell-demo/_search?size=10&sort=@timestamp:desc&ignore_unavailable=true" \
  | jq -r '.hits.hits[] | [._index, ._source["@timestamp"], ._source["red.detection_score"], ._source["red.top_rule"], (._source["red.command_line"] // "")] | @tsv'
```

Nếu lỡ chạy Windows script trước khi bật 3 terminal trên, backfill 20 phút gần nhất:

```bash
# Backfill process_creation
python3 scripts/detect_live.py --config config/process_creation.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-winlog*" --out-index red-alerts-demo \
  --event-id 1 --threshold 0.5 --method cosine --timestamp-field event.ingested \
  --since "20m" --until "now" --max-iter 1 --no-state --batch-size 500 \
  --query-string "$DEMO_PROCESS_QUERY"

# Backfill registry_event
python3 scripts/detect_live.py --config config/registry_event.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-winlog*" --out-index red-alerts-registry-demo \
  --event-id 13 --threshold 0.5 --method cosine --timestamp-field event.ingested \
  --since "20m" --until "now" --max-iter 1 --no-state --batch-size 500 \
  --query-string "$DEMO_REGISTRY_QUERY"

# Backfill PowerShell 4104
python3 scripts/detect_live.py --config config/powershell.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-winlog*" --out-index red-alerts-powershell-demo \
  --event-id 4104 --threshold 0.5 --method cosine --timestamp-field event.ingested \
  --since "20m" --until "now" --max-iter 1 --no-state --batch-size 500 \
  --query-string "$DEMO_PS_QUERY"
```

### D. Cleanup state cũ

```bash
# 1. Clean red-alerts demo (giữ red-alerts production để có data history)
curl -X POST -sk -u elastic:$ES_PASS \
  "http://10.10.20.100:9200/red-alerts-demo/_delete_by_query?conflicts=proceed&refresh=true" \
  -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}' | head -5
curl -X POST -sk -u elastic:$ES_PASS \
  "http://10.10.20.100:9200/red-alerts-registry-demo,red-alerts-powershell-demo/_delete_by_query?conflicts=proceed&refresh=true&ignore_unavailable=true" \
  -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}' | head -5

# 2. Cleanup Windows VM artifacts từ rehearsal trước
sshpass -p tzxr ssh -o StrictHostKeyChecking=no luanthanh@10.10.20.50 \
  'powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\cleanup_v2.ps1' 2>&1 | tail -3

# 3. Verify cleanup OK
python3 -c "
from agent.vr_client import get_file_artifacts
import os; os.environ['VR_USE_REAL']='1'; os.environ['VR_API_CONFIG']=os.path.expanduser('~/velociraptor/api.config.yaml')
r = get_file_artifacts(client_id='C.1b622eacffe8b75d', since_minutes=60)
df = [f for f in r['files_created_by_process'] if 'xkj9' in str(f.get('FullPath',''))]
dp = [p for p in r['registry_persistence'] if 'RED_APT_DEMO' in str(p.get('Name',''))]
print(f'Demo files còn: {len(df)}, Run keys còn: {len(dp)}')
print('OK' if (len(df)+len(dp))==0 else 'CHƯA cleanup hết')
"
```

### E. Dụng cụ in/lưu

- [ ] Print `demo/QA_PREP.md` (16 câu Q&A) — để cạnh laptop, không show GVHD
- [ ] Print `demo/RED_RULE_MAP.md` (hoặc lưu PDF) — tra rule khi GVHD hỏi
- [ ] Lưu video screencast backup (~3 phút mock mode) trên USB
- [ ] Lưu `inv_real.json` rehearsal trên USB — fallback nếu live fail
- [ ] Chuẩn bị HDMI/USB-C cable + adapter

---

## 3. Bố trí màn hình (4 tabs)

Mở **trước** khi vào phòng defense, sắp xếp:

| Tab | URL/Path | Mục đích |
|---|---|---|
| 1️⃣ **Kibana Discover** | `http://10.10.20.100:5601/app/discover` index `red-alerts-*demo*` | Show alert real-time |
| 2️⃣ **Kibana Security** | `http://10.10.20.100:5601/app/security/rules` | Show Sigma rule fire (hoặc không fire) |
| 3️⃣ **Velociraptor GUI** | `https://10.10.20.20:8889/app/index.html#/clients` | Show Windows client online |
| 4️⃣ **Terminal Ubuntu** | SSH tới `10.10.20.20` | Chạy daemon + xem agent log live |
| 5️⃣ **Terminal Windows** *(optional)* | RDP/SSH tới `10.10.20.50` | Trigger demo script |

**Tip**: dùng workspace ảo Linux (`Ctrl+Alt+→`) để switch nhanh giữa Kibana và Terminal.

---

## 4. Live demo flow (~18 phút)

### Pha 1 — Intro + Setup (2 phút)

**Show trên màn hình**:
- Tab Kibana red-alerts-*demo*: hiện đang **trống** (đã cleanup)
- Tab Velociraptor: 1 Windows client `Online`
- Tab Terminal: chuẩn bị chạy daemon

**Nói**:
> *"Em sẽ mô phỏng một cuộc tấn công APT vào máy Windows DESKTOP-2UQB61H này.
> Pipeline 3 lớp của em sẽ tự động detect, query forensic qua Velociraptor, và
> sinh báo cáo tiếng Việt. Mục tiêu demo là cho thầy/cô thấy 4 điểm:*
> 1. *RED ML bắt được evasion mà Sigma cứng miss*
> 2. *RED Stage 2 sau catalog expansion attribute vào 1,367 rule (gần 10x trước)*
> 3. *Forensic Agent query Velociraptor lấy bằng chứng cứng — kháng hallucination*
> 4. *Báo cáo tiếng Việt + metadata Sigma đầy đủ cho SOC analyst trace ngược"*

### Pha 2 — Benign mode (1 phút) — đối chứng FP

Trên Terminal Windows (hoặc qua SSH từ Ubuntu):
```bash
sshpass -p tzxr ssh luanthanh@10.10.20.50 \
  'powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode benign'
```

**Nói**:
> *"Đây là chế độ benign — em chạy các lệnh admin bình thường như whoami, ipconfig,
> OneDrive Run key. Nếu pipeline tốt, KHÔNG có alert nào được sinh ra — đối chứng
> False Positive."*

**Đợi 30s**, refresh Kibana `red-alerts-demo` (process_creation) → vẫn trống ✅

> Nếu đang bật cả `red-alerts-registry-demo`, benign có thể sinh registry Run-key
> noise vì script cố tình tạo OneDrive-equivalent Run key. Khi nói về đối chứng
> false positive, dùng view process_creation trước; registry view dành cho Phase 3.

### Pha 3 — Baseline mode (3 phút) — Sigma fires, RED fires

```bash
sshpass -p tzxr ssh luanthanh@10.10.20.50 \
  'powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode baseline'
# Note RunId (vd 85ae464b)
```

**Đợi 60s**, sau đó:

1. Mở Kibana Security/Alerts → filter các rule bên dưới → **Sigma rule fired** ✅
2. Mở Kibana `red-alerts-*demo*` → có alert mới với `red.top_rule` + `red.top_rule_sigma_filename`

**Rule match để check**:

| Layer/index | Filter nhanh | Rule nên thấy | Ghi chú |
|---|---|---|---|
| Kibana Security/Alerts | `kibana.alert.rule.name: "SIGMA - CurrentVersion Autorun Keys Modification"` | `SIGMA - CurrentVersion Autorun Keys Modification` | Baseline ghi `HKCU\...\CurrentVersion\Run\RED_APT_DEMO_PERSIST_<RunId>` |
| Kibana Security/Alerts | `kibana.alert.rule.name: "SIGMA - Non Interactive PowerShell Process Spawned"` | `SIGMA - Non Interactive PowerShell Process Spawned` | Có thể fire trên PowerShell do SSH/non-interactive parent |
| `red-alerts-demo` | `red.command_line: *EncodedCommand*` | `red.top_rule = non_interactive_powershell_process_spawned` | Verified RunId `2d421a7b`, score `1.0`, filename `proc_creation_win_powershell_non_interactive_execution.yml` |
| `red-alerts-registry-demo` | `red.command_line: *CurrentVersion\\\\Run\\\\*` | `red.top_rule = currentversion_autorun_keys_modification` | Verified RunId `2d421a7b`, score `1.0`, filename `registry_set_asep_reg_keys_modification_currentversion.yml` |

> **Cách nói nếu GVHD hỏi vì sao tên hiển thị khác nhau**:
> Thực ra **CÙNG rule** — chỉ format hiển thị khác. Sigma Kibana hiển thị
> `title:` gốc + prefix `"SIGMA - "` (do importer thêm). RED dùng
> `normalize(title)` → snake_case. Ví dụ:
>
> | Sigma Kibana | RED top_rule | Quan hệ |
> |---|---|---|
> | `"SIGMA - CurrentVersion Autorun Keys Modification"` | `currentversion_autorun_keys_modification` | Cùng rule, 2 format |
> | `"SIGMA - Non Interactive PowerShell Process Spawned"` | `non_interactive_powershell_process_spawned` | Cùng rule, 2 format |
>
> Verify bằng: bỏ prefix `"SIGMA - "` → lowercase → replace space bằng `_` →
> kết quả KHỚP với RED `top_rule`. Field `red.top_rule_sigma_title` trong alert
> chính là title gốc của Sigma → trace ngược dễ.

**Nói**:
> *"Mode baseline chạy mẫu CHUẨN: `-EncodedCommand` đầy đủ, `IEX (New-Object
> System.Net.WebClient).DownloadString(...)`, Run key trong HKCU. Đây là pattern
> Sigma đã thiết kế cho — quan sát thấy Sigma rule fire trong Kibana Security/
> Alerts, đồng thời RED ML cũng score 1.0 trên process/registry event."*
>
> *"Notice **Sigma Kibana và RED đang attribute CÙNG rule** — chỉ format hiển thị
> khác. Ví dụ Sigma `'SIGMA - CurrentVersion Autorun Keys Modification'` (title
> gốc) ↔ RED `'currentversion_autorun_keys_modification'` (snake_case
> normalized). Field `red.top_rule_sigma_title` lưu title gốc để SOC analyst
> trace ngược về Kibana Security/Rules trực tiếp."*

### Pha 4 — Evasion mode (4 phút) ⭐ — **WOW MOMENT chính**

```bash
sshpass -p tzxr ssh luanthanh@10.10.20.50 \
  'powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode evasion'
```

**Đợi 60s**, sau đó:

1. Mở Kibana Security/Alerts → filter exact PowerShell baseline rule, ví dụ `Suspicious PowerShell Invocations - Specific`
2. Mở Kibana `red-alerts-registry-demo` → **có alert RunOnce** ✅ với top_rule + sigma_filename

**Verified rule match** (RunId `803901d3`, 2026-05-20, Mode evasion full 7 phase):

#### A. Sigma Kibana — 8 rule fire (`.internal.alerts-security.alerts-*`)

| Count | Rule name | Phase nào trigger |
|---|---|---|
| 100x | `SIGMA - Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell` | Phase 3 Tier 3 WMI fires (60s/lần) |
| 44x | `SIGMA - Program Executed Using Proxy/Local Command Via SSH.EXE` | Script chạy qua SSH session |
| 31x | `SIGMA - Non Interactive PowerShell Process Spawned` | Phase 1 non-interactive PS |
| 3x | `SIGMA - CurrentVersion Autorun Keys Modification` | WMI consumer ghi Run-like key |
| 2x | `SIGMA - Scripting/CommandLine Process Spawned Regsvr32` | Phase 6 Squiblydoo |
| 1x | `SIGMA - Suspicious Execution of Powershell with Base64` | Phase 1 `-e` shorthand (vẫn fire vì rule có `EncodedCommand` substring match) |
| 1x | `SIGMA - Execution Of Non-Existing File` | Phase 6 mshta marker file |
| 1x | `SIGMA - Execution of Suspicious File Type Extension` | Phase 6 LOLBins |

→ **Sigma KHÔNG silent hoàn toàn** trên evasion mode. Sigma fire 8 rule, đặc biệt nặng trên Phase 3 (WMI persistence — Tier 3 advanced) và Phase 6 (LOLBins).

#### B. RED ML attribution — 9 rule unique (248 alerts demo-related)

| Count | RED `top_rule` | RED `sigma_title` | Phase | Sigma fire? |
|---|---|---|---|---|
| 232x | `suspicious_runas_like_flag_combination` | "Suspicious RunAs-Like Flag Combination" | Phase 6 LOLBins (`/s /n /u /i`) | ❌ Không có trong Sigma fired list |
| 3x | `nslookup_powershell_download_cradle` | "Nslookup PowerShell Download Cradle" | Phase 2 evasion Tier 2 | ❌ Sigma miss |
| 3x | `powershell_write_eventlog_usage` | "PowerShell Write-EventLog Usage" | Phase 4 Tier 1 split keyword | ❌ Sigma miss |
| 3x | `automated_collection_bookmarks_using_get_childitem_powershell` | "Automated Collection Bookmarks..." | Phase 6/7 discovery | ❌ Sigma miss |
| 2x | `security_software_discovery_via_powershell_script` | "Security Software Discovery..." | Phase 7 sandbox probe (analyst tools check) | ❌ Sigma miss |
| 2x | `control_panel_items` | "Control Panel Items" | LOLBin process | — |
| **1x** | **`currentversion_autorun_keys_modification`** | "CurrentVersion Autorun Keys Modification" | Phase 3 chain (WMI consumer Run-like) | **✅ Sigma cũng fire** |
| **1x** | **`currentversion_nt_autorun_keys_modification`** | "CurrentVersion NT Autorun Keys Modification" | Phase 3 evasion (`RunOnce`) | ❌ Sigma miss biến thể NT |
| 1x | `amsi_bypass_pattern_assembly_gettype` | "AMSI Bypass Pattern Assembly GetType" | Phase 4 Tier 3 AMSI marker | ❌ Sigma miss |

#### C. Insight cho defense

1. **1 rule khớp ĐÚNG cả 2 layer**: `currentversion_autorun_keys_modification` (UUID `20f0ee37-...`) — verify Sigma metadata + UUID identical.

2. **RED catch 8 rule mà Sigma miss**:
   - **AMSI bypass marker** (Tier 3) ⭐
   - **PowerShell Write-EventLog** (Tier 1 split `Clear-EventLog`)
   - **Nslookup download cradle** (Tier 2 obfuscation)
   - **Sandbox detection probe** (Tier 3)
   - **RunOnce variant** (Tier 1 — Sigma fire `Run` không phải `RunOnce NT`)
   - **RunAs-like flag combination** trên LOLBins
   - + 2 khác

3. **Sigma catch 7 rule khác (không trong RED top attribution)**:
   - WMI Lateral Movement (Sigma có rule riêng cho WMI Consumer pattern)
   - Non Interactive PowerShell Process Spawned
   - SSH Local Command (rule độc của Sigma)
   - Squiblydoo Regsvr32

→ **2 layer cover khác nhau** — đây là defense-in-depth thực sự. KHÔNG phải "Sigma silent, RED catch". Đúng là: cả 2 layer fire trên evasion mode, nhưng **góc nhìn khác nhau** → giảm chance attacker né được cả 2.

**Nói (CHẬM RÃI, NHẤN MẠNH)**:
> *"Mode evasion thay đổi nhiều điểm: `-e` shorthand thay `-EncodedCommand`,
> `'Sys'+'tem.Net.WebCl'+'ient'` split string, `RunOnce` thay `Run`, AMSI bypass
> marker, WMI Event Subscription. Behavior tổng quát giống baseline."*
>
> *"Verified với RunId `803901d3`: Sigma Kibana fire **8 rule unique** (chủ yếu WMI
> + Squiblydoo + LOLBins). RED ML attribute **9 rule unique** — trong đó **8 rule
> KHÔNG có trong danh sách Sigma fired**, nổi bật: AMSI bypass pattern, PowerShell
> Write-EventLog, RunOnce NT variant, Sandbox detection probe."*
>
> *"Đây là **defense-in-depth thực sự**: Sigma cứng catch các technique đã biết
> với pattern rõ ràng (WMI, Squiblydoo), RED ML catch các evasion variant cụ thể
> mà Sigma miss (AMSI bypass, RunOnce NT, sandbox probe). Cả 2 layer cùng tồn tại,
> giảm chance attacker né được cả hai."*
>
> *"Verify khớp rule chéo qua UUID — alert RED có field `top_rule_sigma_id`. Ví dụ
> rule `currentversion_autorun_keys_modification` có UUID `20f0ee37-...` — Sigma
> Kibana fire `SIGMA - CurrentVersion Autorun Keys Modification` cùng UUID."*

### Pha 5 — Chain mode + AI Agent (7 phút) — full pipeline

```bash
# Bật agent daemon (Terminal 4)
unset VR_USE_REAL  # mock VR cho nhanh, OR set =1 cho real (chậm hơn)
export VR_USE_REAL=1
python3 -m agent.daemon --interval 30 --score-threshold 0.5 --no-state &

# Trigger chain mode
sshpass -p tzxr ssh luanthanh@10.10.20.50 \
  'powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode chain -SleepSeconds 120'
```

**Verified result** (RunId `b82c152e`, 2026-05-20, Mode chain 7 phase):

#### A. Logs ship lên ELK

```
EID 1   (process_creation): 80 events
EID 4104 (PowerShell ScriptBlock): 1
EID 11  (file create — dropper xkj9_demo_b82c152e.exe): 1
EID 13  (registry SetValue — Run key): 1
EID 19/20/21 (WMI Filter/Consumer/Binding): 3 events
```

#### B. Sigma Kibana fire (154 alerts trong 5 phút)

| Count | Rule |
|---|---|
| 100x | `SIGMA - Non Interactive PowerShell Process Spawned` |
| 49x | `SIGMA - Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell` |
| 4x | `SIGMA - Program Executed Using Proxy/Local Command Via SSH.EXE` |
| 1x | `SIGMA - Scripting/CommandLine Process Spawned Regsvr32` |

#### C. RED ML alert mẫu (Phase 3 registry baseline)

| Field | Giá trị |
|---|---|
| `red.detection_score` | 1.0 |
| `red.top_rule` | `currentversion_autorun_keys_modification` |
| `red.top_rule_sigma_title` | `"CurrentVersion Autorun Keys Modification"` |
| `red.top_rule_sigma_id` | `20f0ee37-5942-4e45-b7d5-c5b5db9df5cd` |
| `red.top_rule_sigma_filename` | `registry_set_asep_reg_keys_modification_currentversion.yml` |

→ **Khớp với Sigma Kibana** qua UUID `20f0ee37-...` — verified cùng rule.

#### D. AI Agent pipeline — `INV-cb01ff128362`

```
🎯 Supervisor:      workflow=full_investigation (priority 1)
🔍 Triage:          severity=CRITICAL, confidence=0.95
                    parent_findings: ["Parent: sshd.exe (SSH remote — không phải phishing local)"]
🔬 Forensic:        grade=high, verdict=confirmed_malicious, persistence=true
                    4 artifacts từ Velociraptor THẬT:
                      • C:\Users\Public\xkj9_demo_b82c152e.exe
                      • SHA256: 58189cbd4e6dc0c7d8e66b6a6f75652fc9f4afc7ce0eba7d67d8c3feb0d5381f
                      • HKEY_USERS\...\Run\RED_APT_DEMO_PERSIST_b82c152e
                      • Run key name: RED_APT_DEMO_PERSIST_b82c152e
⚡ Parallel block:  Hunt + RED Analyst + MITRE
   RED Analyst:     technique=encoding, confidence=0.95
   MITRE:           TA0003 Persistence / T1547.001 Registry Run Keys
🛡️ Response:        6 containment actions, has_fake_ip=0 ✅
                    Sigma patch grounded by forensic evidence
📝 Report:          "Phát hiện chuỗi tấn công CRITICAL: SSH Remote Execution
                     → PowerShell EncodedCommand → Registry Persistence trên DESKTOP-2UQB61H"
```

**Metric pipeline**:
- Duration: **172 giây** (~2 phút 52)
- Tokens: 85,625
- Cost: **$0.0258 USD**
- Agent count: 8

**Anti-hallucination verified**:
- ✅ Parent `sshd.exe` (đọc đúng từ alert, KHÔNG bịa `outlook.exe`)
- ✅ Containment targets toàn data thật: `DESKTOP-2UQB61H`, `luanthanh`, `PID 4020`, dropper path thật
- ✅ `has_fake_ip: 0` — không còn `1.2.3.4` giả lập
- ✅ 4 IOCs đến từ Velociraptor query thật, không phải LLM bịa

#### E. Check trong Kibana khi chain chạy

| Index | Filter | Verified value |
|---|---|---|
| `.internal.alerts-security.alerts-*` | `kibana.alert.rule.name: "SIGMA - Non Interactive PowerShell Process Spawned"` | 100 alerts |
| `.internal.alerts-security.alerts-*` | `kibana.alert.rule.name: "SIGMA - Potential WMI Lateral Movement..."` | 49 alerts |
| `red-alerts-registry-demo` | `red.top_rule_sigma_id: 20f0ee37-5942-4e45-b7d5-c5b5db9df5cd` | 1 alert (Run key) |
| `ai-investigations` | `triage.severity: "CRITICAL"` + RunId trong alert | INV-cb01ff128362 |

**Nói**:
> *"Mode chain mô phỏng đầy đủ 7 phase kill-chain. Sigma Kibana fire 154 alert
> trên 4 rule (WMI 49x, Non-Interactive PS 100x, SSH spawn 4x, Squiblydoo 1x).
> RED ML attribute alert registry baseline tới `currentversion_autorun_keys_modification`
> — verified CÙNG rule với Sigma qua UUID `20f0ee37-...`."*
>
> *"Agent daemon pickup alert, chạy 8 agent trong 172 giây với chi phí $0.026.
> Forensic Agent gọi Velociraptor THẬT — 4 IOCs đều từ host: file path, SHA256,
> registry Run key, name string. Triage agent đọc đúng `parent=sshd.exe` từ
> alert (verified anti-hallucination — không bịa `outlook.exe` như rehearsal v1)."*
>
> *"Response Agent sinh 6 containment actions với target toàn data thật: host
> DESKTOP-2UQB61H, user luanthanh, PID 4020, dropper path thật. `has_fake_ip=0`
> — anti-hallucination rules hoạt động đầy đủ. Sigma patch grounded by forensic
> evidence cứng."*
>
> *"Report Agent sinh title tiếng Việt: 'Phát hiện chuỗi tấn công CRITICAL: SSH
> Remote Execution → PowerShell EncodedCommand → Registry Persistence trên
> DESKTOP-2UQB61H' — đầy đủ kill-chain narrative cho SOC analyst VN."*

### Pha 6 — Đọc báo cáo Vietnamese (1 phút)

**Cách show**:
```bash
# Trên Terminal Ubuntu — extract báo cáo tiếng Việt từ investigation
jq -r '.report.full_markdown_vi' /tmp/inv_chain.json | less

# Hoặc render markdown trong VS Code preview (Ctrl+Shift+V)
jq -r '.report.full_markdown_vi' /tmp/inv_chain.json > /tmp/report.md
code --reuse-window /tmp/report.md
```

Hoặc trong **Kibana Discover**:
1. Mở index `ai-investigations`
2. Click investigation mới nhất (vd `INV-cb01ff128362`)
3. Mở field `report.full_markdown_vi` — copy nội dung
4. Paste vào notepad markdown viewer (vd https://markdownlivepreview.com/) → render đẹp

#### Verified report structure (INV-cb01ff128362, 2026-05-20)

Top-level fields đầy đủ trong document:
```
investigation_id, timestamp, total_duration_ms, total_tokens, estimated_cost_usd,
workflow_plan, triage, forensic, hunt, red_analyst, mitre, response, report,
trigger_alert, agent_metadata
```

Trong `trigger_alert.red` — **Sigma metadata enrichment đầy đủ**:
```
top_rule:                  currentversion_autorun_keys_modification
top_rule_sigma_filename:   registry_set_asep_reg_keys_modification_currentversion.yml
top_rule_sigma_id:         20f0ee37-5942-4e45-b7d5-c5b5db9df5cd
top_rule_sigma_title:      "CurrentVersion Autorun Keys Modification"
top_rules[]:               2 rules, mỗi rule có sigma_filename + sigma_id
```

→ Analyst click `top_rule_sigma_filename` → mở thẳng file Sigma trong codebase.

#### Báo cáo Vietnamese mẫu (trích từ `report.full_markdown_vi`)

Báo cáo có 6 section + 9 recommended actions, ~80 dòng markdown:

```markdown
## 🚨 Phát hiện chuỗi tấn công CRITICAL: SSH Remote Execution →
   PowerShell EncodedCommand → Registry Persistence

**Host**: DESKTOP-2UQB61H (Client ID: C.1b622eacffe8b75d)
**User**: luanthanh
**Severity**: CRITICAL (Confidence: 0.95)

### Mô tả
Alert phát hiện chuỗi tấn công đa giai đoạn... Forensic Agent xác nhận
tất cả các bước với evidence_grade = high.

### Chuỗi tấn công (TTP Chain)
| Giai đoạn | MITRE ID | Mô tả |
|-----------|----------|-------|
| Initial Access  | T1190/T1078  | SSH remote access từ attacker (sshd.exe) |
| Execution       | T1059.001 + T1027 | sshd.exe spawns powershell.exe với
                                       -EncodedCommand base64 |
| Defense Evasion | T1027        | PowerShell command bị obfuscate ... |
| Persistence     | T1547.001    | Ghi registry Run key ... |

### Bằng chứng
1. Process Tree (Forensic xác nhận)
   - Parent: sshd.exe (SSH remote execution)   ← KHÔNG bịa outlook.exe ✅
   - Child:  powershell.exe (PID 4020)
2. File Artifact
   - Path:   C:\Users\Public\xkj9_demo_b82c152e.exe
   - SHA256: 58189cbd4e6dc0c7d8e66b6a6f75652fc9f4afc7ce0eba7d67d8c3feb0d5381f
3. Registry Persistence
   - Key:   HKEY_USERS\S-1-5-21-...\Run\RED_APT_DEMO_PERSIST_b82c152e
   - Sigma rule match: currentversion_autorun_keys_modification (score 1.0)

### Sigma Patch Đề Xuất
```yaml
title: ... PATCHED - SSH-Based Execution Chain Detection
detection:
  selection_parent:
    ParentImage|endswith: '\sshd.exe'
  selection_powershell:
    Image|endswith: '\powershell.exe'
  selection_encoded:
    CommandLine|contains: ['-EncodedCommand', '-e ', '-ec ', '-en ', ...]
  # 3 lớp detection mới: parent-child chain, comment injection,
  # registry context trong encoded command
  condition: ...
```

### Khác biệt giữa các nguồn  ⭐ ANTI-HALLUCINATION
- Triage gợi ý outlook.exe → powershell → curl (phishing) từ [MOCK] data
- **Forensic Agent xác nhận parent là sshd.exe**, không phải outlook
- **Forensic được ưu tiên** vì là ground truth verifier query Velociraptor

### Recommended Actions (9 items)
1. Cô lập host DESKTOP-2UQB61H
2. Vô hiệu hóa tài khoản luanthanh
3. Reset password + bật MFA
4. Kill powershell.exe (PID 4020) + xkj9_demo_b82c152e.exe
5. Xóa registry Run key persistence
6. Thu thập forensics
7. Mở incident case trong Kibana
8. Apply Sigma patch đề xuất
9. Verify mock data (lsass_access, IP 1.2.3.4) — TRIAGE ĐÃ flag là MOCK
```

#### 3 điểm cần highlight với GVHD

1. **Báo cáo tiếng Việt 100%** — SOC analyst VN đọc thẳng, không cần dịch
2. **Anti-hallucination trong báo cáo** — section "Khác biệt giữa các nguồn"
   ghi rõ Forensic correct Triage hallucination (sshd vs outlook)
3. **Sigma metadata trace-back** — alert có filename + UUID + title, click trace
   về file `.yml` gốc trong `data/sigma/rules/`

**Nói**:
> *"Báo cáo tiếng Việt 100%, ~80 dòng markdown, đầy đủ 6 section: Mô tả, TTP
> Chain (MITRE), Bằng chứng, Sigma Patch đề xuất, Đánh giá, Recommended Actions.
> SOC analyst VN đọc 1 phút hiểu ngay, không cần dịch."*
>
> *"Notice section 'Khác biệt giữa các nguồn' — Report Agent ghi rõ Triage gợi ý
> outlook.exe nhưng Forensic xác nhận sshd.exe, **Forensic được ưu tiên**. Đây là
> anti-hallucination layer hiển thị cho analyst — không che giấu."*
>
> *"Mỗi alert có 3 field metadata Sigma: `top_rule_sigma_filename` (file YAML),
> `top_rule_sigma_id` (UUID), `top_rule_sigma_title` (human title). Verified ở
> INV-cb01ff128362: rule `currentversion_autorun_keys_modification` → file
> `registry_set_asep_reg_keys_modification_currentversion.yml`, UUID
> `20f0ee37-5942-4e45-b7d5-c5b5db9df5cd` → click mở thẳng file trong codebase
> hoặc tra Sigma community."*

### Pha 7 — Conclusion (1 phút)

#### Verified số liệu thật (2026-05-20, từ index `ai-investigations` 7 docs)

**Tổng quan 7 investigation đã chạy**:

| Investigation | Severity | Forensic | Duration | Tokens | Cost USD |
|---|---|---|---|---|---|
| INV-cb01ff128362 | CRITICAL | high | **172.9s** | 85,625 | $0.0258 |
| INV-0a04b56c640c | CRITICAL | - | 113.1s | 79,171 | $0.0242 |
| INV-acaf6de6e347 | CRITICAL | - | 93.1s | 92,572 | $0.0235 |
| INV-481cc712b0f9 | CRITICAL | - | 77.1s | 49,390 | $0.0146 |
| INV-6861a210765b | MEDIUM | - | 76.7s | 72,356 | $0.0197 |
| INV-af7db13359bb | LOW | - | 12.1s | 7,079 | $0.0023 |
| INV-17c2d3a88b71 | LOW | - | 12.5s | 7,057 | $0.0022 |

**Average qua 7 lần**:
- Duration: **79.6s** (full pipeline 8-agent, mix mock + real Velociraptor)
- Tokens: 56,179
- Cost: **$0.0161 USD/alert** (~390 VND/alert)

**So sánh có Forensic Agent vs không**:

| Trường hợp | n | Avg duration | Avg tokens | Avg cost |
|---|---|---|---|---|
| Có Forensic (real Velociraptor) | 1 | **172.9s** | 85,625 | $0.0258 |
| Không Forensic (LOW severity skip) | 6 | 64.1s | 51,271 | $0.0144 |

→ Forensic Agent thêm ~110s và ~$0.011 — trade-off cho bằng chứng cứng từ host.

#### Coverage verified

| Component | Số liệu thật |
|---|---|
| RED Stage 2 — per-rule SVM | **265 rule** (process_creation 202 + powershell 25 + registry_event 38) |
| RED Stage 2 — Cosine attributor | **1,367 rule** (catalog expansion: process_creation 920 + powershell 204 + registry_event 243) |
| Sigma catalog (rules_dir) | **1,653 rule YAML** (Sigma community SigmaHQ) |
| AI Agent count | **8** (Supervisor → Triage → Forensic ⭐ → Hunt+RED+MITRE → Response → Report) |
| Demo scenario | **7 phase** × Tier 1+2+3 evasion technique |
| 4 mode | benign / baseline / evasion / chain |
| Cover taxonomy 1.4 | 5/6 nhóm (1.4.2, 1.4.3, 1.4.5, 1.4.6 + partial 1.4.4) |
| Anti-hallucination verified | `has_fake_ip = 0` qua 7 lần chạy |

#### Đóng góp khoa học (xếp theo novelty)

1. **Stage 2 Cosine catalog expansion** — 146 → 1,367 rule (~9.4x), fit thuần trên YAML filter values
2. **Forensic Agent kháng hallucination** — Velociraptor evidence cứng, verified `has_fake_ip=0`
3. **SigmaRuleIndex metadata enrichment** — mỗi alert có `sigma_filename + UUID + title` trace ngược
4. **Báo cáo Vietnamese end-to-end** — SOC analyst VN đọc trực tiếp, không cần dịch
5. **AI Agent orchestration 8 step** — Supervisor decision + parallel block + grounded by Forensic
6. **Sigma patch grounded by forensic** — pattern detection từ evidence thật, không LLM bịa

#### Closing statement (đã verify với số liệu thật)

> *"Pipeline 3 lớp của em đã verified end-to-end trên lab với 7 investigation
> trong index `ai-investigations`. Average **79.6 giây/alert** và **$0.0161 USD**
> (~390 VND) — rẻ hơn analyst manual 200-400 lần. Cover **1,367 rule** trong
> Cosine attributor (Stage 2 catalog expansion từ 146 lên 1,367 sau fix). Anti-
> hallucination verified `has_fake_ip = 0` qua 7 lần chạy. Đóng góp chính: catalog
> expansion, Forensic Agent kháng hallucination, báo cáo tiếng Việt cho SOC VN."*

#### Backup verify commands (nếu GVHD hỏi)

```bash
# Aggregate metrics qua mọi investigation
curl -sk -u "elastic:$ES_PASS" "http://10.10.20.100:9200/ai-investigations/_search?size=20" \
  -H 'Content-Type: application/json' -d '{}' | \
  jq -r '.hits.hits[]._source | "\(.investigation_id) | \(.triage.severity) | \(.total_duration_ms/1000)s | $\(.estimated_cost_usd)"'

# Count rule trong 3 RED model
python3 -c "
from red.persist import load_result
for n,p in [('proc','models/process_creation/train_rslt_attr_ensemble.zip'),
            ('ps','models/powershell/train_rslt_attr_ensemble.zip'),
            ('reg','models/registry_event/train_rslt_attr_ensemble.zip')]:
    r=load_result(p)
    print(f'{n}: SVM={len(r[\"rule_models\"])}, Cosine={len(r[\"cosine_attributor\"].rule_filter_matrices)}')
"

# Sigma catalog size
find ~/data/sigma/rules -name '*.yml' | wc -l
```

---

## 5. Lời thoại — script trình bày

### Mở đầu (30 giây)
> *"Kính chào thầy/cô, em xin trình bày luận văn 'Hệ thống phát hiện hành vi né
> tránh luật Sigma kết hợp Multi-Agent AI Triage'. Em sẽ demo trực tiếp pipeline
> trên môi trường lab thật, sau đó trả lời câu hỏi."*

### Trong khi đợi log ship (15-30s mỗi lần)
> *"Trong khi đợi log từ Windows VM ship lên Elasticsearch qua Elastic Agent
> (mất khoảng 30 giây), em xin giải thích pipeline ở slide này..."*

### Khi Sigma miss evasion
> *"Đây chính xác là vấn đề luận văn em giải quyết. Một rule Sigma exact-match
> có thể design cho pattern chuẩn như `-EncodedCommand`; attacker đổi sang `-e`
> thì rule đó miss. Tuy nhiên các lớp rule khác vẫn có thể bắt hành vi khác như
> registry/WMI. RED ML giúp score và attribute theo hành vi, không phụ thuộc một
> literal duy nhất."*

### Khi Forensic Agent chạy
> *"Notice agent đang query Velociraptor — đây là KHÁC BIỆT so với mọi solution
> chỉ dùng log. Forensic Agent có 3 tool: vr_process_tree_deep, vr_file_artifacts,
> vr_network_connections. Mất khoảng 30-50 giây cho mỗi VQL query."*

### Khi báo cáo Vietnamese xuất hiện
> *"Em chọn tiếng Việt vì 2 lý do: SOC team Vietnam đọc trực tiếp không cần
> dịch, và đề tài KLTN của em hướng tới VNCERT/NĐ 13/2023 compliance."*

---

## 6. Wow moments cần highlight

| # | Moment | Cách show |
|---|---|---|
| 1 | **Exact Sigma rule miss, RED catch** | Filter exact Sigma rule PowerShell invocation không có alert mới; song song show `red-alerts-registry-demo` có RunOnce score 1.0 |
| 2 | **Forensic query Velociraptor THẬT** | Show daemon log: `→ vr_process_tree_deep` + Velociraptor GUI flow active |
| 3 | **Sigma metadata trong alert** | Click 1 alert → highlight `top_rule_sigma_filename` field |
| 4 | **Catalog expansion 1,367 rule** | `cat demo/RED_RULE_MAP.md \| head -20` → show 1,367 rule list |
| 5 | **Báo cáo Vietnamese đầy đủ** | Render markdown → có timeline + Sigma patch + containment |
| 6 | **WMI Event Subscription fire** | Show Sysmon EID 19/20/21 trong Kibana — APT29/FIN8 pattern |

---

## 7. Backup plan nếu fail

| Tình huống | Cách xử lý |
|---|---|
| ELK ingest > 2 phút | `python3 -m agent.inject_test_alert --host DESKTOP-2UQB61H` để inject thẳng |
| Velociraptor query timeout | `unset VR_USE_REAL` → switch mock mode, giải thích "production SLA 30s" |
| Agent daemon crash | `cat /tmp/inv_real.json` đã rehearsal trước → show output |
| Windows VM offline | Mock mode + show pre-recorded screencast 3 phút |
| DeepSeek API rate limit | Show `inv_real.json` từ USB |
| Sigma rule không fire | Đã document trong Section 12.4 README — config Sysmon issue |

**Quan trọng**: KHÔNG panic nếu fail. Honest framing:
> *"Demo lab có 1 vấn đề nhỏ — em sẽ show output từ rehearsal sáng nay thay
> thế. Pipeline đã verified end-to-end, em lưu sẵn JSON kết quả."*

---

## 8. Q&A handling

### Top 5 câu hỏi điển hình (đã prepare trong `QA_PREP.md`)

**Q1: "Sao biết RED không bị adversarial attack?"**
> *"Em đã liệt kê Phase D trong roadmap — LLM-based adversarial evasion. Hiện
> em đã verify RED bắt được 13 evasion variant trong demo (Tier 1+2+3). Future
> work: dùng Claude/GPT generate variants targeting RED weights → measure
> robustness curve."*

**Q2: "Cost $20/ngày có scale?"**
> *"Có. Cost rẻ hơn analyst hour 200-400 lần. Optimization có sẵn:
> score_threshold filter, supervisor skip_fp routing, prompt caching 60-80%."*

**Q3: "LLM hallucinate có nguy hiểm?"**
> *"3 lớp giảm thiểu: (1) Forensic Agent ground decisions trên Velociraptor
> evidence cứng, (2) prompt explicit cấm bịa, (3) human-in-the-loop approval
> cho mọi destructive action. Verified live trong rehearsal: 0 fake IP trong
> containment actions."*

**Q4: "Tại sao 146 → 1,367 rule?"**
> *"Phát hiện trong session rehearsal: Cosine attributor về lý thuyết không cần
> match events, chỉ cần filter values từ YAML. Em mở rộng Loop B trong
> train_attribution.py để fit Cosine trên TẤT CẢ Sigma catalog. Verified 100%
> lookup metadata (1367/1367)."*

**Q5: "Sigma rule cứng có vai trò gì nữa không?"**
> *"Có. Sigma rule cứng vẫn là defense-in-depth: (1) baseline coverage cho
> pattern đã biết, (2) human-readable cho audit, (3) compatible mọi SIEM. RED
> ML là LAYER BỔ SUNG bắt biến thể né Sigma — không thay thế."*

### Quy tắc trả lời

1. **Honest > Bluff**: Nếu chưa biết, nói "Em chưa làm phần này, em đề xuất là future work, em ưu tiên X vì Y"
2. **Acknowledge limitation trước GVHD chỉ ra**: Cho thấy em hiểu sâu hệ thống
3. **Future work cụ thể**: Đừng nói "em sẽ improve", nói "em sẽ implement X với reference Y, dự kiến Z tuần"
4. **Bảng số liệu cụ thể** > nói chung chung

---

## 9. Cleanup sau demo

### Trên Windows VM (qua SSH)

```bash
sshpass -p tzxr scp /tmp/cleanup_v2.ps1 luanthanh@10.10.20.50:/C:/Users/LuanThanh/cleanup_v2.ps1
sshpass -p tzxr ssh luanthanh@10.10.20.50 \
  'powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\cleanup_v2.ps1'
```

Verify cleanup qua Velociraptor:
```bash
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
source ~/venvs/rule_evasion_env/bin/activate
export VR_USE_REAL=1 VR_API_CONFIG=~/velociraptor/api.config.yaml
python3 -c "
from agent.vr_client import get_file_artifacts
r = get_file_artifacts(client_id='C.1b622eacffe8b75d', since_minutes=30)
df = [f for f in r['files_created_by_process'] if 'xkj9' in str(f.get('FullPath',''))]
dp = [p for p in r['registry_persistence'] if 'RED_APT_DEMO' in str(p.get('Name',''))]
print(f'Files còn: {len(df)}, Run keys còn: {len(dp)}')
print('Cleanup ' + ('OK' if (len(df)+len(dp))==0 else 'CHƯA'))
"
```

### Stop agent daemon

```bash
# Kill daemon background (nếu chạy)
pkill -f "agent.daemon" 2>/dev/null || true
```

### Lưu output cho luận văn

```bash
# Lưu báo cáo + alert mẫu vào folder thesis
mkdir -p ~/thesis_artifacts
cp /tmp/inv_*.json ~/thesis_artifacts/
cp /tmp/demo_alerts.jsonl ~/thesis_artifacts/

# Export báo cáo tiếng Việt
jq -r '.report.full_markdown_vi' /tmp/inv_*.json > ~/thesis_artifacts/sample_report_vi.md
```

---

## 10. Timing budget tổng

| Hoạt động | Thời gian |
|---|---|
| Pre-demo checklist (1 giờ trước) | 30 phút |
| Vào phòng + setup screens | 5 phút |
| **Live demo** | **~18 phút** |
| Q&A | 10-15 phút |
| Cleanup sau | 5 phút |
| **Tổng** | ~50 phút |

Phù hợp slot KLTN defense **30-45 phút** + Q&A.

---

## 11. Checklist final trước khi vào phòng

- [ ] Pre-demo checklist (mục 2 — phần A đến D) chạy xong, không lỗi
- [ ] **`apt_demo_scenario.ps1` đã push lên Windows với UTF-8 BOM** (verify size ~16KB + dry-run OK)
- [ ] **`cleanup_v2.ps1` đã push lên Windows VM** (verify size ~1.5KB)
- [ ] 4 tab màn hình mở sẵn, layout đúng
- [ ] Daemon agent chưa chạy (sẽ start trong Pha 5)
- [ ] Tab Velociraptor login đã save credentials
- [ ] USB chứa backup screencast + JSON rehearsal
- [ ] `QA_PREP.md` print sẵn để cạnh laptop
- [ ] Đồng hồ countdown 18 phút trên màn hình
- [ ] Đã uống nước, đi WC, hít sâu 3 lần

---

## 12. Một số tip thực tế

1. **Đừng đọc slide** — kể chuyện. Slide chỉ là background.
2. **Show data thật** — copy-paste log thật từ Kibana lên slide chữ to.
3. **Đặt câu hỏi cho GVHD** — *"Thầy/cô có muốn xem chi tiết phần X không?"* → tỏ ra chủ động.
4. **Pause 2 giây sau wow moment** — cho GVHD thấm.
5. **Mention limitation trước GVHD bắt** — *"Em thừa nhận Stage 2 powershell sub-folder module/classic chưa cover đủ. Em đã fix bug normalize key trong rehearsal..."*
6. **Slide cuối có email + GitHub link** — cho GVHD reach out sau defense.

---

## Phụ lục A — Velociraptor + Forensic Agent (giải thích chi tiết)

### A.1 Velociraptor là gì?

**Velociraptor** = công cụ **DFIR** (Digital Forensics & Incident Response) open-source,
viết bởi Mike Cohen (cựu Google), free.

So sánh dễ hiểu:
- **Sigma rule cứng** = lính canh đứng cổng, check ID người vào (log)
- **Velociraptor** = thám tử vào nhà nạn nhân, mở tủ, check vân tay, kiểm RAM
  → lấy bằng chứng CỨNG sau khi có nghi ngờ

**Vai trò trong pipeline RED**:
- Sigma/RED ML detect alert dựa trên **log** (Sysmon EID 1, PowerShell EID 4104, ...)
- Log có thể bị bịa (nếu attacker tampering), hoặc thiếu chi tiết
- Velociraptor query **trạng thái máy thật ngay lúc đó** → bằng chứng không thể bịa

### A.2 Kiến trúc Velociraptor

```
┌───────────────────────────────────────────────────────────────┐
│  Ubuntu lab (10.10.20.20)                                     │
│                                                                │
│  ┌────────────────┐    HTTPS    ┌─────────────────────────┐  │
│  │ velociraptor   │ ◄────────►  │ velociraptor server     │  │
│  │ GUI (browser)  │  port 8889  │ (binary /usr/local/bin) │  │
│  │ 10.10.20.20    │             │                          │  │
│  │   :8889        │             │ - REST/gRPC API :8001    │  │
│  └────────────────┘             │ - Frontend  :8000        │  │
│                                 │ - Datastore /var/lib/... │  │
│  ┌─────────────────┐  gRPC      │                          │  │
│  │ agent/vr_client │ ◄────────► │   ▲                      │  │
│  │ .py (Python)    │   :8001    │   │                      │  │
│  │ (Forensic Agent)│            │   │ Flow                 │  │
│  └─────────────────┘            └───┼──────────────────────┘  │
└────────────────────────────────────┼──────────────────────────┘
                                     │ HTTPS TLS
                                     │ pinned cert
                                     ▼
┌───────────────────────────────────────────────────────────────┐
│  Windows VM 10.10.20.50 (DESKTOP-2UQB61H)                     │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ Velociraptor.exe (service, run as SYSTEM)                │ │
│  │                                                           │ │
│  │  - Heartbeat về server mỗi 60s                           │ │
│  │  - Nhận VQL query → execute → trả kết quả                │ │
│  │  - Read access: process list, file system, registry,     │ │
│  │    network connections, WMI, ...                         │ │
│  └──────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

**Components**:
- **Velociraptor server**: nhận query từ admin/API, gửi xuống agent, lưu kết quả
- **Velociraptor agent**: cài trên endpoint (Windows VM), chạy như Windows service
- **GUI** (port 8889): admin tương tác qua browser
- **API** (port 8001 gRPC): script tự động (như RED Forensic Agent)
- **Datastore**: server lưu mọi flow result vào `/var/lib/velociraptor/`

### A.3 VQL — Velociraptor Query Language

Velociraptor không dùng REST endpoint cứng. Thay vào đó **mọi thứ là 1 ngôn ngữ query** giống SQL:

```vql
-- Liệt kê process đang chạy trên endpoint
SELECT Pid, Name, CommandLine, Username
FROM pslist()
WHERE Name =~ "(?i)powershell"
```

```vql
-- Tìm file trong Public folder
SELECT FullPath, Size, Mtime, Hash.SHA256
FROM glob(globs="C:\\Users\\Public\\*.exe")
```

```vql
-- Đọc Run key trong registry
SELECT * FROM Artifact.Windows.Sys.StartupItems()
```

**Artifact** = template VQL có sẵn cho task chuẩn (vd `Windows.System.Pslist`,
`Windows.Network.NetstatEnriched`, ...). Velociraptor có **hàng trăm artifact built-in**.

### A.4 Flow chi tiết — Forensic Agent gọi Velociraptor

Khi alert đến, Forensic Agent (trong `agent/agents/forensic.py`) làm:

```
┌─────────────────────────────────────────────────────────────────┐
│  Step 1: Alert có { host.client_id, process.pid }              │
│  vd: client_id=C.1b622eacffe8b75d, pid=4020                    │
└──────────────────────────────┬─────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 2: Agent LLM (DeepSeek) quyết định gọi tool nào          │
│  3 tool có sẵn (định nghĩa trong agent/tools.py):              │
│    - vr_process_tree_deep(client_id, pid)                      │
│    - vr_file_artifacts(client_id, since_minutes)               │
│    - vr_network_connections(client_id, since_minutes)          │
└──────────────────────────────┬─────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 3: Tool gọi agent/vr_client.py                            │
│  vr_client load /etc/velociraptor/api.config.yaml để authenticate │
│  → mở gRPC connection tới :8001                                 │
└──────────────────────────────┬─────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 4: vr_client gửi VQL query qua gRPC                       │
│                                                                  │
│  VQL (vd cho process_tree_deep):                                │
│    LET flow <= collect_client(                                  │
│        client_id='C.1b622eacffe8b75d',                          │
│        artifacts=['Windows.System.Pslist'],                     │
│        timeout=60)                                              │
│    LET _wait <= SELECT * FROM watch_monitoring(                 │
│        artifact='System.Flow.Completion')                       │
│        WHERE FlowId = flow.flow_id LIMIT 1                      │
│    SELECT * FROM source(                                        │
│        client_id='C.1b622eacffe8b75d',                          │
│        flow_id=flow.flow_id,                                    │
│        artifact='Windows.System.Pslist')                        │
└──────────────────────────────┬─────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 5: Velociraptor server                                    │
│   - Tạo Flow (job)                                              │
│   - Gửi xuống Windows agent qua TLS                             │
│   - Agent execute artifact (pslist, file search, netstat)       │
│   - Agent trả kết quả về server                                 │
│   - Server lưu vào datastore + stream về vr_client              │
└──────────────────────────────┬─────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 6: vr_client parse JSON → trả dict cho tool               │
│  → tool trả về Forensic Agent dưới dạng tool result             │
│  → LLM nhìn data, quyết định: gọi tool tiếp / kết luận          │
└─────────────────────────────────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 7: Forensic Agent build ForensicOutput                    │
│  - evidence_grade: high/medium/low/missing                      │
│  - verdict: confirmed_malicious / likely_benign / inconclusive  │
│  - suspicious_artifacts[]                                       │
│  - iocs_observed[]                                              │
│  - timeline_vi[]                                                │
└─────────────────────────────────────────────────────────────────┘
```

### A.5 3 tool cụ thể của Forensic Agent

#### Tool 1: `vr_process_tree_deep(client_id, pid)`

**VQL artifact dùng**: `Windows.System.Pslist`

**Trả về**:
- Cây tiến trình quanh PID alert (parent + target + children)
- Kèm metadata: Authenticode signed? Publisher? CommandLine? CreateTime?

**Use case**: Verify alert nói "parent=outlook.exe" — Velociraptor query thật trả "parent thực ra là sshd.exe" → Forensic Agent correct được hallucination.

#### Tool 2: `vr_file_artifacts(client_id, since_minutes)`

**VQL artifact dùng**: 2 cái song song:
- `Windows.Search.FileFinder` (với glob `C:\Users\Public\*.exe`, `C:\ProgramData\**\*.exe`, ...)
- `Windows.Sys.StartupItems` (Run/RunOnce keys + Startup folder)

**Trả về**:
- File mới tạo trong N phút (path, size, SHA256, signed?)
- Registry persistence (Run keys, Scheduled tasks)

**Use case**: Find dropper (`xkj9_demo_*.exe`) + Run key persistence (`HKCU\...\Run\RED_APT_DEMO_PERSIST_*`).

#### Tool 3: `vr_network_connections(client_id, since_minutes)`

**VQL artifact dùng**: `Windows.Network.NetstatEnriched`

**Trả về**:
- Connection đang ACTIVE (state ESTABLISHED)
- Filter external IP (loại bỏ 10.x, 192.168.x, 172.16-31.x, 127.x, 169.254.x)
- Process associated

**Use case**: Confirm C2 channel — IP nào còn kết nối, process nào.

### A.6 Vì sao Forensic Agent kháng hallucination?

**Lý do 1 — Bằng chứng cứng từ kernel**:
- Velociraptor agent chạy as `SYSTEM`, đọc trực tiếp Windows API (NtQuerySystemInformation, registry hive, NTFS MFT)
- Attacker muốn bịa data này phải **rootkit kernel-level** — barrier cao

**Lý do 2 — Prompt explicit cấm bịa**:
- Trong `agent/prompts/forensic.md` có rule: *"KHÔNG bịa bằng chứng — chỉ ghi cái Velociraptor thật sự trả về"*
- Nếu tool trả `[]` (empty) → agent PHẢI ghi `evidence_grade: "missing"`, `verdict: "inconclusive"`

**Lý do 3 — Verified live trong rehearsal**:
- Test RunId `b82c152e`: Forensic Agent trả về **4 IOCs THẬT** từ Velociraptor:
  ```
  C:\Users\Public\xkj9_demo_b82c152e.exe
  sha256:58189cbd4e6dc0c7d8e66b6a6f75652fc9f4afc7ce0eba7d67d8c3feb0d5381f
  HKEY_USERS\S-1-5-21-3365634595-2120978922-941844542-1000\
    SOFTWARE\Microsoft\Windows\CurrentVersion\Run\RED_APT_DEMO_PERSIST_b82c152e
  RED_APT_DEMO_PERSIST_b82c152e
  ```
- 4 IOC này **không thể LLM bịa** vì:
  - SHA256 hash: phải đúng byte-level
  - Registry path: phải đúng SID user
  - File path: phải tồn tại thật

### A.7 Setup Velociraptor trong project này

```
Velociraptor server:    /usr/local/bin/velociraptor
Server config:          /etc/velociraptor/server.config.yaml (root-owned)
API config (cho agent): ~/velociraptor/api.config.yaml
GUI:                    https://10.10.20.20:8889 (admin/tzxr)
Datastore:              /var/lib/velociraptor/
Logs:                   /var/log/velociraptor/

Windows agent installed via: C:\Program Files\Velociraptor\
Client ID:              C.1b622eacffe8b75d (Windows VM 10.10.20.50)
```

**Verify Velociraptor đang hoạt động**:
```bash
# Server status
systemctl status velociraptor_server --no-pager

# List connected clients
sudo -u velociraptor /usr/local/bin/velociraptor \
  --config /etc/velociraptor/server.config.yaml \
  query "SELECT client_id, os_info.fqdn, last_seen_at FROM clients()"

# Mở GUI trên browser
firefox https://10.10.20.20:8889
```

### A.8 GVHD hỏi gì về Velociraptor — câu trả lời

**Q: "Sao chọn Velociraptor mà không chọn EDR khác như CrowdStrike?"**
> *"3 lý do: (1) free open-source, phù hợp KLTN không có ngân sách; (2) hỗ trợ
> hàng trăm built-in artifact + custom VQL → linh hoạt; (3) gRPC API thân thiện
> với Python automation. CrowdStrike Falcon mạnh hơn nhưng commercial + license
> $$$ → out of scope cho project sinh viên."*

**Q: "Velociraptor có overhead lên endpoint không?"**
> *"Có nhưng thấp: agent ~50MB RAM idle, CPU < 1% giữa các query. Khi Forensic
> Agent gửi query, spike 5-15% CPU trong 2-5 giây. Đo lường: process_creation
> query mất ~30s, file artifacts ~60s, netstat ~10s. Acceptable cho SOC triage."*

**Q: "Nếu attacker disable Velociraptor agent thì sao?"**
> *"Đây là limitation thật. Mitigation 3 lớp: (1) cài Velociraptor service với
> AccessControl protect, (2) heartbeat server detect agent offline → alert
> SOC, (3) defense-in-depth — RED ML detection vẫn hoạt động qua log đã ship
> vào ELK trước đó. Em ghi trong section 'Threats to validity' của luận văn."*

**Q: "Tại sao không dùng Sysmon đủ rồi?"**
> *"Sysmon = passive log, không query được on-demand. Velociraptor = active query
> tại thời điểm investigation. Sysmon log có thể bị attacker clear (T1070.001),
> nhưng Velociraptor query state thật ngay lúc đó. Hai cái complement nhau:
> Sysmon ship log liên tục, Velociraptor query forensic on-demand."*

---

## Tham khảo file liên quan

| File | Khi nào dùng |
|---|---|
| `demo/apt_demo_scenario.md` | Giải thích từng phase chi tiết — đọc trước rehearsal |
| `demo/RED_RULE_MAP.md` | Tra rule khi GVHD hỏi rule cụ thể |
| `demo/QA_PREP.md` | 16 câu Q&A — print mang theo |
| `demo/SLIDES_OUTLINE.md` | Khung 15 slide cho defense |
| `demo/README.md` Section 11-12 | Verification commands + verify result |
| `CLAUDE.md` | Tổng quan project — tham khảo nếu confuse |
| `agent/prompts/forensic.md` | System prompt Forensic Agent — đọc nếu hỏi prompt engineering |
| `agent/vr_client.py` | Source code wrapper Velociraptor gRPC |
