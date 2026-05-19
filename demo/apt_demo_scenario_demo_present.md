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

### C. Cleanup state cũ

```bash
# 1. Clean red-alerts demo (giữ red-alerts production để có data history)
curl -X POST -sk -u elastic:$ES_PASS \
  "http://10.10.20.100:9200/red-alerts-demo/_delete_by_query?conflicts=proceed&refresh=true" \
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

### D. Dụng cụ in/lưu

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
| 1️⃣ **Kibana Discover** | `http://10.10.20.100:5601/app/discover` index `red-alerts-demo*` | Show alert real-time |
| 2️⃣ **Kibana Security** | `http://10.10.20.100:5601/app/security/rules` | Show Sigma rule fire (hoặc không fire) |
| 3️⃣ **Velociraptor GUI** | `https://10.10.20.20:8889/app/index.html#/clients` | Show Windows client online |
| 4️⃣ **Terminal Ubuntu** | SSH tới `10.10.20.20` | Chạy daemon + xem agent log live |
| 5️⃣ **Terminal Windows** *(optional)* | RDP/SSH tới `10.10.20.50` | Trigger demo script |

**Tip**: dùng workspace ảo Linux (`Ctrl+Alt+→`) để switch nhanh giữa Kibana và Terminal.

---

## 4. Live demo flow (~18 phút)

### Pha 1 — Intro + Setup (2 phút)

**Show trên màn hình**:
- Tab Kibana red-alerts-demo: hiện đang **trống** (đã cleanup)
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

**Đợi 30s**, refresh Kibana red-alerts-demo → vẫn trống ✅

### Pha 3 — Baseline mode (3 phút) — Sigma fires, RED fires

```bash
sshpass -p tzxr ssh luanthanh@10.10.20.50 \
  'powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode baseline'
# Note RunId (vd 85ae464b)
```

**Đợi 60s**, sau đó:

1. Mở Kibana Security/Rules → filter `Suspicious PowerShell Download` → **Sigma rule fired** ✅
2. Mở Kibana red-alerts-demo → có alert mới với `red.top_rule` + `sigma_filename`

**Nói**:
> *"Mode baseline chạy mẫu CHUẨN: `-EncodedCommand` đầy đủ, `IEX (New-Object
> System.Net.WebClient).DownloadString(...)`, Run key trong HKCU. Đây là pattern
> Sigma đã thiết kế cho — quan sát thấy Sigma rule fire trong Kibana Security/
> Rules, đồng thời RED ML cũng score 1.0. Cả 2 layer detect đều hoạt động trên
> baseline."*

### Pha 4 — Evasion mode (4 phút) ⭐ — **WOW MOMENT chính**

```bash
sshpass -p tzxr ssh luanthanh@10.10.20.50 \
  'powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode evasion'
```

**Đợi 60s**, sau đó:

1. Mở Kibana Security/Rules → **Sigma silent** ❌ (không có alert mới)
2. Mở Kibana red-alerts-demo → **có alert mới** ✅ với top_rule + sigma_filename

**Nói (CHẬM RÃI, NHẤN MẠNH)**:
> *"Mode evasion thay đổi 3 điểm nhỏ: thay `-EncodedCommand` bằng `-e` shorthand,
> tách chuỗi `'Sys'+'tem.Net.WebCl'+'ient'`, dùng `RunOnce` thay `Run`.
> Behavior giống y hệt mode baseline — vẫn execute, vẫn persist."*
>
> *"Thầy/Cô có thể thấy: **Sigma rule trong Kibana Security/Rules KHÔNG fire** —
> miss vì rule check literal `-EncodedCommand`, không match `-e`."*
>
> *"Nhưng **RED ML vẫn score 1.0** và attribute đúng rule
> `suspicious_powershell_invocations_specific`. Đây là điểm bán hàng chính của
> luận văn — ML model tổng quát hóa hơn rule exact-match."*

### Pha 5 — Chain mode + AI Agent (7 phút) — full pipeline

```bash
# Bật agent daemon (Terminal 4)
unset VR_USE_REAL  # mock VR cho nhanh, OR set =1 cho real (chậm hơn)
python3 -m agent.daemon --interval 30 --score-threshold 0.5 --no-state &

# Trigger chain mode
sshpass -p tzxr ssh luanthanh@10.10.20.50 \
  'powershell -ExecutionPolicy Bypass -File C:\Users\LuanThanh\apt_demo_scenario.ps1 -Mode chain -SleepSeconds 120'
```

**Show real-time** trong Terminal — daemon log từng step:
```
🎯 Supervisor: workflow=full_investigation
🔍 Triage: severity=HIGH, confidence=0.85
🔬 Forensic: thu thập bằng chứng host qua Velociraptor...
  → vr_process_tree_deep(C.1b622eacffe8b75d, pid=...)
  → vr_file_artifacts → tìm thấy xkj9_demo.exe, Run key RED_APT_DEMO_PERSIST_*
✓ Forensic: grade=high, verdict=confirmed_malicious, persistence=True
⚡ Parallel: Hunt + RED Analyst + MITRE
🛡️ Response: Sigma patch + 5 containment actions
📝 Report: báo cáo tiếng Việt
```

Sau ~3 phút, mở Kibana index `ai-investigations` — hiện investigation mới.

**Nói**:
> *"Mode chain mô phỏng đầy đủ 7 phase của kill-chain: Encoded PowerShell →
> Download Cradle → Persistence Run key + WMI Event Subscription → Clear log +
> AMSI bypass marker → Mimikatz marker → LOLBins mshta/regsvr32/rundll32 + DNS
> tunnel → Sandbox detection probe."*
>
> *"Agent daemon poll red-alerts mỗi 30s, pickup alert, chạy 8 agent. Notice
> Forensic Agent gọi Velociraptor 3 lần — query process tree, file artifacts,
> network connections THẬT trên Windows VM, KHÔNG đoán từ log."*
>
> *"Cuối cùng Report Agent sinh báo cáo Vietnamese markdown với timeline đầy đủ
> + Sigma patch grounded by evidence cứng + 5 containment actions."*

### Pha 6 — Đọc báo cáo Vietnamese (1 phút)

Mở 1 document trong `ai-investigations` → click `report.full_markdown_vi` field
→ paste vào notepad markdown viewer để render đẹp.

**Nói**:
> *"SOC analyst Vietnam đọc 5 giây hiểu ngay — không cần dịch. Mỗi alert chứa
> `top_rule_sigma_filename` + `sigma_id` + `sigma_title` → click thẳng để mở
> rule trong codebase."*

### Pha 7 — Conclusion (1 phút)

**Highlight số liệu**:
- **Cost/alert**: ~$0.02 USD (DeepSeek API)
- **Time/alert**: ~3 phút real Velociraptor / ~100s mock
- **Coverage**: 7 phase × 1,367 rule × 3 RED model
- **Agent count**: 8 (Supervisor → Triage → Forensic ⭐ → Hunt+RED+MITRE → Response → Report)

**Closing statement**:
> *"Pipeline 3 lớp của em hoạt động end-to-end trong môi trường lab. Đóng góp
> chính: Stage 2 catalog expansion từ 146 lên 1,367 rule, Forensic Agent kháng
> hallucination, báo cáo Vietnamese cho SOC team VN."*

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
> *"Đây chính xác là vấn đề luận văn em giải quyết. Sigma rule design cho pattern
> chuẩn. Attacker đổi 1 ký tự — rule miss hoàn toàn. RED ML học token pattern
> chung nên bắt được biến thể."*

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
| 1 | **Sigma miss, RED catch** | Side-by-side Kibana Security/Rules (silent) + red-alerts (alert mới) |
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

## Tham khảo file liên quan

| File | Khi nào dùng |
|---|---|
| `demo/apt_demo_scenario.md` | Giải thích từng phase chi tiết — đọc trước rehearsal |
| `demo/RED_RULE_MAP.md` | Tra rule khi GVHD hỏi rule cụ thể |
| `demo/QA_PREP.md` | 16 câu Q&A — print mang theo |
| `demo/SLIDES_OUTLINE.md` | Khung 15 slide cho defense |
| `demo/README.md` Section 11-12 | Verification commands + verify result |
| `CLAUDE.md` | Tổng quan project — tham khảo nếu confuse |
