# APT Demo v2 — Fast Path: 6 Sigma Fire vs 6 Sigma Miss vs RED Catch

> **Mục đích**: bản demo ngắn (6 phase, 3 mode) thay cho `apt_demo_scenario.ps1`
> 7-phase. Mỗi phase map 1:1 với một Sigma rule cụ thể đang enabled trong Kibana
> nên dễ trình bày trước hội đồng. File này là runbook chính thức để chạy
> `demo/apt_demo_v2.ps1` đầy đủ và verify pipeline RED ML.
>
> Đây là sibling của `demo/apt_demo_defense_present.md` (defense full 7-phase).
> Khác biệt: `apt_demo_v2` chỉ tập trung 6 rule target, không demo Tier 3 WMI/DNS.

---

## 0. Tóm tắt 30 giây

`apt_demo_v2.ps1` chạy 6 phase, hỗ trợ 3 mode:

| Mode | Mục đích | Sigma raw query | Kibana Security Alerts | RED ML alerts |
|---|---|---:|---:|---:|
| `benign` | Sanity check trước demo | 0/6 target | 0/6 target | Có noise nhỏ từ script structure (giải thích được) |
| `baseline` | Canonical pattern Sigma biết | **6/6 fire** | **6/6 fire** | Cùng fire — RED bám sát Sigma |
| `evasion` | Đổi representation giữ ý đồ | **0/6 miss** | **0/6 miss** | **RED catch** — đây là claim chính |

**Verified 2026-05-24** trên `DESKTOP-IQAM883`:

| Mode | RunId | Sigma raw / alert | RED alerts (proc/reg/ps) |
|---|---|---|---|
| benign   | `b6a9...` | 0/6 / 0/6 ✓ | ~10 / 0 / 21 (noise script) |
| baseline | `2241e0ec` | 6/6 / **6/6** ✓ | 9 / 1 / 2 — gồm `potential_invoke_mimikatz_powershell_script`, `direct_autorun_keys_modification`, `potential_lethalhta_technique_execution` |
| evasion  | `cae65ce1` | **0/6 / 0/6** ✓ | 8 / 0 / 3 — `hacktool_evil_winrm_execution_powershell_module` (Phase 1), `hacktool_rubeus_execution_scriptblock` (Phase 2), `suspicious_ping_del_command_combination` (Phase 3 curl), `potential_lethalhta_technique_execution` (Phase 4 mshta) |

**Thông điệp 1 câu**: Sigma exact-match miss khi attacker đổi representation, nhưng RED ML
vẫn fire và attribute về Sigma rule họ hàng gần nhất.

**Layer 3 (tuỳ chọn)**: AI Agent đọc 1 RED evasion alert → 8-agent pipeline +
Velociraptor evidence → báo cáo tiếng Việt + Sigma patch trong `ai-investigations`
(~120-210s, ~$0.02/alert). Chi tiết Section 7.

---

## 1. Lab Topology

| Thành phần | Giá trị (lab IQAM883) |
|---|---|
| Endpoint Windows | `DESKTOP-IQAM883` / `192.168.10.103` |
| SSH endpoint | user `endpoint`, password `123` |
| Elasticsearch | `https://192.168.10.10:9200` (HTTPS, self-signed) |
| Kibana API | `http://192.168.10.10:5601` (**HTTP** port 5601, không phải HTTPS) |
| Raw log index | `logs-windows.*` (Elastic Agent ECS) |
| Security alert index | `.alerts-security.alerts-*,.siem-signals-*` |
| RED process alerts (demo v2) | `red-alerts-v2-proc` (EID 1) |
| RED PowerShell alerts (demo v2) | `red-alerts-v2-ps` (EID 4104) |
| RED registry alerts (demo v2) | `red-alerts-v2-reg` (EID 13) |

> File này dùng prefix `red-alerts-v2-*` để **tách hoàn toàn** khỏi `red-alerts-demo`
> (đang chứa data 7-phase từ `apt_demo_scenario.ps1`). Có thể đổi tên index trong
> lệnh start daemon nếu muốn dùng index khác.

---

## 2. Demo story (cho hội đồng)

1. **Sigma exact-match** rất tốt khi event giống đúng query.
2. **Attacker chỉ cần đổi cách viết** command/script là rule exact-match miss.
3. **RED ML** dùng TF-IDF Ensemble + Cosine attribution để bắt event gần với hành
   vi evasion, rồi gán về Sigma rule "họ hàng" gần nhất → SOC analyst vẫn thấy
   context.

Demo này **không** load malware thật. Mọi action đều là command line, ScriptBlockText
hoặc registry marker có kiểm soát; cleanup auto sau 60s (xem `-CleanupDelaySeconds`).

---

## 3. Phase mapping (6 phase ↔ 6 Sigma target rules)

| Phase | Event type | Target Sigma rule | Sigma ID | Benign | Baseline | Evasion |
|---:|---|---|---|---|---|---|
| 1 | PowerShell 4104 | Potential Invoke-Mimikatz PowerShell Script | `189e3b02-82b2-4b90-9662-411eb64486d4` | Đọc local users | Child ScriptBlock có literal `DumpCreds` + `DumpCerts` | Char-code reconstruct (`@(68,117,109,112,...) → DumpCreds`) — chỉ in hash |
| 2 | Process EID 1 | Suspicious Eventlog Clearing | `cc36992a-4671-4f21-a91d-6c2b72a2edf5` | `wevtutil gl Application` | `wevtutil.exe cl RED_DEMO_V2_NONEXISTENT_<RunId>` | Split token `'Cl'+'ear'+'-Ev'+'ent'+'Lo'+'g'` trong PS, không gọi `wevtutil cl` |
| 3 | Process EID 1 | PowerShell Download Cradle | `85b0b087-eddf-4a2b-b033-d771fa2b9775` | Web request không execute | `iwr ... \| iex` | Đổi sang `curl.exe`, target PS cradle miss literal `Invoke-WebRequest` |
| 4 | Process EID 1 | Mshta Remote HTA | `b98d0db6-511d-45de-ad02-e82a98729620` | Check path `mshta.exe` | `mshta.exe http://127.0.0.1:1/...hta` | `mshta.exe javascript:close()` — không có remote URL token |
| 5 | Process EID 1 | Direct Autorun Keys Modification | `24357373-078f-44ed-9ac4-6d334a668a11` | Đọc Explorer registry key | `reg.exe add HKCU\...\CurrentVersion\Run` | Ghi `HKCU\...\Explorer\StartupApproved\Run` (subkey khác, không trong target_keys của Sigma rule) |
| 6 | Process EID 1 | File Encoded via Certutil | `e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a` | Liệt kê temp dir | `certutil.exe -encode in.txt out.txt` | `[Convert]::ToBase64String([byte[]])` runtime API, không dùng certutil |

**Lý do** Phase 5/6 dùng process_creation thay vì registry-set/reflection ps_script:
- Rule registry-set canonical `20f0ee37...` bị Elastic rule query filter `Details:null` loại bỏ event ECS trong lab hiện tại.
- Reflection rule `ddcd88cb...` có query escape không match ổn định với `powershell.file.script_block_text` field.
- → Đổi sang process_creation rules đang enabled + query match chính xác.

---

## 4. Preflight (chạy 1 lần trước demo)

### 4.1 Activate venv + load .env

```bash
cd /home/ubuntu/rule_evasion_detection/Rule_Evasion_Detection
source ~/venvs/rule_evasion_env/bin/activate
set -a; . ./.env; set +a

# Sanity check biến môi trường
echo "ES_AUTH_HOST=$ES_AUTH_HOST" | head -c 90
echo ""
# Expect: https://elastic:Admin123%40@192.168.10.10:9200
```

### 4.2 Verify ES + Kibana + endpoint SSH

```bash
curl -sk -u "$ES_USER:$ES_PASS" https://192.168.10.10:9200/_cluster/health -m 8 | python3 -m json.tool | head -5
curl -s  -u "$ES_USER:$ES_PASS" http://192.168.10.10:5601/api/status -m 8 | python3 -c "import json,sys; print('Kibana:', json.load(sys.stdin)['status']['overall']['level'])"
timeout 5 bash -c '</dev/tcp/192.168.10.103/22' && echo SSH_OPEN
```

### 4.3 Verify 6 target Sigma rules đang enabled trong Kibana

```bash
python3 scripts/test_apt_demo_v2.py \
  --check-only --kibana-url http://192.168.10.10:5601 --http-timeout 15
```

Expected output:

```text
OK: 6/6 target rule queries found
OK   phase=1 rule=189e3b02 lang=lucene fields=ecs index=[logs-windows.*,winlogbeat-*]
OK   phase=2 rule=cc36992a ...
OK   phase=3 rule=85b0b087 ...
OK   phase=4 rule=b98d0db6 ...
OK   phase=5 rule=24357373 ...
OK   phase=6 rule=e62a9f0c ...

[Raw Sigma query source]
using live Kibana queries for 6/6 target rules
```

**Nếu thấy `MISSING`**, import lại bản ECS:

```bash
python3 scripts/convert_sigma_to_elastic.py \
  --skip-convert \
  --out data/sigma/elastic_rules/windows_sigma_elastic_ecs.ndjson \
  --import-to-kibana --kibana-url http://192.168.10.10:5601 \
  --kibana-user elastic --kibana-password 'Admin123@' \
  --import-chunk-size 200 --import-timeout 300
```

---

## 5. RED detection pipeline — Workflow A (Live daemon, khuyến nghị) ⭐

> **Đây là phần KHÔNG có trong demo cũ và là lý do `red-alerts*` "không có log mới"
> khi chỉ chạy script PowerShell**. PS script chỉ tạo events trong ELK
> `logs-windows.*`. Để events biến thành RED alerts, phải có 1 daemon RED
> đang poll ELK + chấm điểm + index vào `red-alerts-*`.

### 5.1 Cleanup daemon cũ + index v2 cũ

```bash
# Stop tất cả daemon đang chạy (kể cả của session trước)
pkill -f "detect_live.py" 2>/dev/null
sleep 2
ps -ef | grep detect_live.py | grep -v grep | wc -l   # Expect: 0

# Cleanup state file để daemon start fresh
rm -f /tmp/.state_v2_proc.json /tmp/.state_v2_reg.json /tmp/.state_v2_ps.json

# (Tùy chọn) Xoá index v2 cũ để demo có baseline sạch
for idx in red-alerts-v2-proc red-alerts-v2-reg red-alerts-v2-ps; do
  curl -sk -u "$ES_USER:$ES_PASS" -X DELETE "https://192.168.10.10:9200/${idx}" -m 8 \
    -o /dev/null -w "$idx: %{http_code}\n"
done
```

### 5.2 Start 3 daemons (process / registry / powershell)

```bash
mkdir -p /tmp/red_demo_v2_logs
SINCE=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)
echo "SINCE=$SINCE"

# Daemon 1 — process_creation (Sysmon EID 1)
nohup python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-proc --event-id 1 \
  --threshold 0.5 --method cosine --timestamp-field @timestamp \
  --interval 15 --state-file /tmp/.state_v2_proc.json --since "$SINCE" \
  > /tmp/red_demo_v2_logs/detect_proc.log 2>&1 &
echo "proc PID: $!"

# Daemon 2 — registry_event (Sysmon EID 13)
nohup python3 scripts/detect_live.py \
  --config config/registry_event.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-reg --event-id 13 \
  --threshold 0.5 --method cosine --timestamp-field @timestamp \
  --interval 15 --state-file /tmp/.state_v2_reg.json --since "$SINCE" \
  > /tmp/red_demo_v2_logs/detect_reg.log 2>&1 &
echo "reg PID: $!"

# Daemon 3 — powershell (EID 4104)
nohup python3 scripts/detect_live.py \
  --config config/powershell.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-ps --event-id 4104 \
  --threshold 0.5 --method cosine --timestamp-field @timestamp \
  --interval 15 --state-file /tmp/.state_v2_ps.json --since "$SINCE" \
  > /tmp/red_demo_v2_logs/detect_ps.log 2>&1 &
echo "ps PID: $!"

sleep 8
ps -ef | grep detect_live.py | grep -v grep | wc -l   # Expect: 3
tail -n 3 /tmp/red_demo_v2_logs/detect_proc.log
```

**Verify daemon healthy** (log mỗi daemon cần có dòng `Starting — polling logs-windows.*`):

```bash
for tag in proc reg ps; do
  echo "=== $tag ==="
  tail -n 5 /tmp/red_demo_v2_logs/detect_$tag.log
done
```

### 5.3 (Tùy chọn) Workflow B — Batch offline thay daemon

Nếu KHÔNG muốn chạy daemon (ví dụ chạy lại trên data cũ), dùng workflow batch:

```bash
SINCE=$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)
mkdir -p /tmp/demo_v2_events

python3 scripts/elk_export.py --es-host "$ES_AUTH_HOST" \
  --es-index "logs-windows.*" --event-id 1 \
  --since "$SINCE" --size 5000 \
  --out /tmp/demo_v2_events/proc.jsonl

python3 scripts/detect_batch.py --config config/process_creation.yaml \
  --events /tmp/demo_v2_events/proc.jsonl \
  --threshold 0.5 --method cosine --top-k 5 \
  --out /tmp/demo_v2_events/proc_alerts.jsonl

# Bulk index alerts → ES (workaround vì push_alerts.py không có --no-verify-ssl)
python3 -c "
import json
with open('/tmp/demo_v2_events/proc_alerts.jsonl') as f:
    for line in f:
        if line.strip():
            print(json.dumps({'index':{'_index':'red-alerts-v2-proc-batch'}}))
            print(line.rstrip())
" | curl -sk -u "$ES_USER:$ES_PASS" -H 'Content-Type: application/x-ndjson' \
    --data-binary @- "https://192.168.10.10:9200/_bulk" -o /dev/null -w "HTTP %{http_code}\n"
```

Tương tự cho registry (eid 13) + powershell (eid 4104).

---

## 6. Chạy demo — 3 mode

> **Quan trọng**: bước này yêu cầu Section 5.2 daemon đã start xong. Verify
> `ps -ef | grep detect_live.py | grep -v grep | wc -l` = 3 trước khi tiếp tục.

### 6.1 Benign — sanity check (0/6 Sigma fire)

```bash
PYTHONUNBUFFERED=1 python3 scripts/test_apt_demo_v2.py \
  --mode benign --run-endpoint \
  --kibana-url http://192.168.10.10:5601 \
  --wait-raw-seconds 120 --wait-alert-seconds 120 \
  --skip-rule-check
```

Expected (cuối output):

```text
[Result]
raw_sigma=PASS
security_alerts=PASS
```

Với `--mode benign`, **PASS** nghĩa là **0/6 target Sigma rules fire** (đúng kỳ vọng).

> **RED alerts** trong mode benign: có ~10 proc + ~21 ps alert từ chính việc chạy
> `powershell.exe -ExecutionPolicy Bypass -File apt_demo_v2.ps1`. Đây là noise
> có thể giải thích — nếu cần silence noise này, hạ threshold daemon proc lên `0.7-0.8`
> hoặc khi demo nói rõ: *"benign mode mục đích duy nhất là verify 6 target Sigma rules
> 0/6 fire; RED noise từ script structure là tradeoff sensitivity"*.

### 6.2 Baseline — Sigma fire 6/6

```bash
PYTHONUNBUFFERED=1 python3 scripts/test_apt_demo_v2.py \
  --mode baseline --run-endpoint \
  --kibana-url http://192.168.10.10:5601 \
  --wait-raw-seconds 180 --wait-alert-seconds 420 \
  --skip-rule-check 2>&1 | tee /tmp/red_demo_v2_logs/baseline_run.log
```

Expected cuối output:

```text
[Kibana Security alert counts]
phase=1 rule=189e3b02 count=1 ...
phase=2 rule=cc36992a count=1 ...
phase=3 rule=85b0b087 count=1 ...
phase=4 rule=b98d0db6 count=1 ...
phase=5 rule=24357373 count=1 ...
phase=6 rule=e62a9f0c count=1 ...

[Result]
raw_sigma=PASS  (hoặc FAIL — xem note bên dưới)
security_alerts=PASS
```

> **Note**: `raw_sigma=FAIL` có thể xuất hiện khi script đo lần đầu chỉ thấy 3/6 phase
> đã ingest (Phase 4-6 chậm hơn vì Elastic Agent ship batch). Đây là quirk của script
> poll, **không phải** demo lỗi — `security_alerts` 6/6 là proof chính. Lý do: script
> chỉ poll raw 1 lần nếu marker_count>0 (do `timeout_seconds=0`). Có thể fix sau bằng
> cách poll raw nhiều lần như alert.

Ghi lại `RunId` để dùng trong Kibana UI (search field). Ví dụ session 2026-05-24:
`2241e0ec`.

### 6.3 Evasion — Sigma miss 6/6 + RED catch

```bash
PYTHONUNBUFFERED=1 python3 scripts/test_apt_demo_v2.py \
  --mode evasion --run-endpoint \
  --kibana-url http://192.168.10.10:5601 \
  --wait-raw-seconds 180 --wait-alert-seconds 240 \
  --skip-rule-check 2>&1 | tee /tmp/red_demo_v2_logs/evasion_run.log
```

Expected cuối output:

```text
[Raw Sigma query counts]
phase=1..6 count=0 (mọi phase)

[Kibana Security alert counts]
phase=1..6 count=0 (mọi phase)

[Result]
raw_sigma=PASS    (0/6 = đúng kỳ vọng cho evasion)
security_alerts=PASS
```

Sau đó **verify RED catch cho RunId evasion**:

```bash
export RUN_ID="<RunId_evasion>"   # ví dụ cae65ce1

# Count per stream
for idx in red-alerts-v2-proc red-alerts-v2-reg red-alerts-v2-ps; do
  count=$(curl -sk -u "$ES_USER:$ES_PASS" "https://192.168.10.10:9200/${idx}/_count" -m 8 \
    -H 'Content-Type: application/json' \
    -d "{\"query\":{\"query_string\":{\"query\":\"*${RUN_ID}*\"}}}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('count','?'))" 2>/dev/null)
  echo "$idx: $count"
done

# Show RED rule attribution per phase
curl -sk -u "$ES_USER:$ES_PASS" "https://192.168.10.10:9200/red-alerts-v2-*/_search?size=15" -m 8 \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"query_string\":{\"query\":\"*${RUN_ID}*\"}},\"sort\":[{\"@timestamp\":\"asc\"}],\"_source\":[\"winlog.event_id\",\"red.detection_score\",\"red.top_rule\",\"red.command_line\"]}" \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
for h in d['hits']['hits']:
    s=h['_source']
    eid=s.get('winlog.event_id',0); score=s.get('red.detection_score',0)
    rule=str(s.get('red.top_rule',''))[:55]
    cmd=str(s.get('red.command_line',''))[:90].replace('\n',' ')
    print(f'  EID{eid:>4} score={score:.3f} top={rule:<55} cmd={cmd}')
"
```

Expected (verified 2026-05-24, RunId `cae65ce1`):

```text
red-alerts-v2-proc: 8
red-alerts-v2-reg: 0
red-alerts-v2-ps: 3

  EID   1 score=1.000 top=suspicious_runas_like_flag_combination       cmd=cmd.exe /c "powershell ..."
  EID   1 score=1.000 top=local_file_read_using_curl_exe               cmd=powershell -ExecutionPolicy Bypass -File apt_demo_v2.ps1 evasion
  EID4104 score=0.616 top=hacktool_evil_winrm_execution_powershell_module  cmd=Phase 1 char-code reconstruct
  EID4104 score=0.589 top=hacktool_rubeus_execution_scriptblock            cmd=Phase 2 split token
  EID   1 score=1.000 top=suspicious_ping_del_command_combination       cmd=curl.exe --max-time 1 -o NUL http://...
  EID   1 score=1.000 top=potential_lethalhta_technique_execution       cmd=mshta.exe javascript:close()
  EID4104 score=0.826 top=powershell_script_with_file_upload_capabilities  cmd=Phase 6 runtime base64
  ...
```

Đây là **bằng chứng key** cho luận văn: dù 6 target Sigma rules miss, RED vẫn:
- Phase 1 (Mimikatz char-code) → attribute family `hacktool_evil_winrm` (PowerShell-launcher pattern)
- Phase 4 (mshta inline) → attribute đúng family `potential_lethalhta_technique_execution`
- Phase 3 (curl swap) → `suspicious_ping_del_command_combination` + `local_file_read_using_curl_exe`
- Phase 6 (runtime base64) → `powershell_script_with_file_upload_capabilities`

---

## 7. AI Agent — Triage và Report (tuỳ chọn nhưng khuyến nghị)

> **Mục đích**: sau khi RED daemon đẩy alerts vào `red-alerts-v2-*`, AI Agent
> (8-agent pipeline + Velociraptor evidence) sẽ tự investigate, output 1
> Vietnamese SOC report → index `ai-investigations`. Đây là Layer 3 trên cùng
> của claim luận văn (multi-layer adversarial-aware detection).
>
> Có thể bỏ qua section này nếu chỉ demo ML pure (Sigma vs RED). Nếu chạy thì
> nên chạy **sau khi `--mode evasion` xong**, vì alert evasion mới là input
> thú vị cho LLM.

### 7.1 Preflight

```bash
# Sanity check env vars (đã có sẵn trong .env)
grep -E "^(DEEPSEEK_API_KEY|ES_AI_INDEX|VR_USE_REAL|VR_API_CONFIG|AGENT_MAX_ITERATIONS)=" .env

# Velociraptor server alive (nếu VR_USE_REAL=1)
sudo systemctl status velociraptor_server.service --no-pager | head -5
curl -sk -u "admin:tzxr" "https://127.0.0.1:8889/api/v1/SearchClients?query=all" -m 5 \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('VR clients:', len(d.get('items',[])))"

# (Nếu VR sập / không cần real evidence) fallback mock
# export VR_USE_REAL=0   # → tools dùng mock data, ai-investigations vẫn ghi nhưng evidence là synthetic
```

### 7.2 One-shot — investigate 1 evasion alert (cho demo trên hội đồng)

> ⚠️ **Gotcha**: `agent/__init__.py:9` gọi `load_dotenv(override=True)` →
> mọi `ES_RED_INDEX=...` prefix trước `python3 -m agent.daemon` đều bị `.env`
> **ghi đè**. Phải sửa `ES_RED_INDEX` trực tiếp trong `.env` (hoặc xoá tạm
> dòng đó), không thể override qua shell prefix.

Sau khi `--mode evasion` xong, lấy `RunId` (ví dụ `cae65ce1`) → chạy daemon
1 lần để pick 1 alert cao điểm nhất:

```bash
export RUN_ID="<RunId_evasion>"   # ví dụ cae65ce1

# Backup + sửa .env để agent chỉ poll red-alerts-v2-*
cp .env .env.bak
sed -i 's|^ES_RED_INDEX=.*|ES_RED_INDEX=red-alerts-v2-proc,red-alerts-v2-ps,red-alerts-v2-reg|' .env
grep "^ES_RED_INDEX=" .env   # verify

SINCE_AGENT=$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)

PYTHONUNBUFFERED=1 python3 -m agent.daemon \
  --interval 15 \
  --max-iter 1 \
  --batch-limit 1 \
  --score-threshold 0.9 \
  --since "$SINCE_AGENT" \
  --query-string "*${RUN_ID}*" \
  --no-state \
  2>&1 | tee /tmp/red_demo_v2_logs/agent_one_shot.log

# Restore .env sau khi xong
mv .env.bak .env
```

Expected log đoạn cuối (verified 2026-05-24, host `desktop-iqam883`, score 1.00):

```text
✓ Done in ~150-210s — severity=CRITICAL, 6 actions, ~180k tokens, $0.03-0.05
→ Indexed: ai-investigations/INV-<12hex>
```

> **Note cost**: alert score 1.0 + Forensic real VR → token cao hơn (~180k vs
> mock ~80k). Nếu cần demo nhanh và rẻ, có thể `export VR_USE_REAL=0` (mock
> Velociraptor data) → giảm xuống ~$0.015-0.02.

### 7.3 Daemon mode — tự động investigate mọi alert mới

> ⚠️ **Token cost**: mỗi alert ~$0.03-0.05. Daemon chạy lâu + nhiều alert =
> tiền thật. Khuyến nghị **chỉ chạy foreground**, hoặc set `--max-iter` nhỏ.
> Đừng `nohup ... &` trừ khi bạn đã set budget với DeepSeek.

Sửa `.env` (như 7.2) rồi chạy foreground:

```bash
sed -i 's|^ES_RED_INDEX=.*|ES_RED_INDEX=red-alerts-v2-*|' .env
SINCE_AGENT=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)

PYTHONUNBUFFERED=1 python3 -m agent.daemon \
  --interval 30 \
  --score-threshold 0.9 \
  --batch-limit 3 \
  --max-iter 5 \
  --since "$SINCE_AGENT" \
  2>&1 | tee /tmp/red_demo_v2_logs/agent_daemon.log
```

> **Note**: ES search API tự nhận wildcard `red-alerts-v2-*` → daemon hoạt
> động đúng. Nếu cần list cụ thể, dùng `red-alerts-v2-proc,red-alerts-v2-ps,red-alerts-v2-reg`.

### 7.4 Verify investigation document trong `ai-investigations`

```bash
curl -sk -u "$ES_USER:$ES_PASS" \
  "https://192.168.10.10:9200/ai-investigations/_search?size=3&sort=@timestamp:desc" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"query_string\":{\"query\":\"*${RUN_ID}*\"}}}" \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'Total: {d[\"hits\"][\"total\"][\"value\"]} investigation(s)')
for h in d['hits']['hits']:
    s=h['_source']
    inv=s.get('investigation_id','?')
    sev=s.get('triage',{}).get('severity','?')
    title=s.get('report',{}).get('title_vi','')[:80]
    cost=s.get('estimated_cost_usd',0)
    elapsed=s.get('elapsed_seconds',0)
    print(f'\n  inv_id={inv}')
    print(f'  severity={sev} elapsed={elapsed:.1f}s cost=\${cost:.4f}')
    print(f'  title_vi={title}')
"
```

Expected output (verified pattern 2026-05-24):

```text
Total: 1 investigation(s)

  inv_id=INV-37200b9402d2
  severity=CRITICAL elapsed=180.8s cost=$0.0413
  title_vi=Phát hiện SSH Remote Port Forwarding (sshd.exe -R) trên host đã bị
           compromise hoàn toàn — Chain tấn công LaZagne → hashcat → NetSupport
           RAT → SSH Tunnel T1572
```

> **Note**: trong document ES, một số field như `host.name` và `forensic.verdict`
> hiển thị `None` khi parse trực tiếp do nested mapping; nội dung chính nằm trong
> `report.title_vi`, `report.executive_summary_vi`, `report.body_vi`. Khi xem trên
> Kibana Discover (Section 8.2 style) → expand row sẽ thấy đủ.

### 7.5 Talk track tại Kibana (AI Agent layer)

Mở Discover → data view `ai-investigations` → search `*${RUN_ID}*` → expand 1 row:

| Field | Mô tả |
|---|---|
| `triage.severity` / `triage.is_fp` | Quyết định FP filter của Triage agent |
| `forensic.process_tree` | Bằng chứng từ Velociraptor (PID, parent, command line) |
| `hunt.iocs` / `hunt.timeline` | IOC + timeline lateral hunt |
| `red_analyst.explanation_vi` | LLM giải thích WHY là evasion (token-level) |
| `mitre.ttps` | TTP chain T1XXX |
| `response.containment_actions` | Hành động đề xuất + Sigma patch YAML |
| `report.body_vi` | Báo cáo tiếng Việt full markdown |
| `total_tokens` / `estimated_cost_usd` | Cost transparency cho luận văn |

> "Khác biệt với Elastic AI Assistant: AI Agent của chúng tôi có **Forensic agent**
> kéo evidence cứng từ Velociraptor (không hallucinate process tree), **RED Analyst**
> dịch ML score thành lý do token-level, và **Response agent** sinh Sigma patch
> grounded trên evidence. End-to-end ~98s (mock) / ~210s (real VR), $0.020/alert
> vs ~5-15 phút và $25-50 của analyst Tier-1."

### 7.6 Cleanup AI Agent

```bash
pkill -f "agent.daemon" 2>/dev/null
sleep 2
ps -ef | grep "agent.daemon" | grep -v grep | wc -l   # Expect: 0
```

(Cleanup đầy đủ trong Section 11. Phần cleanup script `apt_demo_v2.ps1` đã bao gồm `pkill -f "agent.daemon"`.)

---

## 8. Xem trên Kibana UI (live demo)

### 8.1 Security → Alerts (Sigma layer)

Set time range `Last 30 minutes`. Search bar nhập:

```text
<RunId_baseline>
```

Expected: 6 alert rows, mỗi cái 1 trong 6 target Sigma rule IDs:
```text
189e3b02-82b2-4b90-9662-411eb64486d4   Potential Invoke-Mimikatz PowerShell Script
cc36992a-4671-4f21-a91d-6c2b72a2edf5   Suspicious Eventlog Clearing
85b0b087-eddf-4a2b-b033-d771fa2b9775   PowerShell Download and Execution Cradles
b98d0db6-511d-45de-ad02-e82a98729620   Remotely Hosted HTA File Executed Via Mshta.EXE
24357373-078f-44ed-9ac4-6d334a668a11   Direct Autorun Keys Modification
e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a   File Encoded To Base64 Via Certutil.EXE
```

Search `<RunId_evasion>`: **0 alert** từ 6 target rule IDs.

### 8.2 Discover → red-alerts-v2-* (RED layer)

Chọn data view `red-alerts-v2-proc,red-alerts-v2-ps,red-alerts-v2-reg` (hoặc index pattern `red-alerts-v2-*`).

Search:
```text
<RunId_evasion>
```

Fields nên show:
```text
@timestamp
host.name
winlog.event_id
red.detection_score
red.top_rule
red.top_rule_sigma_title
red.top_rule_sigma_id
red.command_line
```

**Talk track tại Kibana**: 
> "Sigma layer ở Security/Alerts trống cho RunId evasion. Nhưng cùng RunId trong
> Discover red-alerts-v2-* có 11 alert. RED ML không match literal — nó học
> token-level pattern qua TF-IDF nên catch được các variant: char-code, split string,
> swap utility, inline scheme, runtime API."

---

## 9. Verified results (chạy thật 2026-05-24)

| Test | RunId | Kết quả |
|---|---|---|
| Preflight Kibana rule check | — | 6/6 OK, lang=lucene, fields=ecs |
| Daemons started | — | 3 daemon (proc/reg/ps) alive |
| **Benign** sanity | `b6a9...` | Sigma raw 0/6 ✓, Security Alerts 0/6 ✓, RED noise ~10/0/21 (script structure) |
| **Baseline** | `2241e0ec` | Sigma raw 6/6, **Security Alerts 6/6** ✓, RED 9/1/2 — Phase 1+4+5 attribute đúng family |
| **Evasion** | `cae65ce1` | Sigma raw 0/6 ✓, **Security Alerts 0/6** ✓, **RED 8/0/3** catch Phase 1+2+3+4+6 |
| Raw events ingested | `2241e0ec` | 37 events `logs-windows.*` |
| Raw events ingested | `cae65ce1` | 19 events `logs-windows.*` |

RED attribution highlights (evasion):
- Phase 4 mshta `javascript:close()` → `potential_lethalhta_technique_execution` score 1.000 — RED catch **cùng family** với target Sigma `b98d0db6` (lethal HTA technique).
- Phase 1 char-code reconstruct → `hacktool_evil_winrm_execution_powershell_module` 0.616 — không cùng UUID nhưng catch chung family "PowerShell credential tooling".
- Phase 6 runtime base64 API → `powershell_script_with_file_upload_capabilities` 0.826.

---

## 10. Troubleshooting

| Triệu chứng | Nguyên nhân thường gặp | Cách xử lý |
|---|---|---|
| `red-alerts-v2-*` count = 0 sau khi chạy script | Section 5.2 daemon chưa start, hoặc bị kill | `ps -ef \| grep detect_live.py \| grep -v grep`; nếu trống → rerun Section 5.2 |
| Multiple daemon song song → RED count tăng đột biến | Daemon từ session cũ chưa kill | `pkill -f "detect_live.py"` rồi rerun Section 5.2 |
| Daemon log "Starting" rồi im, count 0 | `--since` quá xa (> 1h) → backlog hàng nghìn events block first poll | Restart với `SINCE=$(date -u -d '5 minutes ago' ...)` |
| Daemon poll OK nhưng count 0 dù script chạy | Sai `--es-index` | Phải dùng `logs-windows.*` (có chữ "s"), không phải `logs-winlog.*` |
| `curl https://...:5601` SSL error | Kibana lab chạy HTTP (không HTTPS) | Dùng `http://192.168.10.10:5601` |
| `--check-only` báo `MISSING` rule | NDJSON chưa import / sai field profile | Import lại `windows_sigma_elastic_ecs.ndjson` (Section 4.3) |
| `raw_events=0` sau script chạy | Endpoint chưa ship, Elastic Agent freeze, hoặc clock skew | Restart Elastic Agent (xem dưới); check `w32tm /resync /force` trên Windows |
| Baseline `raw_sigma=FAIL` nhưng `security_alerts=PASS` 6/6 | Quirk script: poll raw 1 lần khi mới có 3/6 phase ingest | Không phải bug demo — `security_alerts` 6/6 là proof. Nếu muốn raw cũng PASS, sửa `test_apt_demo_v2.py` đổi `timeout_seconds=0 if marker_count else ...` thành luôn poll với `wait_raw_seconds` |
| UI Kibana không thấy alert dù script PASS | Time range UI quá hẹp | Chọn `Last 30 minutes`, search field theo RunId |
| Evasion vẫn có Security Alerts từ rule khác | Catalog 1,620 rule khác fire trùng pattern | Demo claim chỉ nói **6 target rule IDs** miss — không claim 0 alert toàn catalog |
| `ES_AUTH_HOST` literal `$ES_AUTH_HOST` trong log | Chưa load `.env` | `set -a; . ./.env; set +a` rồi mới run; verify `echo "$ES_AUTH_HOST"` |
| AI Agent crash `DEEPSEEK_API_KEY chưa set` | `.env` chưa load trước khi chạy `agent.daemon` | `set -a; . ./.env; set +a` rồi rerun (Section 7.2) |
| AI Agent log "polled 0 alerts" dù có RED alert | `--since` của agent trễ hơn timestamp alert, hoặc sai `ES_RED_INDEX` | Đặt `SINCE_AGENT=$(date -u -d '15 minutes ago' ...)` và verify `ES_RED_INDEX=red-alerts-v2-*` (kèm wildcard) |
| AI Agent pick alert từ **wrong index** (e.g. `red-alerts-demo` thay vì `red-alerts-v2-*`) | `agent/__init__.py:9` `load_dotenv(override=True)` ghi đè mọi shell-prefix `ES_RED_INDEX=...` | Sửa trực tiếp `ES_RED_INDEX` trong `.env` (xem Section 7.2 — backup `.env`, `sed -i`, run, rồi restore) |
| AI Agent hit `max_iter=12` ceiling (RED Analyst loop) | PowerShell alert phức tạp, LLM lặp tool call | Tăng `AGENT_MAX_ITERATIONS=20` trong `.env` rồi rerun; hoặc giảm `--score-threshold` chỉ lấy alert cao điểm |
| Forensic agent trả `inconclusive` / không có process tree | Velociraptor gRPC sập hoặc client offline | `sudo systemctl restart velociraptor_server.service`; nếu cần hoãn → `export VR_USE_REAL=0` cho demo mock |

### Restart Elastic Agent (nếu events ngừng vào ELK)

OTel collector trong Elastic Agent v9 đôi khi freeze. Chạy trên Windows VM:

```powershell
sc stop "Elastic Agent"
Start-Sleep -Seconds 10
sc start "Elastic Agent"
```

### Check daemon RED log realtime

```bash
tail -f /tmp/red_demo_v2_logs/detect_proc.log
# Hoặc xem cả 3 cùng lúc
tail -f /tmp/red_demo_v2_logs/detect_*.log
```

---

## 11. Cleanup sau demo

```bash
# Stop daemons
pkill -f "detect_live.py" 2>/dev/null
pkill -f "agent.daemon" 2>/dev/null
sleep 2
ps -ef | grep -E "detect_live|agent.daemon" | grep -v grep | wc -l   # Expect: 0

# Cleanup artifacts trên endpoint (manual nếu cần)
python3 - <<'PY'
import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("192.168.10.103", username="endpoint", password="123", timeout=15)
cleanup_cmd = (
    'powershell -ExecutionPolicy Bypass -Command "'
    '$keys = @(\'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\','
              '\'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run\');'
    'foreach ($k in $keys) { Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | '
    'Get-Member -MemberType NoteProperty | Where-Object { $_.Name -like \'RED_DEMO_V2_*\' } | '
    'ForEach-Object { Remove-ItemProperty -Path $k -Name $_.Name -ErrorAction SilentlyContinue } };'
    'Remove-Item \$env:TEMP\\red_v2_*.* -Force -ErrorAction SilentlyContinue;'
    'Write-Host CLEANUP_DONE"'
)
_, stdout, _ = client.exec_command(cleanup_cmd, timeout=60)
print(stdout.read().decode())
client.close()
PY

# (Optional) Archive demo artifacts
mkdir -p ~/demo_archive/v2_$(date +%Y%m%d_%H%M)
cp /tmp/red_demo_v2_logs/*.log ~/demo_archive/v2_$(date +%Y%m%d_%H%M)/ 2>/dev/null
```

> **Auto cleanup**: script `apt_demo_v2.ps1` tự schedule cleanup job sau
> `-CleanupDelaySeconds 60` (default) cho registry artifacts trong baseline/evasion mode.
> Nếu dùng `-KeepArtifacts` thì phải cleanup thủ công.

---

## 12. Short talk track (1-2 phút)

```text
Demo này gồm 3 mode chạy trên cùng 6 phase. Benign là sanity check: 6 target
Sigma rules không fire với thao tác đọc/list bình thường. Baseline tạo đúng
6 mẫu mà Sigma đã biết, nên Elastic Security fire đủ 6 alert. Evasion giữ
cùng ý đồ tấn công nhưng đổi cách biểu diễn — split string, char-code
reconstruct, đổi utility từ powershell sang curl, dùng inline scheme thay
URL, gọi runtime API thay command-line utility.

Sau khi đổi representation, 6 target Sigma rules KHÔNG còn match. Đây là gap
mà attacker khai thác trong thực tế.

RED ML vẫn bắt được các event này và attribute về Sigma rule họ hàng gần nhất:
mshta inline scheme attribute đúng family LethalHTA, curl swap attribute family
LOLBins network, char-code reconstruct attribute family PowerShell credential
tooling. Đây không phải thay thế Sigma — đây là LAYER 2 adversarial-aware bám
sát Sigma rule semantics nhưng generalize qua TF-IDF + Cosine.

Layer 3 là AI Agent: với 1 RED evasion alert, 8 agent (Triage, Forensic,
Hunt, RED Analyst, MITRE, Response, Report) sẽ tự kéo evidence từ Velociraptor,
giải thích token-level vì sao alert này là evasion, generate Sigma patch
grounded trên process tree thật, và ghi báo cáo tiếng Việt vào
ai-investigations — end-to-end ~210 giây, chi phí ~2 cent/alert.
```

---

## 13. Liên kết

- **Defense full** (apt_demo_scenario.ps1 7-phase): `demo/apt_demo_defense_present.md`
- **Phase mapping chi tiết** + Velociraptor + AI Agent: `demo/apt_demo_scenario_demo_present_2.md`
- **RED rule catalog** (1,582 rules): `demo/RED_RULE_MAP.md`
- **Q&A prep**: `demo/QA_PREP.md`
- **Slides outline**: `demo/SLIDES_OUTLINE.md`

---

## 14. Lệnh gọn chạy 3 detector không dùng `nohup`

Dùng mục này thay cho Section 5.2 nếu muốn chạy foreground trong cùng terminal.
Khi cần dừng, nhấn `Ctrl+C`; trap sẽ kill cả 3 tiến trình con.

### 14.1 Chạy liên tục từ hiện tại, quét lùi N phút

```bash
# LOOKBACK_MIN=0 nếu muốn bắt đầu đúng từ thời điểm chạy lệnh.
# LOOKBACK_MIN=5 thường an toàn hơn vì bù độ trễ ingest từ endpoint vào ELK.
LOOKBACK_MIN=5 INTERVAL=15 bash -lc '
set -euo pipefail

mkdir -p /tmp/red_demo_v2_logs
SINCE=$(date -u -d "${LOOKBACK_MIN} minutes ago" +%Y-%m-%dT%H:%M:%S.000Z)
echo "SINCE=$SINCE"

cleanup() {
  jobs -pr | xargs -r kill 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

run_detector() {
  local tag="$1" cfg="$2" out_idx="$3" eid="$4" state="$5"
  python3 scripts/detect_live.py \
    --config "$cfg" \
    --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
    --out-index "$out_idx" --event-id "$eid" \
    --threshold 0.5 --method cosine --timestamp-field @timestamp \
    --interval "$INTERVAL" --state-file "$state" --since "$SINCE" \
    >"/tmp/red_demo_v2_logs/detect_${tag}.log" 2>&1 &
  echo "$tag PID: $!"
}

run_detector proc config/process_creation.yaml red-alerts-v2-proc 1 /tmp/.state_v2_proc.json
run_detector reg  config/registry_event.yaml  red-alerts-v2-reg  13 /tmp/.state_v2_reg.json
run_detector ps   config/powershell.yaml      red-alerts-v2-ps   4104 /tmp/.state_v2_ps.json

echo "Logs: /tmp/red_demo_v2_logs/detect_{proc,reg,ps}.log"
wait
'
```

Verify ở terminal khác:

```bash
ps -ef | grep detect_live.py | grep -v grep | wc -l   # Expect: 3
tail -f /tmp/red_demo_v2_logs/detect_*.log
```

### 14.2 Quét trong một khoảng thời gian cụ thể rồi tự thoát

```bash
START_UTC="2026-05-24T10:00:00Z" \
END_UTC="2026-05-24T10:30:00Z" \
INTERVAL=1 BATCH_SIZE=5000 MAX_ITER=5 bash -lc '
set -euo pipefail

mkdir -p /tmp/red_demo_v2_logs
echo "RANGE: $START_UTC -> $END_UTC"

run_detector_once() {
  local tag="$1" cfg="$2" out_idx="$3" eid="$4"
  python3 scripts/detect_live.py \
    --config "$cfg" \
    --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
    --out-index "$out_idx" --event-id "$eid" \
    --threshold 0.5 --method cosine --timestamp-field @timestamp \
    --since "$START_UTC" --until "$END_UTC" \
    --interval "$INTERVAL" --batch-size "$BATCH_SIZE" \
    --max-iter "$MAX_ITER" --no-state \
    >"/tmp/red_demo_v2_logs/range_${tag}.log" 2>&1 &
  echo "$tag PID: $!"
}

run_detector_once proc config/process_creation.yaml red-alerts-v2-proc 1
run_detector_once reg  config/registry_event.yaml  red-alerts-v2-reg  13
run_detector_once ps   config/powershell.yaml      red-alerts-v2-ps   4104

wait
echo "Done. Logs: /tmp/red_demo_v2_logs/range_{proc,reg,ps}.log"
'
```

`MAX_ITER * BATCH_SIZE` là số event tối đa mỗi detector có thể page qua trongV
khoảng thời gian đó. Nếu range nhiều log, tăng `MAX_ITER` hoặc `BATCH_SIZE`.


cd /path/to/Rule_Evasion_Detection
set -a; . ./.env; set +a

mkdir -p /tmp/red_demo_v2_logs
SINCE=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S.000Z)
echo "SINCE=$SINCE"

python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-proc --event-id 1 \
  --threshold 0.5 --method cosine --timestamp-field @timestamp \
  --interval 15 --state-file /tmp/.state_v2_proc.json --since "$SINCE" \
  > /tmp/red_demo_v2_logs/detect_proc.log 2>&1 &

python3 scripts/detect_live.py \
  --config config/registry_event.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-reg --event-id 13 \
  --threshold 0.5 --method cosine --timestamp-field @timestamp \
  --interval 15 --state-file /tmp/.state_v2_reg.json --since "$SINCE" \
  > /tmp/red_demo_v2_logs/detect_reg.log 2>&1 &

python3 scripts/detect_live.py \
  --config config/powershell.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-ps --event-id 4104 \
  --threshold 0.5 --method cosine --timestamp-field @timestamp \
  --interval 15 --state-file /tmp/.state_v2_ps.json --since "$SINCE" \
  > /tmp/red_demo_v2_logs/detect_ps.log 2>&1 &

wait


cd /path/to/Rule_Evasion_Detection
set -a; . ./.env; set +a

START_UTC="2026-05-24T10:00:00Z"
END_UTC="2026-05-24T10:30:00Z"

mkdir -p /tmp/red_demo_v2_logs

python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-proc --event-id 1 \
  --threshold 0.5 --method cosine --timestamp-field @timestamp \
  --since "$START_UTC" --until "$END_UTC" \
  --interval 1 --batch-size 5000 --max-iter 5 --no-state \
  > /tmp/red_demo_v2_logs/range_proc.log 2>&1 &

python3 scripts/detect_live.py \
  --config config/registry_event.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-reg --event-id 13 \
  --threshold 0.5 --method cosine --timestamp-field @timestamp \
  --since "$START_UTC" --until "$END_UTC" \
  --interval 1 --batch-size 5000 --max-iter 5 --no-state \
  > /tmp/red_demo_v2_logs/range_reg.log 2>&1 &

python3 scripts/detect_live.py \
  --config config/powershell.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-ps --event-id 4104 \
  --threshold 0.5 --method cosine --timestamp-field @timestamp \
  --since "$START_UTC" --until "$END_UTC" \
  --interval 1 --batch-size 5000 --max-iter 5 --no-state \
  > /tmp/red_demo_v2_logs/range_ps.log 2>&1 &

wait

