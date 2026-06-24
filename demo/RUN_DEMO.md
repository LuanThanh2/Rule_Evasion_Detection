# RUN_DEMO.md - Chay RED demo v2

File nay dung rieng de copy lenh khi demo. Khong dung `nohup`.

> Chay tren may SERVER-ELK thi thuong dung:
>
> ```bash
> cd ~/rule_evasion_detection/Rule_Evasion_Detection
> ```
>
> Neu chay tren may khac, doi dong `cd` thanh dung thu muc repo cua may do.

---

## 1. Chuan bi moi truong

```bash
cd ~/rule_evasion_detection/Rule_Evasion_Detection || exit 1
source ~/venvs/rule_evasion_env/bin/activate
set -a; . ./.env; set +a

mkdir -p /tmp/red_demo_v2_logs
echo "ES_AUTH_HOST=$ES_AUTH_HOST"
```

---

## 2. Dung detector cu neu dang chay

```bash
pkill -f "scripts/detect_live.py" 2>/dev/null || true
sleep 2
ps -ef | grep detect_live.py | grep -v grep || true
```

---

## 3. Chay lien tuc tu hien tai, quet lui 5 phut

Lenh nay chay 3 detector song song:

- `process_creation.yaml` -> Sysmon EID 1 -> `red-alerts-v2-proc`
- `registry_event.yaml` -> Sysmon EID 13 -> `red-alerts-v2-reg`
- `powershell.yaml` -> PowerShell EID 4104 -> `red-alerts-v2-ps`

```bash
cd ~/rule_evasion_detection/Rule_Evasion_Detection || exit 1
set -a; . ./.env; set +a

mkdir -p /tmp/red_demo_v2_logs
SINCE=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S.000Z)
echo "SINCE=$SINCE"

PY="$HOME/venvs/rule_evasion_env/bin/python"
[ -x "$PY" ] || PY="python3"

"$PY" scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-proc --event-id 1 \
  --threshold 0.5 --method cosine --top-k 10 --timestamp-field @timestamp \
  --interval 15 --state-file /tmp/.state_v2_proc.json --since "$SINCE" \
  --exact-sigma \
  > /tmp/red_demo_v2_logs/detect_proc.log 2>&1 &

"$PY" scripts/detect_live.py \
  --config config/registry_event.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-reg --event-id 13 \
  --threshold 0.5 --method cosine --top-k 10 --timestamp-field @timestamp \
  --interval 15 --state-file /tmp/.state_v2_reg.json --since "$SINCE" \
  --exact-sigma \
  > /tmp/red_demo_v2_logs/detect_reg.log 2>&1 &

"$PY" scripts/detect_live.py \
  --config config/powershell.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-ps --event-id 4104 \
  --threshold 0.5 --method cosine --top-k 10 --timestamp-field @timestamp \
  --interval 15 --state-file /tmp/.state_v2_ps.json --since "$SINCE" \
  --exact-sigma \
  > /tmp/red_demo_v2_logs/detect_ps.log 2>&1 &

wait
```

Dung detector live:

```bash
pkill -f "scripts/detect_live.py"
```

---

## 4. Quet trong mot khoang thoi gian cu the

Sua `START_UTC` va `END_UTC` theo khoang can quet.

```bash
cd ~/rule_evasion_detection/Rule_Evasion_Detection || exit 1
set -a; . ./.env; set +a

START_UTC="2026-05-24T10:00:00Z"
END_UTC="2026-05-24T10:30:00Z"

mkdir -p /tmp/red_demo_v2_logs
echo "RANGE=$START_UTC -> $END_UTC"

PY="$HOME/venvs/rule_evasion_env/bin/python"
[ -x "$PY" ] || PY="python3"

"$PY" scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-proc --event-id 1 \
  --threshold 0.5 --method cosine --top-k 10 --timestamp-field @timestamp \
  --since "$START_UTC" --until "$END_UTC" \
  --interval 1 --batch-size 5000 --max-iter 5 --no-state \
  --exact-sigma \
  > /tmp/red_demo_v2_logs/range_proc.log 2>&1 &

"$PY" scripts/detect_live.py \
  --config config/registry_event.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-reg --event-id 13 \
  --threshold 0.5 --method cosine --top-k 10 --timestamp-field @timestamp \
  --since "$START_UTC" --until "$END_UTC" \
  --interval 1 --batch-size 5000 --max-iter 5 --no-state \
  --exact-sigma \
  > /tmp/red_demo_v2_logs/range_reg.log 2>&1 &

"$PY" scripts/detect_live.py \
  --config config/powershell.yaml \
  --es-host "$ES_AUTH_HOST" --es-index "logs-windows.*" \
  --out-index red-alerts-v2-ps --event-id 4104 \
  --threshold 0.5 --method cosine --top-k 10 --timestamp-field @timestamp \
  --since "$START_UTC" --until "$END_UTC" \
  --interval 1 --batch-size 5000 --max-iter 5 --no-state \
  --exact-sigma \
  > /tmp/red_demo_v2_logs/range_ps.log 2>&1 &

wait
```

Ghi chu:

- `--max-iter 5` va `--batch-size 5000` nghia la moi detector doc toi da khoang `5 * 5000` event.
- Neu range co nhieu log hon, tang `--max-iter` hoac `--batch-size`.
- `--exact-sigma` xac thuc lai rule Sigma tren raw event va ghi `red.exact_sigma_match`
  cung `red.exact_sigma_matches`. Neu nhieu Sigma rule cung fire, xem
  `red.exact_sigma_matches[]` thay vi chi nhin `red.top_rule`.
- Khong mac dinh dung `--exact-sigma-prefer-ids` trong demo sach. Flag nay chi dung
  khi can tie-break top-1 theo mot bang phase co san.

---

## 3L. [LINUX] Chay detector Linux (auditd)

Lenh nay chay detector Linux doc tu `logs-auditd_manager.auditd-*`, ghi alert vao `red-alerts-linux`.

```bash
cd ~/rule_evasion_detection/Rule_Evasion_Detection || exit 1
source ~/venvs/rule_evasion_env/bin/activate
set -a; . ./.env; set +a

mkdir -p /tmp/red_demo_v2_logs
SINCE=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S.000Z)
echo "SINCE=$SINCE"

PY="$HOME/venvs/rule_evasion_env/bin/python"
[ -x "$PY" ] || PY="python3"

RED_DISABLE_INTELEX=1 "$PY" red_linux/scripts/detect_live_linux.py \
  --config config/detect_live_linux.yml \
  --es-host "$ES_AUTH_HOST" \
  --es-index "logs-auditd_manager.auditd-*" \
  --out-index red-alerts-linux \
  --threshold 0.52 --method cosine --top-k 10 \
  --interval 15 --state-file /tmp/.state_linux.json --since "$SINCE" \
  > /tmp/red_demo_v2_logs/detect_linux.log 2>&1 &

echo "Linux detector PID=$!"


# Kill detector cũ
kill 36285

# Chạy lại (từ thư mục project)
cd /home/ubuntu/rule_evasion_detection/Rule_Evasion_Detection
source ~/venvs/rule_evasion_env/bin/activate
set -a; . ./.env; set +a
mkdir -p /tmp/red_demo_v2_logs

PY="$HOME/venvs/rule_evasion_env/bin/python"

RED_DISABLE_INTELEX=1 "$PY" red_linux/scripts/detect_live_linux.py \
  --config config/detect_live_linux.yml \
  --es-host "$ES_AUTH_HOST" \
  --es-index "logs-auditd_manager.auditd-*" \
  --out-index red-alerts-linux \
  --threshold 0.52 --method cosine --top-k 10 \
  --interval 15 --no-state \
  > /tmp/red_demo_v2_logs/detect_linux.log 2>&1 

echo "PID=$!"

```

Dung:

```bash
pkill -f "detect_live_linux.py"
```

---

## 4L. [LINUX] Quet theo khoang thoi gian cu the

```bash
cd ~/rule_evasion_detection/Rule_Evasion_Detection || exit 1
set -a; . ./.env; set +a

START_UTC="2026-06-13T16:00:00Z"
END_UTC="2026-06-13T18:00:00Z"

mkdir -p /tmp/red_demo_v2_logs
echo "RANGE=$START_UTC -> $END_UTC"

PY="$HOME/venvs/rule_evasion_env/bin/python"
[ -x "$PY" ] || PY="python3"

RED_DISABLE_INTELEX=1 "$PY" red_linux/scripts/detect_live_linux.py \
  --config config/detect_live_linux.yml \
  --es-host "$ES_AUTH_HOST" \
  --es-index "logs-auditd_manager.auditd-*" \
  --out-index red-alerts-linux \
  --threshold 0.46 --method cosine --top-k 10 \
  --since "$START_UTC" --until "$END_UTC" \
  --interval 1 --batch-size 2000 --max-iter 10 --no-state \
  > /tmp/red_demo_v2_logs/range_linux.log 2>&1 &

wait
```

---

## 6L. [LINUX] Chay AI Agent cho Linux alert

Tuong tu Section 6 nhung doc tu `red-alerts-linux` thay vi `red-alerts-v2-*`.

> `--red-index` phai explicit — `.env` co the co `ES_RED_INDEX` Windows, flag nay ghi de.

**A. Smoke test** (khong ton token):

```bash
cd ~/rule_evasion_detection/Rule_Evasion_Detection || exit 1
source ~/venvs/rule_evasion_env/bin/activate
set -a; . ./.env; set +a

python3 -m agent.daemon --red-index "red-alerts-linux" \
  --max-iter 1 --batch-limit 1 --score-threshold 99 --no-state
```

**B. One-shot theo `_id`** — investigate dung 1 Linux alert (thay `<DOC_ID>`):

```bash
# Verify _id truoc khi chay
curl -sk "$ES_AUTH_HOST/red-alerts-linux/_search" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"query_string\":{\"query\":\"_id:\\\"$DOC_ID\\\"\"}}}" \
  | python3 -c "import json,sys; print('hits =', json.load(sys.stdin)['hits']['total']['value'])"
  
cd ~/rule_evasion_detection/Rule_Evasion_Detection || exit 1
source ~/venvs/rule_evasion_env/bin/activate
set -a; . ./.env; set +a

SINCE_AGENT=$(date -u -d '24 hour ago' +%Y-%m-%dT%H:%M:%SZ)
DOC_ID="<dan _id vao day>"    # vd Xo0hvZ4BmkchXZ6B8CQ3


PYTHONUNBUFFERED=1 python3 -m agent.daemon \
  --red-index "red-alerts-linux" \
  --max-iter 1 --batch-limit 1 --no-state \
  --since "$SINCE_AGENT" \
  --query-string "_id:\"$DOC_ID\"" \
  2>&1 | tee /tmp/red_demo_v2_logs/agent_linux_one_shot.log
```

**C. Daemon lien tuc Linux** (gioi han 5 vong):

```bash
SINCE_AGENT=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)

PYTHONUNBUFFERED=1 python3 -m agent.daemon \
  --red-index "red-alerts-linux" \
  --interval 30 --batch-limit 3 --max-iter 5 \
  --score-threshold 0.9 --since "$SINCE_AGENT" \
  2>&1 | tee /tmp/red_demo_v2_logs/agent_linux_daemon.log
```

**Verify ket qua:**

```bash
curl -sk "$ES_AUTH_HOST/ai-investigations/_search?size=3&sort=@timestamp:desc" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"match_all":{}}}' \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'Total: {d[\"hits\"][\"total\"][\"value\"]} investigation(s)')
for h in d['hits']['hits']:
    s=h['_source']
    f=s.get('forensic',{})
    print(f\"  inv_id={s.get('investigation_id','?')} \"
          f\"os={s.get('trigger_alert',{}).get('host',{}).get('os',{}).get('type','?')} \"
          f\"grade={f.get('evidence_grade','?')} \"
          f\"verdict={f.get('forensic_verdict_vi','?')} \"
          f\"conf={f.get('confidence',0):.2f}\")
"
```

---

## 6U. [UNKNOWN → AI AGENT] Chay agent cho alert confidence=unknown

Khi Stage 2 khong attribution duoc (Sigma engine khong fire, cosine duoi nguong),
alert duoc danh dau `red.needs_agent=true` va `red.confidence=unknown`.
Dung section nay de chay agent pipeline phan tich behavioral evidence thay vi rule matching.

> **Luong:** Stage 2 unknown → `red.needs_agent:true` trong ES → agent poll → Forensic
> (Velociraptor: process tree, /dev/shm, network) → MITRE map → Report:
> "Evasion phuc tap — attribution dua tren behavioral evidence thay vi rule matching"

### 6U.1 Kiem tra co alert unknown khong

```bash
set -a; . ./.env; set +a

# Windows
curl -sk "$ES_AUTH_HOST/red-alerts-v2-*/_count" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"red.needs_agent":true}}}' \
  | python3 -c "import json,sys; print('Windows unknown:', json.load(sys.stdin)['count'])"

# Linux
curl -sk "$ES_AUTH_HOST/red-alerts-linux/_count" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"red.needs_agent":true}}}' \
  | python3 -c "import json,sys; print('Linux unknown:', json.load(sys.stdin)['count'])"
```

### 6U.2 Chay agent chi xu ly alert unknown (Windows)

```bash
cd ~/rule_evasion_detection/Rule_Evasion_Detection || exit 1
source ~/venvs/rule_evasion_env/bin/activate
set -a; . ./.env; set +a

SINCE_AGENT=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)

PYTHONUNBUFFERED=1 python3 -m agent.daemon \
  --red-index "red-alerts-v2-*" \
  --needs-agent-only \
  --since "$SINCE_AGENT" \
  --max-iter 5 --batch-limit 3 \
  2>&1 | tee /tmp/red_demo_v2_logs/agent_unknown_win.log
```

### 6U.3 Chay agent chi xu ly alert unknown (Linux)

```bash
cd ~/rule_evasion_detection/Rule_Evasion_Detection || exit 1
source ~/venvs/rule_evasion_env/bin/activate
set -a; . ./.env; set +a

SINCE_AGENT=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)

PYTHONUNBUFFERED=1 python3 -m agent.daemon \
  --red-index "red-alerts-linux" \
  --needs-agent-only \
  --since "$SINCE_AGENT" \
  --max-iter 5 --batch-limit 3 \
  2>&1 | tee /tmp/red_demo_v2_logs/agent_unknown_linux.log
```

> `--needs-agent-only` tu dong them filter `red.needs_agent:true` vao query ES.
> Tuong duong `--query-string "red.needs_agent:true"` nhung ro rang hon khi demo.

### 6U.4 Verify ket qua — attribution behavioral

```bash
set -a; . ./.env; set +a

curl -sk "$ES_AUTH_HOST/ai-investigations/_search?size=5&sort=timestamp:desc" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"exists":{"field":"forensic.process_tree_summary_vi"}}}' \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'Total behavioral investigations: {d[\"hits\"][\"total\"][\"value\"]}')
for h in d['hits']['hits']:
    s = h['_source']
    ra = s.get('red_analyst', {}) or {}
    forensic = s.get('forensic', {}) or {}
    mitre = s.get('mitre', {}) or {}
    report = s.get('report', {}) or {}
    print()
    print(f'  inv_id   = {s.get(\"investigation_id\",\"?\")}')
    print(f'  severity = {(s.get(\"triage\") or {}).get(\"severity\",\"?\")}')
    print(f'  evasion  = {ra.get(\"evasion_technique\",\"?\")} (conf={ra.get(\"confidence\",0):.2f})')
    print(f'  forensic = grade={forensic.get(\"evidence_grade\",\"?\")} c2={forensic.get(\"c2_confirmed\",\"?\")}')
    print(f'  mitre    = {mitre.get(\"primary_technique\",\"?\")} / {mitre.get(\"primary_tactic\",\"?\")}')
    print(f'  title    = {report.get(\"title_vi\",\"\")[:80]}')
"
```

Dong log mong doi:

```text
[RED Analyst] BEHAVIORAL ATTRIBUTION MODE — red.confidence=unknown, red.needs_agent=true.
...
✓ Forensic: grade=high, verdict=confirmed_malicious, persistence=True, c2=True
✓ MITRE: T1005 / T1041 / T1053.003
✓ Report: "Evasion phuc tap — attribution dua tren behavioral evidence thay vi rule matching"
→ Indexed: ai-investigations/INV-<12hex>
```

---

## 6P. [LINUX] Chay payload tan cong tren WebServer (Ubuntu DMZ)

> Chay tren WebServer (C.348bd65bf6fd3224, 192.168.50.100) — KHONG chay tren SERVER-ELK.

```bash
# SSH vao WebServer
sshpass -p '123' ssh -o StrictHostKeyChecking=no ubuntu@192.168.50.100

# Chay payload (ghi nho RUN_ID de trace alert sau)
bash ~/payload_baseline_linux.sh
```

Sau khi chay xong, tren SERVER-ELK bat detector (Section 3L) roi investigate alert
tuong ung voi RUN_ID do (Section 6L mode B).

---

## 5. Xem log va kiem tra tien trinh

```bash
ps -ef | grep detect_live | grep -v grep || true
tail -f /tmp/red_demo_v2_logs/detect_*.log
```

Log quet theo range (Windows + Linux):

```bash
tail -f /tmp/red_demo_v2_logs/range_*.log
```

Log Linux:

```bash
tail -f /tmp/red_demo_v2_logs/detect_linux.log
tail -f /tmp/red_demo_v2_logs/agent_linux_one_shot.log
```

---

## 6. Chay AI Agent daemon (tu dong investigate alert)

`agent.daemon` poll alert tu `red-alerts-v2-*`, chay 7-agent pipeline cho moi alert,
ghi ket qua vao index `ai-investigations`. Phai co alert truoc — chay Section 3 (live)
hoac Section 4 (range) de sinh alert.

> Ton token that: moi alert ~$0.03-0.05 (DeepSeek). Chi chay foreground, dat
> `--score-threshold` cao va `--max-iter` nho. Khong `nohup ... &`.
> `--dry-run` VAN goi LLM (chi bo buoc ghi ES) → van ton token.

> Gotcha .env: `agent/__init__.py` goi `load_dotenv(override=True)` → prefix
> `ES_RED_INDEX=...` truoc lenh bi `.env` ghi de. Luon dung flag `--red-index`.

### 6.1 Chuan bi (chay 1 lan)

```bash
cd ~/rule_evasion_detection/Rule_Evasion_Detection || exit 1
source ~/venvs/rule_evasion_env/bin/activate
set -a; . ./.env; set +a

mkdir -p /tmp/red_demo_v2_logs
echo "ES_HOST=$ES_HOST | DEEPSEEK key? ${DEEPSEEK_API_KEY:+yes}"
```

### 6.2 Cac che do chay (chon 1, copy roi chay)

| Che do | Muc dich | Ton token? |
|---|---|---|
| A. Smoke test | Test ES connect + poll, khong investigate | Khong |
| B. One-shot theo RunId | Lay alert **cu nhat** khop RunId | 1 alert |
| C. One-shot theo `_id` | Investigate **dung 1 alert** (vd diem cao nhat) | 1 alert |
| D. Daemon lien tuc | Auto investigate moi alert moi | Nhieu alert |

**A. Smoke test — KHONG ton token** (`--score-threshold 99` → poll khong khop ai → thoat):

```bash
python3 -m agent.daemon --red-index "red-alerts-v2-*" \
  --max-iter 1 --batch-limit 1 --score-threshold 99 --no-state
```

**B. One-shot theo RunId** — lay alert dau tien (cu nhat) khop RunId:

```bash
cd ~/rule_evasion_detection/Rule_Evasion_Detection || exit 1
source ~/venvs/rule_evasion_env/bin/activate
set -a; . ./.env; set +a

export RUN_ID="xOnjyp4BmkchXZ6B95Fp"   # vi du cae65ce1
SINCE_AGENT=$(date -u -d '120 minutes ago' +%Y-%m-%dT%H:%M:%SZ)

PYTHONUNBUFFERED=1 python3 -m agent.daemon \
  --red-index "red-alerts-v2-*" \
  --max-iter 1 --batch-limit 1 --no-state \
  --score-threshold 0.5 --since "$SINCE_AGENT" \
  --query-string "*${RUN_ID}*" \
  2>&1 | tee /tmp/red_demo_v2_logs/agent_one_shot.log
```

> Poll sort `@timestamp` tang dan → `--batch-limit 1` lay alert **cu nhat** khop,
> KHONG phai diem cao nhat. Muon dung alert diem cao nhat → che do C.

**C. One-shot theo `_id`** — investigate **dung 1 alert** (da verify tren ES that:
`_id:"..."` qua query_string tra ve hits=1).

> Bat buoc kem `--since`: daemon van DOC `.agent_daemon_state.json` cu (du co
> `--no-state`) va dung `last_processed_timestamp` lam filter → khong co `--since`
> co the loc mat alert. ID phai dat trong ngoac kep (id ES co the chua `-`).

**C1. Da biet `_id`** (copy thang doc id can chay):

```bash
source ~/venvs/rule_evasion_env/bin/activate
set -a; . ./.env; set +a
DOC_ID="xOnjyp4BmkchXZ6B95Fp"   # vd kcI5VZ4B8R8CqW49PR4Z
SINCE_AGENT=$(date -u -d '3 hour ago' +%Y-%m-%dT%H:%M:%SZ)

# (tuy chon) verify _id co ton tai — khong ton token
curl -sk "$ES_AUTH_HOST/red-alerts-v2-*/_search" -H 'Content-Type: application/json' \
  -d "{\"query\":{\"query_string\":{\"query\":\"_id:\\\"$DOC_ID\\\"\"}}}" \
  | python3 -c "import json,sys; print('hits =', json.load(sys.stdin)['hits']['total']['value'])"

PYTHONUNBUFFERED=1 python3 -m agent.daemon \
  --red-index "red-alerts-v2-*" \
  --max-iter 1 --batch-limit 1 --no-state \
  --since "$SINCE_AGENT" \
  --query-string "_id:\"$DOC_ID\"" \
  2>&1 | tee /tmp/red_demo_v2_logs/agent_one_shot.log
```

**C2. Tu lay `_id` diem cao nhat cua mot RunId** (khi chua biet id):

```bash
export RUN_ID="<RunId>"
SINCE_AGENT=$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)

DOC_ID=$(curl -sk "$ES_AUTH_HOST/red-alerts-v2-*/_search" \
  -H 'Content-Type: application/json' \
  -d "{\"size\":1,\"query\":{\"query_string\":{\"query\":\"*${RUN_ID}*\"}},
       \"sort\":[{\"red.detection_score\":{\"order\":\"desc\",\"unmapped_type\":\"float\"}}]}" \
  | python3 -c "import json,sys; h=json.load(sys.stdin)['hits']['hits']; print(h[0]['_id'] if h else '')")
echo "DOC_ID=$DOC_ID"

PYTHONUNBUFFERED=1 python3 -m agent.daemon \
  --red-index "red-alerts-v2-*" \
  --max-iter 1 --batch-limit 1 --no-state \
  --since "$SINCE_AGENT" \
  --query-string "_id:\"$DOC_ID\"" \
  2>&1 | tee /tmp/red_demo_v2_logs/agent_one_shot.log
```

**D. Daemon lien tuc** — auto investigate moi alert moi (gioi han 5 vong cho demo):

```bash
SINCE_AGENT=$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ)

PYTHONUNBUFFERED=1 python3 -m agent.daemon \
  --red-index "red-alerts-v2-*" \
  --interval 30 --batch-limit 3 --max-iter 5 \
  --score-threshold 0.9 --since "$SINCE_AGENT" \
  2>&1 | tee /tmp/red_demo_v2_logs/agent_daemon.log
```

> Bo `--max-iter` → chay vo han (production). Chi lam khi da set budget DeepSeek.

Dong log cuoi mong doi (che do B/C/D):

```text
✓ Done in ~150-210s — severity=CRITICAL, 6 actions, ~180k tokens, $0.03-0.05
→ Indexed: ai-investigations/INV-<12hex>
```

### 6.3 Dung daemon

```bash
pkill -f "agent.daemon"; sleep 2
ps -ef | grep "agent.daemon" | grep -v grep | wc -l   # Expect: 0
```

### 6.4 Verify ket qua trong ai-investigations

```bash
curl -sk "$ES_AUTH_HOST/ai-investigations/_search?size=3&sort=@timestamp:desc" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"query_string\":{\"query\":\"*${RUN_ID}*\"}}}" \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'Total: {d[\"hits\"][\"total\"][\"value\"]} investigation(s)')
for h in d['hits']['hits']:
    s=h['_source']
    print(f\"  inv_id={s.get('investigation_id','?')} \"
          f\"severity={s.get('triage',{}).get('severity','?')} \"
          f\"cost=\${s.get('estimated_cost_usd',0):.4f}\")
    print('  title_vi=', s.get('report',{}).get('title_vi','')[:80])
"
```

Bang flag tham khao nhanh:

| Flag | Y nghia |
|---|---|
| `--red-index` | Index/alias de poll (wildcard `red-alerts-v2-*` hoac list `a,b,c`) |
| `--ai-index` | Doi index output (mac dinh `ai-investigations`) |
| `--score-threshold N` | Chi xu ly alert co score >= N |
| `--query-string Q` | Loc ES query_string (vd `*RunId*`, `_id:"abc"`) |
| `--max-iter N` | Dung sau N vong (0 = vo han) |
| `--batch-limit N` | So alert lay moi vong (sort `@timestamp` tang dan) |
| `--since` / `--until` | Gioi han `@timestamp` (ISO 8601 / date-math) |
| `--no-state` | Khong luu `.agent_daemon_state.json` (one-shot/lap lai) |
| `--reset-state` | Xoa state, process lai tu dau |
| `--dry-run` | Investigate (VAN ton token) nhung khong ghi ES |
| `--needs-agent-only` | Chi xu ly alert co `red.needs_agent=true` (confidence=unknown) — behavioral attribution mode |
