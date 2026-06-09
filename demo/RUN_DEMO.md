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

## 5. Xem log va kiem tra tien trinh

```bash
ps -ef | grep detect_live.py | grep -v grep || true
tail -f /tmp/red_demo_v2_logs/detect_*.log
```

Log quet theo range:

```bash
tail -f /tmp/red_demo_v2_logs/range_*.log
```
