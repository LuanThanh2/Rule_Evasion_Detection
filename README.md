# Rule Evasion Detection (RED)

RED là hệ thống hỗ trợ phát hiện và quy kết các biến thể né tránh luật Sigma trên Windows Event Logs.


**Đóng góp mới so với AMIDES gốc:**
- Stage 1: **Ensemble Classifier** (SVM + Logistic Regression + Complement Naive Bayes) thay cho SVM đơn lẻ
- Stage 2: **Cosine Similarity** kết hợp với per-rule SVM qua **Reciprocal Rank Fusion**

---

## Mục lục

1. [Cài đặt](#cài-đặt)
2. [Thuật toán sử dụng](#thuật-toán-sử-dụng)
3. [Pipeline tổng quan](#pipeline-tổng-quan)
4. [Cách chạy](#cách-chạy)
5. [ELK Integration — Phát hiện trên hệ thống thật](#elk-integration--phát-hiện-trên-hệ-thống-thật)
6. [Chuẩn bị dữ liệu](#chuẩn-bị-dữ-liệu)
7. [Cấu trúc thư mục](#cấu-trúc-thư-mục)
8. [Config file](#config-file)

---

## Cài đặt

```bash
# Tạo virtualenv (chỉ làm lần đầu)
python3 -m venv ~/venvs/rule_evasion_env

# Activate venv — BẮT BUỘC mỗi lần mở terminal mới
source ~/venvs/rule_evasion_env/bin/activate

cd rule_evasion_detection
pip install -r requirements.txt
```

**Tăng tốc tùy chọn:**
```bash
# NVIDIA GPU (RAPIDS cuML — cần CUDA)
pip install cuml-cu12

# Intel CPU (scikit-learn-intelex)
pip install scikit-learn-intelex  # đã có trong requirements.txt
```

Hệ thống tự động chọn backend: `NVIDIA GPU > Intel CPU > CPU thường`.

> **Lưu ý:** Mọi lệnh `python3 scripts/...` bên dưới đều giả định đã `source ~/venvs/rule_evasion_env/bin/activate` trước đó.

---

## Thuật toán sử dụng

### Tiền xử lý văn bản — Text Normalization

Mọi chuỗi đầu vào (command line, script, registry path, URL) đều qua 6 bước chuẩn hóa trước khi học:

```
"powershell.exe -Exec Bypass -File C:\temp\0xABCD1234.ps1"
    │
    ├─ 1. Lọc ký tự đặc biệt: bỏ " ^ ` '
    ├─ 2. Lowercase
    ├─ 3. Tokenize: tách theo \w+ → ["powershell", "exe", "exec", "bypass", "file", "c", "temp", "0xABCD1234", "ps1"]
    ├─ 4. Lọc token hex/số dài > 3 ký tự: bỏ "0xABCD1234"
    ├─ 5. Lọc token chuỗi dài > 30 ký tự
    └─ 6. Sort + join bằng dấu phẩy
    
→ "bypass,c,exe,exec,file,powershell,ps1,temp"
```

**Mục đích:** Chuẩn hóa giúp các biến thể evasion nhỏ (thay đổi hoa/thường, thêm khoảng trắng...) vẫn cho ra token giống nhau, giảm nhiễu cho SVM.

---

### TF-IDF Vectorization

Chuyển chuỗi token đã chuẩn hóa thành vector số để mô hình ML xử lý:

```
"bypass,c,exe,exec,file,powershell,ps1,temp"
    │
    └─ comma_tokenizer (tách theo dấu phẩy)
    └─ TF-IDF: trọng số = tần suất token × log nghịch đảo tần suất tài liệu
    
→ vector thưa [0, 0.32, 0, 0.71, 0, 0.45, ...]  (chiều = số token trong từ điển)
```

Token xuất hiện nhiều ở malicious nhưng ít ở benign → trọng số TF-IDF cao → SVM dễ phân biệt.

---

### Stage 1 — Ensemble Classifier (Misuse Detection)

Phát hiện event có đáng ngờ không (benign vs. malicious).

#### SVM — Support Vector Machine
Tìm siêu phẳng (hyperplane) phân chia benign và malicious với **khoảng cách lớn nhất** (max margin):

```
Không gian TF-IDF:

  benign  ●  ●  ●          margin
             ●      ← ─────────── → ─ ─ hyperplane
                        ■  ■  ■  malicious
                     ■
```

- Kernel linear phù hợp dữ liệu text thưa chiều cao
- `class_weight=balanced`: bù trọng số khi benign >> malicious
- **GridSearchCV** tìm tham số `C` tốt nhất trong 20 giá trị ∈ [0.01, 10], chạy song song `n_jobs=3`

#### Logistic Regression (LR)
Thay vì tìm margin, LR ước tính **xác suất** một event là malicious:

```
P(malicious | x) = sigmoid(w·x + b)

Nếu P ≥ 0.5 → malicious, ngược lại → benign
```

- Cùng dạng tuyến tính như SVM nhưng nhìn từ góc xác suất
- `decision_function` = log-odds = log(P(mal)/P(ben))
- Bổ sung góc nhìn khác cho Ensemble, giảm false positive

#### Complement Naive Bayes (CNB)
Học từ **tập bù** — thay vì hỏi "token này có trong malicious không?", hỏi "token này có **không phổ biến** ở benign không?":

```
Score malicious ∝ Σ log P(token | KHÔNG phải benign)
```

- Thiết kế đặc biệt cho dữ liệu **mất cân bằng** (benign >> malicious) — phù hợp project này
- Không cần GridSearch, train rất nhanh

#### EnsembleClassifier — Kết hợp 3 mô hình

```
TF-IDF vector
    ├─→ SVM.decision_function()    → score_svm  (raw distance)
    ├─→ LR.decision_function()     → score_lr   (log-odds)
    └─→ CNB: log(P(mal)/P(ben))    → score_cnb

    ↓ z-score normalize từng thành viên (trên training data)
    ↓ weighted average
    
→ ensemble_score

    ↓ MCC Scaler (MinMaxScale → [0,1])
    
→ final_score ∈ [0,1]
    
    ↓ so với threshold
    
→ BENIGN hoặc SUSPICIOUS
```

**Lý do Ensemble tốt hơn SVM đơn lẻ:** 3 thuật toán "suy nghĩ" theo 3 cơ chế khác nhau — khi 1 thằng sai, 2 thằng kia bù lại.

#### MCC Scaler — Hiệu chỉnh ngưỡng
Sau khi có ensemble score, dùng **MCC (Matthews Correlation Coefficient)** để tìm vùng hoạt động tốt nhất và chuẩn hóa về [0,1]:

```
1. Quét 50 ngưỡng trên training data → tính MCC từng ngưỡng
2. Tìm vùng MCC > threshold (0.1)
3. Tạo MinMaxScaler đối xứng quanh điểm MCC tối ưu
4. Áp dụng: shift → scale → clip[0,1]
```

---

### Stage 2 — Rule Attribution

Khi Stage 1 phát hiện event là SUSPICIOUS, Stage 2 xác định **luật Sigma nào** bị evasion.

#### Per-rule SVM
Mỗi luật Sigma có 1 SVM binary riêng, train trên: benign vs. filter values của luật đó:

```
Rule_A: train SVM(benign, ["cscript", "vbs", "wscript"])
Rule_B: train SVM(benign, ["mimikatz", "sekurlsa"])
...

Với evasion mới:
→ transform bằng vectorizer của từng rule
→ decision_function() → score cho từng rule
→ sort → SVM ranking
```

**Yếu điểm:** Mỗi rule có vectorizer riêng → không so sánh được score giữa các rule; rule ít filter values → train không ổn định.

#### Cosine Similarity
Thay vì train model, đo **độ giống nhau** trực tiếp giữa vector TF-IDF của evasion và các filter values của từng rule trong **không gian vector chung**:

```
1. Fit 1 TF-IDF vectorizer dùng chung (tất cả filter values của mọi rule)

2. Với evasion e và rule R có filter values [f1, f2, f3]:
   cos_score(R) = max(cosine(vec(e), vec(f1)),
                      cosine(vec(e), vec(f2)),
                      cosine(vec(e), vec(f3)))

3. Sort theo cos_score → Cosine ranking
```

**Ưu điểm:** Không cần train, xử lý tốt rule ít data, tất cả rules cùng scale.

#### Reciprocal Rank Fusion (RRF) — Kết hợp 2 ranking

```
SVM ranking:    [Rule_B(rank=1), Rule_A(rank=2), Rule_C(rank=3)]
Cosine ranking: [Rule_A(rank=1), Rule_B(rank=2), Rule_C(rank=3)]

RRF score(rule) = Σ  1 / (60 + rank_in_list_i)

Rule_B: 1/(60+1) + 1/(60+2) = 0.0164 + 0.0161 = 0.0325
Rule_A: 1/(60+2) + 1/(60+1) = 0.0161 + 0.0164 = 0.0325
Rule_C: 1/(60+3) + 1/(60+3) = 0.0159 + 0.0159 = 0.0317

→ Final: [Rule_B, Rule_A, Rule_C]  (RRF chỉ dùng thứ hạng, không dùng score trực tiếp)
```

**Ưu điểm RRF:** Không bị ảnh hưởng bởi scale khác nhau giữa SVM score và Cosine score.

---

## Pipeline tổng quan

```
┌─────────────────────────────────────────────────────────────┐
│                    CHUẨN BỊ DỮ LIỆU                        │
│                                                             │
│  Benign:                                                    │
│    LMD Collections (CSV) ──→ lmd_to_benign.py              │
│    MPSD PowerShell .ps1   ──→ mpsd_to_benign.py            │
│    SecRepo Squid log      ──→ secrepo_to_benign.py         │
│                                                             │
│  Malicious:                                                 │
│    Hayabusa JSONL         ──→ hayabusa_to_matches.py        │
│    Sigma rule YAML        ──→ trích xuất filter values      │
│    Match events           ──→ generate_evasions.py          │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              STAGE 1 — MISUSE DETECTION                     │
│                                                             │
│  train.py                                                   │
│    Normalize → TF-IDF → [SVM + LR + CNB] → Ensemble        │
│    → MCC Scaler → lưu train_rslt_*.zip                      │
│                                                             │
│  validate.py                                                │
│    Load model → transform validation data                   │
│    → decision_function() → lưu valid_rslt_*.zip            │
│                                                             │
│  evaluate.py                                                │
│    Scale scores → sweep 51 thresholds                       │
│    → P/R/F1/MCC tại mỗi threshold → lưu eval_rslt_*.zip    │
└─────────────────────────────────────────────────────────────┘
                          │ nếu score ≥ threshold
                          ▼
┌─────────────────────────────────────────────────────────────┐
│             STAGE 2 — RULE ATTRIBUTION                      │
│                                                             │
│  train_attribution.py                                       │
│    Per-rule SVM (mỗi rule 1 model riêng)                    │
│    + CosineRuleAttributor (shared vectorizer)               │
│    → lưu train_rslt_attr_*.zip                              │
│                                                             │
│  eval_attribution.py --method cosine  (production)          │
│    Cosine similarity trên shared TF-IDF space               │
│    → Top-1/5/10 hit rate → lưu eval_attr_*.zip             │
└─────────────────────────────────────────────────────────────┘
```

---

## Cách chạy

> **Trước khi chạy bất kỳ lệnh nào**, activate virtualenv:
> ```bash
> source ~/venvs/rule_evasion_env/bin/activate
> ```
> Mọi lệnh `python3 scripts/...` bên dưới đều phải chạy trong venv đã activate.

> **Khuyến nghị:** Chạy smoke test (~2-3 phút) trước khi chạy full để xác nhận dữ liệu và config đúng.

### Bước 0 — Smoke test (bắt buộc lần đầu)

```bash
source ~/venvs/rule_evasion_env/bin/activate

# Chạy thử với 1000 mẫu benign — xác nhận pipeline end-to-end OK
python3 scripts/train.py --config config/process_creation.yaml \
    --max-benign-samples 1000

python3 scripts/train_attribution.py --config config/process_creation.yaml \
    --max-attribution-benign 1000

# Nếu không có lỗi → chạy full bên dưới
```

Smoke test sẽ fail sớm nếu:
- Đường dẫn file/thư mục sai
- Format benign không đúng hoặc sai `benign_field`
- Thiếu data (events, rules)

---

### Stage 1 — Misuse Detection (Ensemble SVM + LR + CNB)

Config mặc định đã trỏ cả `benign_train` và `benign_valid` → cùng file 100% data
(`benign_train.txt`) cho production. File split 80/20 (`benign_train_split_*.txt`)
chỉ giữ để debug — đổi `benign_valid` trong config nếu muốn dùng.

```bash
source ~/venvs/rule_evasion_env/bin/activate

# Cách 1 — gộp 3 bước (khuyến nghị)
python3 scripts/run_stage1.py --config config/process_creation.yaml

# Cách 2 — chạy từng bước (debug / chỉ chạy 1 phần)
python3 scripts/train.py    --config config/process_creation.yaml --ensemble
python3 scripts/validate.py --config config/process_creation.yaml
python3 scripts/evaluate.py --config config/process_creation.yaml
```

`run_stage1.py` mặc định bật `--ensemble`. Nếu cần SVM baseline để so sánh:

```bash
python3 scripts/run_stage1.py --config config/process_creation.yaml \
    --no-ensemble --result-name svm_baseline
```

**Chạy cho event type khác** — chỉ đổi `--config`:

```bash
python3 scripts/run_stage1.py --config config/registry_event.yaml
python3 scripts/run_stage1.py --config config/powershell.yaml
```

> **Lưu ý:** `train.py` tự validate đường dẫn và benign field trước khi chạy.
> GridSearch chạy **song song** với `n_jobs=3` (config). Nếu OOM giảm `num_jobs: 2`.

---

### Stage 2 — Rule Attribution (Cosine Similarity)

```bash
source ~/venvs/rule_evasion_env/bin/activate

# Train CosineRuleAttributor (+ per-rule SVM lưu kèm để so sánh, không bắt buộc dùng)
# Checkpoint tự động mỗi 20 rules → thoát giữa chừng không mất công
python3 scripts/train_attribution.py --config config/process_creation.yaml

# Evaluate — production dùng Cosine, xuất thêm CSV/JSONL chi tiết Top-3 từng sample
python3 scripts/eval_attribution.py --config config/process_creation.yaml \
    --method cosine --top-k-details 3

# Ví dụ riêng cho registry_event
python3 scripts/eval_attribution.py --config config/registry_event.yaml \
    --method cosine --top-k-details 3
```

> **Production dùng `--method cosine`** vì nhanh + chính xác nhất trên data hiện tại
> (top-1=68.8% so với Hybrid 48.7%, SVM 23.5%). Hybrid/SVM chỉ dùng khi cần so sánh
> trong luận văn — xem [Thuật toán sử dụng](#thuật-toán-sử-dụng).

Sau khi chạy với `--top-k-details 3`, script sinh thêm:

```text
models/<event_type>/eval_attr_cosine_attr_ensemble_details_top3.csv
models/<event_type>/eval_attr_cosine_attr_ensemble_details_top3.jsonl
```

File CSV có các cột chính: `sample`, `true_rule`, `true_rank`,
`top_1_rule`, `top_2_rule`, `top_3_rule` và score tương ứng. Nếu file cũ
không ghi đè được do quyền filesystem, script tự tạo biến thể như
`*_details_top3_new.csv` và ghi đường dẫn mới vào `eval_attr_*_info.json`.

> **Checkpoint:** Nếu Stage 2 bị ngắt giữa chừng, các file
> `models/process_creation/train_rslt_attr_svc_rules_ckpt_20.zip`, `_ckpt_40.zip`, ...
> chứa kết quả đã train. Sau khi chạy xong có thể xóa.

---

### Thí nghiệm so sánh cho luận văn

```bash
# --- Stage 1: SVM đơn vs Ensemble ---
# Baseline SVM
python scripts/train.py --config config/process_creation.yaml \
    --result-name svm_baseline

python scripts/validate.py --config config/process_creation.yaml
python scripts/evaluate.py --config config/process_creation.yaml

# Ensemble SVM+LR+CNB
python scripts/train.py --config config/process_creation.yaml \
    --ensemble --result-name ensemble_full

python scripts/validate.py --config config/process_creation.yaml
python scripts/evaluate.py --config config/process_creation.yaml

# --- Stage 2: So sánh Attribution methods ---
python scripts/eval_attribution.py --config config/process_creation.yaml --method svm
python scripts/eval_attribution.py --config config/process_creation.yaml --method cosine
python scripts/eval_attribution.py --config config/process_creation.yaml --method hybrid
```

---

### Chạy tất cả event types

```bash
source ~/venvs/rule_evasion_env/bin/activate

# Linux/Mac — Stage 1 cho cả 3 event types
for cfg in process_creation registry_event powershell; do
    python3 scripts/run_stage1.py --config config/$cfg.yaml
done

# Full pipeline (Stage 1 + Stage 2) cho 3 event types
for cfg in process_creation registry_event powershell; do
    python3 scripts/run_stage1.py --config config/$cfg.yaml
    python3 scripts/train_attribution.py --config config/$cfg.yaml
    python3 scripts/eval_attribution.py --config config/$cfg.yaml \
        --method cosine --top-k-details 3
done

# Windows PowerShell
foreach ($cfg in @("process_creation","registry_event","powershell","proxy_web")) {
    python scripts/run_stage1.py --config "config/$cfg.yaml"
    python scripts/train_attribution.py --config "config/$cfg.yaml"
    python scripts/eval_attribution.py --config "config/$cfg.yaml" --method cosine --top-k-details 3
}
```

---

### Sinh đồ thị

```bash
python scripts/plot.py pr \
    --result-paths models/process_creation/eval_rslt_*.zip \
    --output figures/stage1_pr_threshold.pdf

python scripts/plot.py attr \
    --result-path models/process_creation/eval_attr_hybrid_*.zip \
    --output figures/stage2_attribution.pdf
```

---

---

## ELK Integration — Phát hiện trên hệ thống thật

Pipeline kết nối trực tiếp với ELK Stack đang giám sát Windows, không cần Hayabusa hay xử lý offline.

### Kiến trúc

```
Windows (Sysmon EID 1)
  └── Winlogbeat / Elastic Agent ──► Elasticsearch
                                          │
                               detect_live.py (poll mỗi N giây)
                                          │
                               Stage 1: Ensemble → score
                                          │ score ≥ threshold
                               Stage 2: Cosine Similarity → top-K rules
                                          │
                               Elasticsearch (index: red-alerts)
                                          │
                                    Kibana Dashboard
```

### Bước 1 — Offline verify (chạy lần đầu)

```bash
# Export events từ 15m qua ra JSONL
python scripts/elk_export.py \
  --es-host http://10.10.20.100:9200 \
  --es-user elastic \
  --es-password tzxr74123 \
  --es-index "logs-winlog*" \
  --since 15m \
  --out ~/detect_logs/events.jsonl


# Index thực tế tùy agent:
#   Winlogbeat:                 --es-index "winlogbeat-*"
#   Elastic Agent (Sysmon):     --es-index "logs-winlog*"
#   Elastic Agent qua Logstash: --es-index "logs-generic*"

# Chạy detection (dùng Cosine — nhanh & chính xác hơn Hybrid với data hiện tại)
python scripts/detect_batch.py \
  --config config/process_creation.yaml \
  --events  ~/detect_logs/events.jsonl \
  --threshold 0.0 \
  --method cosine \
  --out ~/detect_logs/alerts.jsonl

cat ~/detect_logs/alerts.jsonl | python -m json.tool
```

### Bước 2 — Live daemon

```bash
python scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "http://elastic:tzxr74123@10.10.20.100:9200" \
  --es-index "logs-winlog*" \
  --out-index red-alerts \
  --threshold 0.0 \
  --method cosine \
  --interval 60

```

Alerts được ghi vào index `red-alerts` với các field:

| Field | Mô tả |
|---|---|
| `red.detection_score` | Score Stage 1 (cao = suspicious) |
| `red.top_rule` | Rule Sigma bị evasion nhiều khả năng nhất |
| `red.top_rules[]` | Top-5 rules kèm cosine similarity score |
| `red.command_line` | CommandLine của event |
| `host.name` | Tên máy Windows |

Vào Kibana → **Stack Management → Index Patterns** → tạo pattern `red-alerts` để visualize.

### Lưu ý

- **Threshold**: Mặc định `0.0` (raw decision boundary). Tăng lên `0.3`–`0.5` nếu quá nhiều false positive.
- **Method**: Mặc định nên dùng `cosine`. Hybrid/SVM chỉ dùng khi so sánh học thuật.
- **State file**: `.detect_live_state.json` lưu timestamp đã xử lý — restart không bị trùng lặp.
- **Không cần** `elasticsearch-py` — dùng `requests` thuần.
- **Event ID**: Sysmon = `1`, Windows Security Log = `4688`.

---

## Chuẩn bị dữ liệu

### Benign data

```bash
# Process creation + Registry (từ LMD Collections)
python scripts/lmd_to_benign.py \
    --lmd-dir ~/datasets/LMD_Collections \
    --output-dir ~/data/benign

# PowerShell (từ MPSD)
python scripts/mpsd_to_benign.py \
    --mpsd-dir ~/datasets/mpsd/powershell_benign_dataset \
    --output-dir ~/data/benign/powershell

# Web proxy URLs (từ SecRepo Squid log)
python scripts/secrepo_to_benign.py \
    --input ~/datasets/access.log \
    --output-dir ~/data/benign/proxy_web
```

### Match events

```bash
# Từ Hayabusa output
python scripts/hayabusa_to_matches.py \
    --input hayabusa_matches.jsonl \
    --output-dir ~/data/sigma/events_hayabusa/windows/process_creation \
    --event-type process_creation
```

### Evasion variants

```bash
python scripts/generate_evasions.py --config config/process_creation.yaml
python scripts/generate_evasions.py --config config/registry_event.yaml
python scripts/generate_evasions.py --config config/powershell.yaml
```

---

## Cấu trúc thư mục

```
rule_evasion_detection/
├── red/                          # Core library
│   ├── normalize.py              # 6-step text normalization
│   ├── features.py               # TF-IDF / Count vectorizers, comma_tokenizer
│   ├── models.py                 # SVM + LR + CNB + EnsembleClassifier
│   ├── evaluate.py               # BinaryEvaluation, MCC scaler
│   ├── attribution.py            # RuleAttributionEvaluation, CosineRuleAttributor, RRF
│   ├── data.py                   # Data loading (txt/jsonl/json/csv, Sigma rules)
│   ├── persist.py                # save/load pickle+ZIP
│   └── visualize.py              # PR curves, attribution plots
├── scripts/
│   ├── train.py                  # Stage 1 training (--ensemble flag)
│   ├── validate.py               # Transform + decision_function
│   ├── evaluate.py               # MCC scale + threshold sweep
│   ├── train_attribution.py      # Stage 2: per-rule SVM + Cosine
│   ├── eval_attribution.py       # --method svm|cosine|hybrid
│   ├── generate_evasions.py      # Tạo evasion variants
│   ├── run_pipeline.py           # Chạy toàn bộ pipeline
│   ├── plot.py                   # Sinh đồ thị
│   ├── hayabusa_to_matches.py    # Hayabusa JSONL → match events
│   ├── lmd_to_benign.py          # LMD CSV → benign_train.txt
│   ├── mpsd_to_benign.py         # MPSD .ps1 → benign PowerShell
│   ├── mpsd_to_malicious.py      # MPSD malicious .ps1 filter
│   ├── secrepo_to_benign.py      # Squid log → URL benign
│   ├── elk_export.py             # Export events Elasticsearch → JSONL
│   ├── detect_batch.py           # Batch detection: JSONL → alerts (offline)
│   └── detect_live.py            # Live daemon: poll ES → Stage1+2 → red-alerts
├── config/
│   ├── process_creation.yaml
│   ├── registry_event.yaml
│   ├── powershell.yaml
│   └── proxy_web.yaml
├── data/                         # Dữ liệu (không commit)
│   ├── benign/
│   ├── sigma/rules/
│   ├── sigma/events_hayabusa/
│   └── sigma/evasions/
├── models/                       # Output model .zip (không commit)
├── requirements.txt
└── run_all.sh
```

---

## Config file

Giải thích toàn bộ các key trong `config/*.yaml`:

```yaml
data:
  benign_train: ~/data/benign/process_creation/benign_train.txt
  benign_valid: ~/data/benign/process_creation/benign_train.txt
  benign_field: process.command_line      # dot-path để extract từ JSON/CSV (bỏ qua nếu plain text)
  events_dir: ~/data/sigma/events_hayabusa/windows/process_creation
  evasions_dir: ~/data/sigma/evasions/windows/process_creation
  rules_dir: ~/data/sigma/rules/windows/process_creation
  # Sigma native field names — dùng để parse Sigma YAML detection blocks
  search_fields:
    - CommandLine
  # Mapping Sigma field name → list JSON paths để đọc event/log dict
  event_field_map:
    CommandLine:
      - process.command_line
      - winlog.event_data.CommandLine
  max_benign_samples: 30000        # Stage 1: giới hạn benign tránh OOM/chậm (bỏ = không giới hạn)
  max_attribution_benign: 15000    # Stage 2: giới hạn benign mỗi rule (x100+ rules → quan trọng)

training:
  malicious_samples: both         # rule_filters | matches | both
  vectorization: tfidf            # tfidf | count | binary_count | hashing | scaled_count
  ngram_range: [1, 1]
  search_params: true             # dùng GridSearchCV để tìm C tốt nhất
  ensemble: false                 # true = SVM+LR+CNB Ensemble, false = SVM đơn lẻ
  ensemble_members: [svm, lr, cnb]
  scoring: f1                     # metric để GridSearch chọn best params: f1 | mcc
  cv_folds: 5                     # số fold trong cross-validation
  num_jobs: 3                     # core chạy song song GridSearch (giảm xuống 2 nếu OOM)

validation:
  malicious_samples: evasions     # evasions | matches | rule_filters | both

scaling:
  mcc_scaling: true               # dùng MCC calibration để scale score → [0,1]
  mcc_threshold: 0.1              # chỉ dùng vùng df_values có MCC > ngưỡng này

evaluation:
  num_thresholds: 50              # sweep 51 điểm trong [0,1] → P/R/F1/MCC

output:
  dir: models/process_creation
  result_name: misuse_svc_rules_f1
  train_result_path: models/process_creation/train_rslt_misuse_svc_rules_f1.zip  # Stage 2 đọc từ đây
  attr_result_name: attr_svc_rules
```

### Giá trị field per event type

| Event Type | `benign_field` | `search_fields` |
|---|---|---|
| `process_creation` | `process.command_line` | `[CommandLine]` |
| `registry_event` | `winlog.event_data.TargetObject` | `[TargetObject]` |
| `powershell` | `winlog.event_data.ScriptBlockText` | `[ScriptBlockText]` |
| `proxy_web` | `url` (plain text) | `[url, c-uri, cs-uri-stem]` |

---

## Loại sự kiện hỗ trợ

| Event Type | Field | Config | Benign source |
|---|---|---|---|
| `process_creation` | `process.command_line` | `config/process_creation.yaml` | LMD Collections |
| `registry_event` | `winlog.event_data.TargetObject` | `config/registry_event.yaml` | LMD Collections |
| `powershell` | `winlog.event_data.ScriptBlockText` | `config/powershell.yaml` | MPSD |
| `proxy_web` | `c-uri` / URL | `config/proxy_web.yaml` | SecRepo Squid |

---

## Tham khảo

- Uetz et al., *"AMIDES: Adaptive Misuse Detection and Evasion"*, USENIX Security 2024
- SigmaHQ: [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- LMD Collections: Lateral Movement Dataset 2022/2023
- MPSD: [github.com/das-lab/mpsd](https://github.com/das-lab/mpsd)
- Hayabusa: [github.com/Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa)
