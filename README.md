# Rule Evasion Detection (RED)

Mở rộng và tái cài đặt pipeline **AMIDES** (Uetz et al., USENIX Security 2024) để phát hiện và quy kết evasion của luật Sigma trên Windows event logs.

**Đóng góp mới so với AMIDES gốc:**
- Stage 1: **Ensemble Classifier** (SVM + Logistic Regression + Complement Naive Bayes) thay cho SVM đơn lẻ
- Stage 2: **Cosine Similarity** kết hợp với per-rule SVM qua **Reciprocal Rank Fusion**

---

## Mục lục

1. [Cài đặt](#cài-đặt)
2. [Thuật toán sử dụng](#thuật-toán-sử-dụng)
3. [Pipeline tổng quan](#pipeline-tổng-quan)
4. [Cách chạy](#cách-chạy)
5. [Chuẩn bị dữ liệu](#chuẩn-bị-dữ-liệu)
6. [Cấu trúc thư mục](#cấu-trúc-thư-mục)
7. [Config file](#config-file)

---

## Cài đặt

```bash
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
- **GridSearchCV** tìm tham số `C` tốt nhất trong 50 giá trị ∈ [0.01, 10]

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
│  eval_attribution.py --method hybrid                        │
│    SVM ranking + Cosine ranking                             │
│    → RRF Fusion → Top-K rules                               │
│    → Top-1/5/10 hit rate → lưu eval_attr_*.zip             │
└─────────────────────────────────────────────────────────────┘
```

---

## Cách chạy

### Chạy nhanh toàn bộ pipeline

```bash
python scripts/run_pipeline.py --config config/process_creation.yaml
```

### Chạy từng bước (Stage 1)

```bash
# Bước 1: Train model (Ensemble)
python scripts/train.py --config config/process_creation.yaml --ensemble

# Bước 1 thay thế: Train SVM đơn lẻ (baseline)
python scripts/train.py --config config/process_creation.yaml --search-params

# Bước 2: Validate (tính decision_function trên validation set)
python scripts/validate.py --config config/process_creation.yaml

# Bước 3: Evaluate (threshold sweep → metrics)
python scripts/evaluate.py --config config/process_creation.yaml
```

### Stage 2 — Rule Attribution

```bash
# Train per-rule SVM + Cosine attributor
python scripts/train_attribution.py --config config/process_creation.yaml

# Evaluate với 3 method để so sánh
python scripts/eval_attribution.py --config config/process_creation.yaml --method svm
python scripts/eval_attribution.py --config config/process_creation.yaml --method cosine
python scripts/eval_attribution.py --config config/process_creation.yaml --method hybrid
```

### Thí nghiệm so sánh (cho luận văn)

```bash
# So sánh SVM đơn vs Ensemble
python scripts/train.py --config config/process_creation.yaml --search-params \
    --result-name svm_only
python scripts/train.py --config config/process_creation.yaml --ensemble \
    --result-name ensemble_full

# So sánh Attribution methods
python scripts/eval_attribution.py --config config/process_creation.yaml --method svm
python scripts/eval_attribution.py --config config/process_creation.yaml --method cosine
python scripts/eval_attribution.py --config config/process_creation.yaml --method hybrid
```

### Chạy tất cả event types

```bash
bash run_all.sh
```

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
│   └── secrepo_to_benign.py      # Squid log → URL benign
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

```yaml
data:
  benign_train: ~/data/benign/process_creation/benign_train.txt
  benign_valid: ~/data/benign/process_creation/benign_train.txt
  benign_field: process.command_line      # dot-path để extract từ JSON/CSV
  events_dir: ~/data/sigma/events_hayabusa/windows/process_creation
  evasions_dir: ~/data/sigma/evasions/windows/process_creation
  rules_dir: ~/data/sigma/rules/windows/process_creation
  search_fields:
    - process.command_line

training:
  malicious_samples: both         # rule_filters | matches | both
  vectorization: tfidf            # tfidf | count | binary_count | hashing | scaled_count
  ngram_range: [1, 1]
  search_params: true             # GridSearchCV
  ensemble: false                 # true = dùng SVM+LR+CNB Ensemble
  ensemble_members: [svm, lr, cnb]
  scoring: f1                     # f1 | mcc
  cv_folds: 5
  num_jobs: 3

scaling:
  mcc_scaling: true
  mcc_threshold: 0.1

evaluation:
  num_thresholds: 50

output:
  dir: models/process_creation
  result_name: misuse_svc_rules_f1
  attr_result_name: attr_svc_rules
```

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
