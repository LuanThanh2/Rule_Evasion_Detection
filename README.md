# Rule Evasion Detection (RED)

RED là hệ thống end-to-end phát hiện hành vi né tránh luật Sigma, quy kết event về rule Sigma tương ứng, và **tự động triage bằng Multi-Agent AI** trên Windows Event Logs.

**3 lớp chính:**

| Lớp | Vai trò | Output |
|---|---|---|
| **Stage 1 — Misuse Detection** | Ensemble Classifier (SVM + LR + CNB) phân biệt benign vs malicious | Score ∈ [0,1] |
| **Stage 2 — Rule Attribution** | Cosine Similarity trong TF-IDF chung — quy kết rule Sigma bị né | Top-K rules |
| **Phase C — AI Agent SOC Triage** ⭐ | 8 specialized AI agents (incl. Forensic) tự động investigate với host-level evidence từ Velociraptor, sinh Sigma patch, đề xuất action | Vietnamese report + evidence-grounded Sigma patch + containment plan |

**Đóng góp mới so với AMIDES gốc (Uetz et al., USENIX Security 2024):**
- **Stage 1**: Ensemble Classifier thay cho SVM đơn lẻ — recall 100% vs 94.3%
- **Stage 2**: Cosine Similarity trong không gian TF-IDF chung — top-1 accuracy 68.8% vs SVM 23.5%
- **Stage 2 (v2 — 2026-05-19)**: Cosine **catalog expansion** từ 146 lên **1,367 rule** — fit thuần trên Sigma YAML filter values, KHÔNG cần Hayabusa match events
- **Phase C**: Multi-Agent SOC Triage với **auto-generation Sigma rule patch** ⭐ — feature không có trong Elastic AI Assistant / Splunk / Sentinel
- **Phase C (v2 — 2026-05-17)**: Thêm **Forensic Agent** query Velociraptor lấy bằng chứng cứng từ host → kháng hallucination (verified: 0 fake IP trong containment actions)
- **Sigma metadata enrichment**: Mỗi alert có `top_rule_sigma_filename` + `sigma_id` + `sigma_title` → SOC analyst trace ngược về file Sigma trực tiếp

---

## Mục lục

1. [Cài đặt](#cài-đặt)
2. [Trợ giúp lệnh (`-h` / `--help`)](#trợ-giúp-lệnh--h----help)
3. [Thuật toán sử dụng](#thuật-toán-sử-dụng)
4. [Pipeline tổng quan](#pipeline-tổng-quan)
5. [Cách chạy](#cách-chạy)
6. [ELK Integration — Phát hiện trên hệ thống thật](#elk-integration--phát-hiện-trên-hệ-thống-thật)
7. [AI Agent — Multi-Agent SOC Triage](#ai-agent--multi-agent-soc-triage)
8. [Chuẩn bị dữ liệu](#chuẩn-bị-dữ-liệu)
9. [Cấu trúc thư mục](#cấu-trúc-thư-mục)
10. [Config file](#config-file)

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

**Cấu hình cho AI Agent (Phase C, optional):**
```bash
# Copy template, điền DeepSeek API key + ES credentials thật
cp .env.example .env
nano .env
```

Tối thiểu cần điền trong `.env`:
- `DEEPSEEK_API_KEY` — lấy ở [platform.deepseek.com](https://platform.deepseek.com/api_keys) (~$0.27/1M tokens, ~$0.015/alert)
- `ES_HOST`, `ES_USER`, `ES_PASSWORD` — Elasticsearch credentials
- (Optional) `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` để Response Agent push notification

> **Lưu ý:** Mọi lệnh `python3 scripts/...` và `python3 -m agent...` bên dưới đều giả định đã `source ~/venvs/rule_evasion_env/bin/activate` trước đó.

---

## Trợ giúp lệnh (`-h` / `--help`)

**Mọi script trong `scripts/` và `agent/` đều hỗ trợ `-h` hoặc `--help`** — in ra usage,
danh sách tham số, default value và ví dụ chạy. Khi quên cú pháp, chạy `--help` trước.

```bash
source ~/venvs/rule_evasion_env/bin/activate

# Pattern chung
python3 scripts/<tên_script>.py --help
python3 -m agent.<module> --help
```

### Ví dụ

```bash
python3 scripts/run_stage1.py --help
```

```text
usage: run_stage1.py [-h] --config CONFIG [--ensemble] [--no-ensemble]
                     [--result-name RESULT_NAME]

Run Stage 1 pipeline (train + validate + evaluate)

options:
  -h, --help            show this help message and exit
  --config CONFIG       Path to YAML config (config/process_creation.yaml, ...)
  --ensemble            Use EnsembleClassifier SVM+LR+CNB (default)
  --no-ensemble         Use single SVM (baseline so sánh)
  --result-name RESULT_NAME
                        Override output name

Usage:
  python scripts/run_stage1.py --config config/process_creation.yaml
  python scripts/run_stage1.py --config config/powershell.yaml --no-ensemble
```

### Bảng tra nhanh — script nào dùng cho việc gì

| Mục đích | Lệnh xem help |
|---|---|
| **Stage 1 — gộp 3 bước** | `python3 scripts/run_stage1.py --help` |
| Stage 1 — train riêng | `python3 scripts/train.py --help` |
| Stage 1 — validate riêng | `python3 scripts/validate.py --help` |
| Stage 1 — evaluate riêng | `python3 scripts/evaluate.py --help` |
| Stage 1 — diagnose model | `python3 scripts/diagnose_stage1.py --help` |
| **Stage 2 — train attribution** | `python3 scripts/train_attribution.py --help` |
| Stage 2 — eval (cosine/svm/hybrid) | `python3 scripts/eval_attribution.py --help` |
| Toàn pipeline Stage 1+2 | `python3 scripts/run_pipeline.py --help` |
| Sinh evasion variants | `python3 scripts/generate_evasions.py --help` |
| Export evasion → PowerShell | `python3 scripts/export_evasion_scripts.py --help` |
| Sinh đồ thị PR / attribution | `python3 scripts/plot.py --help` |
| **ELK — export events ES → JSONL** | `python3 scripts/elk_export.py --help` |
| ELK — batch detection (offline) | `python3 scripts/detect_batch.py --help` |
| ELK — live daemon (real-time) | `python3 scripts/detect_live.py --help` |
| ELK — push alerts JSONL → ES | `python3 scripts/push_alerts.py --help` |
| Convert Sigma YAML → Elastic NDJSON | `python3 scripts/convert_sigma_to_elastic.py --help` |
| **Data prep — LMD → benign** | `python3 scripts/lmd_to_benign.py --help` |
| Data prep — MPSD → benign PowerShell | `python3 scripts/mpsd_to_benign.py --help` |
| Data prep — SecRepo → benign URL | `python3 scripts/secrepo_to_benign.py --help` |
| Data prep — Hayabusa → match events | `python3 scripts/hayabusa_to_matches.py --help` |
| Data prep — OTRF → match events | `python3 scripts/otrf_to_matches.py --help` |
| Data prep — split 80/20 benign | `python3 scripts/split_benign.py --help` |
| **AI Agent — daemon poll ES** | `python3 -m agent.daemon --help` |
| AI Agent — chạy 1 investigation | `python3 -m agent.run --help` |
| AI Agent — inject mock alert | `python3 -m agent.inject_test_alert --help` |
| AI Agent — single-agent baseline | `python3 -m agent.prototype --help` |
| **🆕 Demo APT scenario** (Windows) | `demo/apt_demo_scenario.ps1 -Mode chain` |
| 🆕 Tra rule RED ↔ Sigma | xem `demo/RED_RULE_MAP.md` (1,367 rule) |
| 🆕 Q&A bank cho defense | xem `demo/QA_PREP.md` |
| 🆕 Slide outline | xem `demo/SLIDES_OUTLINE.md` |

> **Mẹo:** Không nhớ tên script? Liệt kê tất cả bằng `ls scripts/*.py` hoặc `ls agent/*.py`.
> Mọi script dùng `argparse` nên cú pháp help luôn nhất quán.

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

#### Cosine Similarity (production)
Stage 2 production dùng **Cosine Similarity**: đo độ giống nhau trực tiếp giữa vector TF-IDF của event suspicious và các filter values của từng rule trong **không gian vector chung**:

```
1. Fit 1 TF-IDF vectorizer dùng chung (tất cả filter values của mọi rule)

2. Với evasion e và rule R có filter values [f1, f2, f3]:
   cos_score(R) = max(cosine(vec(e), vec(f1)),
                      cosine(vec(e), vec(f2)),
                      cosine(vec(e), vec(f3)))

3. Sort theo cos_score → Cosine ranking
```

**Ưu điểm:** Không cần train, xử lý tốt rule ít data, tất cả rules cùng scale.

#### 🆕 Catalog expansion (2026-05-19) — 146 → 1,367 rule

**Vấn đề trước**: per-rule SVM và Cosine cả 2 đều iterate `events_hayabusa/<event_type>/` — chỉ rule có **match events từ Hayabusa scan** mới được train. Toàn pipeline chỉ phủ 146 rule (83 proc + 25 ps + 38 reg) trên tổng 1,624 Sigma rule có sẵn trong `data/sigma/rules/`.

**Fix**: tách 2 loop trong `scripts/train_attribution.py`:
- **Loop A (SVM)**: cần training samples → giữ nguyên iterate Hayabusa subdir
- **Loop B (Cosine)**: chỉ cần filter values từ YAML detection block → load **TẤT CẢ rule trong rules_dir** + normalize key về snake_case → fit Cosine trên union

**Kết quả**:

| Model | per-rule SVM | Cosine attributor (catalog) |
|---|---|---|
| `process_creation` | 202 | **920** |
| `powershell` | 25 | **204** |
| `registry_event` | 38 | **243** |
| **TỔNG Cosine** | — | **1,367 rule** (~9.4x vs trước) |

→ Khi alert đến, RED ưu tiên per-rule SVM (chất lượng cao hơn), fallback Cosine attribute đến bất kỳ rule nào trong 1,367 catalog. Verified E2E: alert evasion `HKCU\RunOnce` attribute tới rule `currentversion_nt_autorun_keys_modification` — rule MỚI từ catalog, không có trong 38 SVM.

#### Sigma metadata enrichment trong alert (2026-05-19)

Mỗi alert sinh bởi `detect_batch.py` / `detect_live.py` giờ có thêm 3 field:
- `top_rule_sigma_filename` — vd `proc_creation_win_regsvr32_flags_anomaly.yml`
- `top_rule_sigma_id` — UUID universal unique
- `top_rule_sigma_title` — human-readable, hiển thị trong Kibana Security/Rules

Module `red/rule_metadata.py` (class `SigmaRuleIndex`) load 1,624 Sigma YAML 1 lần
khi script start, lookup theo internal name → metadata. Verified 100% (1367/1367).

Xem `demo/RED_RULE_MAP.md` để tra cứu đầy đủ 1,367 rule.

#### Baseline/So sánh: Per-rule SVM và Hybrid/RRF
Để phục vụ thí nghiệm so sánh, project vẫn giữ per-rule SVM và Hybrid/RRF:

- **Per-rule SVM:** mỗi rule có 1 SVM binary riêng, train trên benign vs. filter values của rule đó. Cần Hayabusa match events → giới hạn 265 rule trên 3 model.
- **Hybrid/RRF:** kết hợp ranking từ SVM và Cosine bằng Reciprocal Rank Fusion.

Hai chế độ này không phải cấu hình production hiện tại. Production dùng:

```bash
python3 scripts/eval_attribution.py --config config/process_creation.yaml \
    --method cosine --top-k-details 3
```

Ví dụ RRF dùng trong phần so sánh:

```
SVM ranking:    [Rule_B(rank=1), Rule_A(rank=2), Rule_C(rank=3)]
Cosine ranking: [Rule_A(rank=1), Rule_B(rank=2), Rule_C(rank=3)]

RRF score(rule) = Σ  1 / (60 + rank_in_list_i)

Rule_B: 1/(60+1) + 1/(60+2) = 0.0164 + 0.0161 = 0.0325
Rule_A: 1/(60+2) + 1/(60+1) = 0.0161 + 0.0164 = 0.0325
Rule_C: 1/(60+3) + 1/(60+3) = 0.0159 + 0.0159 = 0.0317

→ Final: [Rule_B, Rule_A, Rule_C]  (RRF chỉ dùng thứ hạng, không dùng score trực tiếp)
```

**Ưu điểm RRF:** Không bị ảnh hưởng bởi scale khác nhau giữa SVM score và Cosine score, nhưng trên dữ liệu hiện tại Cosine được chọn làm phương pháp chính vì nhanh hơn và ổn định hơn.

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
│    Per-rule SVM: 265 rule (cần Hayabusa match events)       │
│    CosineRuleAttributor: 1,367 rule (catalog expansion ⭐)  │
│       ↑ load filter values từ YAML, không cần training data │
│    → lưu train_rslt_attr_*.zip                              │
│                                                             │
│  eval_attribution.py --method cosine  (production)          │
│    Cosine similarity trên shared TF-IDF space               │
│    → Top-1/5/10 hit rate → lưu eval_attr_*.zip             │
└─────────────────────────────────────────────────────────────┘
                          │ trên hệ thống thật, real-time:
                          ▼
┌─────────────────────────────────────────────────────────────┐
│         ELK INTEGRATION (detect_live.py)                    │
│  Sysmon/PowerShell event ──► Elasticsearch ──► RED detect   │
│    ──► SigmaRuleIndex enrichment (filename + UUID + title)  │
│    ──► red-alerts index                                     │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│       PHASE C — AI AGENT SOC TRIAGE ⭐ (8 agents)            │
│                                                             │
│  agent/daemon.py (poll mỗi 60s)                             │
│                                                             │
│  Supervisor → Triage                                        │
│              ├─ 🔬 Forensic Agent (Velociraptor query host) │
│              ├─ parallel(Hunt, RED Analyst, MITRE)          │
│              └─ Response (Sigma patch grounded by forensic) │
│                  → Report (Vietnamese markdown)             │
│                                                             │
│  → lưu ai-investigations index                              │
│  → Kibana dashboard + Telegram notify                       │
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

# Train CosineRuleAttributor (per-rule SVM vẫn lưu kèm để so sánh, không dùng production)
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
  --es-index "logs-winlog.*" \
  --since 15m \
  --out ~/detect_logs/events.jsonl


# Index thực tế tùy agent:
#   Winlogbeat:                 --es-index "winlogbeat-*"
#   Elastic Agent (Sysmon):     --es-index "logs-winlog.*"
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

Daemon demo sạch, chỉ quét rộng family PowerShell process và ghi vào index
riêng `red-alerts-demo` để không lẫn noise như Docker/Chrome/conhost. Query này
chỉ giảm nhiễu nguồn vào, không lọc sẵn `-EncodedCommand`, `-e` hay các token
evasion:

```bash
python3 scripts/detect_live.py \
  --config config/process_creation.yaml \
  --es-host "http://elastic:tzxr74123@10.10.20.100:9200" \
  --es-index "logs-winlog.*" \
  --out-index red-alerts-demo \
  --threshold 0.5 \
  --method cosine \
  --interval 60 \
  --lookback 5m \
  --reset-state \
  --batch-size 500 \
  --query-string 'winlog.event_data.Image:*powershell* OR process.name:*powershell* OR winlog.event_data.CommandLine:*powershell* OR process.command_line:*powershell*'
```

`--interval 60` là chu kỳ poll liên tục; cửa sổ khởi động do `--lookback 5m`
quyết định. `--reset-state` giúp demo bắt đầu từ `now-5m`, tránh kẹt
`.detect_live_state.json` cũ.

Alerts được ghi vào index `red-alerts-demo` với các field:

| Field | Mô tả |
|---|---|
| `red.detection_score` | Score Stage 1 (cao = suspicious) |
| `red.top_rule` | Rule Sigma bị evasion nhiều khả năng nhất (internal name snake_case) |
| `red.top_rule_sigma_filename` | **🆕** Filename Sigma rule YAML (vd `proc_creation_win_regsvr32_flags_anomaly.yml`) — click để mở file gốc |
| `red.top_rule_sigma_id` | **🆕** UUID Sigma rule — universal unique, dùng để tra Sigma community |
| `red.top_rule_sigma_title` | **🆕** Human-readable title (hiển thị trong Kibana Security/Rules) |
| `red.top_rules[]` | Top-5 rules kèm cosine similarity score + metadata Sigma cho mỗi rule |
| `red.command_line` | CommandLine của event |
| `host.name` | Tên máy Windows |

Vào Kibana → **Stack Management → Index Patterns** → tạo pattern `red-alerts-demo` để visualize.

### Lưu ý

- **Threshold**: Mặc định `0.0` (raw decision boundary). Tăng lên `0.3`–`0.5` nếu quá nhiều false positive.
- **Method**: Mặc định nên dùng `cosine`. Hybrid/SVM chỉ dùng khi so sánh học thuật.
- **State file**: `.detect_live_state.json` lưu timestamp đã xử lý — restart không bị trùng lặp.
- **Không cần** `elasticsearch-py` — dùng `requests` thuần.
- **Event ID**: Sysmon = `1`, Windows Security Log = `4688`.

### Convert Sigma rules sang Elastic Detection Rules

Elastic UI **không import trực tiếp Sigma YAML**. Luồng đúng là:

```text
Sigma .yml
  └── sigma-cli / pySigma
        └── Elastic Security Detection Rule .ndjson
              └── Kibana Security → Rules → Import rules
```

Với các rule Windows hiện tại:

```text
~/data/sigma/rules/windows/
├── process_creation
├── powershell
└── registry
```

chạy:

```bash
source ~/venvs/rule_evasion_env/bin/activate
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection

pip install -r requirements.txt

python3 scripts/convert_sigma_to_elastic.py
```

Output mặc định:

```text
/home/luanthanh/data/sigma/elastic_rules/windows_sigma_elastic.ndjson
```

Kết quả hiện tại:

```text
process_creation: 1169 Sigma rules
powershell:        208 Sigma rules
registry:          247 Sigma rules
total:            1624 Elastic Detection Rule objects
```

Mặc định script dùng:

```text
target:   lucene
pipeline: ecs_windows
format:   siem_rule_ndjson
```

`lucene + siem_rule_ndjson` tạo Elastic **Custom Query detection rules** có thể import vào Detection Engine. Không dùng `kibana_ndjson` cho bước này vì format đó là Kibana saved search, không phải Detection Rule import.

Nếu muốn giới hạn index pattern chỉ vào log Windows:

```bash
python3 scripts/convert_sigma_to_elastic.py \
  --index-pattern "logs-winlog.*" \
  --index-pattern "winlogbeat-*"
```

Import bằng UI:

```text
Kibana → Security → Rules → Import rules
```

chọn file:

```text
/home/luanthanh/data/sigma/elastic_rules/windows_sigma_elastic.ndjson
```

Import bằng API qua Kibana port `5601`:

```bash
export KIBANA_PASSWORD='your-password'

python3 scripts/convert_sigma_to_elastic.py \
  --skip-convert \
  --import-to-kibana \
  --kibana-url http://10.10.20.100:5601 \
  --kibana-user elastic \
  --kibana-password "$KIBANA_PASSWORD" \
  --import-chunk-size 200 \
  --import-timeout 300
```

Hoặc convert lại và import ngay trong một lệnh:

```bash
python3 scripts/convert_sigma_to_elastic.py \
  --import-to-kibana \
  --kibana-url http://10.10.20.100:5601 \
  --kibana-user elastic \
  --kibana-password "$KIBANA_PASSWORD" \
  --import-chunk-size 200 \
  --import-timeout 300
```

> **Lưu ý:** Import 1624 rules một lần có thể làm client timeout dù Kibana vẫn đang ghi rule phía server. Dùng `--import-chunk-size 200 --import-timeout 300` để import theo 9 batch nhỏ, dễ theo dõi lỗi và tránh timeout. Script cũng tự normalize severity Sigma `informational` thành Elastic `low` vì Detection Engine chỉ nhận `low|medium|high|critical`.

Nếu Kibana hiện:

```text
Detection engine permissions required
```

thì user hiện tại chưa có quyền Detection Engine. Dùng user `elastic` hoặc cấp role có:

- Kibana Security privileges: `All`
- Rules/Alerts privileges: `All`
- Read index log nguồn: `logs-*`, `logs-winlog.*`, `winlogbeat-*`
- Quyền hệ thống Detection Engine theo yêu cầu của Elastic Security

Sau khi import, vào:

```text
Security → Rules
```

lọc rule theo prefix `SIGMA -`, enable/disable rule cần dùng, rồi theo dõi alert ở:

```text
Security → Alerts
```

---

## AI Agent — Multi-Agent SOC Triage

Lớp cuối của pipeline: **8 specialized AI agents** tự động investigate mọi alert từ `red-alerts`, gọi Velociraptor lấy bằng chứng cứng từ host, sinh báo cáo tiếng Việt, đề xuất Sigma patch và containment actions. Kết quả lưu vào index `ai-investigations` để Kibana visualize.

### Kiến trúc (cập nhật 2026-05-17 — thêm Forensic Agent)

```
red-alerts (ES) ──poll mỗi 60s──►  agent/daemon.py
                                         │
                                         ▼
                            ┌──────────────────────────┐
                            │ 🎯 Supervisor Agent       │  Decide workflow
                            └────────────┬─────────────┘
                                         ▼
                            ┌──────────────────────────┐
                            │ 🔍 Triage Agent           │  Severity + FP filter (log-level)
                            └────────────┬─────────────┘
                                         ▼
                            ┌──────────────────────────┐
                            │ 🔬 Forensic Agent ⭐ NEW │  Host-level evidence
                            │   Velociraptor query:      │  • Process tree thật
                            │    pslist / file / netstat │  • File / Registry
                            │                            │  • Network connections
                            └────────────┬─────────────┘  → evidence_grade + verdict
                                         ▼
                ┌────────────────────────┴────────────────────────┐
                ▼ (asyncio.gather — chạy SONG SONG)                ▼
        ┌──────────────┐   ┌────────────────┐   ┌──────────────┐
        │ Hunt Agent   │   │ RED Analyst ⭐ │   │ MITRE Agent  │
        │ Timeline+IOC │   │ Evasion expl.  │   │ TTP chain    │
        └──────┬───────┘   └────────┬───────┘   └──────┬───────┘
               └────────────┬───────┴────────────┬─────┘
                            ▼                    ▼
                ┌──────────────────────────────────────┐
                │ 🛡️  Response Agent ⭐                 │
                │  • Sigma patch YAML (GROUNDED by      │
                │     Forensic evidence — giảm bịa)     │
                │  • Containment actions (w/ approval)  │
                │  • Telegram notification              │
                └────────────────┬─────────────────────┘
                                 ▼
                ┌──────────────────────────────────────┐
                │ 📝 Report Agent                       │
                │  Vietnamese SOC report kèm forensic   │
                │  timeline (markdown)                  │
                └────────────────┬─────────────────────┘
                                 ▼
                       ai-investigations (ES)
                                 ▼
                          Kibana Dashboard
```

### Đặc tả 8 agents

| Agent | Tools | Output schema | Vai trò |
|---|---|---|---|
| **Supervisor** | (none) | `WorkflowPlan` | Router — decide skip_fp / quick / full_investigation |
| **Triage** | `query_es_history`, `get_process_tree`, `lookup_mitre` | `TriageOutput` | Severity rating + FP filter (log-level) |
| **Forensic** ⭐ NEW | `vr_process_tree_deep`, `vr_file_artifacts`, `vr_network_connections` | `ForensicOutput` | Host-level evidence từ Velociraptor — ground truth verifier, kháng hallucination |
| **Hunt** | + `get_network_connections`, `search_threat_intel` | `HuntOutput` | Timeline, IOCs, network indicators |
| **RED Analyst** ⭐ | `get_sigma_rule_text`, `get_evasion_tokens` | `RedAnalystOutput` | Giải thích kỹ thuật né (shorthand_flag, encoding, ...) |
| **MITRE** | `lookup_mitre` | `MitreOutput` | Map technique + TTP kill-chain |
| **Response** ⭐ | `get_sigma_rule_text`, `suggest_containment`, `send_telegram` | `ResponseOutput` | **Sigma patch YAML** (grounded by forensic) + containment + notify |
| **Report** | (none) | `ReportOutput` | Vietnamese markdown report kèm forensic timeline |

⭐ **Forensic + RED Analyst + Response** là 3 agent NOVELTY chính.
- **Forensic** giải quyết bài toán hallucination: thay vì để LLM đoán từ log, query trực tiếp host qua Velociraptor để có bằng chứng cứng. Khi không có evidence (process đã chết, host offline) → kết luận honest `inconclusive` thay vì bịa.
- **Sigma patch** là **tactical mitigation** (band-aid cho variant cụ thể vừa thấy), **KHÔNG phải silver bullet** — vì có vô hạn variants nên defense thực sự vẫn là RED ML model (generalize) + feedback loop retrain. Xem [Sigma patch limitation](#sigma-patch-limitation--không-phải-silver-bullet) bên dưới.

### Chi tiết từng Agent

Mỗi agent đều là **ReAct loop** (LLM + tools + iteration) — nhận input, dùng tools để gather context, output structured JSON. Vai trò, cách hoạt động, và lý do tồn tại của từng agent:

#### 1. 🎯 Supervisor Agent — Router quyết định workflow

**Vai trò**: Là agent ĐẦU TIÊN nhận mọi alert. Quyết định alert này có đáng investigate không, và investigate ở mức độ nào.

**Inputs**: RED alert raw (host, command_line, top_rules, stage1_score, ...)

**Tools**: (Không có) — Supervisor không gọi external tools, chỉ phân tích dựa trên alert content. Lý do: cần ra quyết định nhanh < 2 giây để route alert.

**Output (`WorkflowPlan`)**:
- `workflow_type`: `skip_fp` | `quick_triage` | `full_investigation`
- `priority`: 1-5
- `agents_to_run`: subset các agents
- `reasoning`: vì sao chọn workflow này

**Cách hoạt động**:
1. Đọc `red.stage1_score`, `red.top_rules`, `process.parent.name`
2. Heuristic-style reasoning bằng LLM:
   - Score < 0.3 + benign parent → `skip_fp`
   - Score 0.3–0.6 → `quick_triage` (Triage + Report only)
   - Score > 0.6 hoặc parent đáng ngờ (outlook, browser) → `full_investigation` (toàn bộ 7 agents)
3. Output JSON wrapped `<final>` tags

**Tại sao cần**: Tiết kiệm token cost — không phải alert nào cũng cần chạy hết 7 agents. Score thấp filter sớm.

---

#### 2. 🔍 Triage Agent — Severity rating + False Positive filter

**Vai trò**: Quyết định severity (CRITICAL/HIGH/MEDIUM/LOW) hoặc đánh dấu FALSE_POSITIVE.

**Inputs**: Alert raw

**Tools (3)**:
- `query_es_history(host, hours)` — alerts trước đó cùng host
- `get_process_tree(host, command_line)` — parent/child processes
- `lookup_mitre(rule_name)` — severity baseline từ MITRE

**Output (`TriageOutput`)**:
- `severity`, `is_false_positive`, `confidence`
- `quick_findings[]`: 3-5 bullet points về evidence
- `mitre_technique`
- `needs_deeper_investigation`: bool

**Cách hoạt động**:
1. Gather context bằng tools (parallel)
2. LLM reason về kill-chain: parent là outlook? → phishing. Có lsass_access trước? → credential dump. Decode base64 ra IEX? → download cradle.
3. Áp dụng severity rubric:
   - CRITICAL: confirmed kill-chain
   - HIGH: confirmed evasion + known-bad behavior
   - MEDIUM: suspicious chưa rõ
   - LOW: edge case
   - FALSE_POSITIVE: matches known-FP pattern (admin script với encoded command)

**Tại sao cần**: Filter 60-80% FP TRƯỚC khi spend tokens cho Hunt/Response. Reduce analyst fatigue.

---

#### 3. 🔬 Forensic Agent ⭐ NEW — Bằng chứng cứng từ host (NOVELTY)

**Vai trò**: Truy vấn TRỰC TIẾP máy nạn nhân qua Velociraptor để lấy bằng chứng cứng — process tree thật, file mới tạo, kết nối mạng active. Khác Triage (đoán từ log) và Hunt (correlate log).

**Inputs**: Alert + Triage output

**Tools (3)** — wrap quanh Velociraptor gRPC API:
- `vr_process_tree_deep(client_id, pid)` — cây tiến trình thật + chữ ký số
- `vr_file_artifacts(client_id, since_minutes)` — file mới tạo + registry persistence
- `vr_network_connections(client_id, since_minutes)` — kết nối mạng external active

**Output (`ForensicOutput`)**:
- `evidence_grade`: `high` | `medium` | `low` | `missing`
- `process_tree_summary_vi`: tóm tắt cấu trúc
- `suspicious_artifacts[]`: list bằng chứng (kind, description, severity_contribution)
- `persistence_found`: bool
- `c2_confirmed`: bool
- `iocs_observed[]`: IP / file path / SHA256 / registry key
- `timeline_vi[]`: chuỗi sự kiện theo thời gian từ host
- `forensic_verdict_vi`: `confirmed_malicious` | `likely_benign` | `inconclusive`
- `confidence`: 0–1

**Cách hoạt động**:
1. Resolve `host.name` → Velociraptor `client_id` qua `vr_client_map.yaml`
2. Gọi 3 VR tool song song (asyncio) — mỗi tool ~25-30s vì `collect_client → wait → source`
3. LLM tổng hợp evidence, phân loại theo rubric:
   - ≥ 2 evidence `high` → `confirmed_malicious`
   - Toàn signed Microsoft + không có file lạ → `likely_benign`
   - Bằng chứng mâu thuẫn hoặc query fail → `inconclusive`
4. Downstream agents (Response, Report) nhận `ForensicOutput` qua optional kwarg `forensic=`

**Tại sao cần** — đây là điểm NOVELTY chính của v2 pipeline:
- Pipeline cũ (7-agent): LLM Response có thể **bịa Sigma patch** dựa trên log alert giả
- Pipeline mới (8-agent): Response ground patch trên evidence cứng (file path thật, IP thật từ host)
- **Test minh chứng**: với mock alert có PID=0 (Idle Process không tồn tại), Forensic Agent KHÔNG bịa — scan 166 process thật, không thấy match → trả `evidence_grade: missing`, `verdict: inconclusive`. Đây là **kháng hallucination measurable**.

**Modes**:
- **Mock mode** (default): trả mock data shape giống VQL thật → test agent loop khi chưa cài Velociraptor
- **Real mode**: `export VR_USE_REAL=1` + `VR_API_CONFIG=~/velociraptor/api.config.yaml` → query Velociraptor thật

**Limitation cần biết**:
- Latency: +27s (mock) → +112s (real) vì 3 VR query × 25-30s mỗi cái
- Cần Windows VM có Velociraptor agent connected
- Process đã chết / host reboot → không lấy được bằng chứng (đúng kỳ vọng, không phải bug)
- Clock skew giữa Windows VM và server có thể ảnh hưởng timeline tuyệt đối (xem [Time Synchronization](#time-synchronization) bên dưới)

---

#### 4. 🕵️ Hunt Agent — Correlate signals + Build timeline

**Vai trò**: Investigate sâu — tìm related events, IOCs, network indicators, dựng timeline.

**Inputs**: Alert + Triage output

**Tools (5)**:
- `query_es_history`, `get_process_tree` (shared với Triage)
- `get_network_connections(host, timeframe_minutes)` — C2 channels
- `search_threat_intel(indicator)` — IP/hash reputation (VirusTotal/AbuseIPDB)
- `lookup_mitre`

**Output (`HuntOutput`)**:
- `related_events_count`
- `timeline_vi[]`: chuỗi sự kiện theo thời gian, tiếng Việt
- `iocs_found[]`: IP, hash, domain, URL
- `network_indicators[]`: connection details
- `hunt_summary_vi`: tóm tắt
- `suspicious_score`: 0–1

**Cách hoạt động**:
1. Query ES với time window ±15 phút
2. Build process tree để hiểu chain (e.g. outlook → powershell → curl)
3. Extract IOCs từ command lines + network logs
4. Cho mỗi IOC quan trọng, lookup threat intel
5. Sort events theo timestamp → timeline

**Tại sao cần**: Analyst phải spend 5-15 phút query ES, build timeline. Hunt Agent làm trong ~10s.

---

#### 5. 🧠 RED Analyst Agent ⭐ — Giải thích kỹ thuật evasion (NOVELTY)

**Vai trò**: Đây là agent UNIQUE — translate ML model output (black-box score) thành **technical explanation** tại sao đây là evasion.

**Inputs**: Alert raw (đặc biệt là `red.top_rules` + `process.command_line`)

**Tools (2)**:
- `get_sigma_rule_text(rule_name)` — đọc YAML rule bị né
- `get_evasion_tokens(command_line, rule_name)` — phân tích tokens

**Output (`RedAnalystOutput`)**:
- `evasion_technique`: `shorthand_flag` | `case_manipulation` | `encoding` | `obfuscation` | `concatenation` | `unknown`
- `evasion_reasoning_vi`: giải thích chi tiết
- `discriminative_tokens[]`: tokens nào giúp RED model bắt
- `sigma_rule_comparison_vi`: so sánh rule pattern vs command thực
- `confidence`: 0–1

**Cách hoạt động**:
1. Lấy YAML rule gốc (`get_sigma_rule_text`)
2. So sánh rule pattern (e.g. `CommandLine|contains: '-EncodedCommand'`) với command line thực (`powershell -e SQBu...`)
3. Phân loại kỹ thuật né (`get_evasion_tokens`)
4. LLM giải thích: *"Attacker dùng `-e` thay vì `-EncodedCommand`. PowerShell parser tự expand vì `-e` là prefix duy nhất. Sigma rule exact-match bị né."*

**Tại sao cần**:
- ML score 0.87 không có nghĩa với analyst
- RED Analyst dịch sang **human reasoning** với evidence
- Đây là **interpretability layer** giữa black-box ML và SOC analyst
- Elastic AI Assistant không làm được — nó chỉ chat với data có sẵn, không hiểu nội tại RED model

---

#### 6. 🗺️ MITRE Agent — Map sang ATT&CK framework

**Vai trò**: Mapping technique + dựng TTP kill-chain hoàn chỉnh.

**Inputs**: Alert

**Tools (1)**:
- `lookup_mitre(rule_name)` — local lookup table mapping rule → technique

**Output (`MitreOutput`)**:
- `primary_tactic`: TA0001 Initial Access, TA0002 Execution, ...
- `primary_technique`: T1059.001, T1003.001, ...
- `sub_techniques[]`: techniques liên quan
- `ttp_chain_vi[]`: kill-chain từng bước tiếng Việt
- `severity_baseline`: low/medium/high/critical theo technique

**Cách hoạt động**:
1. Map top rule sang technique
2. Phân tích process tree + command line → infer thêm techniques
   - curl gọi IP → thêm T1105 Ingress Tool Transfer
   - lsass_access → thêm T1003.001
3. Sort techniques theo cyber kill-chain order

**Tại sao cần**: Standardize threat reporting cho SOC team, cross-team communication. MITRE là vocabulary chung.

---

#### 7. 🛡️ Response Agent ⭐ — Sigma patch + Containment + Notify (NOVELTY)

**Vai trò**: Output các actions thực tế: Sigma patch tactical, containment actions, notification.

**Inputs**: Alert + Triage + Hunt + RED Analyst + MITRE outputs

**Tools (3)**:
- `get_sigma_rule_text` — đọc rule gốc để patch
- `suggest_containment(host, severity, has_credential_access)` — action templates
- `send_telegram(message_summary, severity)` — push notification (mock nếu chưa config bot)

**Output (`ResponseOutput`)**:
- `sigma_patch_yaml`: YAML patched rule
- `sigma_patch_explanation_vi`: tại sao patch này work
- `containment_actions[]`: list `ResponseAction` (isolate, kill, block_ip, ...)
  - Mỗi action có `needs_approval`, `priority`, `rationale_vi`
- `notification_sent`: bool
- `requires_human_approval`: bool
- `summary_vi`: tóm tắt cho SOC

**Cách hoạt động**:
1. Đọc Sigma rule gốc
2. Dựa vào `evasion_technique` (từ RED Analyst), sinh patch YAML phù hợp:
   - `shorthand_flag` → thêm các shorthand variants (`-e `, `-ec `, `-en `, ...)
   - `case_manipulation` → thêm `|cased` modifier hoặc explicit case variants
   - `encoding` → thêm decode pre-processing, detect entropy
3. Lấy containment action templates, customize với host/IP/user cụ thể
4. Send Telegram với summary

**Sigma patch limitation — KHÔNG phải silver bullet**:

> ⚠️ **Quan trọng**: Sigma patch chỉ là **tactical mitigation** cho variant CỤ THỂ vừa thấy. Có vô hạn evasion variants — patch hôm nay obsolete ngày mai khi attacker dùng variant mới.
>
> Defense **thực sự** là:
> 1. **RED ML model** — generalize qua shared token patterns, bắt cả họ variants
> 2. **Feedback loop**: evasion samples → retrain RED weekly → model adapt
> 3. **Sigma patch**: chỉ giảm noise SIEM trong vòng vài ngày
>
> Đừng claim "AI Agent giải quyết evasion vĩnh viễn" — đó là cat-and-mouse vô hạn.

**Human-in-the-loop**: Mọi action destructive (`isolate_host`, `kill_process`, `disable_user`) có `needs_approval=true`. Daemon hiện tại CHƯA tự execute — chỉ log đề xuất. SOC analyst review trên Kibana → approve → manually execute.

---

#### 8. 📝 Report Agent — Vietnamese SOC report

**Vai trò**: Tổng hợp 5 outputs trên thành báo cáo markdown tiếng Việt chuẩn SOC.

**Inputs**: Alert + ALL outputs từ Triage/Hunt/RED Analyst/MITRE/Response

**Tools**: (Không có) — chỉ format dữ liệu đã có

**Output (`ReportOutput`)**:
- `title_vi`: 1 dòng tóm tắt
- `summary_vi`: 2-3 câu
- `full_markdown_vi`: full report với sections (Mô tả, Kill chain, Bằng chứng, Sigma patch, Containment, Đánh giá, Recommended actions)
- `recommended_actions_vi[]`: 5-10 action items

**Cách hoạt động**:
1. Nhận tất cả outputs trên
2. LLM compose markdown theo template SOC chuẩn
3. Embed Sigma patch YAML trong code block để analyst copy-paste
4. List actions từ Response Agent

**Tại sao cần**: Analyst đọc 1 báo cáo gọn thay vì 5 JSON outputs. Vietnamese cho team VN. Format markdown để paste vào Kibana Cases / Telegram.

---

### Workflow tổng quan

```
Supervisor (~2s, no tools, decide workflow)
   │
   ▼
Triage (~7s, 3 tools, severity + FP filter từ log)
   │
   ├──► IF is_false_positive → skip rest, lưu investigation với FP marker
   │
   ▼
Forensic (~22s mock / ~150s real, 3 VR tools — bằng chứng cứng từ host)
   │
   ├──► IF severity=LOW → skip để tiết kiệm
   ├──► IF verdict=likely_benign → close case
   │
   ▼
parallel(Hunt + RED Analyst + MITRE)  ← asyncio.gather (~10s max trong 3)
   │     • Hunt: timeline + IOCs
   │     • RED Analyst: explain evasion
   │     • MITRE: TTP chain
   ▼
Response (~15-20s, 3 tools, Sigma patch GROUNDED bởi forensic + containment + notify)
   │
   ▼
Report (~15-25s, no tools, Vietnamese markdown + forensic timeline)
   │
   ▼
ai-investigations index (Kibana visualize)
```

**Cost breakdown** (per investigation):

| Agent | Tokens | Cost | Time (mock) | Time (real VR) |
|---|---|---|---|---|
| Supervisor | ~900 | $0.0003 | 1.7s | 1.8s |
| Triage | ~4,300 | $0.0014 | 7s | 6s |
| **Forensic** ⭐ | **~9,000-20,000** | **$0.003-0.005** | **22s** | **150s** |
| Hunt | ~7,700-10,700 | $0.0026 | 10s (parallel) | 11s (parallel) |
| RED Analyst | ~3,900 | $0.0013 | 7s (parallel) | 6s (parallel) |
| MITRE | ~4,400 | $0.0015 | 5s (parallel) | 4s (parallel) |
| Response | ~18,000 | $0.0061 | 15-20s | 17s |
| Report | ~7,700-8,500 | $0.0026 | 15-25s | 23s |
| **Total** | **~67,000** | **~$0.018-0.020** | **~98s** | **~210s** |

> Real mode chậm hơn 2× vì 3 query Velociraptor (`collect_client → wait → source`) mỗi cái ~25-30s. Đây là trade-off để có bằng chứng cứng. Tham khảo [Forensic Agent](#3--forensic-agent--neww--bằng-chứng-cứng-từ-host-novelty).

### Cài đặt nhanh

```bash
source ~/venvs/rule_evasion_env/bin/activate
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection

# Copy template .env, điền DeepSeek key
cp .env.example .env
nano .env    # → điền DEEPSEEK_API_KEY và ES credentials

# Verify config load đúng
python3 -c "import os; from dotenv import load_dotenv; load_dotenv('.env'); print('OK' if os.environ.get('DEEPSEEK_API_KEY') else 'CHƯA SET API KEY')"

# (Optional cho real Velociraptor mode — xem section Forensic Setup bên dưới)
pip install pyvelociraptor grpcio pyyaml
```

### Forensic Agent Setup (Velociraptor — optional)

Forensic Agent có **2 chế độ**:

#### Mock mode (default — không cần Velociraptor)
Tự động khi `VR_USE_REAL` không set. Trả về mock data shape giống VQL thật → test agent loop nhanh.

```bash
unset VR_USE_REAL   # đảm bảo mock mode
python3 -m agent.run
```

#### Real mode (cần Velociraptor server + Windows agent)

**Bước 1 — Cài Velociraptor server** (tham khảo `~/velociraptor/VELOCI_INSTALL_NOTES.md` nếu đã có, hoặc download từ [velocidex.com](https://docs.velociraptor.app/downloads/)).

**Bước 2 — Cài client lên Windows VM**. Trên VM Windows (PowerShell admin):
```powershell
cd C:\Path\To\windows_client
Set-ExecutionPolicy -Scope Process Bypass -Force
.\install_velociraptor_client_windows.ps1
```

**Bước 3 — Generate API config cho agent**:
```bash
sudo -u velociraptor /usr/local/bin/velociraptor \
  --config /etc/velociraptor/server.config.yaml \
  config api_client --name agent ~/velociraptor/api.config.yaml
sudo chown $USER ~/velociraptor/api.config.yaml

# Tạo API user + grant role
sudo -u velociraptor /usr/local/bin/velociraptor \
  --config /etc/velociraptor/server.config.yaml \
  user add --role administrator agent agent_api_pass
sudo systemctl restart velociraptor_server
```

**Bước 4 — Map hostname → Velociraptor client_id**:

Lấy client_id của VM Windows:
```bash
python3 -c "
import os; os.environ['VR_USE_REAL']='1'; os.environ['VR_API_CONFIG']=os.path.expanduser('~/velociraptor/api.config.yaml')
from agent.vr_client import _run_vql
print(_run_vql('SELECT client_id, os_info.fqdn AS hostname FROM clients()', client_id='_'))
"
```

Điền vào `agent/vr_client_map.yaml`:
```yaml
WIN-01: C.1b622eacffe8b75d            # cho mock alert
DESKTOP-2UQB61H: C.1b622eacffe8b75d   # tên thật của VM
```

**Bước 5 — Chạy real mode**:
```bash
export VR_USE_REAL=1
export VR_API_CONFIG=~/velociraptor/api.config.yaml
export VR_QUERY_TIMEOUT=180

python3 -m agent.run --save /tmp/inv_real.json
```

Expected: ~210s/alert, ~$0.018 tokens. Forensic Agent sẽ query thật vào Windows VM, scan process list, file events, network connections.

#### Time Synchronization

Pipeline correlate event giữa **Windows VM**, **ELK server**, **Velociraptor server**, **lab agent**. Lệch giờ giữa các máy gây 4 vấn đề:

1. Forensic Agent kết luận sai về process còn live/dead
2. Query `since_minutes=30` bị méo window
3. Timeline trong báo cáo không đúng thứ tự
4. Cross-host correlation cho lateral movement không tin cậy

**Khuyến nghị (10 phút)**: cài NTP trên tất cả máy:

```bash
# Ubuntu (lab + ELK + Velociraptor server)
sudo apt install -y chrony
sudo systemctl enable --now chrony
chronyc tracking   # check drift
```

```powershell
# Windows VM
w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /update
w32tm /resync
```

**Lưu ý quan trọng**: bằng chứng **cấu trúc** (process tree, file path, hash, IP, registry key) **KHÔNG** bị ảnh hưởng bởi clock skew. Chỉ **timeline tuyệt đối** và quyết định **process live/dead** bị ảnh hưởng. Pipeline vẫn dùng được khi lệch giờ — chỉ giảm độ chính xác timeline.

### Cách chạy

#### Bước 1 — Test 1 alert mock (offline, không cần ES)

```bash
# Chạy 8-agent pipeline (mock VR mode) trên mock alert có sẵn, in báo cáo
python3 -m agent.run

# Lưu kết quả ra JSON để inspect
python3 -m agent.run --save /tmp/investigation.json
```

Expected: ~98 giây, ~$0.020 tokens. Output gồm severity, **forensic evidence + verdict**, kill-chain timeline, Sigma patch YAML (grounded by forensic), 5–8 containment actions, báo cáo markdown tiếng Việt.

#### Bước 2 — Test ES integration (cần ES reachable)

```bash
# Verify ES connection
python3 -c "from agent.es_io import check_es_connection; check_es_connection()"

# Inject 1 test alert vào red-alerts để có data process
python3 -m agent.inject_test_alert

# Dry-run: daemon poll → investigate → IN log nhưng KHÔNG ghi ES
python3 -m agent.daemon --dry-run --max-iter 1 --interval 5

# Real run: ghi vào ai-investigations
python3 -m agent.daemon --max-iter 1 --interval 5

# Verify document đã index
curl -u elastic:PASSWORD "http://10.10.20.100:9200/ai-investigations/_search?pretty&size=1"
```

#### Bước 3 — Production daemon

```bash
# Chạy vô hạn, poll mỗi 60s, chỉ process alerts có score >= 0.5
python3 -m agent.daemon --interval 60 --score-threshold 0.5

# Ctrl+C để graceful shutdown (đợi alert hiện tại xong rồi dừng)
```

Daemon argument đầy đủ:

| Flag | Default | Ý nghĩa |
|---|---|---|
| `--interval` | 60 | Polling interval (giây) |
| `--max-iter` | 0 (∞) | Stop sau N iterations (0 = run forever) |
| `--dry-run` | False | Không ghi ES |
| `--reset-state` | False | Xóa state file, process lại từ đầu |
| `--score-threshold` | 0.0 | Skip alerts có RED score < threshold |
| `--batch-limit` | 20 | Số alerts max lấy về mỗi iteration |
| `--since` | (None) | Override state, chỉ process alerts có `@timestamp > ISO_value` |
| `--no-state` | False | Không save `.agent_daemon_state.json` — dùng cho demo one-shot |
| `--query-string` | (None) | ES `query_string` filter bổ sung trên `red-alerts` |
| `--skip-health-check` | False | Bỏ qua ES connection check |

### Output: index `ai-investigations`

Mỗi investigation = 1 document với structure:

```json
{
  "investigation_id": "INV-481cc712b0f9",
  "timestamp": "2026-05-14T15:05:13Z",
  "trigger_alert": { ... full RED alert input ... },
  "workflow_plan": {"workflow_type": "full_investigation", "priority": 4, ...},
  "triage": {"severity": "CRITICAL", "confidence": 0.95, ...},
  "hunt": {"iocs_found": ["1.2.3.4", ...], "timeline_vi": [...], ...},
  "red_analyst": {"evasion_technique": "shorthand_flag", "confidence": 0.92, ...},
  "mitre": {"primary_technique": "T1059.001", "ttp_chain_vi": [...], ...},
  "response": {
    "sigma_patch_yaml": "title: ...PATCHED...\ndetection:\n  ...",
    "containment_actions": [
      {"action_type": "isolate_host", "needs_approval": true, ...},
      ...
    ],
    "notification_sent": true
  },
  "report": {"full_markdown_vi": "## 🚨 ...", ...},
  "total_duration_ms": 77200,
  "total_tokens": 49390,
  "estimated_cost_usd": 0.015
}
```

### Cost & Performance

| Metric | Giá trị |
|---|---|
| Time per alert | ~98s (mock VR) / ~210s (real Velociraptor) |
| Tokens per alert | ~67k (với prompt caching) |
| Cost per alert | ~$0.018–0.020 USD (~450 VND) |
| Daemon overhead | < 5% (polling + ES write) |

Scale ~30 alerts/giờ → ~$0.60/giờ, ~$14/ngày. Filter `--score-threshold 0.7` giảm ~5–10× thực tế. Real VR mode 2× chậm hơn mock vì 3 query Velociraptor mỗi cái 25-30s — trade-off để có evidence cứng.

### File structure (module `agent/`)

```
agent/
├── __init__.py             # auto-load .env
├── llm.py                  # Async DeepSeek/OpenAI client
├── schemas.py              # Pydantic models (Investigation, ForensicOutput, *Output)
├── tools.py                # 12 shared tools (9 ES/MITRE/Sigma + 3 Velociraptor)
├── vr_client.py            # NEW — Velociraptor gRPC wrapper + mock + hostname resolver
├── vr_client_map.yaml      # NEW — Map hostname → Velociraptor client_id
├── _loop.py                # Generic ReAct loop (tool exec + final parsing)
├── orchestrator.py         # 8-agent workflow runner
├── es_io.py                # ES read/write + state management
├── daemon.py               # Long-running polling daemon
├── inject_test_alert.py    # Helper: inject mock alert vào red-alerts
├── run.py                  # CLI: chạy 1 investigation
├── prototype.py            # Single-agent baseline (giữ để so sánh)
├── agents/
│   ├── supervisor.py
│   ├── triage.py
│   ├── forensic.py         # NEW — Forensic Agent (Velociraptor)
│   ├── hunt.py
│   ├── red_analyst.py
│   ├── mitre.py
│   ├── response.py         # nhận thêm forensic= để ground Sigma patch
│   └── report.py           # nhận forensic= để đưa vào timeline
└── prompts/
    ├── supervisor.md
    ├── triage.md
    ├── forensic.md         # NEW — Forensic Agent prompt
    ├── hunt.md
    ├── red_analyst.md
    ├── mitre.md
    ├── response.md
    └── report.md
```

### Lưu ý quan trọng

- **`.env`** chứa API keys — đã trong `.gitignore`, KHÔNG commit
- **DeepSeek Pro / ChatGPT Plus subscription** không cho phép gọi API — phải dùng API key riêng
- **Telegram notify**: mock mặc định. Set `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` để gửi thật
- **Human-in-the-loop**: mỗi `ResponseAction` có `needs_approval=true/false`. Destructive actions (isolate, kill, disable_user) luôn cần approval — daemon hiện tại CHƯA tự execute, chỉ log đề xuất
- **State file** `.agent_daemon_state.json` lưu timestamp đã process — restart không bị duplicate

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

Các file JSON evasion được lưu sâu theo cấu trúc:

```text
event_type/rule_name/*.json
```

Vì vậy nếu kiểm tra bằng `tree -L 2` ở thư mục gốc `evasions/windows` có thể chưa thấy file JSON trực tiếp.

### Export evasion scripts

Script `export_evasion_scripts.py` chuyển các JSON evasion thành script PowerShell để kiểm thử trong Windows lab.

Bộ script safe đã export sẵn:

```text
/home/luanthanh/data/sigma/evasion_scripts/windows
```

Kết quả hiện tại:

```text
process_creation: 446 scripts
powershell:       131 scripts
registry_event:    29 scripts
total:            606 scripts
```

Manifest:

```text
/home/luanthanh/data/sigma/evasion_scripts/windows/manifest.csv
```

Export ở `safe` mode:

```bash
cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection

python3 scripts/export_evasion_scripts.py \
  --evasions-dir ~/data/sigma/evasions/windows \
  --out-dir ~/data/sigma/evasion_scripts/windows \
  --event-type all \
  --mode safe
```

`safe` mode chỉ in nội dung ra script, chưa chạy payload. Muốn tạo script chạy thật trên Windows để sinh log, dùng `execute` mode:

```bash
python3 scripts/export_evasion_scripts.py \
  --evasions-dir ~/data/sigma/evasions/windows \
  --out-dir ~/data/sigma/evasion_scripts_execute/windows \
  --event-type all \
  --mode execute \
  --i-understand-risk \
  --limit-per-rule 2
```

Khuyến nghị chạy thử nhỏ trước:

```bash
python3 scripts/export_evasion_scripts.py \
  --event-type powershell \
  --mode execute \
  --i-understand-risk \
  --limit-per-rule 1
```

Trên Windows VM:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
cd C:\path\to\evasion_scripts_execute\windows
.\run_all_execute.ps1
```

> **Cảnh báo:** Chỉ chạy `execute` mode trong Windows lab/VM snapshot. Một số mẫu có hành vi nhạy như registry persistence, PowerShell suspicious, tắt firewall/defender, hoặc LSASS-related strings. Để thu log đúng, bật Sysmon ProcessCreate/RegistryEvent và PowerShell Script Block Logging, sau đó cho Elastic Agent collect các channel đó.

---

## Cấu trúc thư mục

```
rule_evasion_detection/
├── red/                          # Core library
│   ├── normalize.py              # 6-step text normalization
│   ├── features.py               # TF-IDF / Count vectorizers, comma_tokenizer
│   ├── models.py                 # SVM + LR + CNB + EnsembleClassifier
│   ├── evaluate.py               # BinaryEvaluation, MCC scaler
│   ├── attribution.py            # RuleAttributionEvaluation, CosineRuleAttributor, RRF baseline
│   ├── data.py                   # Data loading (txt/jsonl/json/csv, Sigma rules)
│   ├── rule_metadata.py          # 🆕 SigmaRuleIndex — load Sigma YAML → filename/id/title lookup
│   ├── persist.py                # save/load pickle+ZIP
│   └── visualize.py              # PR curves, attribution plots
├── scripts/
│   ├── run_stage1.py             # Gộp train + validate + evaluate (khuyến nghị)
│   ├── train.py                  # Stage 1 training (--ensemble flag)
│   ├── validate.py               # Transform + decision_function
│   ├── evaluate.py               # MCC scale + threshold sweep
│   ├── train_attribution.py      # Stage 2: Cosine + per-rule SVM baseline
│   ├── eval_attribution.py       # production: --method cosine; baseline: svm|hybrid
│   ├── generate_evasions.py      # Tạo evasion variants
│   ├── export_evasion_scripts.py # Export evasion JSON → PowerShell scripts
│   ├── convert_sigma_to_elastic.py # Sigma YAML → Elastic Detection Rule NDJSON
│   ├── run_pipeline.py           # Chạy toàn bộ pipeline (Stage 1+2)
│   ├── plot.py                   # Sinh đồ thị
│   ├── hayabusa_to_matches.py    # Hayabusa JSONL → match events
│   ├── lmd_to_benign.py          # LMD CSV → benign_train.txt
│   ├── mpsd_to_benign.py         # MPSD .ps1 → benign PowerShell
│   ├── mpsd_to_malicious.py      # MPSD malicious .ps1 filter
│   ├── secrepo_to_benign.py      # Squid log → URL benign
│   ├── elk_export.py             # Export events Elasticsearch → JSONL
│   ├── detect_batch.py           # Batch detection: JSONL → alerts (offline)
│   ├── detect_live.py            # Live daemon: poll ES → Stage1+2 → red-alerts
│   ├── diagnose_stage1.py        # Analyze Stage 1 model (F1=1.0, token analysis)
│   └── push_alerts.py            # Bulk index alerts JSONL → Elasticsearch
├── agent/                        # Phase C: Multi-Agent SOC Triage ⭐
│   ├── llm.py                    # Async DeepSeek/OpenAI client
│   ├── schemas.py                # Pydantic typed outputs (incl. ForensicOutput)
│   ├── tools.py                  # 12 shared tools (9 ES + 3 Velociraptor)
│   ├── vr_client.py              # ⭐ NEW — Velociraptor gRPC wrapper + hostname resolver
│   ├── vr_client_map.yaml        # ⭐ NEW — Map hostname → Velociraptor client_id
│   ├── _loop.py                  # Generic ReAct loop
│   ├── orchestrator.py           # 8-agent workflow runner
│   ├── es_io.py                  # ES poll red-alerts + write ai-investigations
│   ├── daemon.py                 # Long-running polling daemon
│   ├── inject_test_alert.py      # Helper inject mock alert
│   ├── run.py                    # CLI run 1 investigation
│   ├── prototype.py              # Single-agent baseline (so sánh)
│   ├── agents/
│   │   ├── supervisor.py         # Router decide workflow
│   │   ├── triage.py             # Severity + FP filter (log-level)
│   │   ├── forensic.py           # ⭐ NEW — Host evidence từ Velociraptor
│   │   ├── hunt.py               # Timeline + IOC (parallel)
│   │   ├── red_analyst.py        # ⭐ Evasion explanation (parallel)
│   │   ├── mitre.py              # TTP mapping (parallel)
│   │   ├── response.py           # ⭐ Sigma patch (grounded by forensic) + containment
│   │   └── report.py             # Vietnamese markdown report + forensic timeline
│   └── prompts/                  # 8 system prompts (markdown)
├── demo/                         # 🆕 Demo scripts + tài liệu defense
│   ├── apt_demo_scenario.ps1     # Kịch bản APT 7 phase (Tier 1+2+3 evasion)
│   ├── powershell_scenarios.ps1  # Demo PowerShell ScriptBlock
│   ├── process_creation_scenarios.ps1
│   ├── registry_scenarios.ps1
│   ├── monitor.sh                # Live monitor red-alerts/ai-investigations
│   ├── RED_RULE_MAP.md           # Bảng tra 1,367 RED rule ↔ Sigma metadata
│   ├── QA_PREP.md                # 16 câu hỏi GVHD + câu trả lời defensible
│   ├── SLIDES_OUTLINE.md         # Khung 15 slide cho defense
│   └── README.md                 # Runbook + verification commands
├── config/
│   ├── process_creation.yaml
│   ├── registry_event.yaml
│   ├── powershell.yaml
│   └── proxy_web.yaml
├── data/                         # Dữ liệu (không commit)
│   ├── benign/
│   ├── sigma/rules/
│   ├── sigma/events_hayabusa/
│   ├── sigma/evasions/
│   ├── sigma/evasion_scripts/         # Safe scripts export
│   └── sigma/evasion_scripts_execute/ # Execute scripts export cho Windows lab
├── models/                       # Output model .zip (không commit)
├── .env                          # Local config: API keys, ES creds (gitignored)
├── .env.example                  # Template config (committed)
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
