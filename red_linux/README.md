# RED-Linux

RED-Linux là nhánh mở rộng pipeline **Rule Evasion Detection (RED)** từ Windows sang
**Linux/Ubuntu**. Pipeline dùng log **auditd/process_creation**, chạy luật Sigma bằng
**Zircolite**, sau đó huấn luyện:

- **Stage 1 - Detection:** phát hiện lệnh tấn công hoặc lệnh đã né luật Sigma.
- **Stage 2 - Attribution:** quy kết event nghi vấn về luật Sigma liên quan nhất.
- **Coverage analysis:** đo định lượng phần tấn công thật mà SigmaHQ Linux rules bỏ sót.

> Code nằm trong repo (`red_linux/scripts/`). Dữ liệu lớn nằm ngoài mount KLTN tại
> `/home/luanthanh/data/red_linux/`. Chạy script bằng
> `~/venvs/rule_evasion_env/bin/python` từ root project
> `/home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection`.

Tài liệu liên quan: [RUN_NOTE.md](RUN_NOTE.md) cho runbook pipeline Sigma 5 bước,
[CLAUDE.md](CLAUDE.md) cho ghi chú dev/known issues, và
[RESULT_LINUX_COMBINED.md](RESULT_LINUX_COMBINED.md) cho bản chương kết quả chi tiết.
README này ưu tiên số liệu đã kiểm lại trực tiếp từ artifact hiện có; các file
`RESULT_*.md` là output chi tiết có thể regenerate khi chạy lại script.

---

## 1. Kết Quả Chính

> ⚠️ **CẬP NHẬT 2026-06-05 — đọc trước**: con số **F1 in-distribution (~0.83) KHÔNG còn
> dùng làm headline**. Đã chứng minh nó bị **confound nguồn** (model tách "văn phong template
> ART vs log thật" thay vì malicious-vs-benign — xem §5.4, §11.5). **Bằng chứng năng lực chính
> giờ là OOD trên tấn công THẬT.**

| Kết luận | Số liệu chuẩn | Cách đọc |
| --- | --- | --- |
| **Năng lực xác thực qua OOD (bằng chứng chính)** | Bắt SVM **73/107 (68%)** / Ensemble **67/107 (63%)** lệnh tấn công thật, label-leak **2/107** | Model train-ART bắt tấn công thật độc lập → học tín hiệu thật, không chỉ artifact. §11.5 |
| **F1 in-distribution bị confound nguồn (đã chứng minh)** | F1 **bất biến 0.865→0.867** dù xóa sạch artifact ART | Token top là `pathtoatomicsfolder`/`tmp_evilbinary`... → tách nguồn, không tách malicious. KHÔNG headline. §5.4 |
| **Benign khớp miền giảm FP (định lượng)** | FP **26.9%→4.5%** khi thêm benign CAM-LDS, recall giữ | Hợp lệ cho **server IDS** (benign = system-background, KHÔNG phải user). §11.5 |
| **Sigma bỏ sót phần lớn lệnh tấn công ART** | 581/771 lệnh né toàn bộ rule = **75.4%** | Luận điểm định lượng cho việc cần Stage 1 ML (không dính confound). |
| **Khảo sát family phi-lệnh (hướng phát triển)** | network: C2-over-443 (87%); auth: behavioral | ⚠️ **Ngoài phạm vi né-luật** (sự kiện phi-lệnh không có gì để "viết lại né luật"). Khảo sát sơ bộ, không phải kết quả lõi. §11.6–11.8 |
| **Dataset Sigma gốc nhiễm nhãn nặng** | Sigma-match trùng benign train **67.7%**; ART **1.6%** | Không dùng bộ Sigma để claim accuracy tuyệt đối. |
| **Stage 2 cần Layer-3** | Cosine top-1 **44.8%** -> Cosine + Sigma-logic top-1 **90.2%** | Cosine lọc ứng viên, Zircolite xác nhận rule thật fire. |

Tóm lại (cách báo cáo trung thực): pipeline Linux chạy end-to-end. Bộ Sigma từ Linux-APT bị
nhiễm nhãn + vòng tròn → chỉ dùng đối chiếu. Nhánh **ART** cho F1 in-distribution ~0.83
**nhưng số đó bị confound nguồn** (chứng minh ở §5.4) → **không khoe F1**; thay vào đó **báo cáo
bằng OOD SVM 68% (73/107) / Ensemble 63% (67/107) trên tấn công thật** + đo định lượng (mitigation FP, behavioral auth). Mở rộng
đa family qua **CAM-LDS** (process/network/auth, mỗi family nhãn riêng).

---

## 2. Trạng Thái Hiện Tại

| Hạng mục | Trạng thái |
| --- | --- |
| Linux-APT auditd -> Zircolite -> Sigma match | Hoàn tất end-to-end |
| Sinh evasion từ Sigma match và verify lại bằng Zircolite | Hoàn tất, 68 true evasion |
| Chẩn đoán nhiễm nhãn bộ Sigma | Hoàn tất, overlap benign/Sigma-match khoảng 68% |
| ART malicious độc lập-Sigma | Hoàn tất, 771 command process-like / 108 technique |
| Stage 1 ART random split và hold-out technique | Hoàn tất |
| Model production `config/linux_atomic.yaml` -> `models/linux_atomic/` | Hoàn tất, sau fix `normalize_benign` |
| Zircolite trên ART để đo Sigma coverage | Hoàn tất, 75.4% lệnh né hết rule |
| GTFOBins malicious độc lập-Sigma | Hoàn tất, 812 command / 8 MITRE technique; Sigma miss 90.0% |
| Model riêng `config/linux_gtfobins.yaml` -> `models/linux_gtfobins/` | Hoàn tất, test F1 0.876 (⚠️ **cũng dính confound nguồn như ART §5.4** — GTFOBins là lệnh mẫu tổng hợp; đọc bằng OOD) |
| Stage 2 Cosine + Layer-3 Sigma-logic | Hoàn tất, top-1 fired đạt 90.2% |
| Multi-seed ablation | Code có sẵn, mới chạy một phần |
| Chạy ART thật trên VM để thu auditd EXECVE hậu-expand | Tùy chọn, cần sudo/auditd |

---

## 3. Dữ Liệu Và Quy Ước Số Liệu

### 3.1. Nguồn dữ liệu

| Nguồn | Vai trò | Quy mô đã dùng | Ghi chú |
| --- | --- | --- | --- |
| **Linux-APT-Dataset-2024** | Benign auditd/process_creation và nguồn Sigma match ban đầu | 71,228 process events; 17,548 benign command unique | Benign split: 12,283 train / 2,632 valid / 2,633 test; khi train thường cap 12,000 benign train. |
| **Sigma match set** | Dùng để port pipeline, sinh evasion, phân tích nhiễm nhãn | Full: 3,395 events / 20 rules; lõi medium+: 111 events / 6 rules | Không dùng để claim accuracy cuối vì malicious = event đã match Sigma. |
| **Atomic Red Team raw** | Nguồn malicious độc lập-Sigma | 915 command unique / 111 MITRE technique | Sinh bởi `atomic_to_malicious.py` từ `executor.command`. |
| **Atomic Red Team process-like** | Bộ malicious chính cho train/eval/Zircolite | 771 command / 108 MITRE technique | Lọc bỏ dòng gán biến/control-flow thuần; overlap benign chỉ 12/771 = 1.6%. |
| **GTFOBins LOLBin abuse** | Nguồn malicious độc lập-Sigma thứ hai | 812 command / 8 MITRE technique | Sinh bởi `gtfobins_to_malicious.py`; overlap benign 2/812 = 0.25%. |

Khi README nói **ART 771**, đó là tập process-like dùng cho Stage 1 production và
`atomic_zircolite.py`. Khi nói **ART raw 915/111**, đó là output thô của
`atomic_to_malicious.py` trước khi lọc dòng không phải process.

### 3.2. Bộ Sigma và bộ ART

| Tiêu chí | Bộ Sigma (Linux-APT + Zircolite) | Bộ ART (Atomic Red Team) |
| --- | --- | --- |
| Cách sinh malicious | Event auditd khớp luật Sigma | Lệnh tấn công từ atomic tests |
| Nguồn nhãn | Sigma/Wazuh alert | MITRE ATT&CK |
| Độc lập với Sigma | Không | Có |
| Overlap với benign sau normalize | Khoảng 68% | 1.6% |
| Cách dùng đúng | Kiểm thử port pipeline, sinh evasion, chỉ ra caveat dữ liệu | Kết quả chính và model production |

---

## 4. Pipeline

### 4.1. Pipeline Sigma trên Linux-APT

```text
Linux-APT auditd events
  [1] linux_apt_to_zircolite.py
      parse event.original, decode hex argv, emit SYSCALL + EXECVE rows
  [2] Zircolite -j + SigmaHQ Linux rules
      process_creation + auditd rules -> detections.json
  [3] zircolite_to_matches.py
      dedupe theo redrow -> Sigma match events
  [4] linux_evasion_generate.py
      sinh biến thể argv-level
  [5] linux_evasion_verify.py
      re-run Zircolite -> giữ true evasion
```

Kết quả pipeline Sigma:

- Full match set: **20 rules / 3,395 events**.
- Match set lõi medium+: **6 rules / 111 events**.
- True evasion sau verify: **68**.
- Kỹ thuật evasion còn lại: `relative_path` 29, `busybox_applet` 23,
  `tool_swap` 12, `alt_subcommand` 4.

Chi tiết từng lệnh chạy nằm trong [RUN_NOTE.md](RUN_NOTE.md).

### 4.2. Pipeline ART sạch

```text
Atomic Red Team atomics/
  [1] atomic_to_malicious.py
      trích executor.command -> atomic_malicious.jsonl
  [2] atomic_to_events.py
      lọc process-like, chia 70/15/15 -> split_atomic/
  [3] scripts/run_stage1.py --config config/linux_atomic.yaml
      train model production -> models/linux_atomic/
  [4] atomic_zircolite.py
      chạy Zircolite trên ART -> atomic_fired.jsonl
  [5] stage2_atomic.py + stage3_layer3_linux.py
      đánh giá attribution và rerank bằng Sigma-logic
```

---

## 5. Kết Quả Stage 1

### 5.1. Bộ Sigma: kết quả chỉ để đối chiếu

Stage 1 trên bộ Sigma đạt F1 cao, nhưng chịu nhiễm nhãn và bài toán vòng tròn nên
không được đọc là độ chính xác phát hiện tấn công thật.

| Ngưỡng | Precision | Recall | F1 | MCC | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| optimal (0.68) | 0.903 | 0.956 | **0.929** | **0.927** | 65 | 7 | 3 |
| default (0.50) | 0.708 | 1.000 | 0.829 | 0.837 | 68 | 28 | 0 |

Cách đọc đúng: F1 0.929 nghĩa là model nhận lại tốt các command **giống Sigma misuse**,
không phải benign-vs-malicious độc lập. Các ablation gần 1.0 là dấu hiệu đụng trần,
không phải bằng chứng một model thắng tuyệt đối.

### 5.2. Bộ ART: F1 độc lập-Sigma — NHƯNG bị confound nguồn (xem §5.4)

> ⚠️ Các số F1 dưới đây độc lập với **Sigma** (hết vòng tròn V2), nhưng §5.4 chứng minh chúng
> vẫn bị **confound nguồn** (ART tổng hợp vs Linux-APT thật). Đọc kèm §5.4; KHÔNG dùng làm
> headline.

| Model | F1 random split | Macro F1 random | F1 hold-out technique | Macro F1 hold-out |
| --- | ---: | ---: | ---: | ---: |
| SVM | 0.820 | 0.906 | **0.827** | **0.908** |
| LR | 0.814 | 0.903 | 0.796 | 0.891 |
| CNB | 0.796 | 0.894 | 0.745 | 0.865 |
| Ensemble | **0.828** | **0.910** | 0.788 | 0.887 |

Random split cho thấy bài toán không còn đụng trần: F1 nằm quanh 0.80-0.83. Hold-out
technique khắt khe hơn vì test gồm kỹ thuật MITRE chưa thấy khi train; trong split này
SVM cân bằng nhất, CNB sụp recall, còn LR/Ensemble thiên về recall cao nhưng FP nhiều.
Do tập hold-out nhỏ, README không kết luận lại thứ hạng model chỉ từ Linux; cấu hình
production vẫn dùng Ensemble để nhất quán với thiết kế RED.

### 5.3. Model production sau fix tiền xử lý

Model production được train qua pipeline triển khai thật:

- Config: `config/linux_atomic.yaml`
- Model: `models/linux_atomic/train_rslt_ensemble_atomic.zip`
- Data: benign Linux-APT + malicious ART process-like
- Training: Ensemble SVM + LR + CNB, TF-IDF unigram, MCC scaling
- Fix quan trọng: `training.normalize_benign: true`

Lỗi đã sửa: pipeline cũ normalize malicious nhưng không normalize benign khi train/eval.
Trong khi đó `detect_batch.py`/`detect_live.py` normalize mọi event lúc deploy. Model cũ
vì vậy học lối tắt "đã normalize = độc", cho eval đẹp giả nhưng deploy FP rất cao.

| Phiên bản | Test F1 eval | Test FP eval | FP khi deploy trên benign |
| --- | ---: | ---: | ---: |
| Trước fix bất đối xứng | 0.874 giả | 0 giả | **83.7%** |
| Sau fix đối xứng | **0.833** | **17/2633 = 0.65%** | **0.65%** |

Chi tiết model production sau fix:

| Split | Threshold | Precision | Recall | F1 | MCC | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Valid | 0.46 | 0.783 | 0.810 | 0.797 | 0.788 | 94 | 26 | 2606 | 22 |
| Test | 0.46 | **0.848** | **0.819** | **0.833** | **0.826** | 95 | 17 | 2616 | 21 |

### 5.4. Kiểm chứng độ tin cậy: confound nguồn + OOD (2026-06-05)

Sau khi có model production, chúng tôi **kiểm chứng** xem F1 in-distribution (~0.83) có phản
ánh năng lực thật không. Kết quả: **không** — nó bị **confound nguồn**.

**Confound nguồn là gì**: malicious (ART/GTFOBins) là **lệnh mẫu tổng hợp**, chứa dấu vết
thư-viện (`PathToAtomicsFolder`, technique-ID trong path như `/tmp/T1003.007.sh`,
`AtomicRedTeam`, `evilbinary`); benign (Linux-APT) là **log thật**, không bao giờ có mấy token
đó. → Model có thể tách hai bên bằng "văn phong nguồn" thay vì bản chất tấn công.

**Chứng minh (không phải suy đoán)** — `camlds_confound_probe.py` + `art_clean_eval.py`:

| Phép đo | RAW | Sau khi xóa sạch artefact |
| --- | ---: | ---: |
| Artefact trong top-40 feature malicious | 9 | **0** |
| In-dist F1 (ART/GTFO) | 0.865 | **0.867** (bất biến!) |
| **CAM-LDS OOD recall** (tấn công thật) | 62/107 | **61/107** (bất biến) |
| CAM-LDS tách biệt mal−ben | +0.215 | +0.218 |

→ Xóa sạch artefact mà **F1 không nhúc nhích** = artefact ART **pervasive, không gỡ được bằng
tiền xử lý** (token path-tổng-hợp khác thế chỗ). Vậy **F1 in-distribution không là thước đo
hợp lệ** cho năng lực malicious-vs-benign.

**Thước đo hợp lệ = OOD** (RESULT_CAMLDS_OOD.md): áp model train-ART lên tấn công **thật, độc
lập** (CAM-LDS, 107 lệnh thật) → recall SVM **73/107 (68%)**, label-leak **2/107** → model học tín hiệu thật (curl/chmod/
base64), không chỉ artefact. Tách biệt OOD +0.20 (khiêm tốn) → năng lực thật **vừa phải**,
không phải F1 0.87.

**Cách báo cáo**: trình bày F1 (có caveat) + thí nghiệm kiểm chứng (điểm cộng) + OOD SVM 68% (73/107) (bằng
chứng chính). Một F1 in-distribution "sạch confound" đòi hỏi malicious **thực thi thật cùng môi
trường** benign (hướng phát triển: thu auditd khi chạy tấn công trên VM). Chi tiết:
`RESULT_CAMLDS_CONFOUND.md`, `RESULT_CAMLDS_ARTCLEAN.md`, `RESULT_CAMLDS_OOD.md`.

---

## 6. Sigma Coverage Trên ART

`atomic_zircolite.py` chạy 771 lệnh ART process-like qua SigmaHQ Linux rules bằng
Zircolite, cùng kiểu input SYSCALL + EXECVE như pipeline chính.

| Kết quả | Số lệnh | Tỷ lệ |
| --- | ---: | ---: |
| Bị ít nhất một rule Sigma bắt | 190 | 24.6% |
| Né toàn bộ rule Sigma | **581** | **75.4%** |

Đây là kết quả quan trọng nhất về mặt luận điểm: signature-based detection bằng Sigma
bỏ sót khoảng ba phần tư lệnh tấn công ART trong tập thử này. Stage 1 ML được dùng để
tổng quát hóa ra ngoài các token/rule cứng.

---

## 7. Kết Quả Stage 2 Attribution

### 7.1. CosineRuleAttributor trên ART

Ground-truth **fired** nghĩa là rule thật sự fire khi chạy Zircolite trên lệnh ART.
Ground-truth **technique-tag** nới lỏng hơn: rule có tag MITRE cùng base technique.

| Ground-truth | Top-1 | Top-3 | Top-5 | Top-10 | n |
| --- | ---: | ---: | ---: | ---: | ---: |
| fired | **44.8%** | **77.6%** | 83.2% | **90.2%** | 143 |
| technique-tag | 24.3% | 35.8% | 44.1% | 56.1% | 374 |
| random baseline | 4.4% | 11.8% | 17.7% | 28.8% | - |

Cosine top-1 thấp hơn bộ Sigma vì ART độc lập hơn: lệnh không được sinh từ chính rule
Sigma nên không sẵn token chữ ký để "ăn điểm".

### 7.2. Layer-3 Sigma-logic

`stage3_layer3_linux.py` dùng cosine để lấy top-N ứng viên, sau đó chạy Zircolite để xác nhận
rule nào thật sự khớp command. Kết quả trên ground-truth fired:

| Phương pháp | Top-1 | Top-3 | Top-5 | Top-10 |
| --- | ---: | ---: | ---: | ---: |
| Cosine baseline | 44.8% | 77.6% | 83.2% | 90.2% |
| Cosine + Layer-3 @top-5 | 83.2% | 90.2% | 90.9% | 90.2% |
| Cosine + Layer-3 @top-10 | **90.2%** | 92.3% | 90.9% | 90.2% |

Giới hạn cần ghi rõ: Layer-3 chỉ giúp khi có rule thật sự fire. Với evasion thuần,
tức không rule nào còn khớp, Sigma-logic không có rule để xác nhận và phải rơi về
xếp hạng cosine.

---

## 8. Script Chính

| Nhóm | Script |
| --- | --- |
| Pipeline Sigma | `linux_apt_to_zircolite.py`, `zircolite_to_matches.py`, `linux_evasion_generate.py`, `linux_evasion_verify.py` |
| ART clean data | `atomic_to_malicious.py`, `atomic_to_events.py`, `atomic_zircolite.py` |
| GTFOBins clean data | `gtfobins_to_malicious.py`, `gtfobins_to_events.py`, `gtfobins_zircolite.py` |
| Stage 1 | `stage1_atomic.py`, root `scripts/run_stage1.py`, root `scripts/validate.py`, root `scripts/evaluate.py` |
| Stage 2 | `stage2_atomic.py`, `stage3_layer3_linux.py` |
| Chẩn đoán | `contamination_report.py`, `bootstrap_ci.py`, `benign_sanity.py` |
| Báo cáo/demo | `generate_linux_report.py`, `generate_linux_figures.py`, `demo_linux.py`, `demo_linux_art.py` |
| Multi-seed | `run_multiseed.sh` |

Tài liệu kèm theo:

- [RESULT_LINUX_COMBINED.md](RESULT_LINUX_COMBINED.md) — chương kết quả chi tiết (Chương 5 luận văn).
- [RUN_NOTE.md](RUN_NOTE.md) — runbook pipeline Sigma + log lần chạy.
- [demo/DEMO_LINUX.md](demo/DEMO_LINUX.md) — demo Sigma-fire/miss/RED-catch.
- Stage 1 ART (`RESULT_LINUX_ATOMIC*`) và GTFOBins (`RESULT_LINUX_GTFOBINS`) là output
  regenerate được; số liệu đã tổng hợp ở §5/§6, chạy lại script để sinh lại nếu cần.

---

## 9. Chạy Lại

```bash
VENV=~/venvs/rule_evasion_env
PROJ=/home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection
DATA=/home/luanthanh/data/red_linux
RULES=/home/luanthanh/data/sigma/rules/linux
ART=~/tools/atomic-red-team
GTFO=~/tools/gtfobins

cd "$PROJ"
```

### 9.1. Cài tool ngoài một lần

```bash
git clone --depth 1 https://github.com/wagga40/Zircolite.git ~/tools/Zircolite
$VENV/bin/pip install -r ~/tools/Zircolite/requirements.txt

git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/redcanaryco/atomic-red-team.git "$ART"
git -C "$ART" sparse-checkout set atomics

git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/GTFOBins/GTFOBins.github.io.git "$GTFO"
git -C "$GTFO" sparse-checkout set _gtfobins _data
```

### 9.2. Pipeline Sigma Linux-APT

```bash
$VENV/bin/python red_linux/scripts/linux_apt_to_zircolite.py \
  --input data_external/linux_apt_dataset_2024/converted_samples/linux_apt_auditd_process_candidates.jsonl \
  --output "$DATA/work/zircolite_input.jsonl"

cd ~/tools/Zircolite
$VENV/bin/python zircolite.py \
  -e "$DATA/work/zircolite_input.jsonl" -j \
  -r "$RULES/process_creation" "$RULES/auditd" \
  -o "$DATA/work/detections.json" --keepflat -q
cd "$PROJ"

$VENV/bin/python red_linux/scripts/zircolite_to_matches.py \
  --input "$DATA/work/detections.json" \
  --output-dir "$DATA/events/linux/process_creation" \
  --ruleset "$RULES" --min-level medium

$VENV/bin/python red_linux/scripts/linux_evasion_generate.py \
  --matches-dir "$DATA/events/linux/process_creation" \
  --out "$DATA/work/evasion_candidates.jsonl" \
  --meta "$DATA/work/evasion_meta.json"

cd ~/tools/Zircolite
$VENV/bin/python zircolite.py \
  -e "$DATA/work/evasion_candidates.jsonl" -j \
  -r "$RULES/process_creation" "$RULES/auditd" \
  -o "$DATA/work/detections_evasion.json" --keepflat -q
cd "$PROJ"

$VENV/bin/python red_linux/scripts/linux_evasion_verify.py \
  --meta "$DATA/work/evasion_meta.json" \
  --detections "$DATA/work/detections_evasion.json" \
  --out-dir "$DATA/evasions/linux/process_creation"
```

### 9.3. ART clean data và Stage 1

```bash
$VENV/bin/python red_linux/scripts/atomic_to_malicious.py \
  --art "$ART" \
  --out "$DATA/benign/process_creation/atomic_malicious.jsonl"

$VENV/bin/python red_linux/scripts/stage1_atomic.py \
  --models svm lr cnb ensemble

$VENV/bin/python red_linux/scripts/stage1_atomic.py \
  --models svm lr cnb ensemble --holdout-technique
```

### 9.4. Model production

```bash
$VENV/bin/python red_linux/scripts/atomic_to_events.py
$VENV/bin/python scripts/run_stage1.py --config config/linux_atomic.yaml

# Đánh giá test với threshold cố định từ valid, hiện là 0.46.
$VENV/bin/python scripts/validate.py --config config/linux_atomic.yaml \
  --result-path models/linux_atomic/train_rslt_ensemble_atomic.zip \
  --data-split test --malicious-type matches --result-name atomic_test

$VENV/bin/python scripts/evaluate.py --config config/linux_atomic.yaml \
  --result-path models/linux_atomic/valid_rslt_atomic_test.zip \
  --use-threshold 0.46
```

### 9.5. Sigma coverage và Stage 2

```bash
$VENV/bin/python red_linux/scripts/atomic_zircolite.py
$VENV/bin/python red_linux/scripts/stage2_atomic.py --ground-truth fired
$VENV/bin/python red_linux/scripts/stage2_atomic.py --ground-truth technique
$VENV/bin/python red_linux/scripts/stage3_layer3_linux.py
```

### 9.6. GTFOBins clean LOLBin extension

```bash
$VENV/bin/python red_linux/scripts/gtfobins_to_malicious.py \
  --gtfobins "$GTFO" \
  --out "$DATA/benign/process_creation/gtfobins_malicious.jsonl"

$VENV/bin/python red_linux/scripts/gtfobins_to_events.py
$VENV/bin/python red_linux/scripts/gtfobins_zircolite.py
$VENV/bin/python scripts/run_stage1.py --config config/linux_gtfobins.yaml

# Đánh giá test với threshold cố định từ valid, hiện là 0.48.
$VENV/bin/python scripts/validate.py --config config/linux_gtfobins.yaml \
  --data-split test --result-name gtfobins_test

$VENV/bin/python scripts/evaluate.py --config config/linux_gtfobins.yaml \
  --result-path models/linux_gtfobins/valid_rslt_gtfobins_test.zip \
  --result-name gtfobins_test --use-threshold 0.48
```

### 9.7. Demo và biểu đồ

```bash
$VENV/bin/python red_linux/scripts/demo_linux_art.py
$VENV/bin/python red_linux/scripts/benign_sanity.py
$VENV/bin/python red_linux/scripts/generate_linux_figures.py
```

---

## 10. Đường Dẫn Artifact

| Artifact | Đường dẫn |
| --- | --- |
| Venv | `~/venvs/rule_evasion_env` |
| Zircolite | `~/tools/Zircolite` |
| Atomic Red Team | `~/tools/atomic-red-team` |
| GTFOBins | `~/tools/gtfobins` |
| SigmaHQ Linux rules | `/home/luanthanh/data/sigma/rules/linux/` |
| Dữ liệu RED-Linux | `/home/luanthanh/data/red_linux/` |
| ART raw corpus | `/home/luanthanh/data/red_linux/benign/process_creation/atomic_malicious.jsonl` |
| ART fired mapping | `/home/luanthanh/data/red_linux/benign/process_creation/atomic_fired.jsonl` |
| ART production split | `/home/luanthanh/data/red_linux/split_atomic/` |
| GTFOBins corpus | `/home/luanthanh/data/red_linux/benign/process_creation/gtfobins_malicious.jsonl` |
| GTFOBins fired mapping | `/home/luanthanh/data/red_linux/benign/process_creation/gtfobins_fired.jsonl` |
| GTFOBins production split | `/home/luanthanh/data/red_linux/split_gtfobins/` |
| Model Sigma cũ | `models/linux_process_creation/` |
| Model production sạch | `models/linux_atomic/` |
| Model GTFOBins | `models/linux_gtfobins/` |
| Figures chương Linux | `reports/linux/figures/` |

---

## 11. Mở Rộng Ngoài process_creation (khảo sát + probe dataset ngoài)

Nhánh hiện tại chỉ có **một** event family sạch (`process_creation`) vì chỉ family này có
benign thật + nhãn malicious độc lập (ART/GTFOBins theo MITRE). Phần này tổng hợp việc
khảo sát và probe các nguồn để mở sang `auth`, `file_event`, `web_http`, `dns`, `network`.

### 11.1. Vì sao các family khác của Linux-APT-2024 KHÔNG dùng được

Probe `probe_external_families.py` (LR + TF-IDF, full vs masked) cho thấy nhãn 3 family
ngoài bám **loại sự kiện**, không phải tính độc hại:

| Family | n (mal/benign) | F1 full | F1 masked | Kết luận |
| --- | --- | ---: | ---: | --- |
| web | 19,696 | 0.975 | 0.972 | nhãn = "tấn công lọt vs bị chặn 400" — vòng tròn với Wazuh |
| auth | 1,816 | 0.998 | 0.998 | nhãn = "mở phiên vs đóng phiên", không phải attack-vs-normal |
| file_event | 4,122 | 0.998 | 0.816 | nhãn = verb FIM (modified/deleted vs added) |

→ Trong Linux-APT-2024, **chỉ `process_creation`** có nhãn sạch. Family khác cần nguồn khác.

### 11.2. Khảo sát nguồn ngoài

Ứng viên Linux-only, có cả benign lẫn malicious, nhãn độc lập:

| Ưu tiên | Dataset | Family dùng được | Caveat |
| --- | --- | --- | --- |
| **P0** | **CAM-LDS** (2025) | audit, auth, apache, syslog, dns, netflow | Tập trung manifestation tấn công; ghép benign từ nguồn khác |
| P0 | AIT-LDSv2 (non-audit) | web_http, auth, dns, syslog | Audit/process rows quá thưa — xem 11.3 |
| P0 | BETH | process_event, dns | Real benign cloud honeypot; dạng CSV feature |
| P1 | LID-DS 2021 | syscall_sequence | Branch HIDS riêng, cần converter khác |
| P1 | DEDALE | host + network APT timeline | **Có lẫn Winlogbeat** → phải lọc Windows |
| P2 | ADFA-LD | syscall traces | Cũ (2013), chỉ syscall ID |

### 11.3. Probe AIT-LDSv2 audit — vì sao không dùng audit của nó

Probe 8 testbed (đọc audit log qua HTTP range): audit rows giàu nhưng **process-like
gần như không có nhãn** — mỗi testbed chỉ ~2–4 lệnh process được gán nhãn, phần lớn là
`USER_ACCT/USER_AUTH/LOGIN`. Ví dụ `fox`: 24,082 audit lines nhưng chỉ 2 `USER_CMD`
labeled (`ls -laR /root/`, `cat /etc/shadow`). → Dùng **log non-audit** của AIT (Apache,
auth.log, DNS, Suricata) cho web/auth/dns, **không** dùng audit/process của nó.

### 11.4. Probe CAM-LDS — đã test thực tế, chọn làm P0

> ⚠️ **CẢNH BÁO BẢN CHẤT DATASET (đọc trước khi diễn giải mọi số "benign" dưới đây)**:
> CAM-LDS là dataset **attack-manifestation** — tác giả CHỦ ĐÍCH **không mô phỏng hành vi
> người dùng bình thường** khi thu thập. Vì vậy log trong cửa sổ thu thập chủ yếu là **hậu
> quả tấn công + hoạt động idle/daemon hệ thống + thao tác admin**, KHÔNG có user-behavior.
> → Cái gọi là "benign" của CAM-LDS thực chất là **system/service background + admin**, KHÔNG
> phải "user-behavior benign". Bằng chứng từ chính dữ liệu: benign pool bị thống trị bởi agent
> giám sát AMiner (`cut/sed/grep` ×17k), daemon (df/awk), cron (php cron.php), admin (iptables),
> container ops — **0 phiên người dùng tương tác**.
>
> **Hệ quả cho luận văn**: (1) Với **server IDS**, benign liên quan CHÍNH LÀ system/service
> background → CAM-LDS benign DÙNG ĐƯỢC nhưng phải nói rõ phạm vi. (2) Với ngữ cảnh user-facing,
> VẪN cần nguồn user-behavior riêng (Linux-APT, LMD, hoặc log Kyoushi của AIT-LDSv2). (3) Mọi
> kết quả "benign" dưới đây phải đọc là **system-background benign**, không phải user benign.

Tải `scenario_7` (DNS/container/nextcloud), parse + label thật:

- Audit giàu: docker host 25,128 dòng → 7,045 event, 2,173 EXECVE (đủ SYSCALL/EXECVE/PATH/PROCTITLE).
- Ground truth `attackmate.json`: mỗi bước có timestamp + MITRE technique/tactic + lệnh thật.
- **Timezone**: ground truth và audit epoch đều **UTC, offset 0** (cái "+7h" thấy lúc đầu
  là artifact do `fromtimestamp()` render theo giờ máy VN UTC+7).
- **Nhãn theo từng family**: `process_creation`/`file_event` dùng **lineage** (seed từ lệnh
  attacker → lan ppid→pid); time-window over-label nặng (830 = 11.8% lẫn cron benign vs
  lineage 90 = 1.28% sạch). `auth`/network brute-force thì dùng time-window + match log.

Scripts: `camlds_to_events.py` (parser), `camlds_label_lineage.py` (lineage),
`camlds_label_timewindow.py` (đối chiếu). Data ngoài repo: `data/red_linux/camlds/`.

### 11.5. CAM-LDS process_creation — volume nhỏ, dùng làm OOD probe + benign khớp miền

Chạy parser + lineage cả 3 audit host scenario_7 (`docker`/`corpdns`/`inetfw`):

| Host | Events | EXECVE | Malicious EXECVE |
|:--|--:|--:|--:|
| docker | 7,045 | 2,173 | 15 (**9 lệnh unique**) |
| corpdns | 4,197 | 1,423 | 0 |
| inetfw | 5,682 | 2,040 | 0 |

**Phát hiện quan trọng**: tấn công chỉ đổ bộ docker host (nextcloud RCE → container escape);
DNS/firewall chỉ định tuyến traffic → 0 malicious process. "90 malicious" báo trước đó gồm
cả non-EXECVE (syscall 42 connect ×53 = network, 105/106 setuid ×20, 59 execve ×15). **Riêng
process_creation chỉ 9 lệnh unique** → KHÔNG đủ để train Stage-1 độc lập từ 1 scenario.

→ Hai cách dùng đã chứng minh giá trị (scripts: `camlds_to_cmdlines.py` xuất corpus;
`camlds_ood_probe.py`; `camlds_benign_mitigation.py`):

**(A) OOD probe** — model train trên ART có generalize sang tấn công THẬT không? (`RESULT_CAMLDS_OOD.md`)
- Recall SVM **73/107 (68%)** / Ensemble **67/107 (63%)**, **label-leak 2/107** → không bó hẹp pattern ART.
- Miss (~32–40 lệnh): `cat /etc/shadow`, `rm`, `mkdir`, `find`, `lspci`... — trông benign khi
  đứng một mình; cần ngữ cảnh lineage/Stage-2 để phân biệt.
- FP-rate cao 27% trên benign CAM-LDS — do **dịch chuyển phân phối** + admin Linux trùng
  pattern ART (`sh -c iptables`, `php -r`, container ops).

**(B) Giảm FP bằng benign khớp miền** (`RESULT_CAMLDS_MITIGATION.md`) — đóng góp định lượng:

| Train negative | Recall (107 tấn công) | FP-rate (benign hold-out) |
|:--|--:|--:|
| Linux-APT only (baseline) | 67/107 (63%) | 26.9% (267/993) |
| + CAM-LDS benign khớp miền | 65/107 (61%) | **4.5%** (45/993) |

**ΔFP = −22.4 điểm %, recall giữ nguyên** → FP cao chủ yếu do phân phối benign, sửa được
bằng dữ liệu. ⚠️ **Phạm vi chính xác** (xem cảnh báo §11.4): benign thêm vào là **system/service
background của host triển khai** (daemon/cron/admin/container), KHÔNG phải user-behavior. Nên
kết quả đọc đúng là: *"thêm system-background của môi trường triển khai → model ART hết over-flag
lệnh daemon/admin → FP trên system-background giảm 27%→4.5% (held-out 50/50)"*. Hợp lệ cho
**server IDS** (server vốn ít user tương tác); KHÔNG kết luận gì về user-behavior benign.

### 11.6. network_connection — parser + IOC-labeling, và giới hạn audit-metadata

Script `camlds_network_parse.py`: group SYSCALL(connect, syscall=42) + SOCKADDR theo event id,
giải mã `SADDR={...}`, giữ `saddr_fam∈{inet,inet6}` (bỏ unix-socket local + netlink), gán nhãn
**IOC-match** (dst_addr ∈ IP attacker từ attackmate.json) — chiến lược **family-specific**
khác lineage: một kết nối C2 nhận diện bằng ĐÍCH ĐẾN, không phải provenance process.

| Host | inet/inet6 conn | Malicious (tới C2) |
|:--|--:|--:|
| docker | 892 | 42 |
| corpdns | 335 | 3 |
| inetfw | 606 | 0 |

→ 45 malicious / **5 endpoint unique** (C2 = 192.42.1.174:{443,8080,4444,8888}, .254:9092);
1,833 benign / 275 endpoint. ⚠️ **Bug labeling đã sửa**: IOC harvest ban đầu dính wildcard
`0.0.0.0` → gán nhầm 73 service-bind benign (SSH:22/MySQL:3306/SMTP:25) là malicious; lọc
`WILDCARD` (0.0.0.0/127.0.0.1/::) khỏi IOC.

**Phát hiện đắt (cho luận văn)**: **39/45 (87%) malicious đi qua port 443** — C2 ngụy trang
HTTPS. Metadata connect() của audit (port + process) **KHÔNG tách được** C2-over-443 với
HTTPS benign nếu thiếu IOC địa chỉ → family network cần **IP-reputation / DNS context / payload**,
không thể chỉ dựa audit. Vì 5 endpoint → KHÔNG train classifier (chỉ học thuộc IP C2, vô nghĩa);
giá trị ở đây là **infrastructure parser+labeler** + finding trên.

**Bước tiếp (đã chứng minh 2 lần — wall volume)**: cả process_creation (9 lệnh) lẫn
network_connection (5 endpoint) đều quá nhỏ từ 1 scenario → cần gom nhiều scenario.

### 11.7. manifestations_filtered (564 sequences) — đặc tả thực tế cho việc scale

Tải `manifestations_filtered.zip` (204 MB, Zenodo 18861762) — **564 sequence** đặt tên
`<scenario>-<step_ids>` phủ mọi loại tấn công (privesc pwnkit/sudo/racecondition; persistence
cron/autostart; lateral ssh_apt/vnc_apt; rootkit). Mỗi sequence = **cửa sổ log quanh các bước
tấn công** (audit.log + auth.log + attackmate.json per-host). Quy mô: **141,723 EXECVE** (503
audit.log), 1,112 dòng auth.log (182 file).

**Phát hiện then chốt — "filtered" = cửa sổ log, KHÔNG phải nhãn từng dòng:**
- Top EXECVE KHÔNG phải lệnh tấn công mà là mảnh pipeline của **agent giám sát AMiner/aecid**
  của testbed AIT chạy liên tục (`cut -d % -f 1` ×17,712, `sort/uniq/sed/grep` ×nghìn). 141K
  EXECVE → 4,701 unique, **phần lớn là monitoring benign**.
- Lệnh attacker trong attackmate.json chạy **trên máy attacker** (`hydra`, `dnsenum`) hoặc qua
  **implant sliver-session** (`ifconfig`) → đa số KHÔNG xuất hiện trực tiếp trong audit EXECVE
  của target, cái xuất hiện thì giống lệnh benign → **lineage-seed từ attackmate KHÔNG đáng tin**
  cho scenario multi-host implant. (Đây đúng là lý do tác giả phát hành ở mức cửa sổ.)

**→ Tín hiệu malicious sạch (labelable) từ manifestations:**

| Family | Nguồn | Nhãn | Volume (toàn bộ sequences) |
|:--|:--|:--|:--|
| **auth** | auth.log | IOC + time-window | 49 Failed password (**100% từ 192.42.1.174**), 48 Accepted, 24 Invalid user; sudo 32/151 attack-ish (`cat /etc/shadow` ×12 = T1003, `nmap` ×18) |
| **network** | audit connect+SOCKADDR | IOC-match | như §11.6 |
| process_creation | audit EXECVE | ❌ line-level không tin được | 141K EXECVE nhưng nhiễu monitoring; cần dùng ART/GTFOBins làm malicious |

**Kết luận kiến trúc (củng cố thiết kế gốc):**
- `process_creation`: malicious = **ART + GTFOBins** (độc lập, nhãn MITRE) + benign =
  CAM-LDS/Linux-APT. Line-level labeling process trong CAM-LDS multi-host là bài toán nghiên
  cứu riêng → KHÔNG dùng làm nguồn malicious chính.
- `auth`/`network`: malicious = CAM-LDS **IOC-labeled** (sshd brute-force/C2 từ 192.42.1.174)
  + benign = CAM-LDS background. Đây là nơi CAM-LDS đóng góp family MỚI sạch.
- CAM-LDS benign (mọi family) = nguồn benign khớp miền, justify tốt hơn Linux-APT weak-negative
  (đã định lượng: FP 27%→4.5% §11.5).

Data: `data/red_linux/camlds/downloads/manifestations_filtered/`. Scripts:
`camlds_network_parse.py` (network IOC), `camlds_auth_parse.py` + `camlds_auth_features.py` (auth).

### 11.8. auth family — SSH brute-force bằng HÀNH VI (IP-agnostic)

Parse auth.log của 564 sequence (`camlds_auth_parse.py`): 268 event (49 failed, 24 invalid_user,
40 accepted, 39 closed, 116 sudo). 152 sshd event.

**Phát hiện then chốt — IOC-IP THẤT BẠI ở auth**: IP `192.42.1.174` **vừa là attacker vừa là
IP quản trị hợp lệ** — 29 login THÀNH CÔNG (webadmin/root/debian/john) + 73 failed brute-force
cùng từ nó. Gán nhãn theo IP sẽ dán nhầm admin thật là tấn công → **bắt buộc dùng hành vi**.
(Khác network §11.6 nơi C2 IP không bị dùng chung → IOC còn dùng được.)

`camlds_auth_features.py`: window (host, src_ip, 60s) → feature **không chứa IP/username**
(n_failed, n_invalid_user, n_distinct_users, failed_ratio, attempts_per_sec...). Ground-truth
brute-force = window có invalid_user≥1 & failed≥1 (admin hợp lệ không bao giờ thử user không
tồn tại), định nghĩa độc lập với feature đếm.

| Feature (TB) | Brute-force (3 win) | Benign (34 win) |
|:--|--:|--:|
| n_failed | 16.3 | 0.0 |
| n_invalid_user | 8.0 | 0.0 |
| n_distinct_users | 3.0 | 1.0 |
| failed_ratio | 0.62 | 0.00 |

Detector ngưỡng IP-free (`n_failed≥3 & n_distinct_users≥2`): P/R/F1 = 1.0 (TP3/FP0/FN0/TN34).
⚠️ Chỉ **3 window tấn công** (1 đợt hydra) → là **nghiên cứu phân tách hành vi**, KHÔNG phải
benchmark ML; gom thêm scenario brute-force để train classifier. → `RESULT_CAMLDS_AUTH.md`.

**Bảng labeling theo family (tổng kết — cho hội đồng):**

| Family | Chiến lược nhãn | Vì sao |
|:--|:--|:--|
| process_creation / file_event | **lineage** (provenance ppid→pid) | tấn công có cây tiến trình; benign trùng thời gian không phải con attacker |
| network_connection | **IOC-match** (dst IP) | C2 nhận diện bằng đích đến; C2 IP không dùng chung |
| auth | **behavioral / time-window** | attacker dùng CHUNG IP admin → IOC sai; chỉ burst-hành-vi tách được |

---

## 12. Hạn Chế Và Roadmap

- **Bộ Sigma không phải benchmark accuracy cuối:** nhiễm nhãn khoảng 68% và malicious
  được định nghĩa bằng chính Sigma match.
- **ART hiện là corpus tĩnh:** command lấy từ YAML atomic, chưa phải telemetry auditd
  sau khi chạy thật. Bước tốt nhất tiếp theo là chạy ART trên VM có auditd để thu EXECVE.
- **Một event type:** nhánh Linux hiện tập trung vào `process_creation`; chưa mở rộng
  sang file/network event.
- **Multi-seed chưa đầy đủ:** script đã có, nhưng chưa chạy đủ toàn bộ seed để siết CI.
- **Stage 2 Layer-3 phụ thuộc rule fire:** không thể xác nhận rule bằng Sigma-logic nếu
  lệnh đã né sạch mọi rule.

Roadmap ưu tiên: chạy ART thật trên VM, hoàn tất multi-seed, tích hợp Layer-3 vào
`detect_batch.py`/`detect_live.py`, mở rộng generator bằng semantic-equivalent swaps,
và bổ sung thêm event type ngoài process command line.
