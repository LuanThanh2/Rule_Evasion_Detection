# Chương 5 — Kết Quả Thực Nghiệm

Chương này trình bày kết quả huấn luyện và đánh giá pipeline RED Stage 1 (Misuse Detection) trên 3 event type Windows: `process_creation`, `powershell`, `registry_event`. Đánh giá được thực hiện trên 7 cấu hình mô hình: **4 single classifier** (SVM, LR, CNB, Ensemble đầy đủ) và **3 combo ablation** (SVM+LR, SVM+CNB, LR+CNB) — tổng cộng 21 cấu hình thực nghiệm.

> **Lưu ý quan trọng về tính trung thực (sửa lỗi tiền xử lý).** Toàn bộ số liệu trong chương này được tạo lại **sau khi sửa một lỗi tiền xử lý**: trước đây pipeline chỉ chuẩn hóa (normalize) phía malicious mà **không** chuẩn hóa benign trước khi vector hóa, trong khi đường suy luận lúc triển khai (`detect_batch`/`detect_live`) chuẩn hóa **mọi** event. Sự bất đối xứng này làm mô hình học "lối tắt" *chưa-chuẩn-hóa = benign* — khiến F1 trên eval rất cao (≈0.98) nhưng khi triển khai thật **~87% benign bị gắn cờ sai**. Sau khi bật `normalize_benign: true` (chuẩn hóa benign đối xứng với malicious), số liệu eval phản ánh đúng hiệu năng deployment. Đây cũng là lý do **thứ hạng mô hình ở bản này khác bản trước**: LR không còn được lợi từ lối tắt nên không còn dẫn đầu, SVM hết bị "degenerate".

---

## I. Thiết lập thực nghiệm

### 1.1. Dataset split

Dữ liệu được chia theo three-way split 70/15/15 stratified theo Sigma rule cho match events; benign chia 70/15/15 random shuffle; evasion variants chia 2-way 50/50 (do evasion không tham gia training):

| Event type | Benign train/valid/test | Match train/valid/test | Evasion valid/test |
|:---|:---:|:---:|:---:|
| process_creation | 1279 / 274 / 275 | 243 / 49 / 76 (37 rules) | 151 / 159 |
| powershell | 2986 / 639 / 641 | 92 / 19 / 25 (6 rules) | 54 / 57 |
| registry_event | 8243 / 1766 / 1767 | 60 / 11 / 18 (6 rules) | 8 / 8 |

⚠️ Rule có dưới 5 events bị loại khỏi evaluation (process_creation chỉ còn 37/202 rule). Test set evasion của `registry_event` quá nhỏ (8 sample) → kết quả mang tính tham khảo, không ổn định thống kê.

### 1.2. Quy trình đánh giá

1. **Train** trên train set (70% benign + 70% match + `malicious_samples: both` từ Sigma rule_filters), **chuẩn hóa benign đối xứng với malicious** (`normalize_benign: true`).
2. **Validate** trên validation set (15% benign + 50% evasion) → sweep 50 threshold để tìm threshold tối ưu T\*.
3. **Test** trên test set với threshold T\* đã chốt từ validation (KHÔNG sweep lại) → báo cáo số cuối cùng.

Tách 2 test subset:
- **Test match**: benign_test + match_test (non-regression baseline so với Sigma rule).
- **Test evasion**: benign_test + evasion_test (adversarial robustness — đóng góp khoa học chính).

### 1.3. Metric

Báo cáo song song **Weighted** (W) và **Macro** (M) cho Precision, Recall, F1-score nhằm phản ánh trung thực hiệu suất trên class minority (malicious) khi dataset bị mất cân bằng:

- **Weighted**: trung bình có trọng số theo class size — dễ bị benign (majority) dominate.
- **Macro**: trung bình đều giữa 2 class — reveal performance thực trên malicious.

---

## II. Kết quả 4 mô hình chính trên 3 event type

### 2.1. process_creation

#### Bảng 5.1. Kết quả 4 mô hình chính — process_creation, test_match

| Model | Precision (W) | Precision (M) | Recall (W) | Recall (M) | F1 (W) | F1 (M) | Accuracy | Training (s) |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| **SVM** | 0.962 | 0.897 | 0.953 | 0.971 | 0.955 | **0.928** | 0.953 | 56.89 |
| LR | 0.953 | 0.873 | 0.938 | 0.962 | 0.941 | 0.908 | 0.938 | 4.63 |
| CNB | 0.927 | 0.815 | 0.893 | 0.922 | 0.901 | 0.850 | 0.893 | 2.76 |
| Ensemble | 0.961 | 0.899 | 0.953 | 0.965 | 0.954 | 0.927 | 0.953 | 72.91 |

#### Bảng 5.2. Kết quả 4 mô hình chính — process_creation, test_evasion

| Model | Precision (W) | Precision (M) | Recall (W) | Recall (M) | F1 (W) | F1 (M) | Accuracy | Training (s) |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| **SVM** | 0.961 | 0.934 | 0.956 | 0.966 | 0.957 | **0.948** | 0.956 | 56.89 |
| LR | 0.951 | 0.917 | 0.943 | 0.957 | 0.944 | 0.933 | 0.943 | 4.63 |
| CNB | 0.926 | 0.875 | 0.906 | 0.929 | 0.909 | 0.893 | 0.906 | 2.76 |
| Ensemble | 0.960 | 0.935 | 0.956 | 0.964 | 0.956 | 0.947 | 0.956 | 72.91 |

**Quan sát**: trên process_creation — event type khó tách nhất — SVM và Ensemble dẫn đầu sát nhau (F1 Macro evasion 0.948 vs 0.947), cao hơn LR (0.933) và CNB (0.893). Sau khi sửa lỗi tiền xử lý, SVM **không còn degenerate** như báo cáo trước (trước đây F1 Macro chỉ ~0.55–0.60 do feed benign thô làm lệch threshold).

### 2.2. powershell

#### Bảng 5.3. Kết quả 4 mô hình chính — powershell, test_match

| Model | Precision (W) | Precision (M) | Recall (W) | Recall (M) | F1 (W) | F1 (M) | Accuracy | Training (s) |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| SVM | 0.996 | 0.954 | 0.995 | 0.975 | 0.996 | 0.964 | 0.995 | 88.36 |
| **LR** | 0.999 | 0.977 | 0.998 | 0.999 | 0.999 | **0.988** | 0.998 | 17.52 |
| CNB | 0.993 | 0.916 | 0.992 | 0.973 | 0.993 | 0.942 | 0.992 | 8.86 |
| **Ensemble** | 0.999 | 0.977 | 0.998 | 0.999 | 0.999 | **0.988** | 0.998 | 96.67 |

#### Bảng 5.4. Kết quả 4 mô hình chính — powershell, test_evasion

| Model | Precision (W) | Precision (M) | Recall (W) | Recall (M) | F1 (W) | F1 (M) | Accuracy | Training (s) |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| SVM | 0.997 | 0.972 | 0.997 | 0.998 | 0.997 | 0.985 | 0.997 | 88.36 |
| **LR** | 0.999 | 0.986 | 0.999 | 0.999 | 0.999 | **0.992** | 0.999 | 17.52 |
| CNB | 0.982 | 0.927 | 0.982 | 0.879 | 0.982 | 0.902 | 0.982 | 8.86 |
| **Ensemble** | 0.999 | 0.986 | 0.999 | 0.999 | 0.999 | **0.992** | 0.999 | 96.67 |

**Quan sát**: LR và Ensemble đồng hạng nhất (F1 Macro evasion 0.992), SVM sát ngay (0.985). CNB thấp hơn rõ rệt trên evasion (0.902, recall Macro chỉ 0.879 — bỏ sót 8/34 mẫu). Data PowerShell tương đối dễ tách.

### 2.3. registry_event

#### Bảng 5.5. Kết quả 4 mô hình chính — registry_event, test_match

| Model | Precision (W) | Precision (M) | Recall (W) | Recall (M) | F1 (W) | F1 (M) | Accuracy | Training (s) |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| SVM | 0.998 | 0.999 | 0.998 | 0.893 | 0.998 | 0.940 | 0.998 | 58.86 |
| LR | 0.998 | 0.999 | 0.998 | 0.893 | 0.998 | 0.940 | 0.998 | 2.86 |
| CNB | 0.998 | 0.999 | 0.998 | 0.857 | 0.998 | 0.916 | 0.998 | 1.21 |
| **Ensemble** | 0.999 | 0.999 | 0.999 | 0.929 | 0.999 | **0.961** | 0.999 | 77.98 |

#### Bảng 5.6. Kết quả 4 mô hình chính — registry_event, test_evasion

| Model | Precision (W) | Precision (M) | Recall (W) | Recall (M) | F1 (W) | F1 (M) | Accuracy | Training (s) |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| SVM | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 58.86 |
| LR | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 2.86 |
| CNB | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.21 |
| Ensemble | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 77.98 |

**Quan sát**: trên test_match, Ensemble đạt F1 Macro cao nhất (0.961) nhờ bắt 12/14 match (SVM/LR chỉ 11/14, CNB 10/14). Trên test_evasion (chỉ 4 sample) mọi model đều đạt 1.000 — **kết quả mang tính tham khảo** do test set evasion quá nhỏ (8 samples).

---

## III. Ablation Study — 3 combo

### 3.1. process_creation (event type có khả năng phân biệt cao nhất)

#### Bảng 5.7. Ablation study — process_creation, test_evasion

| Configuration | Precision (W) | Precision (M) | Recall (W) | Recall (M) | F1 (W) | F1 (M) | Accuracy | Training (s) |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| SVM | 0.961 | 0.934 | 0.956 | 0.966 | 0.957 | 0.948 | 0.956 | 56.89 |
| LR | 0.951 | 0.917 | 0.943 | 0.957 | 0.944 | 0.933 | 0.943 | 4.63 |
| CNB | 0.926 | 0.875 | 0.906 | 0.929 | 0.909 | 0.893 | 0.906 | 2.76 |
| SVM+LR | 0.959 | 0.930 | 0.953 | 0.965 | 0.954 | 0.945 | 0.953 | 51.15 |
| **SVM+CNB** | 0.962 | 0.938 | 0.958 | 0.965 | 0.959 | **0.950** | 0.958 | 53.98 |
| LR+CNB | 0.945 | 0.911 | 0.938 | 0.948 | 0.939 | 0.927 | 0.938 | 4.80 |
| Ensemble | 0.960 | 0.935 | 0.956 | 0.964 | 0.956 | 0.947 | 0.956 | 72.91 |

#### Bảng 5.8. Ablation study — process_creation, test_match

| Configuration | F1 (W) | F1 (M) | Accuracy | Training (s) |
|:---|---:|---:|---:|---:|
| **SVM** | 0.955 | **0.928** | 0.953 | 56.89 |
| LR | 0.941 | 0.908 | 0.938 | 4.63 |
| CNB | 0.901 | 0.850 | 0.893 | 2.76 |
| SVM+LR | 0.949 | 0.919 | 0.947 | 51.15 |
| SVM+CNB | 0.951 | 0.921 | 0.950 | 53.98 |
| LR+CNB | 0.938 | 0.903 | 0.935 | 4.80 |
| Ensemble | 0.954 | 0.927 | 0.953 | 72.91 |

**Quan sát ablation**:
- Trên evasion, các cấu hình có SVM (SVM, SVM+CNB, SVM+LR, Ensemble) đều ở nhóm dẫn đầu (F1 Macro 0.945–0.950); SVM+CNB cao nhất sít sao (0.950).
- Các cấu hình thuần-LR (LR, LR+CNB) thấp hơn ~0.02 → trên process_creation, thành phần SVM đóng góp nhiều hơn LR.
- Chênh lệch trong nhóm dẫn đầu rất nhỏ (≤0.005) và test set nhỏ → không nên kết luận một combo "thắng tuyệt đối"; xu hướng ổn định là **có SVM thì tốt hơn**.

### 3.2. registry_event

#### Bảng 5.9. Ablation study — registry_event, test_match

| Configuration | F1 (W) | F1 (M) | Accuracy | Training (s) |
|:---|---:|---:|---:|---:|
| SVM | 0.998 | 0.940 | 0.998 | 58.86 |
| LR | 0.998 | 0.940 | 0.998 | 2.86 |
| CNB | 0.998 | 0.916 | 0.998 | 1.21 |
| SVM+LR | 0.998 | 0.940 | 0.998 | 71.76 |
| **SVM+CNB** | 0.999 | **0.961** | 0.999 | 60.57 |
| **LR+CNB** | 0.999 | **0.961** | 0.999 | 3.50 |
| **Ensemble** | 0.999 | **0.961** | 0.999 | 77.98 |

**Quan sát**: sau khi sửa lỗi tiền xử lý, hiện tượng "SVM+LR / SVM+CNB sụp xuống F1≈0.76–0.94" trong báo cáo trước **không còn xuất hiện** — đó là artifact của threshold lệch do feed benign thô. Với số liệu trung thực, các cấu hình **có CNB** (SVM+CNB, LR+CNB, Ensemble) bắt thêm 1 match (12/14) nên F1 Macro nhỉnh hơn (0.961 vs 0.940). Đây là tín hiệu nhẹ cho thấy CNB bổ trợ trên registry, nhưng test set quá nhỏ nên chỉ mang tính tham khảo.

---

## IV. Tổng hợp ranking và Macro F1 aggregate

### Bảng 5.10. Ranking theo Macro F1 trung bình trên 6 cells (3 event type × 2 subset)

| Rank | Configuration | Macro F1 Avg | Gap vs top | Training time avg (s) |
|---:|:---|---:|---:|---:|
| **1** | **Ensemble (SVM+LR+CNB)** | **0.961** | — | 82.52 |
| **2** | **SVM+LR** | 0.957 | -0.0038 | 71.00 |
| 3 | SVM | 0.956 | -0.0043 | 68.04 |
| 4 | SVM+CNB | 0.951 | -0.0102 | 64.22 |
| 5 | LR | 0.950 | -0.0106 | 8.33 |
| 6 | LR+CNB | 0.938 | -0.0230 | 8.79 |
| 7 | CNB | 0.908 | -0.0523 | 4.28 |

> Macro F1 Avg = trung bình Macro F1 của test_match và test_evasion sau khi gộp confusion matrix của 3 event type. Khác bản trước (LR đứng đầu 0.983), bản trung thực cho **Ensemble đứng đầu (0.961)**, LR rớt xuống #5.

### Bảng 5.11. Top-1 frequency (số cell đạt F1 Macro cao nhất trong 6 cells)

| Configuration | Top-1 (kể cả đồng hạng) | Ghi chú |
|:---|---:|:---|
| Ensemble | 3 / 6 | Dẫn đầu reg_match + đồng hạng ps + reg_evasion |
| SVM+CNB | 3 / 6 | Cao nhất proc_evasion + reg_match |
| SVM | 2 / 6 | Cao nhất proc_match |
| SVM+LR | 2 / 6 | Cao nhất ps_evasion |
| LR | 2 / 6 | Đồng hạng ps |
| LR+CNB | 2 / 6 | Đồng hạng reg_match |
| CNB | 1 / 6 | Chỉ thắng ở reg_evasion (đồng hạng toàn bộ) |

> Cell `registry_event` test_evasion cho **mọi** model = 1.000 (4 sample) nên đồng hạng toàn bộ — top-1 frequency vì vậy chỉ nên đọc tham khảo, ưu tiên Macro F1 Avg (Bảng 5.10).

---

## V. So sánh với baseline (AMIDES paper)

### Bảng 5.12. So sánh với nghiên cứu liên quan

| Method | Year | Dataset | F1 Macro avg | Adversarial robustness | Note |
|:---|:---:|:---:|---:|:---:|:---|
| Sigma rule (rule-based, baseline) | — | per-rule | 0.500 (lý thuyết: 1.0 match, 0.0 evasion) | ✗ Không bắt được evasion | Baseline truyền thống |
| AMIDES (Uetz et al.) | 2024 | tự build | ~0.96 (paper) | ✓ Có (SVM-based) | Paper RED dựa trên |
| **RED — Full Ensemble** | 2026 | Sigma+LMD/MPSD | **0.961** | ✓ Có | Theo design RED gốc |
| RED — SVM+LR | 2026 | Sigma+LMD/MPSD | 0.957 | ✓ Có | Combo 2 classifier |
| RED — Single LR | 2026 | Sigma+LMD/MPSD | 0.950 | ✓ Có | Production-efficient |

→ Cả 3 cấu hình KLTN đều **vượt rule-based** trên adversarial robustness và **ngang/nhỉnh hơn AMIDES baseline**. Lưu ý: con số RED nay là **số trung thực** (eval khớp đường runtime), không còn bị thổi phồng như bản trước.

---

## VI. Đánh giá tổng quan và đề xuất mô hình

### 6.1. Đánh giá đa tiêu chí (multi-criteria)

#### Bảng 5.13. Bảng đánh giá đa tiêu chí cho 3 candidate finalist

| Tiêu chí | LR | SVM+LR | Ensemble (SVM+LR+CNB) |
|:---|:---:|:---:|:---:|
| Macro F1 avg (6 cells) | 0.950 | 0.957 | **0.961** |
| F1 process_creation evasion (hardest adversarial) | 0.933 | 0.945 | 0.947 |
| F1 registry_event match (data dễ) | 0.940 | 0.940 | **0.961** |
| Top-1 wins | 2/6 | 2/6 | **3/6** |
| Training time (avg) | **8.33 s** | 71.00 s | 82.52 s |
| Số classifier (complexity) | **1** | 2 | 3 |
| Match RED/AMIDES paper narrative | ✗ | ⚠️ | **✓** |
| FP trên test_evasion (gộp, /2683 benign) | 22 | 17 | **16** |
| CNB rescue trên registry_event | ✗ | ✗ | **✓** |

### 6.2. Khuyến nghị mô hình triển khai

Với số liệu trung thực (eval = runtime), chúng tôi đề xuất:

**🥇 Đề xuất chính: Ensemble (SVM+LR+CNB)**
- Macro F1 avg = 0.961 — **cao nhất** trong 7 cấu hình.
- Đồng hạng nhất trên test_evasion (0.969 khi gộp) và **ít false positive nhất** trong nhóm dẫn đầu (16/2683 benign).
- **Match với design RED gốc** (mở rộng AMIDES bằng Ensemble SVM + LR + CNB) → defense rõ ràng cho luận văn.
- Trade-off: training time cao nhất (~82s) nhưng chỉ phát sinh lúc train, không ảnh hưởng inference.

**🥈 Đề xuất thay thế: LR alone** (khi ưu tiên đơn giản hóa)
- Macro F1 avg = 0.950 — chỉ thấp hơn Ensemble 0.011.
- Training time = 8.33s — nhanh nhất; single-classifier dễ debug/monitor/giải thích.
- Phù hợp khi tài nguyên hạn chế hoặc cần interpretability.

**🥉 Đề xuất thay thế: SVM+LR** (khi muốn cân bằng hiệu năng/độ phức tạp)
- Macro F1 avg = 0.957, sát Ensemble nhưng chỉ 2 classifier.

**KHÔNG khuyến nghị**:
- CNB alone — yếu nhất (0.908), đặc biệt recall thấp trên powershell evasion.
- LR+CNB — thấp hơn cả LR alone trên evasion process_creation.

### 6.3. Hướng phát triển

- Multi-run với 5 seeds để có mean ± std và bootstrap CI 95% — kiểm định ý nghĩa thống kê của chênh lệch (hiện chênh lệch Ensemble vs SVM+LR/SVM khá nhỏ).
- Mở rộng test set evasion cho registry_event (hiện chỉ 8 samples).
- **Hold-out theo rule/technique**: hiện evasion sinh từ chính match events nên chia sẻ nhiều token với train sau normalize (overlap nội dung lớn) → dataset vẫn "dễ". Hold-out theo rule/technique sẽ cho đánh giá tổng quát hóa khắt khe hơn (giống cách bộ Linux-ART làm).
- Đánh giá inference latency và memory footprint cho production.
- Stage 2 attribution (cosine) đánh giá độc lập với cùng split.

---

## Phụ lục: Trích kết quả từ JSON output

Mỗi file `models/<event_type>/eval_rslt_<cfg>_<subset>_info.json` chứa:
```json
{
  "optimal": {"threshold": ..., "f1": ..., "mcc": ..., "tp": ..., "fp": ..., "tn": ..., "fn": ...},
  "default_0.5": {...}
}
```
Hoặc khi sử dụng test set với threshold cố định:
```json
{
  "fixed_threshold": {"threshold": ..., "f1": ..., "tp": ..., "fp": ..., "tn": ..., "fn": ...}
}
```

Macro F1 được tính từ TP/FP/TN/FN:
- F1_pos = 2·TP / (2·TP + FP + FN)
- F1_neg = 2·TN / (2·TN + FP + FN)
- **F1 Macro = (F1_pos + F1_neg) / 2**
