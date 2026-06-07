# Chương 5 - Kết Quả Thực Nghiệm Tổng Hợp

Chương này trình bày kết quả thực nghiệm của pipeline RED Stage 1 (Misuse Detection) trên tập kiểm thử tổng hợp. Khác với bản kết quả chi tiết theo từng event type, phần này gộp kết quả của ba nhóm sự kiện Windows gồm `process_creation`, `powershell` và `registry_event` để đánh giá hiệu năng tổng quan của hệ thống. Cách trình bày tham khảo cấu trúc báo cáo thực nghiệm trong tài liệu TK.pdf: mô tả dữ liệu, bảng hiệu suất tổng hợp, biểu đồ so sánh mô hình và phần đề xuất mô hình triển khai.

Kết quả trong báo cáo này được sinh tự động từ các file `eval_rslt_*_info.json` và log huấn luyện hiện có. Script chỉ đọc output thực nghiệm đã có, không huấn luyện lại mô hình.

---

## I. Thiết Lập Thực Nghiệm

### 1.1. Phân phối dữ liệu hiệu dụng

Bảng 5.1 trình bày số mẫu hiệu dụng được pipeline sử dụng sau bước chuẩn hóa, loại trùng và lọc rule hiếm. Số lượng này có thể nhỏ hơn số mẫu thô ban đầu trong split dataset, vì evaluation chỉ giữ các mẫu/rule đủ điều kiện đánh giá.

**Bảng 5.1. Phân phối dữ liệu hiệu dụng trong thực nghiệm**

| Event type | Train benign | Train malicious | Valid benign | Valid evasion | Test benign | Test match | Test evasion |
| --- | --- | --- | --- | --- | --- | --- | --- |
| process_creation | 1279 | 6745 | 274 | 107 | 275 | 62 | 109 |
| powershell | 2986 | 3294 | 639 | 30 | 641 | 21 | 34 |
| registry_event | 8243 | 1551 | 1766 | 3 | 1767 | 14 | 4 |
| Tổng | 12508 | 11590 | 2679 | 140 | 2683 | 97 | 147 |

![Hình 5.1. Phân phối mẫu kiểm thử hiệu dụng theo event type](reports/combined/figures/dataset_distribution.png)

### 1.2. Các cấu hình mô hình đánh giá

Thực nghiệm đánh giá 7 cấu hình: 3 single classifier, 3 combo ablation và 1 full ensemble.

**Bảng 5.2. Các mô hình được đánh giá**

| Nhóm | Cấu hình | Thành phần | Vai trò |
| --- | --- | --- | --- |
| Single classifier | SVM | 1 classifier | Baseline |
| Single classifier | LR | 1 classifier | Baseline |
| Single classifier | CNB | 1 classifier | Baseline |
| Ablation ensemble | SVM+LR | 2 classifiers | Ablation |
| Ablation ensemble | SVM+CNB | 2 classifiers | Ablation |
| Ablation ensemble | LR+CNB | 2 classifiers | Ablation |
| Full ensemble | Ensemble | 3 classifiers | Full ensemble |

### 1.3. Phương pháp tổng hợp kết quả

Đối với từng mô hình và từng subset kiểm thử, báo cáo cộng confusion matrix của ba event type:

```text
TP_total = TP_process_creation + TP_powershell + TP_registry_event
FP_total = FP_process_creation + FP_powershell + FP_registry_event
TN_total = TN_process_creation + TN_powershell + TN_registry_event
FN_total = FN_process_creation + FN_powershell + FN_registry_event
```

Từ confusion matrix tổng hợp, báo cáo tính lại Precision, Recall, F1-score theo cả Weighted và Macro. Macro F1 được ưu tiên khi diễn giải vì dataset mất cân bằng mạnh giữa benign và malicious.

---

## II. Kết Quả Kiểm Thử Tổng Hợp

### 2.1. Kết quả trên test_match

`test_match` đo khả năng phát hiện các malicious events khớp với Sigma rule gốc, đồng thời kiểm tra model không làm suy giảm khả năng nhận diện baseline.

**Bảng 5.3. Kết quả hiệu suất tổng hợp trên test_match**

| Model | P(W) | P(M) | R(W) | R(M) | F1(W) | F1(M) | Accuracy | Train(s) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SVM | 0.993 | 0.918 | 0.992 | 0.976 | 0.992 | 0.945 | 0.992 | 68.04 |
| LR | 0.992 | 0.905 | 0.991 | 0.980 | 0.991 | 0.939 | 0.991 | 8.33 |
| CNB | 0.987 | 0.850 | 0.984 | 0.957 | 0.985 | 0.896 | 0.984 | 4.28 |
| SVM+LR | 0.993 | 0.921 | 0.992 | 0.971 | 0.992 | 0.945 | 0.992 | 71.00 |
| SVM+CNB | 0.992 | 0.923 | 0.992 | 0.961 | 0.992 | 0.941 | 0.992 | 64.22 |
| LR+CNB | 0.992 | 0.900 | 0.990 | 0.975 | 0.991 | 0.934 | 0.990 | 8.79 |
| Ensemble | 0.994 | 0.927 | 0.993 | 0.982 | 0.993 | 0.952 | 0.993 | 82.52 |

### 2.2. Kết quả trên test_evasion

`test_evasion` là subset quan trọng hơn đối với mục tiêu của RED, vì nó đo khả năng phát hiện các biến thể né luật không tham gia training.

**Bảng 5.4. Kết quả hiệu suất tổng hợp trên test_evasion**

| Model | P(W) | P(M) | R(W) | R(M) | F1(W) | F1(M) | Accuracy | Train(s) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SVM | 0.994 | 0.945 | 0.993 | 0.993 | 0.993 | 0.968 | 0.993 | 68.04 |
| LR | 0.993 | 0.934 | 0.992 | 0.992 | 0.992 | 0.961 | 0.992 | 8.33 |
| CNB | 0.985 | 0.890 | 0.983 | 0.959 | 0.984 | 0.921 | 0.983 | 4.28 |
| SVM+LR | 0.994 | 0.948 | 0.994 | 0.993 | 0.994 | 0.969 | 0.994 | 71.00 |
| SVM+CNB | 0.992 | 0.947 | 0.992 | 0.973 | 0.992 | 0.960 | 0.992 | 64.22 |
| LR+CNB | 0.989 | 0.926 | 0.988 | 0.958 | 0.988 | 0.941 | 0.988 | 8.79 |
| Ensemble | 0.994 | 0.950 | 0.994 | 0.990 | 0.994 | 0.969 | 0.994 | 82.52 |

![Hình 5.2. So sánh Precision, Recall, F1-score và Accuracy của các mô hình](reports/combined/figures/model_metrics_combined.png)

![Hình 5.3. So sánh Macro F1 trên test_match và test_evasion](reports/combined/figures/match_vs_evasion_f1.png)

### 2.3. Xếp hạng tổng hợp

Để tránh cộng lặp benign test set giữa hai kịch bản `test_match` và `test_evasion`, ranking tổng hợp sử dụng trung bình Macro F1 của hai subset sau khi đã gộp ba event type.

**Bảng 5.5. Ranking mô hình theo Macro F1 tổng hợp**

| Rank | Model | Macro F1 avg | Weighted F1 avg | Accuracy avg | Train(s) | Gap vs top |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Ensemble | 0.961 | 0.994 | 0.993 | 82.52 | 0.0000 |
| 2 | SVM+LR | 0.957 | 0.993 | 0.993 | 71.00 | -0.0038 |
| 3 | SVM | 0.956 | 0.993 | 0.993 | 68.04 | -0.0043 |
| 4 | SVM+CNB | 0.951 | 0.992 | 0.992 | 64.22 | -0.0102 |
| 5 | LR | 0.950 | 0.992 | 0.991 | 8.33 | -0.0106 |
| 6 | LR+CNB | 0.938 | 0.989 | 0.989 | 8.79 | -0.0230 |
| 7 | CNB | 0.908 | 0.984 | 0.983 | 4.28 | -0.0523 |

![Hình 5.4. Ranking mô hình theo Macro F1 tổng hợp](reports/combined/figures/macro_f1_ranking.png)

---

## III. Phân Tích Trade-off Hiệu Năng Và Chi Phí Huấn Luyện

Bảng và biểu đồ tổng hợp cho thấy `Ensemble` là mô hình đứng đầu theo Macro F1 trung bình với giá trị `0.961`. Ensemble đạt Macro F1 trung bình `0.961` (chi phí huấn luyện ~`82.52`s), trong khi LR đạt `0.950` với thời gian huấn luyện chỉ ~`8.33`s — hai thái cực của trục hiệu-năng/chi-phí.

![Hình 5.5. Macro F1 và chi phí huấn luyện của từng mô hình](reports/combined/figures/performance_training_cost.png)

![Hình 5.6. Trade-off giữa Macro F1 và thời gian huấn luyện](reports/combined/figures/f1_training_tradeoff.png)

Biểu đồ trade-off giúp tách rõ hai hướng lựa chọn. LR là cấu hình production-efficient vì đạt hiệu năng rất cao trong khi chi phí huấn luyện thấp và độ phức tạp triển khai nhỏ. Ensemble là cấu hình robust-oriented vì kết hợp nhiều classifier với inductive bias khác nhau, chấp nhận chi phí huấn luyện cao hơn để giảm phụ thuộc vào một mô hình đơn lẻ.

---

## IV. So Sánh Candidate Finalist

Ba cấu hình finalist gồm LR, SVM+LR và Ensemble được so sánh theo hiệu năng tổng hợp, khả năng phát hiện evasion, chi phí huấn luyện và độ phức tạp triển khai.

**Bảng 5.6. So sánh đa tiêu chí giữa LR, SVM+LR và Ensemble**

| Tiêu chí | LR | SVM+LR | Ensemble |
| --- | --- | --- | --- |
| Macro F1 avg | 0.950 | 0.957 | 0.961 |
| Macro F1 test_evasion | 0.961 | 0.969 | 0.969 |
| Accuracy avg | 0.991 | 0.993 | 0.993 |
| Training time avg (s) | 8.33 | 71.00 | 82.52 |
| Complexity | 1 classifier | 2 classifiers | 3 classifiers |
| Production efficiency | Cao | Thấp hơn | Thấp hơn |
| Robust-oriented deployment | Trung bình | Cao | Cao |

![Hình 5.7. Confusion matrix của LR và Ensemble trên test_evasion](reports/combined/figures/confusion_lr_ensemble_evasion.png)

---

## V. Đề Xuất Mô Hình Triển Khai

Với số liệu trung thực (eval khớp đường suy luận lúc triển khai), Ensemble là mô hình đạt Macro F1 tổng hợp cao nhất, dẫn đầu trên test_evasion và có số false positive thấp nhất trong nhóm dẫn đầu. Lựa chọn này cũng nhất quán với hướng thiết kế gốc của RED (mở rộng AMIDES bằng ensemble nhiều classifier), nên được đề xuất làm cấu hình triển khai chính.

LR vẫn là lựa chọn thay thế hấp dẫn khi ưu tiên chi phí: chỉ một classifier, huấn luyện nhanh hơn nhiều, dễ debug/monitor/giải thích, với Macro F1 chỉ thấp hơn Ensemble không đáng kể.

Do đó, kết luận phù hợp là:

> Ensemble là lựa chọn triển khai chính theo kết quả hiện tại — hiệu năng cao nhất và nhất quán với thiết kế RED. LR là lựa chọn thay thế production-efficient khi ưu tiên chi phí huấn luyện và độ đơn giản.

---

## VI. Hạn Chế Và Hướng Phát Triển

- Kết quả tổng hợp giúp đánh giá hiệu năng toàn hệ thống, nhưng có thể che khuất hiện tượng suy giảm trên từng event type; do đó kết quả chi tiết theo event type vẫn nên giữ ở phụ lục.
- Tập `registry_event` có số mẫu evasion rất nhỏ, nên kết quả ở nhóm này chưa ổn định về mặt thống kê.
- Cần chạy thêm multi-seed hoặc bootstrap confidence interval để kiểm tra khác biệt giữa LR và Ensemble có ý nghĩa thống kê hay không.
- Learning curve chưa được đưa vào báo cáo này. Nếu cần, có thể thực hiện thí nghiệm bổ sung bằng cách train LR/Ensemble với nhiều tỷ lệ dữ liệu huấn luyện khác nhau.

---

## VII. Hướng Dẫn Chạy Lại

Từ thư mục gốc project:

```bash
cd /home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection
python3 scripts/generate_combined_report.py
```

Nếu Python báo thiếu `matplotlib` hoặc `numpy`, cài dependency trước:

```bash
python3 -m venv .venv-report
.venv-report/bin/python -m pip install matplotlib numpy
.venv-report/bin/python scripts/generate_combined_report.py
```

Các output chính:

- `RESULT_COMBINED.md`: file báo cáo tổng hợp.
- `reports/combined/combined_metrics_by_subset.csv`: metric gộp theo `test_match` và `test_evasion`.
- `reports/combined/overall_ranking.csv`: ranking tổng hợp theo Macro F1.
- `reports/combined/training_times.csv`: thời gian huấn luyện đọc từ log.
- `reports/combined/figures/`: thư mục chứa biểu đồ PNG dùng cho báo cáo/slide.
