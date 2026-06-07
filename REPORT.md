# CHƯƠNG 5. KẾT QUẢ THỰC NGHIỆM

Chương này trình bày kết quả thực nghiệm của hệ thống Rule Evasion Detection (RED) ở giai đoạn Stage 1 - Misuse Detection. Mục tiêu của thực nghiệm là đánh giá khả năng phát hiện các sự kiện độc hại, bao gồm cả các biến thể né tránh luật phát hiện (evasion), dựa trên dữ liệu benign, dữ liệu match với Sigma rule và dữ liệu evasion được tạo từ các rule tương ứng.

Trong phần báo cáo này, kết quả được trình bày theo hướng tổng hợp toàn hệ thống. Thay vì phân tích riêng lẻ từng nhóm sự kiện như `process_creation`, `powershell` và `registry_event`, các confusion matrix của ba nhóm sự kiện được gộp lại để tính toán chỉ số chung. Cách trình bày này giúp đánh giá trực quan hơn hiệu năng tổng thể của pipeline khi triển khai như một hệ thống phát hiện thống nhất.

Các biểu đồ trong chương này được sinh từ output thực nghiệm thật, bao gồm các file `eval_rslt_*_info.json` và log huấn luyện trong thư mục `logs/`. Script sinh báo cáo và biểu đồ là `scripts/generate_combined_report.py`.

---

## 5.1. Thiết Lập Thực Nghiệm

### 5.1.1. Dữ liệu thực nghiệm

Dữ liệu thực nghiệm gồm ba nhóm sự kiện Windows:

- `process_creation`: các sự kiện tạo tiến trình.
- `powershell`: các sự kiện PowerShell, chủ yếu dựa trên nội dung script block.
- `registry_event`: các sự kiện liên quan đến registry.

Mỗi nhóm sự kiện gồm ba loại mẫu:

- `benign`: sự kiện bình thường.
- `match`: sự kiện độc hại khớp với Sigma rule gốc.
- `evasion`: biến thể độc hại được điều chỉnh để né tránh rule gốc.

Trong quá trình huấn luyện, mô hình chỉ sử dụng dữ liệu benign, match và rule filter. Các mẫu evasion không được đưa vào training, mà chỉ được dùng ở validation/test nhằm đánh giá khả năng phát hiện biến thể né luật.

**Bảng 5.1. Phân phối dữ liệu hiệu dụng trong thực nghiệm**

| Event type | Train benign | Train malicious | Valid benign | Valid evasion | Test benign | Test match | Test evasion |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| process_creation | 1279 | 6745 | 274 | 107 | 275 | 62 | 109 |
| powershell | 2986 | 3294 | 639 | 30 | 641 | 21 | 34 |
| registry_event | 8243 | 1551 | 1766 | 3 | 1767 | 14 | 4 |
| **Tổng** | **12508** | **11590** | **2679** | **140** | **2683** | **97** | **147** |

![Hình 5.1. Phân phối mẫu kiểm thử hiệu dụng theo event type](reports/combined/figures/dataset_distribution.png)

Quan sát Bảng 5.1 và Hình 5.1 cho thấy dữ liệu có sự mất cân bằng rõ rệt giữa benign và malicious. Số lượng benign lớn hơn rất nhiều so với match và evasion. Đặc biệt, `registry_event` có số mẫu evasion rất nhỏ, do đó kết quả trên nhóm này chỉ nên được xem là tham khảo và cần được mở rộng trong các thí nghiệm tiếp theo.

### 5.1.2. Các mô hình đánh giá

Thực nghiệm đánh giá 7 cấu hình mô hình, bao gồm 3 mô hình đơn lẻ, 3 cấu hình ablation và 1 mô hình ensemble đầy đủ.

**Bảng 5.2. Các mô hình được đánh giá**

| Nhóm | Cấu hình | Thành phần | Vai trò |
| --- | --- | --- | --- |
| Single classifier | SVM | 1 classifier | Baseline |
| Single classifier | LR | 1 classifier | Baseline |
| Single classifier | CNB | 1 classifier | Baseline |
| Ablation ensemble | SVM+LR | 2 classifiers | Ablation |
| Ablation ensemble | SVM+CNB | 2 classifiers | Ablation |
| Ablation ensemble | LR+CNB | 2 classifiers | Ablation |
| Full ensemble | Ensemble | 3 classifiers | Cấu hình kết hợp đầy đủ |

Trong đó, LR là Logistic Regression, CNB là Complement Naive Bayes, còn Ensemble là cấu hình kết hợp SVM, LR và CNB bằng cơ chế tổng hợp điểm dự đoán.

### 5.1.3. Quy trình đánh giá

Quy trình đánh giá gồm ba bước chính:

1. Huấn luyện mô hình trên tập train.
2. Chọn threshold tối ưu trên tập validation.
3. Đánh giá trên tập test với threshold đã chọn, không sweep lại threshold trên test set.

Tập test được chia thành hai kịch bản:

- `test_match`: gồm benign test và malicious match test.
- `test_evasion`: gồm benign test và malicious evasion test.

`test_match` dùng để kiểm tra mô hình có phát hiện tốt các sự kiện khớp luật gốc hay không. `test_evasion` quan trọng hơn đối với mục tiêu của đề tài, vì nó đánh giá khả năng phát hiện biến thể né tránh rule.

**Lưu ý về tính trung thực của số liệu (sửa lỗi tiền xử lý).** Trong quá trình rà soát, chúng tôi phát hiện pipeline chỉ chuẩn hóa (normalize) phía malicious mà không chuẩn hóa benign trước khi vector hóa, trong khi đường suy luận lúc triển khai (`detect_batch`/`detect_live`) lại chuẩn hóa **mọi** event. Sự bất đối xứng này khiến mô hình học một "lối tắt" — *chưa-chuẩn-hóa = benign, đã-chuẩn-hóa = malicious* — nên số F1 trên eval (benign feed thô) rất cao nhưng khi triển khai thật thì ~87% benign bị gắn cờ sai. Toàn bộ kết quả trong chương này được tạo lại **sau khi bật chuẩn hóa benign đối xứng** (`normalize_benign: true`), đảm bảo số liệu eval phản ánh đúng hiệu năng deployment (đã kiểm chứng: tỷ lệ false positive trên benign khi eval trùng khớp với khi chạy runtime).

### 5.1.4. Phương pháp gộp kết quả

Với mỗi mô hình và mỗi kịch bản test, kết quả được tổng hợp bằng cách cộng confusion matrix của ba event type:

```text
TP_total = TP_process_creation + TP_powershell + TP_registry_event
FP_total = FP_process_creation + FP_powershell + FP_registry_event
TN_total = TN_process_creation + TN_powershell + TN_registry_event
FN_total = FN_process_creation + FN_powershell + FN_registry_event
```

Từ confusion matrix tổng hợp, các chỉ số Precision, Recall, F1-score và Accuracy được tính lại. Do dữ liệu bị mất cân bằng mạnh, báo cáo sử dụng song song hai nhóm chỉ số:

- Weighted: trung bình có trọng số theo số lượng mẫu của từng class.
- Macro: trung bình đều giữa các class, phản ánh tốt hơn hiệu năng trên class minority.

Trong phần phân tích, Macro F1 được ưu tiên hơn Weighted F1 vì malicious/evasion là nhóm mẫu quan trọng nhưng có số lượng nhỏ hơn nhiều so với benign.

---

## 5.2. Kết Quả Kiểm Thử Tổng Hợp

### 5.2.1. Kết quả trên test_match

Bảng 5.3 trình bày kết quả kiểm thử tổng hợp trên tập `test_match`.

**Bảng 5.3. Kết quả hiệu suất tổng hợp trên test_match**

| Model | Precision (W) | Precision (M) | Recall (W) | Recall (M) | F1 (W) | F1 (M) | Accuracy | Training (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SVM | 0.993 | 0.918 | 0.992 | 0.976 | 0.992 | 0.945 | 0.992 | 68.04 |
| LR | 0.992 | 0.905 | 0.991 | 0.980 | 0.991 | 0.939 | 0.991 | 8.33 |
| CNB | 0.987 | 0.850 | 0.984 | 0.957 | 0.985 | 0.896 | 0.984 | 4.28 |
| SVM+LR | 0.993 | 0.921 | 0.992 | 0.971 | 0.992 | 0.945 | 0.992 | 71.00 |
| SVM+CNB | 0.992 | 0.923 | 0.992 | 0.961 | 0.992 | 0.941 | 0.992 | 64.22 |
| LR+CNB | 0.992 | 0.900 | 0.990 | 0.975 | 0.991 | 0.934 | 0.990 | 8.79 |
| **Ensemble** | **0.994** | **0.927** | **0.993** | **0.982** | **0.993** | **0.952** | **0.993** | 82.52 |

Trên `test_match`, Ensemble đạt Macro F1 cao nhất với giá trị 0.952, nhỉnh hơn SVM và SVM+LR (cùng 0.945) và LR (0.939). CNB đơn lẻ thấp nhất (0.896). Khác với báo cáo trước (khi tiền xử lý benign bất đối xứng làm SVM "degenerate" và thổi phồng các mô hình dựa-LR), sau khi chuẩn hóa benign đối xứng với malicious thì khoảng cách giữa các mô hình thu hẹp và phản ánh đúng hiệu năng triển khai.

### 5.2.2. Kết quả trên test_evasion

Bảng 5.4 trình bày kết quả kiểm thử tổng hợp trên tập `test_evasion`.

**Bảng 5.4. Kết quả hiệu suất tổng hợp trên test_evasion**

| Model | Precision (W) | Precision (M) | Recall (W) | Recall (M) | F1 (W) | F1 (M) | Accuracy | Training (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SVM | 0.994 | 0.945 | 0.993 | 0.993 | 0.993 | 0.968 | 0.993 | 68.04 |
| LR | 0.993 | 0.934 | 0.992 | 0.992 | 0.992 | 0.961 | 0.992 | 8.33 |
| CNB | 0.985 | 0.890 | 0.983 | 0.959 | 0.984 | 0.921 | 0.983 | 4.28 |
| **SVM+LR** | **0.994** | **0.948** | **0.994** | **0.993** | **0.994** | **0.969** | **0.994** | 71.00 |
| SVM+CNB | 0.992 | 0.947 | 0.992 | 0.973 | 0.992 | 0.960 | 0.992 | 64.22 |
| LR+CNB | 0.989 | 0.926 | 0.988 | 0.958 | 0.988 | 0.941 | 0.988 | 8.79 |
| **Ensemble** | **0.994** | **0.950** | **0.994** | **0.990** | **0.994** | **0.969** | **0.994** | 82.52 |

Trên `test_evasion`, SVM+LR và Ensemble cùng đạt Macro F1 cao nhất (0.969), kế đến là SVM (0.968) và LR (0.961). Đáng chú ý, Ensemble đạt Precision Macro cao nhất (0.950) — tức ít false positive nhất trong nhóm dẫn đầu — phù hợp với mục tiêu giảm tải cho analyst trong môi trường SOC. CNB và LR+CNB thấp hơn rõ rệt.

![Hình 5.2. So sánh Precision, Recall, F1-score và Accuracy của các mô hình](reports/combined/figures/model_metrics_combined.png)

![Hình 5.3. So sánh Macro F1 trên test_match và test_evasion](reports/combined/figures/match_vs_evasion_f1.png)

Hình 5.2 cho thấy sau khi sửa lỗi tiền xử lý, các mô hình đạt Macro F1 cao và **đồng đều hơn** (trừ CNB đơn lẻ); Accuracy đơn thuần không đủ để đánh giá vì benign chiếm tỷ lệ lớn. Hình 5.3 cho thấy Ensemble và SVM+LR duy trì hiệu năng cao nhất trên cả hai kịch bản match và evasion.

---

## 5.3. Xếp Hạng Mô Hình Và Phân Tích Tổng Quan

Để đánh giá hiệu năng tổng quan, báo cáo sử dụng trung bình Macro F1 của hai kịch bản `test_match` và `test_evasion` sau khi đã gộp ba event type.

**Bảng 5.5. Ranking mô hình theo Macro F1 tổng hợp**

| Rank | Model | Macro F1 avg | Weighted F1 avg | Accuracy avg | Training (s) | Gap vs top |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Ensemble | 0.961 | 0.994 | 0.993 | 82.52 | 0.0000 |
| 2 | SVM+LR | 0.957 | 0.993 | 0.993 | 71.00 | -0.0038 |
| 3 | SVM | 0.956 | 0.993 | 0.993 | 68.04 | -0.0043 |
| 4 | SVM+CNB | 0.951 | 0.992 | 0.992 | 64.22 | -0.0102 |
| 5 | LR | 0.950 | 0.992 | 0.991 | 8.33 | -0.0106 |
| 6 | LR+CNB | 0.938 | 0.989 | 0.989 | 8.79 | -0.0230 |
| 7 | CNB | 0.908 | 0.984 | 0.983 | 4.28 | -0.0523 |

![Hình 5.4. Ranking mô hình theo Macro F1 tổng hợp](reports/combined/figures/macro_f1_ranking.png)

Kết quả xếp hạng cho thấy **Ensemble (SVM+LR+CNB) đạt Macro F1 trung bình cao nhất (0.961)**, kế đến là SVM+LR (0.957) và SVM (0.956). LR — vốn đứng đầu trong bản báo cáo trước — nay xếp thứ 5 (0.950). Sự thay đổi thứ hạng này là hệ quả trực tiếp của việc sửa lỗi tiền xử lý benign (xem mục 5.1.3): khi benign được chuẩn hóa đối xứng với malicious đúng như đường suy luận lúc triển khai, các mô hình tuyến tính (LR) không còn được lợi từ "lối tắt" thô-vs-chuẩn-hóa, còn SVM hết bị degenerate. Kết quả mới phản ánh đúng hiệu năng deployment và **củng cố lựa chọn Ensemble theo đúng tinh thần thiết kế RED**.

CNB đơn lẻ xếp cuối (0.908): tuy Precision khá nhưng Recall trên malicious thấp hơn các mô hình khác. Tuy nhiên CNB vẫn đóng vai trò "đối trọng" hữu ích bên trong Ensemble (xem phân tích từng event type ở RESULT_2).

---

## 5.4. Phân Tích Chi Phí Huấn Luyện

Bên cạnh hiệu năng phát hiện, chi phí huấn luyện cũng là yếu tố quan trọng khi xét khả năng triển khai. Hệ thống phát hiện trong môi trường bảo mật có thể cần retrain khi cập nhật rule, bổ sung log mới hoặc thay đổi môi trường vận hành.

![Hình 5.5. Macro F1 và chi phí huấn luyện của từng mô hình](reports/combined/figures/performance_training_cost.png)

![Hình 5.6. Trade-off giữa Macro F1 và thời gian huấn luyện](reports/combined/figures/f1_training_tradeoff.png)

Từ Hình 5.5 và Hình 5.6, có hai hướng trade-off rõ rệt. Ensemble đạt Macro F1 cao nhất (0.961) nhưng thời gian huấn luyện trung bình ~82.5 giây — cao nhất do phải fit cả ba classifier kèm GridSearch. LR ở thái cực còn lại: Macro F1 0.950 (thấp hơn Ensemble 0.011) nhưng chỉ ~8.3 giây huấn luyện. CNB nhanh nhất nhưng Macro F1 thấp nhất.

Kết quả này cho thấy: nếu tiêu chí chính là triển khai gọn nhẹ, retrain nhanh và tiết kiệm tài nguyên thì LR là lựa chọn hiệu quả; còn nếu ưu tiên hiệu năng phát hiện cao nhất và độ bền trước thay đổi phân phối thì Ensemble là lựa chọn tốt hơn, đổi lại chi phí huấn luyện cao hơn (chỉ tốn một lần khi train, không ảnh hưởng inference).

---

## 5.5. So Sánh Các Candidate Chính

Ba cấu hình được chọn để phân tích sâu hơn gồm LR, SVM+LR và Ensemble. Đây là ba mô hình có Macro F1 tổng hợp cao nhất.

**Bảng 5.6. So sánh đa tiêu chí giữa LR, SVM+LR và Ensemble**

| Tiêu chí | LR | SVM+LR | Ensemble |
| --- | ---: | ---: | ---: |
| Macro F1 avg | 0.950 | 0.957 | **0.961** |
| Macro F1 test_evasion | 0.961 | 0.969 | **0.969** |
| Accuracy avg | 0.991 | 0.993 | **0.993** |
| Training time avg (s) | **8.33** | 71.00 | 82.52 |
| Số classifier | 1 | 2 | 3 |
| Production efficiency | **Cao** | Thấp hơn | Thấp hơn |
| Model diversity | Thấp | Trung bình | **Cao** |

![Hình 5.7. Confusion matrix của LR và Ensemble trên test_evasion](reports/combined/figures/confusion_lr_ensemble_evasion.png)

Ensemble đạt Macro F1 tổng hợp cao nhất (0.961) và đồng hạng nhất trên `test_evasion` (0.969) với SVM+LR, đồng thời có Precision Macro evasion cao nhất (ít false positive nhất). LR vẫn là lựa chọn hấp dẫn về chi phí: huấn luyện chỉ ~8.3s so với ~82.5s của Ensemble, đổi lại Macro F1 thấp hơn 0.011. SVM+LR nằm giữa: hiệu năng sát Ensemble nhưng chỉ 2 classifier.

Hình 5.7 cho thấy LR và Ensemble có confusion matrix gần nhau trên `test_evasion`. LR phát hiện 146/147 mẫu malicious evasion với 22 false positive trên 2683 benign; Ensemble phát hiện 145/147 nhưng chỉ **16 false positive** — tức Ensemble đánh đổi 1 true positive để giảm 6 false positive, một trade-off có lợi trong vận hành SOC.

---

## 5.6. Đề Xuất Mô Hình

Dựa trên kết quả thực nghiệm (sau khi sửa lỗi tiền xử lý benign), báo cáo đề xuất Ensemble là cấu hình chính, kèm LR như lựa chọn thay thế khi ưu tiên chi phí.

### 5.6.1. Lựa chọn ưu tiên: Ensemble (SVM+LR+CNB)

Ensemble đạt Macro F1 tổng hợp cao nhất (0.961), đồng hạng nhất trên `test_evasion` (0.969) và có Precision Macro evasion cao nhất (ít false positive nhất trong nhóm dẫn đầu). Cấu hình này kết hợp ba hướng học bổ trợ:

- SVM học theo biên phân tách.
- LR học quan hệ tuyến tính ổn định giữa feature và nhãn.
- CNB khai thác phân phối token/feature, phù hợp với dữ liệu dạng command line, script và registry string.

Quan trọng hơn, lựa chọn Ensemble nay được hậu thuẫn bằng **số liệu trung thực** (eval khớp đường suy luận lúc triển khai), không còn dựa vào kết quả bị thổi phồng do lỗi tiền xử lý. Điều này cũng **nhất quán với hướng thiết kế gốc của RED** (mở rộng AMIDES bằng ensemble nhiều classifier). Trade-off duy nhất là chi phí huấn luyện cao hơn (~82s), chỉ phát sinh lúc train chứ không ảnh hưởng inference.

### 5.6.2. Lựa chọn thay thế khi ưu tiên chi phí: LR

Nếu tiêu chí chính là triển khai gọn nhẹ, retrain nhanh và đơn giản, LR là lựa chọn hợp lý: Macro F1 0.950 (chỉ thấp hơn Ensemble 0.011) với thời gian huấn luyện ~8.3s và chỉ một classifier — dễ debug, dễ monitor, dễ giải thích.

Kết luận phù hợp là:

> Ensemble là mô hình đạt hiệu năng cao nhất theo kết quả thực nghiệm hiện tại (Macro F1 tổng hợp 0.961, dẫn đầu test_evasion, ít false positive nhất) và nhất quán với thiết kế RED — là lựa chọn triển khai chính. LR là lựa chọn thay thế production-efficient khi ưu tiên chi phí huấn luyện và độ đơn giản, với hiệu năng chỉ thấp hơn không đáng kể.

---

## 5.7. Hạn Chế Của Thực Nghiệm

Thực nghiệm hiện tại còn một số hạn chế:

- Số lượng evasion của `registry_event` rất nhỏ, làm kết quả trên nhóm này chưa ổn định về mặt thống kê.
- Kết quả tổng hợp giúp đánh giá toàn hệ thống, nhưng có thể che khuất vấn đề riêng của từng event type.
- Chưa thực hiện multi-seed hoặc bootstrap confidence interval để kiểm tra ý nghĩa thống kê của chênh lệch giữa các mô hình.
- Chưa đánh giá inference latency và memory footprint, trong khi đây là yếu tố quan trọng khi triển khai thực tế.
- Chưa có learning curve để quan sát mô hình có bão hòa hoặc overfit khi tăng kích thước tập huấn luyện hay không.

---

## 5.8. Hướng Phát Triển

Các hướng phát triển tiếp theo gồm:

- Mở rộng số lượng evasion, đặc biệt cho `registry_event`.
- Chạy nhiều seed hoặc bootstrap confidence interval để đánh giá độ ổn định của kết quả.
- Đánh giá inference latency theo số event/giây để xác định khả năng triển khai thời gian thực.
- Thử nghiệm learning curve cho LR và Ensemble để đánh giá tác động của kích thước dữ liệu huấn luyện.
- Đánh giá Stage 2 attribution để xác định khả năng truy vết rule bị né tránh.
- Thử nghiệm trên dữ liệu log mới hoặc dữ liệu ngoài phân phối để kiểm tra khả năng tổng quát hóa.

---

## 5.9. Hướng Dẫn Sinh Lại Báo Cáo Và Biểu Đồ

Từ thư mục gốc project:

```bash
cd /home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection
python3 scripts/generate_combined_report.py
```

Nếu môi trường Python thiếu `matplotlib` hoặc `numpy`, có thể tạo virtual environment riêng:

```bash
python3 -m venv .venv-report
.venv-report/bin/python -m pip install matplotlib numpy
.venv-report/bin/python scripts/generate_combined_report.py
```

Các output chính:

- `RESULT_COMBINED.md`: báo cáo tổng hợp tự động.
- `reports/combined/combined_metrics_by_subset.csv`: metric theo `test_match` và `test_evasion`.
- `reports/combined/overall_ranking.csv`: ranking tổng hợp theo Macro F1.
- `reports/combined/training_times.csv`: thời gian huấn luyện đọc từ log.
- `reports/combined/figures/`: các biểu đồ dùng cho báo cáo và slide.

---

## 5.10. Kết Luận Chương

Chương này đã trình bày kết quả thực nghiệm của pipeline RED Stage 1 trên tập kiểm thử tổng hợp, sau khi phát hiện và sửa một lỗi tiền xử lý benign khiến số liệu trước đó bị thổi phồng (xem mục 5.1.3). Với số liệu trung thực, các mô hình SVM, SVM+LR và Ensemble đều đạt hiệu năng cao trong phát hiện malicious match và evasion. Trong đó, **Ensemble đạt Macro F1 tổng hợp cao nhất (0.961)** và dẫn đầu trên test_evasion với số false positive thấp nhất.

Do đó, đề xuất triển khai chính là Ensemble — vừa đạt hiệu năng cao nhất, vừa nhất quán với hướng thiết kế RED. LR là lựa chọn thay thế production-efficient khi ưu tiên chi phí huấn luyện và độ đơn giản, với hiệu năng chỉ thấp hơn không đáng kể (0.950 so với 0.961).
