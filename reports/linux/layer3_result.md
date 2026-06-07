# RED-Linux — Stage 2 Layer-3 Sigma-logic validator

> `stage3_layer3_linux.py`. Cosine lọc top-N ứng viên → Zircolite (Sigma engine thật) xác nhận rule nào khớp → đẩy #1. Đánh giá trên ground-truth *fired* (n=143 lệnh ART có rule fire).


## So sánh top-k hit rate


| Phương pháp | Top-1 | Top-3 | Top-5 | Top-10 |
|---|--:|--:|--:|--:|
| Cosine (baseline) | 44.8% | 77.6% | 83.2% | 90.2% |
| **Cosine + Layer-3 @top-3** | **77.6%** | 77.6% | 83.2% | 90.2% |
| **Cosine + Layer-3 @top-5** | **83.2%** | 83.2% | 83.2% | 90.2% |
| **Cosine + Layer-3 @top-10** | **90.2%** | 90.2% | 90.2% | 90.2% |

→ Layer-3 nâng **top-1 từ 44.8% lên 90.2%** (xác nhận trong top-10 cosine). Top-1 sau Layer-3 = đúng bằng **recall top-N của cosine**: Sigma-logic chọn chính xác rule khớp trong số ứng viên cosine đưa ra.


## Đọc kết quả (trung thực)


- **Cơ chế đúng đắn**: cosine một mình hay nhầm rule họ-hàng (top-1 45%); thêm bước chạy logic Sigma thật để **xác nhận** thì loại được nhầm lẫn → top-1 ≈ 90%.

- **Giới hạn**: Layer-3 chỉ giúp lệnh mà **có rule thật khớp** (đã/đang fire). Với **evasion thuần** (không rule nào fire — attacker xoá hết chữ ký) thì Sigma-logic không xác nhận được gì → rơi về cosine. Đây là ranh giới bản chất: token bị xoá thì không phương pháp nào (kể cả Sigma-logic) quy về đúng rule đã bị né.

- **Chi phí**: chỉ chạy Sigma-logic trên **N rule ứng viên** (không phải toàn catalog) → rẻ. Cosine làm phần nặng (lọc), Sigma-logic làm phần chính xác (chốt).

- Top-N nhỏ hơn → trần thấp hơn: @top-3 78% / @top-5 83% / @top-10 90% (đánh đổi số rule phải kiểm tra vs độ chính xác).
