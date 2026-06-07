# RED-Windows — Stage 3 Layer-3 Sigma-logic validator

> Cosine lọc top-N ứng viên, Layer-3 dùng Hayabusa/fired oracle để xác nhận rule nào thật sự khớp event. Đây là đánh giá offline trên match events EVTX đã được Hayabusa xác nhận, **không dùng evasion-sinh-từ-match** (tránh lạm phát token).

Split: `test`. Dedupe: `sample_rule`. Ground truth key: `dir`.

> ⚠️ **Lưu ý về số liệu**: Số `top-1 = 68.8%` được báo cáo trước đây trên tập evasion-sinh-từ-match (lạm phát — evasion chia sẻ token sẵn với rule). Bảng dưới đây là đo trên **fired ground-truth trung thực** (match events EVTX, Hayabusa xác nhận rule thật fire), khó hơn và phản ánh đúng hiệu năng deployment.

---

## Cosine Baseline (ground-truth: fired/trung thực)

| Event type | n | Top-1 | Top-3 | Top-5 | Top-10 | Layer-3 cứu được (gt ∈ top2–10) |
|---|--:|--:|--:|--:|--:|--:|
| process_creation | 68 | 38.2% | 64.7% | 75.0% | 79.4% | **41.2%** |
| powershell | 23 | 73.9% | 95.7% | 95.7% | 100% | 26.1% |
| registry_event | 14 | 71.4% | 92.9% | 92.9% | 100% | 28.6% |

→ `process_creation` top-1 chỉ 38.2% (thấp hơn tưởng) vì catalog Windows lớn ~1,119 rule → nhiều rule họ hàng chia token (LOLBin, PowerShell, path). Column "Layer-3 cứu được" = % sample mà rule đúng nằm **trong** top-10 nhưng **không phải** top-1 — tức cosine lọc đúng nhưng không chốt đúng top-1.

---

## Layer-3 Top-1 After Rerank

| Event type | n | Cosine top-1 | +Layer-3 @top-3 | +Layer-3 @top-5 | +Layer-3 @top-10 |
|---|--:|--:|--:|--:|--:|
| **process_creation** | 68 | 38.2% | **64.7%** | **75.0%** | **79.4%** |
| powershell | 23 | 73.9% | **95.7%** | 95.7% | **100%** |
| registry_event | 14 | 71.4% | **92.9%** | 92.9% | **100%** |

→ **process_creation: top-1 38.2% → 79.4%** (+41pp, gần ×2 — cùng magnitude với Linux: 44.8%→90.2%).
`top-1 sau Layer-3 @top-N = cosine top-N recall`: Layer-3 chọn chính xác rule khớp trong số ứng viên cosine đề xuất — cơ chế hoàn toàn đối xứng Linux.

---

## So sánh Windows vs Linux

| | Windows (process_creation) | Linux (ART, process_creation) |
|---|---|---|
| Cosine top-1 (fired/trung thực) | 38.2% | 44.8% |
| +Layer-3 @top-10 | **79.4%** | **90.2%** |
| Gain | +41.2pp | +45.4pp |
| Catalog size | ~1,119 rule | ~208 rule |
| Lý do cosine thấp | Catalog lớn → nhiều rule họ hàng | ART lệnh độc lập-Sigma → ít token overlap |

→ Cosine Windows thấp hơn Linux (~38% vs 45%) do catalog lớn hơn ~5×, nhưng **dư địa Layer-3 xấp xỉ nhau** (~41pp vs 45pp). Đây là bằng chứng Layer-3 có giá trị đối xứng trên cả 2 OS.

---

## Caveat (trung thực)

- **Layer-3 chỉ giúp lệnh có rule thật fire trong top-N.** Với evasion thuần (attacker xoá hết chữ ký → không rule nào fire), validator không xác nhận được gì → rơi về cosine. Đây là ranh giới bản chất, giống hệt Linux (token bị xoá thì không phương pháp nào quy về đúng rule).
- **Trần thật = cosine top-N recall**: với catalog 1,119 rule Windows, top-10 chỉ đạt 79.4% cho process_creation (20.6% sample có rule đúng nằm ngoài top-10 hoàn toàn → không cứu được).
- **Oracle vs production**: script này dùng Hayabusa-confirmed match labels làm oracle (perfect). Production thực tế phải chạy Hayabusa hoặc pySigma **chỉ trên top-N rule ứng viên** (không quét toàn catalog) — chi phí thấp, cosine lo recall, Sigma-logic lo precision.
- **powershell / registry_event**: Layer-3 đạt 100% @top-10 nhưng n nhỏ (23/14) và cosine recall top-10 đã 100% → không phân biệt được giá trị thêm; process_creation là event type đáng tin nhất để đánh giá.

---

## Artifacts

- `process_creation` details: `reports/windows/layer3_process_creation_test_details.jsonl`
- `powershell` details: `reports/windows/layer3_powershell_test_details.jsonl`
- `registry_event` details: `reports/windows/layer3_registry_event_test_details.jsonl`

Tái tạo: `~/venvs/rule_evasion_env/bin/python scripts/stage3_layer3_windows.py`
