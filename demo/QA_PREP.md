# Q&A Bank — Demo RED + AI Agent Pipeline

Câu hỏi tiềm năng GVHD sẽ hỏi, với câu trả lời sẵn. Đọc 1 lần trước demo, không cần thuộc lòng — biết hướng trả lời là đủ.

---

## 🎯 Nhóm 1: Kỹ thuật ML / Detection

### Q1. Tại sao Ensemble (SVM+LR+CNB) tốt hơn SVM đơn?

**Trả lời ngắn**: Mỗi classifier "nhìn" data theo cách khác nhau — SVM tìm hyperplane tối ưu, LR ưu tiên xác suất calibrated, CNB phù hợp với text class-imbalanced. Khi vote ensemble, các weakness của từng cái được cover.

**Dữ liệu cụ thể**:
- SVM đơn: Recall 94.3%, F1 0.9706, **17 false negatives**
- Ensemble: Recall 100%, F1 1.0000, **0 FN**
- CNB cứu được 17 evasion mà SVM bỏ sót (xem bảng trong CLAUDE.md)

**Caveat honest**: sau MCC scaling, cả 2 đều F1=1.0 vì data dễ tách → em dùng **raw threshold=0 metrics** làm bằng chứng chính trong luận văn.

---

### Q2. Tại sao Stage 2 Cosine Similarity vượt Stage 2 SVM (68.8% vs 23.5% top-1)?

**Trả lời**: SVM bị underfit vì per-rule chỉ có 1-15 match events (rule hiếm khi có nhiều mẫu match). Cosine Similarity dùng **shared TF-IDF** (330 filter values từ tất cả rule) → vector hóa robust hơn.

**Insight**: Đây là kết quả ngược kỳ vọng. Em ghi rõ trong luận văn rằng SVM tốt cho dataset lớn, Cosine tốt cho rule attribution với data thưa.

---

### Q3. Mô hình có overfit không? F1=1.0 trên validation hơi đáng nghi.

**Trả lời (honest)**: Có rủi ro overfit vì hiện tại config production dùng `benign_valid = benign_train` (100% benign, không holdout). Em đã thử setup 80/20 split → kết quả vẫn ~F1=0.98 → mô hình thực sự tách được, không phải data leak.

**Bằng chứng bổ sung**:
- `scripts/diagnose_stage1.py` phân tích tokens → discriminative tokens hợp lý (`bypass`, `encoded`, `base64`)
- Test trên ELK events thật (không thấy trong training) → vẫn classify đúng

**Threat to validity em sẽ ghi trong thesis**: cần test trên dataset độc lập (LMD-2024 nếu có) để verify generalization.

---

## 🤖 Nhóm 2: AI Agent / LLM

### Q4. Mô hình này khác gì Splunk SOAR / Cortex XSOAR thương mại?

**3 điểm khác biệt**:

1. **Tự sinh Sigma patch grounded by forensic** — Splunk/Cortex chỉ chạy playbook cứng (if X then Y). Pipeline của em **dynamic** — LLM hiểu evasion technique và generate patch phù hợp.

2. **Vietnamese-native report** — Splunk/Cortex output English. Em báo cáo tiếng Việt cho SOC team VN đọc trực tiếp, có MITRE mapping VN context.

3. **ML model interpretability** — RED Analyst Agent giải thích **WHY** alert này là evasion (translate ML score → human reasoning). Splunk/Cortex chỉ chat với data có sẵn, không hiểu nội tại detector.

**Honest**: Splunk/Cortex enterprise hơn (ticketing, RBAC, audit log). Em không cố thay thế họ, em build prototype để chứng minh **Multi-Agent + ML interpretability** approach khả thi.

---

### Q5. LLM có hallucinate không? Làm sao em biết Sigma patch không bịa?

**Trả lời 3 lớp giảm thiểu**:

1. **Forensic Agent ground patch trên evidence cứng** (NEW v2):
   - Velociraptor query host thật → process tree, file hash, registry, IP đều thật
   - Response Agent nhận `ForensicOutput` → patch reference data có evidence

2. **Prompt engineering explicit**:
   - Forensic prompt: *"KHÔNG bịa bằng chứng — chỉ ghi cái Velociraptor thật sự trả về"*
   - Nếu tool fail → đánh dấu `evidence_grade: missing`

3. **Demonstrated experimentally** (kết quả test hôm nay):
   - Inject alert giả với `PID=0` (Idle Process không tồn tại)
   - Forensic Agent **scan 166 real processes** trên Windows VM, không tìm thấy
   - Trả `evidence_grade: missing, verdict: inconclusive` thay vì bịa
   - Đây là **kháng hallucination measurable** → claim defensible trong thesis

**Future work em đề xuất** — Layer 3 validator:
- Parse YAML patch
- Run thử trên evasion sample → phải catch
- Run thử trên 100 benign samples → FP rate phải < threshold
- Reject patch nếu fail

---

### Q6. Pipeline chạy 100s — không phải real-time, có dùng được không?

**Trả lời**: Đúng, không real-time, nhưng **acceptable cho SOC triage tier**.

**Khung tham chiếu**:
- L1 SOC analyst trung bình: **5-15 phút/alert**
- Pipeline của em: **~98s mock / ~210s real VR**
- **Improvement 4-12× faster** vẫn rất giá trị

**Trade-off thiết kế**:
- Real-time defense (block ngay) → đã có ở layer trước (Stage 1 ML scoring < 5ms)
- Triage + investigation (deep analysis) → tier sau, có thể chấp nhận ~100s

**Áp dụng thực tế**: 1000 alerts/ngày × 100s = 28 giờ compute → chỉ cần 2-3 worker parallel là kịp.

---

### Q7. Cost $0.02/alert nhân lên 1000 alerts/ngày = $20/ngày — có sustainable không?

**Trả lời**: Có, và rẻ hơn analyst nhiều lần.

**So sánh**:
- $20/ngày = ~$600/tháng = ~$7,200/năm cho LLM API
- 1 SOC analyst Junior VN ~$1,200/tháng = ~$14,400/năm
- 1 alert manual analyst 10 phút = $4-8 cost human → 1000 alerts/ngày = $4,000-8,000/ngày

**Cost ROI**: Pipeline rẻ hơn analyst **200-400×** trên cùng workload.

**Optimization có sẵn**:
- Score threshold filter: chỉ chạy alerts > 0.5 → giảm ~5-10× alerts
- Supervisor skip_fp routing: tiết kiệm 60-80% token
- Prompt caching (DeepSeek hit 60-80%): giảm 4× input cost

---

### Q8. Em đã test trên bao nhiêu alerts thật?

**Trả lời (honest)**:
- ~30 mock alerts test development
- 1 real Velociraptor scenario hôm nay (rehearsal)
- 1 demo scenario sẽ chạy live cho thầy/cô xem

**Limitation em thừa nhận**: chưa có **labeled dataset 100-200 alerts** để đo accuracy formally (severity vs ground truth, FP rate, hallucination count). Em ghi rõ trong **roadmap future work**.

**Cách build dataset đề xuất** (em viết trong luận văn):
1. Hayabusa scan LMD-2023 → ground truth labels
2. Generate evasion variants từ matched rules
3. Run pipeline → so sánh agent severity vs Hayabusa label
4. Measure: accuracy, precision, recall, F1 cho severity classification

---

## 🛡️ Nhóm 3: Defense / Security

### Q9. Sigma patch có giải quyết được vấn đề evasion vĩnh viễn không?

**Trả lời thẳng — KHÔNG, và em đã thừa nhận trong luận văn**:

> *"Sigma patch là **tactical mitigation** cho variant cụ thể vừa thấy, KHÔNG phải silver bullet. Có vô hạn evasion variants — patch hôm nay obsolete ngày mai khi attacker dùng variant mới."*

**Defense thực sự là 3-layer**:
1. **RED ML model** generalize qua shared token patterns → bắt cả họ variants
2. **Feedback loop**: evasion samples → retrain RED weekly → model adapt
3. **Sigma patch**: chỉ là band-aid SHORT-TERM, giảm noise SIEM trong vòng vài ngày trong khi ML model retrain

**Em vẫn giữ Sigma patch trong pipeline** vì 3 lý do:
1. Bridge gap thời gian giữa "phát hiện evasion" và "ML retrained" (vài ngày tới vài tuần)
2. Analyst đọc được patch (audit + customize), không như ML score 0.87
3. Compatible với SIEM ecosystem (Wazuh, Splunk, Elastic) — sẵn sàng deploy

---

### Q10. Forensic Agent có ảnh hưởng performance VM Windows không?

**Trả lời**: Có nhưng thấp.

**Đo lường**:
- 1 VQL query (`pslist`, `netstat`, `file events`) trên Velociraptor agent: ~5-15% CPU spike trong 2-5s
- Không có sustained load — burst rồi giảm
- Pipeline query 3 lần/alert → tổng ~10-30s spike CPU

**Mitigation**:
- Forensic Agent CHỈ chạy khi `triage.severity in (CRITICAL, HIGH, MEDIUM)` — bỏ qua LOW
- Có thể throttle qua `interval` của daemon
- Velociraptor có quota built-in: `Quota.max_cpu_percent`, `Quota.max_rows`

**Honest**: Trong môi trường production có > 1000 endpoints, cần load test trước khi roll out.

---

## 🇻🇳 Nhóm 4: Vietnamese Context

### Q11. Pipeline này dùng được cho doanh nghiệp VN không?

**Trả lời 4 lý do PHÙ HỢP**:

1. **Vietnamese report native** — SOC team VN đọc 5 giây hiểu ngay, không cần dịch
2. **Tương thích NĐ 13/2023** — em có thiết kế PII redaction trong logs (mask user, IP nội bộ)
3. **Stack open-source** — Elastic + Wazuh + Velociraptor đều free, phù hợp SME ngân sách hạn chế
4. **Cost $20/ngày** affordable cho startup/SME VN

**Limitation cần thừa nhận**:
- Cần DeepSeek API (Trung Quốc) hoặc OpenAI API (Mỹ) → có thể data sovereignty concern
- **Future work**: thử LLM local (Qwen, Llama 3, Foundation-Sec-8B) → zero data egress

---

## 🚨 Nhóm 5: Câu khó / Critique

### Q12. Em demo 1 scenario thành công không chứng minh được pipeline robust. Em phản biện thế nào?

**Trả lời (acknowledge + plan)**:

*"Thầy/Cô đúng. 1 demo không đủ. Em có 3 mức validation:*

1. **Hôm nay**: 1 end-to-end scenario thành công → chứng minh **pipeline integration works**
2. **Trong luận văn**: chạy 30 mock alerts + 5 real Velociraptor scenarios → đo per-agent metrics (time, tokens, cost)
3. **Future work em đề xuất**: build labeled dataset 100-200 alerts từ Hayabusa baseline, đo accuracy/precision/recall formally — em viết trong roadmap"*

---

### Q13. LLM Trung Quốc (DeepSeek) có rủi ro security/IP không?

**Trả lời (honest)**:

*"Em chọn DeepSeek vì giá rẻ ($0.27/1M input vs OpenAI $2.50) cho thí nghiệm. Em thừa nhận:*

- Data có thể bị log/train trên server DeepSeek (theo TOS không khẳng định không)
- Với enterprise sensitive: cần dùng OpenAI Enterprise (HIPAA), Anthropic Claude Enterprise (zero retention), hoặc **local LLM**

**Mitigation trong production**:
1. **PII redaction trước khi gửi LLM** — mask user, host, IP nội bộ
2. **Local LLM option** — em đã thiết kế `agent/llm.py` modular, có thể swap sang Ollama + Qwen/Llama-3 trong 1 ngày
3. **Logging tất cả prompts** — để audit sau"*

---

### Q14. Em không phải security expert chuyên nghiệp — sao em đảm bảo Sigma patch sinh ra không break production?

**Trả lời (acknowledge + concrete plan)**:

*"Đúng, em là sinh viên. Đó là lý do em có 2 cơ chế bảo vệ:*

1. **Human-in-the-loop bắt buộc**: mọi Sigma patch và containment action đều có `requires_human_approval: true`. Daemon chỉ **đề xuất**, không tự deploy. SOC analyst review → approve → manual deploy.

2. **Layer 3 validator (future work)**: parse YAML → run trên evasion sample (phải catch) + 100 benign samples (FP rate < 5%) → reject nếu fail. Em đã liệt kê SigmaOptimizer (GitHub project) làm tham khảo cho implementation."*

---

## 🎓 Nhóm 6: Đánh giá luận văn

### Q15. Đóng góp khoa học của luận văn là gì?

**Trả lời (7 contributions)**:

1. **ML model generalize over evasion variants** tốt hơn Sigma exact-match (Ensemble F1=1.0 vs SVM 0.97 raw)
2. **Cosine Similarity attribution** simple + scalable (top-1 68.8% vs SVM 23.5%)
3. **Multi-Agent SOC orchestration** tự động hóa workflow analyst (~98s vs 5-15 phút)
4. **Explainable ML detection** qua RED Analyst Agent — LLM dịch ML score sang human reasoning với evidence ⭐
5. **Evidence-grounded Sigma patch** qua Forensic Agent + Velociraptor — kháng hallucination ⭐ NEW
6. **Vietnamese-language SOC automation** cho VNCERT compliance
7. **Tactical Sigma patch + Feedback loop** strategy (KHÔNG claim solve evasion)

**Novelty cao nhất**: #4, #5, #6 — không có trong Elastic AI Assistant, Splunk SOAR, Sentinel.

---

### Q16. Em sẽ làm gì tiếp sau khi tốt nghiệp?

**Trả lời (chuẩn bị career)**:

*"Em quan tâm SOC engineering và security ML. Em sẽ:*

- **Open-source pipeline này** trên GitHub → community feedback
- Publish 1 paper short cho hội nghị VN (ATC, FAIR) hoặc international workshop
- Apply security engineer roles tại VN — pipeline này là portfolio mạnh
- Học sâu hơn về adversarial ML + LLM safety nếu có cơ hội master"*

---

## 💡 Mẹo trả lời khi bí

1. **Honest > Bluff** — GVHD ấn tượng với "Em chưa biết, nhưng em sẽ research X" hơn là bịa
2. **Acknowledge limitation trước khi GVHD chỉ ra** — chứng minh em hiểu sâu vấn đề
3. **Future work cụ thể** — không nói "em sẽ improve", nói "em sẽ implement Layer 3 validator với SigmaOptimizer reference, dự kiến X tuần"
4. **Bảng số liệu cụ thể** > nói chung chung — luôn có ít nhất 1 con số trong câu trả lời
5. **Comparison frame** — đặt mọi claim trong context comparison (vs SVM, vs analyst, vs commercial SOAR)
