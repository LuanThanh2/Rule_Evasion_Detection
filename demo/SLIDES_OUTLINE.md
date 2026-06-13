# Slides Outline — Demo RED + AI Agent (15 slides, ~20 phút)

Khung slide để bạn build bằng PowerPoint/Beamer/Marp. Mỗi slide có:
- **Tiêu đề** (top)
- **Nội dung chính** (bullet)
- **Visual** (gợi ý hình ảnh / diagram)
- **Talking time** (mục tiêu)

---

## 🎬 Slide 1 — Title (30s)

**Tiêu đề**:
> Hệ thống phát hiện hành vi né tránh luật + AI Agent Triage  
> Khóa luận tốt nghiệp KLTN — 2026

**Nội dung**:
- Tên: Lương Thành (?)  | MSSV: ___
- GVHD: ___
- Chuyên ngành: An toàn thông tin / Khoa học máy tính

**Visual**: Logo trường + 1 ảnh minh họa pipeline đơn giản

---

## 🎬 Slide 2 — Bài toán (1 phút)

**Tiêu đề**: *Vấn đề: Sigma rule bị né bằng biến thể nhỏ*

**Nội dung**:
- SOC dùng Sigma rules (exact-match) — phổ biến nhất ngành
- Attacker dễ né bằng: shorthand flag, case manipulation, encoding, obfuscation
- Ví dụ: `-EncodedCommand` (Sigma catch) → `-e` (Sigma miss, **vẫn chạy được**)
- SOC analyst overwhelmed: trung bình 5-15 phút/alert, hàng nghìn alerts/ngày

**Visual**: 
```
[Sigma rule: -EncodedCommand]  ← catch
        ↓
   Attacker dùng -e          ← miss, lọt qua
```

---

## 🎬 Slide 3 — Mục tiêu luận văn (45s)

**Tiêu đề**: *Mục tiêu*

**3 mục tiêu**:
1. **Phát hiện** evasion bằng ML (RED model) — không phụ thuộc exact pattern
2. **Quy kết** alert về rule Sigma cụ thể bị né (Stage 2 attribution)
3. **Tự động triage** bằng Multi-Agent AI — giảm gánh nặng analyst

**Visual**: 3 cột tương ứng 3 Phase A/B/C

---

## 🎬 Slide 4 — Kiến trúc tổng thể (1.5 phút)

**Tiêu đề**: *Pipeline 3 lớp: ML → Attribution → AI Agent*

**Visual**: Diagram 3 box ngang

```
┌─────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ Stage 1         │  │ Stage 2          │  │ Phase C ⭐       │
│ Ensemble        │→ │ Cosine           │→ │ 8 Multi-Agent    │
│ SVM+LR+CNB      │  │ Similarity       │  │ + Velociraptor   │
│ Score ∈ [0,1]   │  │ Top-K rules      │  │ Vietnamese report│
└─────────────────┘  └──────────────────┘  └──────────────────┘
   Misuse              Rule Attribution       SOC Triage
   Detection
```

**Nói**: *"Em sẽ demo end-to-end từ Windows VM bị tấn công → ML detect → 8-agent investigate → báo cáo VN."*

---

## 🎬 Slide 5 — Stage 1: Ensemble vượt SVM (1 phút)

**Tiêu đề**: *Stage 1: Ensemble Classifier — 17 FN → 0 FN*

**Bảng**:

| Metric (raw threshold=0) | SVM đơn | **Ensemble** |
|---|---|---|
| Recall | 94.3% | **100%** |
| F1 | 0.9706 | **1.0000** |
| False Negatives | 17 | **0** |

**Insight**: CNB cứu 17 evasion mà SVM bỏ sót.

**Visual**: Bar chart so sánh F1 score

---

## 🎬 Slide 6 — Stage 2: Cosine Attribution (1 phút)

**Tiêu đề**: *Stage 2: Cosine Similarity > SVM cho rule attribution*

**Bảng**:

| Method | Top-1 | Top-3 | Top-5 |
|---|---|---|---|
| SVM | 23.5% | 53.7% | 73.2% |
| **Cosine** | **68.8%** | **92.6%** | **97.3%** |
| Hybrid | 48.7% | 85.9% | 91.9% |

**Giải thích**: SVM underfit (1-15 samples/rule). Cosine trên shared TF-IDF mạnh hơn.

---

## 🎬 Slide 7 — Phase C: Multi-Agent Architecture (1.5 phút)

**Tiêu đề**: *AI Agent — 8 specialized agents*

**Visual**: Architecture diagram (giống README.md)

```
Supervisor → Triage → Forensic ⭐NEW → parallel(Hunt+RED+MITRE) → Response → Report
                       │
                       └─→ Velociraptor (host-level evidence)
```

**Highlight**:
- 🔬 **Forensic Agent** = NEW v2 — query host thật, kháng hallucination
- ⭐ **RED Analyst** = explain WHY this is evasion
- 🛡️ **Response** = sinh Sigma patch grounded by forensic

---

## 🎬 Slide 8 — Forensic Agent (đột phá) (1.5 phút)

**Tiêu đề**: *Forensic Agent — Bằng chứng cứng từ host*

**Vấn đề pipeline cũ**:
- 7-agent chỉ đọc LOG → LLM có thể **bịa Sigma patch**
- Risk: SOC follow patch giả → block IP vô tội

**Giải pháp Forensic Agent**:
1. Query Velociraptor → process tree thật, file hash thật, registry thật
2. Sinh `ForensicOutput` → ground downstream agents
3. Khi không có evidence → trả `inconclusive`, **không bịa**

**Demonstrated**: alert giả PID=0 → scan 166 process thật → verdict `inconclusive`

**Visual**: Side-by-side comparison "Without Forensic (hallucinated)" vs "With Forensic (grounded)"

---

## 🎬 Slide 9 — DEMO LIVE (1 phút intro + 7 phút demo)

**Tiêu đề**: *Demo trực tiếp — Kịch bản APT*

**Setup** (slide tĩnh, switch sang màn hình demo sau):
- Mục tiêu APT giả định: đánh cắp báo cáo Q1
- Nạn nhân: Alice (kế toán) — VM `DESKTOP-2UQB61H`
- Kill-chain: Phishing → PS encoded `-e` → Discovery → Drop binary → Persistence → Fake C2

**Switch sang màn hình thực tế** — chạy script `apt_demo_scenario.ps1` trên Windows VM

**Theo dõi**:
- Kibana red-alerts populate
- Agent daemon log streaming
- Velociraptor GUI hiện flow

---

## 🎬 Slide 10 — Kết quả demo (3 phút trên màn hình thực)

**Khi quay lại slide sau demo**:

**Visual**: Screenshot báo cáo Vietnamese từ Report Agent + Sigma patch YAML

**Số liệu**:
- Thời gian: ~210s (real Velociraptor)
- Tokens: ~67k
- Cost: ~$0.018
- Forensic artifacts: N (process + file + registry + network)
- Verdict: confirmed_malicious

---

## 🎬 Slide 11 — So sánh có/không Forensic (1.5 phút)

**Tiêu đề**: *Kháng hallucination — measurable*

**Bảng**:

| Test case | Without Forensic | With Forensic |
|---|---|---|
| Alert PID thật (process alive) | Sigma patch generic | **Patch tham chiếu file path thật** |
| Alert giả PID=0 (Idle Process) | LLM bịa evidence | **`verdict: inconclusive`** ✅ |
| Latency | ~70s | ~210s (+140s) |
| Cost | $0.015 | $0.018 (+$0.003) |
| Sigma patch quality | unmeasurable | grounded by real artifacts |

**Trade-off**: +3× latency, +20% cost, đổi lại **defensible against hallucination claim**.

---

## 🎬 Slide 12 — Đóng góp khoa học (1.5 phút)

**Tiêu đề**: *Đóng góp luận văn*

**7 contributions**:
1. ML model generalize over evasion variants (Ensemble F1=1.0 vs SVM 0.97)
2. Cosine attribution simple + scalable (top-1 68.8%)
3. Multi-Agent SOC orchestration (~98s vs analyst 5-15 phút)
4. **Explainable ML** qua RED Analyst Agent (LLM dịch ML → human reasoning) ⭐
5. **Evidence-grounded Sigma patch** qua Forensic Agent (kháng hallucination) ⭐ NEW
6. **Vietnamese-language SOC automation** cho VNCERT compliance
7. Tactical patch + Feedback loop (KHÔNG claim solve evasion)

**Novelty cao nhất**: #4, #5, #6 — không có trong commercial tools.

---

## 🎬 Slide 13 — Limitation honest (1 phút)

**Tiêu đề**: *Hạn chế (em thừa nhận)*

**5 limitation**:
1. **Latency 210s** không real-time → acceptable cho triage tier, không phải defense
2. **Sigma patch là tactical band-aid** → KHÔNG silver bullet, vẫn cần ML + retrain
3. **Phụ thuộc Velociraptor agent installed** → không cover endpoint chưa cài
4. **Chưa labeled dataset 100-200 alerts** → accuracy formal chưa đo được
5. **Phụ thuộc LLM cloud (DeepSeek)** → data sovereignty concern, future local LLM

**Tại sao thừa nhận**: Honest framing > over-claim. GVHD sẽ ấn tượng.

---

## 🎬 Slide 14 — Future work (45s)

**Tiêu đề**: *Hướng phát triển*

**5 hướng chính** (theo priority):
1. **Layer 3 Sigma patch validator** — YAML parse + test trên evasion/benign → reject invalid (1-2 tuần)
2. **Labeled dataset 100-200 alerts** — Hayabusa baseline → ground truth (2-3 tuần)
3. **Local LLM option** — Foundation-Sec-8B hoặc Qwen-32B qua Ollama (3-4 tuần)
4. **Statistical rigor** — Bootstrap CI, McNemar's test cho Ensemble vs SVM
5. **Production hardening** — FastAPI server, React dashboard, audit log, RBAC

---

## 🎬 Slide 15 — Q&A (mở)

**Tiêu đề**: *Câu hỏi & Thảo luận*

**Visual**: Thank you + email + GitHub link

**Backup slides** sẵn sàng nếu GVHD hỏi sâu:
- Backup 1: VQL queries cụ thể
- Backup 2: Code structure agent/ module
- Backup 3: Velociraptor lab setup diagram
- Backup 4: Cost calculation detail
- Backup 5: Hayabusa data pipeline

---

## 📋 Tips trình bày

| Mục | Khuyến nghị |
|---|---|
| **Trang phục** | Sơ mi + quần dài, không cần vest |
| **Thiết bị** | Mang laptop riêng + cable HDMI/USB-C → tránh dependency phòng họp |
| **Backup** | Demo video 3 phút lưu USB → fallback nếu live demo fail |
| **Slide format** | 16:9, font Inter/Roboto 24pt+, contrast cao |
| **Animation** | Tối thiểu — chỉ "Appear" cho bullet, không transition fancy |
| **Code on slide** | Font Cascadia Code/JetBrains Mono 18pt+, syntax highlight |
| **Demo backup** | Pre-recorded screencast 3 phút trong case |

## 🕐 Timing tổng

| Slides | Thời gian | Cộng dồn |
|---|---|---|
| 1-4 (Intro + Architecture) | ~4 phút | 4' |
| 5-8 (Stage 1+2+Agent+Forensic) | ~5 phút | 9' |
| 9-11 (DEMO LIVE) | ~8-10 phút | 17-19' |
| 12-14 (Contribution + Limit + Future) | ~3 phút | 20-22' |
| 15 (Q&A) | ~5-10 phút | 25-30' |

→ **Tổng: 25-30 phút bao gồm Q&A**. Phù hợp KLTN defense slot 30-45 phút.

## ⚠️ Pre-defense checklist (3 ngày trước)

- [ ] Rehearsal full timing 2 lần (đo bằng đồng hồ)
- [ ] Print 3 bản slide + 3 bản đề cương cho hội đồng
- [ ] Test live demo TỪ ĐẦU đến CUỐI 1 lần ngay tại phòng defense (nếu có thể)
- [ ] Backup screencast 3 phút (mp4, không cần internet)
- [ ] USB lưu: slides + screencast + báo cáo PDF
- [ ] Internet check: DeepSeek API reachable? Velociraptor port mở?
- [ ] Print bảng Q&A bank (`QA_PREP.md`) — không show GVHD, chỉ cho mình
