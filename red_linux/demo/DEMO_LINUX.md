# RED-Linux Demo — Sigma Fire vs Sigma Miss vs RED Catch (lệnh tấn công THẬT)

> Bản demo cho nhánh **Linux/auditd** (song song `demo/apt_demo_v2.md` của Windows). Dùng
> **lệnh tấn công thật từ Atomic Red Team** (ATT&CK): mỗi phase là một lệnh ART **đang fire
> một Sigma Linux rule**; khi đổi cách biểu diễn lệnh (cấp argv) thì **Sigma miss**, nhưng
> **RED-Linux ML (model production đã sửa lỗi) vẫn bắt**.
>
> Chạy **offline** bằng một script: `auditd → Zircolite (Sigma) → RED Stage 1/Stage 2`. Không
> cần network/endpoint. Mọi cặp lệnh **verify bằng Zircolite** (baseline fire, evasion không).

---

## 0. Tóm tắt 30 giây

| | Sigma (Zircolite) | RED-Linux (model fix) |
|---|:--:|:--:|
| **benign** = lệnh hệ thống bình thường | — | **0.8% cờ** (không vu oan) ✅ |
| **baseline** = lệnh ART tấn công thật | **6/6 FIRE** | bắt (score cao) |
| **evasion** = đổi representation (curl→wget, busybox, relative path) | **6/6 MISS** | **bắt 6/6** |

**Thông điệp 1 câu**: benign sạch (FP 0.8%); Sigma fire baseline nhưng miss khi attacker đổi
cách viết; RED-Linux ML vẫn bắt **toàn bộ 6/6** evasion và quy về Sigma rule họ hàng.

---

## 1. Kiến trúc demo (offline)

```
   Lệnh ART (baseline tấn công)  ──transform──►  evasion
              │                                     │
   ┌──────────┼─────────────────────────────────────┼──────────┐
   ▼          ▼                                     ▼          ▼
[Zircolite] [RED]                              [Zircolite]  [RED]
 FIRE rule   score cao                          MISS rule    vẫn cao  + Stage2 attribute
```

| Thành phần | Vị trí |
|---|---|
| Engine Sigma | Zircolite `~/tools/Zircolite` + SigmaHQ Linux rules `…/sigma/rules/linux/` |
| Lệnh ART fire Sigma | `…/red_linux/benign/process_creation/atomic_fired.jsonl` (190 lệnh) |
| Transform evasion | `linux_evasion_generate.TRANSFORMS` (tool_swap, busybox, relative_path…) |
| Model RED **đã fix** | `models/linux_atomic/train_rslt_ensemble_atomic.zip` (Ensemble, `normalize_benign`) |
| Driver demo | `red_linux/scripts/demo_linux_art.py` |

> **Model đã sửa lỗi tiền xử lý** (`normalize_benign`): trước đây benign không được chuẩn hoá
> → model ăn gian → khi deploy thật 84% benign bị cờ. Sau fix: test F1=0.833, deploy chỉ 0.65%
> benign bị cờ. Xem RESULT_LINUX_COMBINED §3.4.

---

## 2. Demo story (cho hội đồng)

1. **Sigma exact-match rất tốt** khi lệnh đúng khuôn (baseline ART → 6/6 fire).
2. **Attacker chỉ đổi cách viết** (giữ nguyên ý đồ) là rule miss:
   - `curl` → `wget` (tool_swap)
   - `cat /etc/passwd` → `busybox cat /etc/passwd` (LOLBin: exe=busybox)
   - `find /…` → `busybox find /…`
   - `> /etc/cron.daily/x` → `> cron.daily/x` (relative path, bỏ tiền tố `/etc/`)
   - script `/tmp/art.sh` → `art.sh` (relative path)
3. **RED-Linux ML** (học từ chính ART) bắt được cả baseline lẫn evasion, rồi Stage 2 quy về
   Sigma rule họ hàng để analyst có context.

> Demo **không** chạy malware thật — mọi lệnh là command-line ATT&CK có kiểm soát, dựng thành
> sự kiện auditd cho Zircolite chấm.

---

## 3. Phase mapping (6 phase — lệnh ART thật → Sigma rule)

| Phase | Sigma rule (bị né) | Kỹ thuật ATT&CK | Evasion |
|---:|---|---|---|
| 1 | Potential Suspicious Change To Sensitive/Critical Files | Persistence qua cron (`/etc/cron.daily/`) | `relative_path` (bỏ `/etc/`) |
| 2 | Curl Usage on Linux | Tải payload (T1059.004) | `tool_swap` curl→wget |
| 3 | Local System Accounts Discovery | Dump `/etc/passwd` (T1003.008) | `busybox_applet` |
| 4 | Execution Of Script In Suspicious Directory | Chạy script `/tmp/art.sh` | `relative_path` |
| 5 | Print History File Contents | Xoá `~/.bash_history` (T1070) | `busybox_applet` |
| 6 | File and Directory Discovery | Tìm `places.sqlite` Firefox (T1217) | `busybox_applet` |

---

## 4. Preflight

```bash
cd /home/luanthanh/KLTN/KLTN/Rule_Evasion_Detection_2/Rule_Evasion_Detection
VENV=~/venvs/rule_evasion_env

ls $VENV/bin/python ~/tools/Zircolite/zircolite.py                    # Zircolite
ls models/linux_atomic/train_rslt_ensemble_atomic.zip                 # model đã fix
ls /home/luanthanh/data/red_linux/benign/process_creation/atomic_fired.jsonl   # lệnh ART fire
```

Nếu thiếu `atomic_fired.jsonl`: chạy `atomic_zircolite.py` (xem [../README.md](../README.md) §7).
Nếu thiếu model: chạy mục "Model PRODUCTION" trong README §7.

---

## 5. Chạy demo (một lệnh)

```bash
$VENV/bin/python red_linux/scripts/demo_linux_art.py
# tuỳ chọn: --threshold 0.42 (T* model fix) | --n-phases 6
```

Driver tự động: lấy lệnh ART fire Sigma → áp mọi transform → Zircolite xác nhận luật hết fire
→ RED chấm điểm + attribute → in bảng, lưu `reports/linux/demo_art_result.md`.

---

## 6. Kết quả (verified, model đã fix, T\*=0.42)

| # | Sigma rule (bị né) | Kỹ thuật | RED baseline | RED evasion | RED bắt? | Stage 2 |
|--:|---|---|:--:|:--:|:--:|:--:|
| 1 | Suspicious Change To Sensitive/Critical Files | `relative_path` | 0.712 | 0.742 | ✅ | top-1 |
| 2 | Curl Usage on Linux | `tool_swap` | 0.708 | 0.664 | ✅ | top-67 |
| 3 | Local System Accounts Discovery | `busybox_applet` | 0.608 | 0.663 | ✅ | top-1 |
| 4 | Execution Of Script In Suspicious Directory | `relative_path` | 0.691 | 0.656 | ✅ | top-13 |
| 5 | Print History File Contents | `busybox_applet` | 0.594 | 0.651 | ✅ | top-3 |
| 6 | File and Directory Discovery | `busybox_applet` | 0.588 | 0.643 | ✅ | top-1 |

**Tổng**: baseline **Sigma fire 6/6** · evasion **Sigma né 6/6** · **RED bắt 6/6** evasion ·
Stage 2 rule gốc ∈ **top-5: 4/6**.

**Talk track:**
> "6 lệnh này là tấn công thật từ Atomic Red Team — tải payload, dump /etc/passwd, cài cron
> persistence, xoá history. Cả 6 đều khiến Sigma fire. Nhưng chỉ cần đổi cách viết — curl
> thành wget, gọi qua busybox, bỏ tiền tố đường dẫn — **cả 6 rule đều miss**. RED-Linux ML
> vẫn bắt **toàn bộ 6/6**, và quy đúng rule gốc vào top-5 ở 4/6 ca."

---

## 6b. Benign sanity — RED có vu oan benign không?

Demo tấn công chưa đủ; phải chứng minh RED **không cờ bừa** lệnh bình thường. Chạy:

```bash
$VENV/bin/python red_linux/scripts/benign_sanity.py
```

Kết quả (model đã fix, mô phỏng đúng `detect_batch` — chuẩn hoá mọi lệnh):

| Model | Benign (2633 lệnh thật) bị cờ | Điểm benign TB |
|---|:--:|:--:|
| **Đã fix (`normalize_benign`)** | **0.65%** (17) ✅ | 0.223 |
| Cũ (`*.PRE_NORMFIX.zip`, có bug) | **83.7%** (2204) ❌ | 0.597 |

→ Model fix tách rõ: **benign tụ ~0.22**, tấn công ART ~0.45+. FP thật chỉ **0.65%**. Bản cũ
(lỗi tiền xử lý) cờ 84% benign khi deploy — minh hoạ trực tiếp vì sao phải fix (xem
RESULT_LINUX_COMBINED §3.4).

Ví dụ benign điểm thấp (không cờ): `ps -p 129` (0.12) · `mkdir -p /var/tmp/...` (0.14) ·
`cp -pP /lib/modules/...` (0.18) · `mv -f apt.extended_states...` (0.30).

---

## 7. Hạn chế (nói thẳng)

- **Stage 2 origin∈top-5 = 4/6**: hai ca trượt là `curl→wget` (top-67) — tool_swap **xoá sạch
  token** `curl` mà rule dựa vào → cosine không bắc cầu được; và một ca relative_path (top-13).
  Đây là giới hạn token-similarity → động lực **Layer-3 Sigma-logic validator** (cosine lọc
  top-10 đạt 90%, Sigma-logic chốt top-1 ~90%). Xem RESULT_LINUX_COMBINED §5.1.
- **Evasion là transform cấp argv** (curl→wget, busybox, relative). Né **thật** (auditd ghi
  argv sau shell-expand), không phải mẹo che chuỗi kiểu `cu''rl`.
- Demo dùng lệnh ART tĩnh; ART thật trên VM (auditd EXECVE) là bước nâng cấp (cần sudo).

---

## 8. Troubleshooting

| Triệu chứng | Cách xử lý |
|---|---|
| `atomic_fired.jsonl` thiếu | Chạy `red_linux/scripts/atomic_zircolite.py` |
| Model load lỗi | Train model fix: README §7 "Model PRODUCTION" (config có `normalize_benign: true`) |
| RED score thấp bất thường / benign bị cờ nhiều | Đảm bảo dùng model **đã fix** (không phải `*.PRE_NORMFIX.zip`) |
| Zircolite không ra detection | Kiểm tra `~/tools/Zircolite` + `…/sigma/rules/linux/process_creation` |
| 0 phase tìm được | Threshold quá cao → giảm `--threshold`, hoặc `atomic_fired.jsonl` rỗng |

---

## 9. Ghi chú: 2 driver demo

| Script | Dùng lệnh | Khi nào |
|---|---|---|
| **`demo_linux_art.py`** ⭐ | **lệnh tấn công ART thật** | **Khuyến nghị** — thuyết phục, nhất quán model fix |
| `demo_linux.py` | cặp evasion từ dataset Sigma (admin-flavored) | Đối chiếu/phụ — minh hoạ nhiễm nhãn V1 (model fix xử lý đúng: không cờ mạnh lệnh admin) |

---

## 10. Liên kết

- Tổng quan + kết quả: [../README.md](../README.md)
- Báo cáo Chương 5 (Linux): [../RESULT_LINUX_COMBINED.md](../RESULT_LINUX_COMBINED.md)
- Demo Windows (đối chiếu): [../../demo/apt_demo_v2.md](../../demo/apt_demo_v2.md)
