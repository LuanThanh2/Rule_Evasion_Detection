# RED-Linux — Kết quả Demo (Sigma vs RED)

> Sinh bởi `demo_linux.py --mode all` (T\*=0.42). Zircolite = engine Sigma thật; RED = model production `models/linux_atomic`.


## Mode `benign` — lệnh quản trị read-only → kỳ vọng Sigma 0 fire, RED không cờ (sanity check)

| Phase | Kỹ thuật | Sigma rule | Sigma | RED score | RED cờ? |
|---|---|---|:--:|:--:|:--:|
| 1. curl upload → wget | `tool_swap` | Suspicious Curl File Upload - Linux | — | 0.455 | ✅ |
| 2. systemctl stop → mask | `alt_subcommand` | Disable Or Stop Services | — | 0.510 | ✅ |
| 3. chmod thư mục hệ thống → busybox | `busybox_applet` | Chmod Suspicious Directory | — | 0.459 | ✅ |
| 4. chmod thư mục hệ thống → relative | `relative_path` | Chmod Suspicious Directory | — | 0.323 | ❌ |
| 5. useradd → adduser | `tool_swap` | Creation Of An User Account | — | 0.456 | ✅ |

**Tổng kết benign:** Sigma fire **0/5** (kỳ vọng 0); RED cờ **4/5** → kiểm chứng RED không cờ bừa.


## Mode `baseline` — lệnh canonical Sigma biết → kỳ vọng Sigma FIRE

| Phase | Kỹ thuật | Sigma rule | Sigma | RED score | RED cờ? |
|---|---|---|:--:|:--:|:--:|
| 1. curl upload → wget | `tool_swap` | Suspicious Curl File Upload - Linux | 🔴 FIRE | 0.410 | ❌ |
| 2. systemctl stop → mask | `alt_subcommand` | Disable Or Stop Services | 🔴 FIRE | 0.432 | ✅ |
| 3. chmod thư mục hệ thống → busybox | `busybox_applet` | Chmod Suspicious Directory | 🔴 FIRE | 0.348 | ❌ |
| 4. chmod thư mục hệ thống → relative | `relative_path` | Chmod Suspicious Directory | 🔴 FIRE | 0.348 | ❌ |
| 5. useradd → adduser | `tool_swap` | Creation Of An User Account | 🔴 FIRE | 0.492 | ✅ |

**Tổng kết baseline:** Sigma **FIRE 5/5** — chữ ký hoạt động tốt khi lệnh đúng khuôn.


## Mode `evasion` — đổi representation cấp argv → kỳ vọng Sigma MISS nhưng RED catch

| Phase | Kỹ thuật | Sigma rule | Sigma | RED score | RED cờ? | Stage2 origin-rank |
|---|---|---|:--:|:--:|:--:|:--:|
| 1. curl upload → wget | `tool_swap` | Suspicious Curl File Upload - Linux | 🟢 MISS | 0.409 | ❌ | top-121 |
| 2. systemctl stop → mask | `alt_subcommand` | Disable Or Stop Services | 🟢 MISS | 0.413 | ❌ | top-4 |
| 3. chmod thư mục hệ thống → busybox | `busybox_applet` | Chmod Suspicious Directory | 🟢 MISS | 0.450 | ✅ | top-2 |
| 4. chmod thư mục hệ thống → relative | `relative_path` | Chmod Suspicious Directory | 🟢 MISS | 0.374 | ❌ | top-2 |
| 5. useradd → adduser | `tool_swap` | Creation Of An User Account | 🟢 MISS | 0.405 | ❌ | — |

**Tổng kết evasion:** Sigma **né 5/5** rule mục tiêu; **RED Stage 1 bắt 1/5**; Stage 2 rule gốc ∈ **top-5: 3/5**.


> Stage 2 quy về rule gốc khó vì evasion **cố tình xoá token chữ ký** của chính rule đó (top-1 có thể là rule họ hàng) → giới hạn token-similarity, động lực Layer-3 Sigma-logic validator.


## Phụ lục — lệnh mỗi phase


**1. curl upload → wget** → rule *Suspicious Curl File Upload - Linux* (`tool_swap`)
- benign  : `curl -s -o /tmp/index.html https://example.com`
- baseline: `curl -i -s -k -X POST -H User-Agent: python-requests/2.28.2 -H Accept-Encoding: gzip, deflate, `
- evasion : `wget -i -s -k -X POST -H User-Agent: python-requests/2.28.2 -H Accept-Encoding: gzip, deflate, `

**2. systemctl stop → mask** → rule *Disable Or Stop Services* (`alt_subcommand`)
- benign  : `systemctl status snapd.service`
- baseline: `systemctl stop snap-snapd-20092.mount`
- evasion : `systemctl mask snap-snapd-20092.mount`

**3. chmod thư mục hệ thống → busybox** → rule *Chmod Suspicious Directory* (`busybox_applet`)
- benign  : `ls -la /var/tmp`
- baseline: `chmod 755 /var/tmp/mkinitramfs_e2XAqT`
- evasion : `busybox chmod 755 /var/tmp/mkinitramfs_e2XAqT`

**4. chmod thư mục hệ thống → relative** → rule *Chmod Suspicious Directory* (`relative_path`)
- benign  : `stat /var/tmp`
- baseline: `chmod 755 /var/tmp/mkinitramfs_e2XAqT`
- evasion : `chmod 755 mkinitramfs_e2XAqT`

**5. useradd → adduser** → rule *Creation Of An User Account* (`tool_swap`)
- benign  : `getent passwd root`
- baseline: `useradd -D`
- evasion : `adduser -D`