# RED-Linux — Demo trên lệnh tấn công THẬT (Atomic Red Team)

> `demo_linux_art.py` (T\*=0.42, model production đã fix). Lệnh ART fire Sigma → transform evasion cấp argv → Zircolite xác nhận luật hết fire → RED vẫn bắt.


| # | Sigma rule (bị né) | Kỹ thuật | RED baseline | RED evasion | RED bắt? | Stage2 origin |
|--:|---|---|:--:|:--:|:--:|:--:|
| 1 | Potential Suspicious Change To Sensitive/Critical Files | `relative_path` | 0.729 | 0.760 | ✅ | top-1 |
| 2 | File or Folder Permissions Change | `busybox_applet` | 0.643 | 0.701 | ✅ | — |
| 3 | Execution Of Script Located In Potentially Suspicious Directory | `relative_path` | 0.734 | 0.700 | ✅ | top-13 |
| 4 | Local System Accounts Discovery - Linux | `busybox_applet` | 0.634 | 0.695 | ✅ | top-1 |
| 5 | Print History File Contents | `busybox_applet` | 0.625 | 0.688 | ✅ | top-3 |
| 6 | Chmod Suspicious Directory | `busybox_applet` | 0.614 | 0.676 | ✅ | top-12 |

**Tổng kết:** 6 lệnh ART tấn công — baseline **fire Sigma**, sau evasion **Sigma né hết**, **RED bắt 6/6** evasion; Stage 2 rule gốc ∈ top-5: 3/6.


## Chi tiết lệnh


**Phase 1** — rule *Potential Suspicious Change To Sensitive/Critical Files* (`relative_path`)
- baseline (Sigma FIRE, RED 0.729): `echo "echo '*/5     *       *       *       *       root    echo "Hello from Atomic Red Team"' > /tmp/atomic.log" > /etc/cron.d/persistevil`
- evasion  (Sigma MISS, RED 0.760): `echo "echo '*/5     *       *       *       *       root    echo "Hello from Atomic Red Team"' > atomic.log" > cron.d/persistevil`

**Phase 2** — rule *File or Folder Permissions Change* (`busybox_applet`)
- baseline (Sigma FIRE, RED 0.643): `chown -R root /tmp/AtomicRedTeam/atomics/T1222.002`
- evasion  (Sigma MISS, RED 0.701): `busybox chown -R root /tmp/AtomicRedTeam/atomics/T1222.002`

**Phase 3** — rule *Execution Of Script Located In Potentially Suspicious Directory* (`relative_path`)
- baseline (Sigma FIRE, RED 0.734): `sh -c "echo 'echo Hello from the Atomic Red Team' > /tmp/art.sh"`
- evasion  (Sigma MISS, RED 0.700): `sh -c "echo 'echo Hello from the Atomic Red Team' > art.sh"`

**Phase 4** — rule *Local System Accounts Discovery - Linux* (`busybox_applet`)
- baseline (Sigma FIRE, RED 0.634): `cat /etc/passwd > /tmp/T1003.008.txt`
- evasion  (Sigma MISS, RED 0.695): `busybox cat /etc/passwd > /tmp/T1003.008.txt`

**Phase 5** — rule *Print History File Contents* (`busybox_applet`)
- baseline (Sigma FIRE, RED 0.625): `cat /dev/null > ~/.bash_history`
- evasion  (Sigma MISS, RED 0.688): `busybox cat /dev/null > ~/.bash_history`

**Phase 6** — rule *Chmod Suspicious Directory* (`busybox_applet`)
- baseline (Sigma FIRE, RED 0.614): `chmod -R a+w /tmp/AtomicRedTeam/atomics/T1222.002`
- evasion  (Sigma MISS, RED 0.676): `busybox chmod -R a+w /tmp/AtomicRedTeam/atomics/T1222.002`