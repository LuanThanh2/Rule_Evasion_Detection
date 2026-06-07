<#
.SYNOPSIS
    APT demo v2 - six phases mapped to six Sigma target rules.

.DESCRIPTION
    Modes:
      benign   - normal read-only activity
      baseline - one event per phase should match the target Sigma rule
      evasion  - same intent, changed representation so target Sigma rule misses

    Design note:
      The parent file intentionally avoids target ps_script literals. Baseline
      ps_script phases generate a short child script at runtime so only the child
      ScriptBlock contains the exact target text.

.PARAMETER Mode
    benign | baseline | evasion

.PARAMETER Phase
    0 = all phases, 1-6 = one phase only.

.PARAMETER RunId
    8-char marker used to find events and alerts.

.PARAMETER SleepSeconds
    Pause between phases.

.PARAMETER CleanupDelaySeconds
    Delay before async cleanup of registry artifacts.

.PARAMETER KeepArtifacts
    Do not start the async cleanup job.

.PARAMETER DryRun
    Print phase flow without executing actions.
#>

param(
    [ValidateSet('benign','baseline','evasion')]
    [string]$Mode = 'baseline',

    [ValidateRange(0,6)]
    [int]$Phase = 0,

    [string]$RunId = ([guid]::NewGuid().ToString('N').Substring(0,8)),

    [int]$SleepSeconds = 2,

    [int]$CleanupDelaySeconds = 60,

    [switch]$KeepArtifacts,

    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'
$Marker = "RED_DEMO_V2_${RunId}"
$TempScripts = New-Object System.Collections.Generic.List[string]

$RuleMap = @(
    [pscustomobject]@{ Phase = 1; Event = 'ps_script'; RuleId = '189e3b02-82b2-4b90-9662-411eb64486d4' },
    [pscustomobject]@{ Phase = 2; Event = 'process_creation'; RuleId = 'cc36992a-4671-4f21-a91d-6c2b72a2edf5' },
    [pscustomobject]@{ Phase = 3; Event = 'process_creation'; RuleId = '85b0b087-eddf-4a2b-b033-d771fa2b9775' },
    [pscustomobject]@{ Phase = 4; Event = 'process_creation'; RuleId = 'b98d0db6-511d-45de-ad02-e82a98729620' },
    [pscustomobject]@{ Phase = 5; Event = 'process_creation'; RuleId = '24357373-078f-44ed-9ac4-6d334a668a11' },
    [pscustomobject]@{ Phase = 6; Event = 'process_creation'; RuleId = 'e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a' }
)

function Join-Ascii {
    param([int[]]$Codes)
    return -join ($Codes | ForEach-Object { [char]$_ })
}

function Should-RunPhase {
    param([int]$ThisPhase)
    return ($Phase -eq 0 -or $Phase -eq $ThisPhase)
}

function Write-Phase {
    param([int]$Number, [string]$Name)
    $rule = $RuleMap | Where-Object { $_.Phase -eq $Number } | Select-Object -First 1
    Write-Host ""
    Write-Host ("[Phase {0}/6] {1}" -f $Number, $Name) -ForegroundColor Cyan
    Write-Host ("  Target: {0} | {1}" -f $rule.RuleId, $rule.Event) -ForegroundColor DarkCyan
}

function Write-Action {
    param([string]$Message)
    Write-Host ("  -> {0}" -f $Message) -ForegroundColor Yellow
}

function Invoke-Step {
    param([scriptblock]$Block)
    if ($DryRun) {
        Write-Host "     [DryRun] skipped" -ForegroundColor DarkYellow
        return
    }
    try {
        & $Block
    } catch {
        Write-Host ("     WARN: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
}

function New-ChildScript {
    param([int]$ForPhase, [string]$Body)
    $path = Join-Path $env:TEMP ("red_v2_p{0}_{1}.ps1" -f $ForPhase, $RunId)
    $header = "Write-Host 'RED_DEMO_V2_PHASE{0}_{1}'" -f $ForPhase, $RunId
    Set-Content -Path $path -Encoding ASCII -Value ($header + [Environment]::NewLine + $Body)
    [void]$TempScripts.Add($path)
    return $path
}

function Invoke-ChildFile {
    param([string]$Path)
    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File', $Path) `
        -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
}

function Invoke-ChildCommand {
    param([string]$Command)
    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command', $Command) `
        -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
}

function Invoke-ChildEncoded {
    param([string]$Code)
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Code)
    $encoded = [Convert]::ToBase64String($bytes)
    $encodedFlag = Join-Ascii @(45,69,110,99,111,100,101,100,67,111,109,109,97,110,100)
    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass', $encodedFlag, $encoded) `
        -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
}

function Remove-TempScripts {
    foreach ($path in $TempScripts) {
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "==============================================================="
Write-Host ("  APT Demo v2 | Mode: {0} | Phase: {1} | RunId: {2}" -f $Mode, $(if ($Phase -eq 0) { 'all' } else { $Phase }), $RunId)
Write-Host "==============================================================="
if ($DryRun) { Write-Host "  DRY RUN" -ForegroundColor DarkYellow }

# Phase 1 - credential-tool marker, ps_script rule.
if (Should-RunPhase 1) {
    Write-Phase 1 'Credential access marker'
    if ($Mode -eq 'benign') {
        Write-Action 'Read local user list only'
        Invoke-Step { Get-LocalUser -ErrorAction SilentlyContinue | Select-Object -First 3 | Out-Null }
    } elseif ($Mode -eq 'baseline') {
        Write-Action 'Baseline child ScriptBlock contains selection_1 markers'
        Invoke-Step {
            $a = Join-Ascii @(68,117,109,112,67,114,101,100,115)
            $b = Join-Ascii @(68,117,109,112,67,101,114,116,115)
            $body = "`$m = '$a $b'; Write-Host '$Marker phase1 baseline length:' `$m.Length"
            $path = New-ChildScript -ForPhase 1 -Body $body
            Invoke-ChildFile -Path $path
        }
    } else {
        Write-Action 'Evasion uses numeric reconstruction and emits only hashes'
        Invoke-Step {
            $code = @"
Write-Host 'RED_DEMO_V2_PHASE1_$RunId'
`$a = @(68,117,109,112,67,114,101,100,115)
`$b = @(68,117,109,112,67,101,114,116,115)
`$x = -join (`$a | ForEach-Object { [char]`$_ })
`$y = -join (`$b | ForEach-Object { [char]`$_ })
Write-Host 'phase1 evasion hashes:' `$x.GetHashCode() `$y.GetHashCode()
"@
            Invoke-ChildEncoded -Code $code
        }
    }
    Start-Sleep -Seconds $SleepSeconds
}

# Phase 2 - log cleanup process rule.
if (Should-RunPhase 2) {
    Write-Phase 2 'Log cleanup marker'
    if ($Mode -eq 'benign') {
        Write-Action 'List log channels only'
        Invoke-Step {
            Start-Process -FilePath 'wevtutil.exe' `
                -ArgumentList @('gl', 'Application') `
                -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        }
    } elseif ($Mode -eq 'baseline') {
        Write-Action 'Baseline invokes log utility clear verb against nonexistent log'
        Invoke-Step {
            Start-Process -FilePath 'wevtutil.exe' `
                -ArgumentList @('cl', "RED_DEMO_V2_NONEXISTENT_$RunId") `
                -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        }
    } else {
        Write-Action 'Evasion uses split tokens and emits only a hash'
        Invoke-Step {
            $code = @"
Write-Host 'RED_DEMO_V2_PHASE2_$RunId'
`$p1 = 'Cl' + 'ear'
`$p2 = '-Ev' + 'ent'
`$p3 = 'Lo' + 'g'
`$x = `$p1 + `$p2 + `$p3
Write-Host 'phase2 evasion hash:' `$x.GetHashCode()
"@
            Invoke-ChildEncoded -Code $code
        }
    }
    Start-Sleep -Seconds $SleepSeconds
}

# Phase 3 - process command line download/execute cradle.
if (Should-RunPhase 3) {
    Write-Phase 3 'PowerShell child process cradle'
    $scheme = Join-Ascii @(104,116,116,112,58,47,47)
    $url = "${scheme}127.0.0.1:1/$Marker"
    if ($Mode -eq 'benign') {
        Write-Action 'Child process performs a simple web request without execution'
        Invoke-Step {
            $web = Join-Ascii @(73,110,118,111,107,101,45,87,101,98,82,101,113,117,101,115,116,32)
            $cmd = "${web}-Uri '$url' -UseBasicParsing -TimeoutSec 1 -ErrorAction SilentlyContinue | Out-Null"
            Invoke-ChildCommand -Command $cmd
        }
    } elseif ($Mode -eq 'baseline') {
        Write-Action 'Baseline child process command line has both target selections'
        Invoke-Step {
            $fetch = Join-Ascii @(105,119,114,32)
            $run = Join-Ascii @(124,32,105,101,120,32)
            $cmd = "${fetch}-Uri '$url' -UseBasicParsing -TimeoutSec 1 -ErrorAction SilentlyContinue $run"
            Invoke-ChildCommand -Command $cmd
        }
    } else {
        Write-Action 'Evasion swaps to curl utility so PowerShell cradle target misses'
        Invoke-Step {
            Start-Process -FilePath 'curl.exe' `
                -ArgumentList @('--max-time','1','-o','NUL', $url) `
                -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds $SleepSeconds
}

# Phase 4 - hta utility process rule.
if (Should-RunPhase 4) {
    Write-Phase 4 'Mshta remote-vs-inline'
    $htaExe = Join-Ascii @(109,115,104,116,97,46,101,120,101)
    $htaName = Join-Ascii @(109,115,104,116,97)
    if ($Mode -eq 'benign') {
        Write-Action 'Check utility path only'
        Invoke-Step { Test-Path (Join-Path "$env:SystemRoot\System32" $htaExe) | Out-Null }
    } elseif ($Mode -eq 'baseline') {
        Write-Action 'Baseline starts hta utility with remote-style URL'
        Invoke-Step {
            $scheme = Join-Ascii @(104,116,116,112,58,47,47)
            $arg = "${scheme}127.0.0.1:1/$Marker.hta"
            $p = Start-Process -FilePath $htaExe -ArgumentList $arg -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
            Get-Process $htaName -ErrorAction SilentlyContinue | Where-Object { $_.StartTime -gt (Get-Date).AddMinutes(-2) } | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Action 'Evasion starts hta utility with inline script scheme, no remote URL token'
        Invoke-Step {
            $arg = (Join-Ascii @(106,97,118,97,115,99,114,105,112,116,58)) + 'close()'
            $p = Start-Process -FilePath $htaExe -ArgumentList $arg -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
            Get-Process $htaName -ErrorAction SilentlyContinue | Where-Object { $_.StartTime -gt (Get-Date).AddMinutes(-2) } | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds $SleepSeconds
}

# Phase 5 - direct autorun registry modification process rule.
if (Should-RunPhase 5) {
    Write-Phase 5 'Registry persistence marker'
    $runKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    $bypassKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    $valueName = "RED_DEMO_V2_${RunId}"
    $dummyExe = "C:\Users\Public\xkj9_demo_v2_${RunId}.exe"

    if ($Mode -eq 'benign') {
        Write-Action 'Read an Explorer registry key only'
        Invoke-Step { Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction SilentlyContinue | Out-Null }
    } elseif ($Mode -eq 'baseline') {
        Write-Action 'Baseline uses reg utility to add HKCU CurrentVersion Run value'
        Invoke-Step {
            $regPath = 'HKCU\software\Microsoft\Windows\CurrentVersion\Run'
            Start-Process -FilePath 'reg.exe' `
                -ArgumentList @('add', $regPath, '/v', $valueName, '/t', 'REG_SZ', '/d', $dummyExe, '/f') `
                -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
            Write-Host "     $Marker phase5 baseline value: $runKey\$valueName" -ForegroundColor DarkGray
        }
    } else {
        Write-Action 'Evasion writes StartupApproved Run metadata outside target key list'
        Invoke-Step {
            New-Item -Path $bypassKey -Force | Out-Null
            New-ItemProperty -Path $bypassKey -Name $valueName -Value ([byte[]](2,0,0,0,0,0,0,0,0,0,0,0)) -PropertyType Binary -Force | Out-Null
            Write-Host "     $Marker phase5 evasion value: $bypassKey\$valueName" -ForegroundColor DarkGray
        }
    }
    Start-Sleep -Seconds $SleepSeconds
}

# Phase 6 - file encoding utility process rule.
if (Should-RunPhase 6) {
    Write-Phase 6 'File encoding marker'
    if ($Mode -eq 'benign') {
        Write-Action 'Read temp directory only'
        Invoke-Step { Get-ChildItem $env:TEMP -ErrorAction SilentlyContinue | Select-Object -First 3 | Out-Null }
    } elseif ($Mode -eq 'baseline') {
        Write-Action 'Baseline uses encoding utility with target flag'
        Invoke-Step {
            $inFile = Join-Path $env:TEMP ("red_v2_p6_in_{0}.txt" -f $RunId)
            $outFile = Join-Path $env:TEMP ("red_v2_p6_out_{0}.txt" -f $RunId)
            Set-Content -Path $inFile -Encoding ASCII -Value $Marker
            $tool = Join-Ascii @(99,101,114,116,117,116,105,108,46,101,120,101)
            $flag = Join-Ascii @(45,101,110,99,111,100,101)
            Start-Process -FilePath $tool `
                -ArgumentList @($flag, $inFile, $outFile) `
                -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
            Remove-Item -Path $inFile, $outFile -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Action 'Evasion uses runtime base64 API without target utility'
        Invoke-Step {
            $code = @"
Write-Host 'RED_DEMO_V2_PHASE6_$RunId'
`$bytes = [Text.Encoding]::UTF8.GetBytes('$Marker')
`$method = 'To' + 'Base64' + 'String'
`$encoded = [Convert].GetMethod(`$method, [type[]]@([byte[]])).Invoke(`$null, @(,`$bytes))
Write-Host 'phase6 evasion encoded length:' `$encoded.Length
"@
            Invoke-ChildEncoded -Code $code
        }
    }
    Start-Sleep -Seconds $SleepSeconds
}

Remove-TempScripts

if (-not $DryRun -and -not $KeepArtifacts -and $Mode -ne 'benign') {
    $cleanupBlock = {
        param($Delay, $RunIdArg)
        Start-Sleep -Seconds $Delay
        $name = "RED_DEMO_V2_${RunIdArg}"
        foreach ($key in @(
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        )) {
            Remove-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
        }
    }
    Start-Job -ScriptBlock $cleanupBlock -ArgumentList $CleanupDelaySeconds, $RunId | Out-Null
    Write-Host ""
    Write-Host ("Cleanup job scheduled after {0}s." -f $CleanupDelaySeconds) -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "==============================================================="
Write-Host ("  Demo v2 complete. RunId: {0} | Marker: {1}" -f $RunId, $Marker)
Write-Host "  Baseline expectation: six target Sigma rule IDs fire."
Write-Host "  Evasion expectation : those six target IDs miss; RED ML alerts remain."
Write-Host "==============================================================="
