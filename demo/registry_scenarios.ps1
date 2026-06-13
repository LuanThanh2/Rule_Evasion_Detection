<#
RED demo generator for the registry_event event type.

This script is intentionally lab-safe: it writes short-lived demo registry
values to generate Sysmon registry events, then removes them by default.

Requires Sysmon registry event collection (commonly Event ID 12/13/14) and
Elastic Agent collection on the Windows lab VM.

Usage:
  Set-ExecutionPolicy Bypass -Scope Process -Force
  .\registry_scenarios.ps1 -Scenario benign
  .\registry_scenarios.ps1 -Scenario baseline
  .\registry_scenarios.ps1 -Scenario evasion -SleepSeconds 20
  .\registry_scenarios.ps1 -Scenario chain
  .\registry_scenarios.ps1 -Scenario all
  .\registry_scenarios.ps1 -Scenario evasion -DryRun
  .\registry_scenarios.ps1 -Scenario baseline -KeepArtifacts
#>

param(
    [ValidateSet("benign", "baseline", "evasion", "chain", "all")]
    [string]$Scenario = "all",

    [int]$SleepSeconds = 20,

    [switch]$DryRun,

    [switch]$KeepArtifacts
)

$ErrorActionPreference = "Continue"

$EncodedPayload = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFIARQBEACAAZABlAG0AbwAgAG0AYQByAGsAZQByACcA"

function Invoke-DemoRegistrySet {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$ValueName,
        [Parameter(Mandatory = $true)][string]$ValueData,
        [ValidateSet("String", "ExpandString", "DWord", "QWord", "MultiString", "Binary")]
        [string]$PropertyType = "String",
        [int]$PauseSeconds = 0
    )

    Write-Host ""
    Write-Host "[$(Get-Date -Format o)] $Label" -ForegroundColor Cyan
    Write-Host "  Key:   $KeyPath" -ForegroundColor Gray
    Write-Host "  Value: $ValueName" -ForegroundColor Gray
    Write-Host "  Data:  $ValueData" -ForegroundColor Gray

    if (-not $DryRun) {
        try {
            New-Item -Path $KeyPath -Force | Out-Null
            New-ItemProperty -Path $KeyPath -Name $ValueName -Value $ValueData -PropertyType $PropertyType -Force | Out-Null
        } catch {
            Write-Warning "Registry set failed: $($_.Exception.Message)"
        }
    }

    if ($PauseSeconds -gt 0) {
        Start-Sleep -Seconds $PauseSeconds
    }

    if ((-not $DryRun) -and (-not $KeepArtifacts)) {
        try {
            Remove-ItemProperty -Path $KeyPath -Name $ValueName -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Registry cleanup failed: $($_.Exception.Message)"
        }
    }
}

function Invoke-BenignScenario {
    Write-Host "`n=== Scenario: benign registry activity ===" -ForegroundColor Green

    Invoke-DemoRegistrySet -Label "Benign app setting write" `
        -KeyPath "HKCU:\Software\RED_Demo\Settings" `
        -ValueName "LastInventory" `
        -ValueData "$(Get-Date -Format o)"

    Invoke-DemoRegistrySet -Label "Benign preference write" `
        -KeyPath "HKCU:\Software\RED_Demo\Settings" `
        -ValueName "Theme" `
        -ValueData "light"
}

function Invoke-BaselineScenario {
    Write-Host "`n=== Scenario: baseline registry persistence marker ===" -ForegroundColor Green

    Invoke-DemoRegistrySet -Label "Baseline: Run key with full -EncodedCommand marker" `
        -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -ValueName "RED_Demo_Baseline" `
        -ValueData "powershell.exe -NoProfile -EncodedCommand $EncodedPayload"
}

function Invoke-EvasionScenario {
    Write-Host "`n=== Scenario: registry event evasion variants ===" -ForegroundColor Green

    Invoke-DemoRegistrySet -Label "Variant 1: Run key with short PowerShell flag" `
        -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -ValueName "RED_Demo_EvasionShortFlag" `
        -ValueData "PoWeRsHeLl.exe -NoP -e $EncodedPayload" `
        -PauseSeconds $SleepSeconds

    Invoke-DemoRegistrySet -Label "Variant 2: RunOnce key marker" `
        -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" `
        -ValueName "RED_Demo_RunOnce" `
        -ValueData "cmd.exe /c echo RED_DEMO_REG_RUNONCE" `
        -PauseSeconds $SleepSeconds

    Invoke-DemoRegistrySet -Label "Variant 3: Explorer policy Run key marker" `
        -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" `
        -ValueName "RED_Demo_PolicyRun" `
        -ValueData "%ComSpec% /c echo RED_DEMO_REG_POLICY_RUN" `
        -PropertyType "ExpandString" `
        -PauseSeconds $SleepSeconds

    Invoke-DemoRegistrySet -Label "Variant 4: IFEO Debugger marker under HKCU" `
        -KeyPath "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\red_demo.exe" `
        -ValueName "Debugger" `
        -ValueData "cmd.exe /c echo RED_DEMO_REG_IFEO"
}

function Invoke-ChainScenario {
    Write-Host "`n=== Scenario: simple registry persistence chain ===" -ForegroundColor Green

    Invoke-DemoRegistrySet -Label "Stage A: benign staging value" `
        -KeyPath "HKCU:\Software\RED_Demo\Chain" `
        -ValueName "Stage" `
        -ValueData "inventory" `
        -PauseSeconds $SleepSeconds

    Invoke-DemoRegistrySet -Label "Stage B: Run key evasion marker" `
        -KeyPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -ValueName "RED_Demo_Chain" `
        -ValueData "powershell.exe -NoProfile -e $EncodedPayload" `
        -PauseSeconds $SleepSeconds

    Invoke-DemoRegistrySet -Label "Stage C: cleanup marker" `
        -KeyPath "HKCU:\Software\RED_Demo\Chain" `
        -ValueName "CleanupMarker" `
        -ValueData "RED_DEMO_REG_CHAIN_COMPLETE"
}

switch ($Scenario) {
    "benign" { Invoke-BenignScenario }
    "baseline" { Invoke-BaselineScenario }
    "evasion" { Invoke-EvasionScenario }
    "chain" { Invoke-ChainScenario }
    "all" {
        Invoke-BenignScenario
        Start-Sleep -Seconds $SleepSeconds
        Invoke-BaselineScenario
        Start-Sleep -Seconds $SleepSeconds
        Invoke-EvasionScenario
        Start-Sleep -Seconds $SleepSeconds
        Invoke-ChainScenario
    }
}

Write-Host "`nDone. Wait for Sysmon registry event ingestion, then poll with RED using config/registry_event.yaml." -ForegroundColor Green
