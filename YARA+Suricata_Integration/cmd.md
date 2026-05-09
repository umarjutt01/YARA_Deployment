# What & Why?

Right now YARA and Suricata work independently. Integration means when Suricata detects suspicious network traffic, it can automatically trigger 
YARA to scan the related file — giving you both network + file analysis together. This is a major audit point.
# ------------------------------

Suricata detects suspicious traffic
          ↓
Extracts the file/payload
          ↓
YARA automatically scans it
          ↓
Combined alert generated
          ↓
Single unified log for PTA audit

# ----------------------------

## 1.1 — Check Suricata's File Extraction Setup

find /opt/suricata -name "suricata.yaml" 2>/dev/null
ls /etc/suricata/ 2>/dev/null

### Check if file extraction is enabled:

grep -n "file-store\|filestore\|extract" \
/etc/suricata/suricata.yaml 2>/dev/null | head -20


## 1.2 — Check Where Suricata Stores Extracted Files

grep -n "file-store\|filestore\|extract" \
/etc/suricata/suricata.yaml 2>/dev/null | head -20

## 1.3 — Check Suricata Log Directory

ls /var/log/suricata/ 2>/dev/null
ls /opt/suricata/logs/ 2>/dev/null
ls /opt/suricata/var/log/ 2>/dev/null

# ------------------------------------
<img width="646" height="246" alt="image" src="https://github.com/user-attachments/assets/877e00f2-b486-4daa-bbd7-14d1c3298c23" />

## eve.json is the most important file — it's Suricata's unified event log. Everything Suricata detects gets written here. YARA will monitor this file for triggers.

# ===============================================
# Step 1.4 — Create Corrected Integration Script
# ===============================================

sudo nano /etc/yara/suricata_yara_integration.sh

## (start) paste:

#!/bin/bash
# ─────────────────────────────────────────────
# YARA + Suricata Integration Script
# KKN Security Team
# ─────────────────────────────────────────────

YARA_RULES="/etc/yara/rules"
SURICATA_LOG="/opt/suricata/logs/eve.json"        # Correct path
SURICATA_FAST="/opt/suricata/logs/fast.log"       # Correct path
FILESTORE_DIR="/opt/suricata/filestore"
LOG_DIR="/etc/yara/logs"
DATE=$(date '+%Y-%m-%d')
TIME=$(date '+%Y-%m-%d %H:%M:%S')
INTEGRATION_LOG="$LOG_DIR/suricata_yara_$DATE.log"

mkdir -p $LOG_DIR

echo "========================================" >> $INTEGRATION_LOG
echo " Suricata + YARA Integration Report"     >> $INTEGRATION_LOG
echo " Time    : $TIME"                         >> $INTEGRATION_LOG
echo " Host    : $(hostname)"                   >> $INTEGRATION_LOG
echo "========================================" >> $INTEGRATION_LOG

# ── Section 1: Parse Suricata Alerts from eve.json ──
echo "" >> $INTEGRATION_LOG
echo "[*] Parsing Suricata alerts from eve.json..." >> $INTEGRATION_LOG

ALERT_COUNT=$(grep '"event_type":"alert"' $SURICATA_LOG 2>/dev/null | wc -l)
echo "[*] Total alerts in eve.json: $ALERT_COUNT" >> $INTEGRATION_LOG

grep '"event_type":"alert"' $SURICATA_LOG 2>/dev/null | \
tail -20 | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        ts  = e.get('timestamp','')
        src = e.get('src_ip','')
        sp  = e.get('src_port','')
        dst = e.get('dest_ip','')
        dp  = e.get('dest_port','')
        sig = e.get('alert',{}).get('signature','')
        sev = e.get('alert',{}).get('severity','')
        print(f'[SURICATA] {ts} | {src}:{sp} -> {dst}:{dp} | {sig} | SEV:{sev}')
    except:
        pass
" >> $INTEGRATION_LOG 2>&1

# ── Section 2: Scan Filestore if Exists ──
echo "" >> $INTEGRATION_LOG
echo "[*] Checking filestore for extracted files..." >> $INTEGRATION_LOG

if [ -d "$FILESTORE_DIR" ]; then
    FILE_COUNT=$(find "$FILESTORE_DIR" -type f | wc -l)
    echo "[*] Files in filestore: $FILE_COUNT" >> $INTEGRATION_LOG

    find "$FILESTORE_DIR" -type f | while read EXTRACTED_FILE; do
        for RULE in $YARA_RULES/*.yar; do
            RESULT=$(yara "$RULE" "$EXTRACTED_FILE" 2>/dev/null)
            if [ ! -z "$RESULT" ]; then
                echo "[YARA ALERT] $RESULT" >> $INTEGRATION_LOG
            fi
        done
    done
else
    echo "[*] Filestore not enabled yet - enable in suricata.yaml" \
    >> $INTEGRATION_LOG
fi

# ── Section 3: Cross-reference fast.log with YARA ──
echo "" >> $INTEGRATION_LOG
echo "[*] Recent entries from fast.log:" >> $INTEGRATION_LOG
tail -10 $SURICATA_FAST >> $INTEGRATION_LOG 2>&1

echo "" >> $INTEGRATION_LOG
echo "========================================" >> $INTEGRATION_LOG
echo " Integration Complete: $(date '+%Y-%m-%d %H:%M:%S')" >> $INTEGRATION_LOG
echo "========================================" >> $INTEGRATION_LOG

echo "Integration scan complete. Log: $INTEGRATION_LOG"

## end script

## 1.5 — Make Executable & Run

sudo chmod +x /etc/yara/suricata_yara_integration.sh
sudo /etc/yara/suricata_yara_integration.sh

## 1.6 — View Integration Results

cat /etc/yara/logs/suricata_yara_$(date '+%Y-%m-%d').log

## 1.7 — Fix Log Directory Symlink

sudo ln -s /opt/suricata/logs /var/log/suricata
ls -la /var/log/suricata/

## 1.8 — Add Integration to Cron

sudo crontab -e

## add:

### YARA + Suricata integration every hour
0 * * * * /etc/yara/suricata_yara_integration.sh
