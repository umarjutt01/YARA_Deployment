# Why Automation Matters for PTA Audit

## Manual scanning is not enough for audit. PTA expects evidence of continuous, scheduled monitoring — automation proves your security is always running, not just when someone remembers.

## 1.1 — Create Master Scan Script

## script start

#!/bin/bash
# ─────────────────────────────────────────────
# YARA Automated Scanner - Fixed Version
# KKN Security Team
# ─────────────────────────────────────────────

DATE=$(date '+%Y-%m-%d_%H-%M-%S')
RULES_DIR="/etc/yara/rules"
LOG_DIR="/etc/yara/logs"
LOG_FILE="$LOG_DIR/yara_scan_$DATE.log"
ALERT_FILE="$LOG_DIR/alerts_$DATE.log"

# Scan targets as array (fixes flex scanner error)
SCAN_TARGETS=("/home" "/tmp" "/opt/containerd")

mkdir -p $LOG_DIR

echo "========================================" >> $LOG_FILE
echo " YARA Scan Report"                        >> $LOG_FILE
echo " Started : $DATE"                         >> $LOG_FILE
echo " Host    : $(hostname)"                   >> $LOG_FILE
echo "========================================" >> $LOG_FILE

# ── Function to scan one rule against all targets ──
scan_rule() {
    local RULE="$1"
    for TARGET in "${SCAN_TARGETS[@]}"; do
        yara -r "$RULE" "$TARGET" >> $LOG_FILE 2>&1
    done
}

# ── Custom Rules ──
echo "" >> $LOG_FILE
echo "[*] Running Custom Rules..." >> $LOG_FILE
for RULE in $RULES_DIR/*.yar; do
    echo "[*] Rule: $RULE" >> $LOG_FILE
    scan_rule "$RULE"
done

# ── Signature-Base APT Rules ──
echo "" >> $LOG_FILE
echo "[*] Running Signature-Base APT Rules..." >> $LOG_FILE
find $RULES_DIR/signature-base/yara/ -name "apt_*.yar" | while read RULE; do
    yara -r "$RULE" /home >> $LOG_FILE 2>&1
    yara -r "$RULE" /tmp  >> $LOG_FILE 2>&1
done

# ── Elastic Ransomware Rules ──
echo "" >> $LOG_FILE
echo "[*] Running Elastic Ransomware Rules..." >> $LOG_FILE
find $RULES_DIR/elastic-rules/ransomware/ -name "*.yar" | while read RULE; do
    yara -r "$RULE" /home >> $LOG_FILE 2>&1
    yara -r "$RULE" /tmp  >> $LOG_FILE 2>&1
done

# ── Extract Real Alerts Only ──
grep -v "^\[" $LOG_FILE | \
grep -v "^=" | \
grep -v "^$" | \
grep -v "^error" > $ALERT_FILE 2>&1

echo "" >> $LOG_FILE
echo "========================================" >> $LOG_FILE
echo " Scan Completed: $(date '+%Y-%m-%d_%H-%M-%S')" >> $LOG_FILE
echo "========================================" >> $LOG_FILE

echo "Scan complete. Log saved: $LOG_FILE"

## script end

## 1.2 — Make Script Executable

sudo chmod +x /etc/yara/yara_scan.sh

## 1.3 — Run First Manual Scan

sudo /etc/yara/yara_scan.sh

## 1.4 — check output and alerts

cat $(ls -t /etc/yara/logs/yara_scan_*.log | head -1) | tail -20

cat $(ls -t /etc/yara/logs/alerts_*.log | head -1)

## 1.5 — Schedule Automated Scans via Cron

### What is Cron?

Cron is Linux's built-in task scheduler. It runs commands automatically at defined times — like Windows Task Scheduler. 
We use it so YARA scans run without any human intervention, which proves continuous monitoring to PTA auditors.

## Open Cron Editor

sudo crontab -e

## Add These Lines at the Bottom
start
### ── YARA Automated Scanning ──

### Full scan every 6 hours
0 */6 * * * /etc/yara/yara_scan.sh

### Rules update every Sunday 2AM
0 2 * * 0 /etc/yara/update_rules.sh >> /etc/yara/logs/update.log 2>&1

end

## Verify Cron Service is Running

sudo systemctl status cron



