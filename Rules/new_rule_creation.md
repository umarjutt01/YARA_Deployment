# step1 - Create Your Own Rules Directory

## 1.1 - Create organized folder structure

sudo mkdir -p /etc/yara/rules
sudo mkdir -p /etc/yara/logs
sudo mkdir -p /etc/yara/quarantine

## 1.2 — Verify structure created

ls -la /etc/yara/

### Expected output:

drwxr-xr-x  logs/
drwxr-xr-x  quarantine/
drwxr-xr-x  rules/

# Step 2 — Write Real Detection Rules

## 2.1 — Rule 1: Detect Webshells

Webshells are scripts attackers plant on servers for remote access — very common in PTA audit findings.

sudo nano /etc/yara/rules/webshells.yar

paste this:

rule Detect_Webshell {
    meta:
        author      = "KKN Security Team"
        description = "Detects common PHP/ASP webshells"
        severity    = "critical"
        date        = "2026-05-09"

    strings:
        $php1 = "eval(base64_decode"
        $php2 = "system($_GET"
        $php3 = "passthru($_POST"
        $php4 = "shell_exec($_REQUEST"
        $asp1 = "cmd.exe /c" nocase
        $asp2 = "WScript.Shell" nocase

    condition:
        any of them
}


## 2.2 — Rule 2: Detect Ransomware Behavior

sudo nano /etc/yara/rules/ransomware.yar

paste this:

rule Detect_Ransomware {
    meta:
        author      = "KKN Security Team"
        description = "Detects common ransomware strings"
        severity    = "critical"
        date        = "2026-05-09"

    strings:
        $s1 = "Your files have been encrypted" nocase
        $s2 = "bitcoin" nocase
        $s3 = "pay ransom" nocase
        $s4 = "decrypt your files" nocase
        $s5 = ".locked" nocase
        $s6 = "HOW_TO_RECOVER" nocase

    condition:
        2 of them
}

## 2.3 — Rule 3: Detect Reverse Shell Attempts

sudo nano /etc/yara/rules/reverse_shell.yar

paste this:

rule Detect_Reverse_Shell {
    meta:
        author      = "KKN Security Team"
        description = "Detects reverse shell payloads"
        severity    = "high"
        date        = "2026-05-09"

    strings:
        $b1 = "bash -i >& /dev/tcp" nocase
        $b2 = "nc -e /bin/bash" nocase
        $b3 = "0>&1"
        $p1 = "import socket,subprocess" 
        $p2 = "/bin/sh -i"

    condition:
        any of them
}

## 2.4 — Verify all rules are saved

ls -la /etc/yara/rules/


# Step 3 — Test Your New Rules

## 3.1 — Test webshell rule

echo '<?php eval(base64_decode("dGVzdA==")); ?>' > /tmp/fake_webshell.php
yara /etc/yara/rules/webshells.yar /tmp/fake_webshell.php

### output
Expected: Detect_Webshell /tmp/fake_webshell.php

## 3.2 — Scan entire directory with all rules

yara -r /etc/yara/rules/webshells.yar /var/www/html/

### -r flag = recursive scan through all subdirectories

## 3.3 — Scan with ALL rules at once

yara -r /etc/yara/rules/*.yar /var/www/html/
