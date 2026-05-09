
# YARA Installation Guide

## Create VM(Linux) where you want to deploy

# Step 1 — Update System & Install Dependencies
Before installing YARA, update your system and install required libraries.

## 1.1 - Update package list:
sudo apt update && sudo apt upgrade -y

## 1.2 - Install required dependencies:
sudo apt install -y \
  gcc \
  make \
  libssl-dev \
  libjansson-dev \
  libmagic-dev \
  libpcre3-dev \
  pkg-config \
  autoconf \
  libtool \
  git \
  wget \
  curl

# Step 2 — Install YARA

##  Install via APT
sudo apt install -y yara

## varify installation
yara --version


# Step 3 — Verify YARA is Working

## 3.1 — Create a simple test rule:
cat << 'EOF' > /tmp/test_rule.yar
rule Test_Hello {
    strings:
        $a = "Hello YARA"
    condition:
        $a
}
EOF

## 3.2 — Create a test file to scan:
echo "Hello YARA - Test File" > /tmp/test_file.txt

### Expected output:
Test_Hello /tmp/test_file.txt

If you see this — YARA is installed and working perfectly


  
