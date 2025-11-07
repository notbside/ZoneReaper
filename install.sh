#!/bin/bash

# ZoneReaper Installer
# Author: notbside
# Version: 1.0.0

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        ███████╗ ██████╗ ███╗   ██╗███████╗              ║
║        ╚══███╔╝██╔═══██╗████╗  ██║██╔════╝              ║
║          ███╔╝ ██║   ██║██╔██╗ ██║█████╗                ║
║         ███╔╝  ██║   ██║██║╚██╗██║██╔══╝                ║
║        ███████╗╚██████╔╝██║ ╚████║███████╗              ║
║        ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝              ║
║                                                           ║
║     ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗     ║
║     ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗    ║
║     ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝    ║
║     ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗    ║
║     ██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║    ║
║     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝    ║
║                                                           ║
║                    INSTALLER v1.0.0                      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${BLUE}[*] ZoneReaper Installation Script${NC}"
echo -e "${BLUE}[*] Author: notbside${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}[!] This script requires root privileges. Please run with sudo.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Starting installation...${NC}"
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo -e "${RED}[✗] Cannot detect operating system${NC}"
    exit 1
fi

echo -e "${BLUE}[*] Detected OS: $OS $VER${NC}"

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
REQUIRED_VERSION="3.8"

echo -e "${BLUE}[*] Checking Python version...${NC}"
if (( $(echo "$PYTHON_VERSION >= $REQUIRED_VERSION" | bc -l) )); then
    echo -e "${GREEN}[+] Python $PYTHON_VERSION found${NC}"
else
    echo -e "${RED}[✗] Python $REQUIRED_VERSION or higher is required${NC}"
    echo -e "${YELLOW}[!] Installing Python 3...${NC}"
    
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        apt update
        apt install -y python3 python3-pip
    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]]; then
        yum install -y python3 python3-pip
    elif [[ "$OS" == *"Arch"* ]]; then
        pacman -S --noconfirm python python-pip
    else
        echo -e "${RED}[✗] Unsupported OS for automatic Python installation${NC}"
        exit 1
    fi
fi

# Install pip if not present
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}[!] pip3 not found. Installing...${NC}"
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    python3 get-pip.py
    rm get-pip.py
fi

echo -e "${GREEN}[+] pip3 is available${NC}"

# Install system dependencies
echo -e "${BLUE}[*] Installing system dependencies...${NC}"

if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    apt update
    apt install -y git dnsutils bind9-utils
elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]]; then
    yum install -y git bind-utils
elif [[ "$OS" == *"Arch"* ]]; then
    pacman -S --noconfirm git bind-tools
fi

echo -e "${GREEN}[+] System dependencies installed${NC}"

# Install Python dependencies
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt

echo -e "${GREEN}[+] Python dependencies installed${NC}"

# Make scripts executable
echo -e "${BLUE}[*] Setting executable permissions...${NC}"
chmod +x dns-recon.py
chmod +x zone-transfer-scanner.sh 2>/dev/null || true

echo -e "${GREEN}[+] Permissions set${NC}"

# Create symlinks
echo -e "${BLUE}[*] Creating symlinks...${NC}"
ln -sf "$(pwd)/dns-recon.py" /usr/local/bin/zonereaper
ln -sf "$(pwd)/zone-transfer-scanner.sh" /usr/local/bin/zone-scanner 2>/dev/null || true

echo -e "${GREEN}[+] Symlinks created${NC}"

# Create output directories
echo -e "${BLUE}[*] Creating output directories...${NC}"
mkdir -p results wordlists logs

echo -e "${GREEN}[+] Directories created${NC}"

# Download default wordlist
echo -e "${BLUE}[*] Downloading default wordlist...${NC}"
if [ ! -f "wordlists/subdomains-top10000.txt" ]; then
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt \
        -o wordlists/subdomains-top110000.txt
    head -10000 wordlists/subdomains-top110000.txt > wordlists/subdomains-top10000.txt
    echo -e "${GREEN}[+] Wordlist downloaded${NC}"
else
    echo -e "${YELLOW}[!] Wordlist already exists${NC}"
fi

# Test installation
echo ""
echo -e "${BLUE}[*] Testing installation...${NC}"
if python3 dns-recon.py --help &>/dev/null; then
    echo -e "${GREEN}[+] Installation successful!${NC}"
else
    echo -e "${RED}[✗] Installation test failed${NC}"
    exit 1
fi

# Print success message
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                           ║${NC}"
echo -e "${GREEN}║           ✓ INSTALLATION COMPLETED SUCCESSFULLY           ║${NC}"
echo -e "${GREEN}║                                                           ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Quick Start:${NC}"
echo -e "  ${YELLOW}zonereaper -d example.com --zone-transfer${NC}"
echo -e "  ${YELLOW}zonereaper -f domains.txt --all${NC}"
echo -e "  ${YELLOW}zonereaper --help${NC}"
echo ""
echo -e "${CYAN}Documentation:${NC} ${BLUE}https://github.com/notbside/ZoneReaper${NC}"
echo ""
echo -e "${GREEN}Happy Hunting! 🎯${NC}"
