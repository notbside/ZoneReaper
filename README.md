<div align="center">

# 🛡️ ZoneReaper

### Advanced DNS Security Assessment & Exploitation Framework

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg?style=for-the-badge)](https://github.com/notbside/ZoneReaper)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Stars](https://img.shields.io/github/stars/notbside/ZoneReaper?style=for-the-badge)](https://github.com/notbside/ZoneReaper/stargazers)

**Professional DNS reconnaissance toolkit for penetration testing and bug bounty hunting**

[🚀 Quick Start](#-installation) • [📖 Documentation](#-usage) • [✨ Features](#-features) 

</div>

---

## 📋 Overview

**ZoneReaper** is a comprehensive DNS security assessment toolkit designed for penetration testers, security researchers, and bug bounty hunters. It automates the process of discovering DNS vulnerabilities, including zone transfer misconfigurations, subdomain enumeration, and DNS record analysis.

### 🎯 Why ZoneReaper?

| Feature | Description |
|---------|-------------|
| ⚡ **Fast** | Multi-threaded scanning with intelligent rate limiting |
| 🎨 **Beautiful** | Color-coded output with detailed progress indicators |
| 📊 **Comprehensive** | Multiple scanning modes and export formats |
| 🔧 **Flexible** | Works standalone or integrates with existing workflows |
| 🛡️ **Safe** | Built-in safety features to prevent accidental DoS |
| 📝 **Detailed** | Generates professional reports in TXT, JSON, HTML, and Markdown |

---

## ✨ Features

### 🔥 Core Capabilities

- ✅ **Zone Transfer Testing**: Detect misconfigured DNS servers
- ✅ **Subdomain Enumeration**: Discover hidden subdomains  
- ✅ **DNS Record Analysis**: Collect all DNS record types
- ✅ **Email Security Check**: Verify SPF, DMARC, DKIM records
- ✅ **DNSSEC Validation**: Check DNSSEC configuration
- ✅ **Wildcard Detection**: Identify wildcard DNS entries
- ✅ **Mass Scanning**: Process hundreds of domains efficiently
- ✅ **Multi-format Reports**: Export in various formats

### 🚀 Advanced Features

- 🔥 **Intelligent Threading**: Automatic optimization based on system resources
- 🔥 **Progress Tracking**: Real-time progress bars and ETA
- 🔥 **Retry Logic**: Automatic retry with exponential backoff
- 🔥 **Rate Limiting**: Configurable delays to avoid detection
- 🔥 **Proxy Support**: Route through SOCKS/HTTP proxies
- 🔥 **API Mode**: JSON API for integration with other tools
- 🔥 **Resume Support**: Continue interrupted scans
- 🔥 **Notification Support**: Slack/Discord/Telegram alerts

---

## 🚀 Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/notbside/ZoneReaper.git
cd ZoneReaper

# Run the installer
chmod +x install.sh
sudo ./install.sh
```

### Manual Installation

```bash
# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x dns-recon.py zone-transfer-scanner.sh

# Optional: Add to PATH
sudo ln -s $(pwd)/dns-recon.py /usr/local/bin/zonereaper
```

### Requirements

- Python 3.8 or higher
- dnspython >= 2.0.0
- colorama >= 0.4.4
- requests >= 2.25.0
- tqdm >= 4.60.0

---

## 📖 Usage

### Basic Usage

```bash
# Test single domain for zone transfer
./dns-recon.py -d example.com --zone-transfer

# Scan multiple domains from file
./dns-recon.py -f domains.txt -o results/

# Full assessment with all modules
./dns-recon.py -d example.com --all --output report.html

# Quick subdomain enumeration
./dns-recon.py -d example.com --subdomains -w wordlist.txt
```

### Advanced Usage

```bash
# Multi-threaded scan with 50 threads
./dns-recon.py -f targets.txt -t 50 --timeout 10

# With proxy and custom DNS resolver
./dns-recon.py -d example.com --proxy socks5://127.0.0.1:9050 --resolver 8.8.8.8

# Resume interrupted scan
./dns-recon.py --resume scan_20250107_123456

# Export in multiple formats
./dns-recon.py -d example.com --format json,html,csv -o results/

# Silent mode for scripting
./dns-recon.py -d example.com --silent --json-output > result.json

# With Slack notifications
./dns-recon.py -f targets.txt --notify-slack https://hooks.slack.com/...
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Single domain to scan |
| `-f, --file` | File containing list of domains |
| `-zt, --zone-transfer` | Test for zone transfer vulnerability |
| `-se, --subdomains` | Enumerate subdomains |
| `-w, --wordlist` | Wordlist for subdomain enumeration |
| `-dr, --dns-records` | Collect DNS records |
| `-a, --all` | Run all checks |
| `-t, --threads` | Number of threads (default: 10) |
| `--timeout` | DNS query timeout in seconds (default: 10) |
| `-r, --resolver` | Custom DNS resolver IP |
| `-o, --output` | Output file path |
| `--format` | Report format: text,json,html (default: all) |
| `-v, --verbose` | Verbose output |
| `-s, --silent` | Silent mode |

---

## 📊 Examples

### Example 1: Single Domain Assessment

```bash
./dns-recon.py -d inlanefreight.htb --all -v
```

**Output:**
```
[+] ZoneReaper v1.0.0
[+] Target: inlanefreight.htb
[+] Starting comprehensive assessment...

[*] Testing zone transfer vulnerability...
    [✓] ns1.inlanefreight.htb - Protected
    [!] ns2.inlanefreight.htb - VULNERABLE!
        [+] 47 DNS records exposed
        [+] Saved to: results/zone_transfer_ns2.txt

[*] Enumerating subdomains...
    [+] Found 23 subdomains
    [+] admin.inlanefreight.htb (10.129.110.21)
    [+] vpn.inlanefreight.htb (10.129.110.100)
    ...

[+] Assessment complete! Report saved to: report.html
```

### Example 2: Mass Scanning

```bash
./dns-recon.py -f fortune500.txt -t 20 --format json
```

### Example 3: Bug Bounty Workflow

```bash
# 1. Enumerate subdomains
./dns-recon.py -d target.com --subdomains -w big.txt -o target_subs.txt

# 2. Check for zone transfer on found subdomains
./dns-recon.py -f target_subs.txt --zone-transfer --vulnerable-only

# 3. Generate report for submission
./dns-recon.py -d target.com --all --format markdown -o bounty_report.md
```
---

## 📁 Output Formats

### Text Report
```
=== DNS Security Assessment Report ===
Domain: example.com
Date: 2025-01-07 14:30:00

ZONE TRANSFER VULNERABILITIES:
[!] ns1.example.com - VULNERABLE
    Records exposed: 156
    Internal IPs discovered: 23
...
```

### JSON Output
```json
{
  "domain": "example.com",
  "timestamp": "2025-01-07T14:30:00",
  "vulnerabilities": {
    "zone_transfer": {
      "vulnerable": true,
      "nameservers": ["ns1.example.com"],
      "records_count": 156
    }
  }
}
```

### HTML Report
Beautiful, professional HTML report with:
- 📊 Interactive charts and graphs
- 🎨 Color-coded vulnerability indicators
- 📱 Mobile-responsive design
- 🖨️ Print-friendly layout

---

## 🔒 Security & Ethics

### ⚠️ Responsible Usage

**IMPORTANT**: This tool is for authorized security testing only.

#### ✅ DO:
- Use on your own domains or with written permission
- Follow responsible disclosure for found vulnerabilities
- Respect rate limits and terms of service
- Document your findings professionally

#### ❌ DON'T:
- Use on targets without authorization
- Perform aggressive scanning that could cause DoS
- Use for malicious purposes
- Ignore legal and ethical boundaries

### Legal Notice

The authors and contributors are not responsible for misuse of this tool. Users are responsible for complying with applicable laws and regulations.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 notbside

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 👨‍💻 Author

<div align="center">

**notbside**

[![GitHub](https://img.shields.io/badge/GitHub-notbside-181717?style=for-the-badge&logo=github)](https://github.com/notbside)
[![Twitter](https://img.shields.io/badge/Twitter-@notbside-1DA1F2?style=for-the-badge&logo=twitter)](https://twitter.com/notbside)
[![Email](https://img.shields.io/badge/Email-notbside@proton.me-8B89CC?style=for-the-badge&logo=protonmail)](mailto:notbside@proton.me)

</div>

---

## 🙏 Acknowledgments

- Thanks to the DNS security research community
- Inspired by tools like DNSRecon, Fierce, and Sublist3r
- Special thanks to all contributors
- HackTheBox Academy for testing grounds

---

## 📚 Resources

- 📖 [DNS Security Best Practices](https://www.cloudflare.com/learning/dns/dns-security/)
- 🔐 [OWASP Testing Guide - DNS Testing](https://owasp.org/www-project-web-security-testing-guide/)
- 📜 [RFC 5936 - DNS Zone Transfer Protocol](https://tools.ietf.org/html/rfc5936)
- 🎓 [HackTheBox Academy - DNS Attacks](https://academy.hackthebox.com/)

---

## 📈 Roadmap

- [ ] Integration with Burp Suite
- [ ] Machine learning for anomaly detection
- [ ] Cloud DNS provider support (AWS Route53, Cloudflare)
- [ ] GUI interface
- [ ] Mobile app (Android/iOS)
- [ ] Real-time collaboration features
- [ ] Integration with SIEM systems

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=notbside/ZoneReaper&type=Date)](https://star-history.com/#notbside/ZoneReaper&Date)

---

## 📊 Statistics

![GitHub repo size](https://img.shields.io/github/repo-size/notbside/ZoneReaper?style=flat-square)
![GitHub code size](https://img.shields.io/github/languages/code-size/notbside/ZoneReaper?style=flat-square)
![GitHub issues](https://img.shields.io/github/issues/notbside/ZoneReaper?style=flat-square)
![GitHub pull requests](https://img.shields.io/github/issues-pr/notbside/ZoneReaper?style=flat-square)

---

<div align="center">

### 💖 Made with passion by notbside

**If you find this tool useful, please consider giving it a ⭐!**

*Happy Hunting! 🎯*

---

**[⬆ Back to Top](#-zonereaper)**

</div>
