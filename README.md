# ZoneReaper
DNS Zone Transfer exploitation and enumeration framework

mples • Contributing

📋 Overview
DNS Recon Toolkit is a comprehensive collection of tools for DNS security assessment, penetration testing, and bug bounty hunting. It automates the process of discovering DNS vulnerabilities, including zone transfer misconfigurations, subdomain enumeration, and DNS record analysis.
🎯 Why This Tool?

🚀 Fast: Multi-threaded scanning with intelligent rate limiting
🎨 Beautiful: Color-coded output with detailed progress indicators
📊 Comprehensive: Multiple scanning modes and export formats
🔧 Flexible: Works standalone or integrates with existing workflows
🛡️ Safe: Built-in safety features to prevent accidental DoS
📝 Detailed: Generates professional reports in TXT, JSON, HTML, and Markdown


✨ Features
Core Capabilities

✅ Zone Transfer Testing: Detect misconfigured DNS servers
✅ Subdomain Enumeration: Discover hidden subdomains
✅ DNS Record Analysis: Collect all DNS record types
✅ Email Security Check: Verify SPF, DMARC, DKIM records
✅ DNSSEC Validation: Check DNSSEC configuration
✅ Wildcard Detection: Identify wildcard DNS entries
✅ Mass Scanning: Process hundreds of domains efficiently
✅ Multi-format Reports: Export in various formats

Advanced Features

🔥 Intelligent Threading: Automatic optimization based on system resources
🔥 Progress Tracking: Real-time progress bars and ETA
🔥 Retry Logic: Automatic retry with exponential backoff
🔥 Rate Limiting: Configurable delays to avoid detection
🔥 Proxy Support: Route through SOCKS/HTTP proxies
🔥 API Mode: JSON API for integration with other tools
🔥 Resume Support: Continue interrupted scans
🔥 Notification Support: Slack/Discord/Telegram alerts


🚀 Installation
Quick Install
bash# Clone the repository
git clone https://github.com/notbside/dns-recon-toolkit.git
cd dns-recon-toolkit

# Run the installer
chmod +x install.sh
sudo ./install.sh

# Or manual install
pip3 install -r requirements.txt
chmod +x dns-recon.py zone-transfer-scanner.sh
Docker Installation
bash# Build Docker image
docker build -t dns-recon-toolkit .

# Run with Docker
docker run -it dns-recon-toolkit -d example.com
Requirements

Python 3.8 or higher
dnspython >= 2.0.0
colorama >= 0.4.4
requests >= 2.25.0
tqdm >= 4.60.0


📖 Usage
Basic Usage
bash# Test single domain for zone transfer
./dns-recon.py -d example.com --zone-transfer

# Scan multiple domains from file
./dns-recon.py -f domains.txt -o results/

# Full assessment with all modules
./dns-recon.py -d example.com --all --output report.html

# Quick subdomain enumeration
./dns-recon.py -d example.com --subdomains -w wordlist.txt
Advanced Usage
bash# Multi-threaded scan with 50 threads
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
Bash Script Usage
bash# Zone transfer scanner
./zone-transfer-scanner.sh domains.txt

# Comprehensive assessment
./comprehensive-assessment.sh domains.txt --html-report

# Quick check
./quick-check.sh example.com

📊 Examples
Example 1: Single Domain Assessment
bash./dns-recon.py -d inlanefreight.htb --all -v
Output:
[+] DNS Recon Toolkit v1.0.0
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
Example 2: Mass Scanning
bash./dns-recon.py -f fortune500.txt -t 20 --format json
Example 3: Bug Bounty Workflow
bash# 1. Enumerate subdomains
./dns-recon.py -d target.com --subdomains -w big.txt -o target_subs.txt

# 2. Check for zone transfer on found subdomains
./dns-recon.py -f target_subs.txt --zone-transfer --vulnerable-only

# 3. Generate report for submission
./dns-recon.py -d target.com --all --format markdown -o bounty_report.md

📁 Output Formats
Text Report
=== DNS Security Assessment Report ===
Domain: example.com
Date: 2025-01-07 14:30:00

ZONE TRANSFER VULNERABILITIES:
[!] ns1.example.com - VULNERABLE
    Records exposed: 156
    Internal IPs discovered: 23
...
JSON Output
json{
  "domain": "example.com",
  "timestamp": "2025-01-07T14:30:00",
  "vulnerabilities": {
    "zone_transfer": {
      "vulnerable": true,
      "nameservers": ["ns1.example.com"],
      "records_count": 156
    }
  },
  "subdomains": [...],
  "dns_records": {...}
}
HTML Report
Beautiful, professional HTML report with charts and graphs.

🛠️ Configuration
Config File (config.yaml)
yaml# DNS Recon Toolkit Configuration

general:
  threads: 10
  timeout: 10
  retry_attempts: 3
  output_dir: "results"

dns:
  resolvers:
    - 8.8.8.8
    - 1.1.1.1
  fallback_resolver: 8.8.8.8

scanning:
  rate_limit: 100  # requests per second
  delay_between_requests: 0.1
  
wordlists:
  default: "wordlists/subdomains-top10000.txt"
  large: "wordlists/subdomains-top1million.txt"

notifications:
  slack_webhook: ""
  discord_webhook: ""
  telegram_bot_token: ""
  telegram_chat_id: ""

reports:
  default_format: "html"
  include_timestamps: true
  save_raw_data: true

🔒 Security & Ethics
Responsible Usage
⚠️ IMPORTANT: This tool is for authorized security testing only.

✅ DO: Use on your own domains or with written permission
✅ DO: Follow responsible disclosure for found vulnerabilities
✅ DO: Respect rate limits and terms of service
❌ DON'T: Use on targets without authorization
❌ DON'T: Perform aggressive scanning that could cause DoS
❌ DON'T: Use for malicious purposes

Legal Notice
The authors and contributors are not responsible for misuse of this tool. Users are responsible for complying with applicable laws and regulations.

🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
Development Setup
bash# Clone and setup development environment
git clone https://github.com/notbside/dns-recon-toolkit.git
cd dns-recon-toolkit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linting
flake8 dns-recon.py
pylint dns-recon.py
Contribution Guidelines

Fork the repository
Create your feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add some AmazingFeature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request


📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

👨‍💻 Author
notbside

GitHub: @notbside
Twitter: @notbside
Email: notbside@proton.me


🙏 Acknowledgments

Thanks to the DNS security research community
Inspired by tools like DNSRecon, Fierce, and Sublist3r
Special thanks to all contributors


📚 Resources

DNS Security Best Practices
OWASP Testing Guide - DNS Testing
RFC 5936 - DNS Zone Transfer Protocol


⭐ Star History
If you find this tool useful, please consider giving it a star on GitHub!
Show Image

<div align="center">
Made with ❤️ by notbside
Happy Hunting! 🎯
</div>
