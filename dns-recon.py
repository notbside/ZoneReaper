#!/usr/bin/env python3
"""
DNS Recon Toolkit - Professional DNS Security Assessment Tool
Author: notbside (https://github.com/notbside)
Version: 1.0.0
License: MIT

A comprehensive DNS security assessment toolkit for penetration testers,
security researchers, and bug bounty hunters.
"""

import dns.resolver
import dns.zone
import dns.query
import dns.exception
import argparse
import sys
import os
import json
import time
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
import signal

# Color support
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS_ENABLED = True
except ImportError:
    COLORS_ENABLED = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = ''
    class Style:
        BRIGHT = RESET_ALL = ''

# Progress bar support
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

__version__ = "1.0.0"
__author__ = "notbside"
__license__ = "MIT"

class Colors:
    """Color codes for terminal output"""
    if COLORS_ENABLED:
        RED = Fore.RED
        GREEN = Fore.GREEN
        YELLOW = Fore.YELLOW
        BLUE = Fore.BLUE
        CYAN = Fore.CYAN
        MAGENTA = Fore.MAGENTA
        WHITE = Fore.WHITE
        BRIGHT = Style.BRIGHT
        RESET = Style.RESET_ALL
    else:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = BRIGHT = RESET = ''

class Banner:
    """ASCII art banner"""
    @staticmethod
    def show():
        banner = f"""
{Colors.CYAN}{Colors.BRIGHT}
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        ██████╗ ███╗   ██╗███████╗                        ║
║        ██╔══██╗████╗  ██║██╔════╝                        ║
║        ██║  ██║██╔██╗ ██║███████╗                        ║
║        ██║  ██║██║╚██╗██║╚════██║                        ║
║        ██████╔╝██║ ╚████║███████║                        ║
║        ╚═════╝ ╚═╝  ╚═══╝╚══════╝                        ║
║                                                           ║
║     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗         ║
║     ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║         ║
║     ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║         ║
║     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║         ║
║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║         ║
║     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝         ║
║                                                           ║
║            Professional DNS Security Toolkit             ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.WHITE}Version: {Colors.GREEN}{__version__}{Colors.WHITE} | Author: {Colors.CYAN}@{__author__}{Colors.WHITE} | License: {Colors.YELLOW}{__license__}{Colors.RESET}
"""
        print(banner)

class Logger:
    """Logging utility with color support"""
    def __init__(self, verbose: bool = False, silent: bool = False):
        self.verbose = verbose
        self.silent = silent
        self.log_file = None
    
    def set_log_file(self, filepath: str):
        """Set log file for output"""
        self.log_file = filepath
    
    def _write_to_file(self, message: str):
        """Write message to log file"""
        if self.log_file:
            with open(self.log_file, 'a') as f:
                # Remove color codes for file
                import re
                clean_message = re.sub(r'\033\[[0-9;]+m', '', message)
                f.write(clean_message + '\n')
    
    def info(self, message: str):
        """Info level message"""
        if not self.silent:
            msg = f"{Colors.BLUE}[*]{Colors.RESET} {message}"
            print(msg)
            self._write_to_file(msg)
    
    def success(self, message: str):
        """Success level message"""
        if not self.silent:
            msg = f"{Colors.GREEN}[+]{Colors.RESET} {message}"
            print(msg)
            self._write_to_file(msg)
    
    def warning(self, message: str):
        """Warning level message"""
        if not self.silent:
            msg = f"{Colors.YELLOW}[!]{Colors.RESET} {message}"
            print(msg)
            self._write_to_file(msg)
    
    def error(self, message: str):
        """Error level message"""
        if not self.silent:
            msg = f"{Colors.RED}[✗]{Colors.RESET} {message}"
            print(msg)
            self._write_to_file(msg)
    
    def vuln(self, message: str):
        """Vulnerability found message"""
        if not self.silent:
            msg = f"{Colors.RED}{Colors.BRIGHT}[VULN]{Colors.RESET} {message}"
            print(msg)
            self._write_to_file(msg)
    
    def debug(self, message: str):
        """Debug level message"""
        if self.verbose and not self.silent:
            msg = f"{Colors.CYAN}[DEBUG]{Colors.RESET} {message}"
            print(msg)
            self._write_to_file(msg)

class DNSRecon:
    """Main DNS reconnaissance class"""
    
    def __init__(self, logger: Logger, threads: int = 10, timeout: int = 10, 
                 resolver: Optional[str] = None):
        self.logger = logger
        self.threads = threads
        self.timeout = timeout
        self.results = {
            'zone_transfers': [],
            'subdomains': [],
            'dns_records': {},
            'vulnerabilities': [],
            'errors': []
        }
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        if resolver:
            self.resolver.nameservers = [resolver]
        
        self.logger.debug(f"Initialized with {threads} threads, {timeout}s timeout")
    
    def get_nameservers(self, domain: str) -> List[Tuple[str, str]]:
        """
        Get nameservers for a domain
        Returns: List of (nameserver, ip) tuples
        """
        nameservers = []
        try:
            answers = self.resolver.resolve(domain, 'NS')
            for rdata in answers:
                ns_name = str(rdata.target).rstrip('.')
                try:
                    ns_ip = str(self.resolver.resolve(ns_name, 'A')[0])
                    nameservers.append((ns_name, ns_ip))
                    self.logger.debug(f"Found nameserver: {ns_name} ({ns_ip})")
                except Exception as e:
                    self.logger.debug(f"Could not resolve {ns_name}: {e}")
                    nameservers.append((ns_name, None))
        except dns.resolver.NXDOMAIN:
            self.logger.error(f"Domain not found: {domain}")
        except dns.resolver.NoAnswer:
            self.logger.warning(f"No NS records found for: {domain}")
        except Exception as e:
            self.logger.error(f"Error getting nameservers for {domain}: {e}")
        
        return nameservers
    
    def test_zone_transfer(self, domain: str, nameserver: str, ns_ip: str) -> Dict:
        """
        Test zone transfer vulnerability
        Returns: Dictionary with results
        """
        result = {
            'domain': domain,
            'nameserver': nameserver,
            'ns_ip': ns_ip,
            'vulnerable': False,
            'records': [],
            'record_count': 0,
            'error': None
        }
        
        if not ns_ip:
            result['error'] = "Nameserver IP not resolved"
            return result
        
        try:
            self.logger.debug(f"Attempting zone transfer: {domain} from {nameserver} ({ns_ip})")
            
            # Attempt zone transfer
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=self.timeout))
            
            if zone:
                result['vulnerable'] = True
                result['record_count'] = len(zone.nodes)
                
                # Extract records
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            record = {
                                'name': f"{name}.{domain}" if name.to_text() != '@' else domain,
                                'type': dns.rdatatype.to_text(rdataset.rdtype),
                                'value': str(rdata),
                                'ttl': rdataset.ttl
                            }
                            result['records'].append(record)
                
                self.logger.vuln(f"Zone transfer successful on {nameserver}! {result['record_count']} records exposed")
                self.results['vulnerabilities'].append({
                    'type': 'zone_transfer',
                    'severity': 'high',
                    'domain': domain,
                    'nameserver': nameserver,
                    'details': f"{result['record_count']} DNS records exposed"
                })
        
        except dns.exception.FormError:
            result['error'] = "Transfer refused (FormError)"
            self.logger.debug(f"Zone transfer refused on {nameserver}: FormError")
        except dns.query.TransferError as e:
            result['error'] = f"Transfer error: {str(e)}"
            self.logger.debug(f"Zone transfer failed on {nameserver}: {e}")
        except socket.timeout:
            result['error'] = "Connection timeout"
            self.logger.debug(f"Zone transfer timeout on {nameserver}")
        except Exception as e:
            result['error'] = str(e)
            self.logger.debug(f"Zone transfer error on {nameserver}: {e}")
        
        return result
    
    def enumerate_subdomains(self, domain: str, wordlist: str, 
                           resolver_ip: Optional[str] = None) -> List[Dict]:
        """
        Enumerate subdomains using wordlist
        Returns: List of found subdomains with their IPs
        """
        subdomains = []
        
        if not os.path.exists(wordlist):
            self.logger.error(f"Wordlist not found: {wordlist}")
            return subdomains
        
        # Read wordlist
        with open(wordlist, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
        
        self.logger.info(f"Starting subdomain enumeration with {len(words)} entries")
        
        # Configure resolver for subdomain queries
        sub_resolver = dns.resolver.Resolver()
        sub_resolver.timeout = self.timeout
        sub_resolver.lifetime = self.timeout
        if resolver_ip:
            sub_resolver.nameservers = [resolver_ip]
        
        def check_subdomain(word: str) -> Optional[Dict]:
            """Check if subdomain exists"""
            subdomain = f"{word}.{domain}"
            try:
                answers = sub_resolver.resolve(subdomain, 'A')
                ips = [str(rdata) for rdata in answers]
                self.logger.success(f"Found: {subdomain} -> {', '.join(ips)}")
                return {
                    'subdomain': subdomain,
                    'ips': ips,
                    'type': 'A'
                }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            except Exception as e:
                self.logger.debug(f"Error checking {subdomain}: {e}")
            return None
        
        # Multi-threaded subdomain enumeration
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            if TQDM_AVAILABLE and not self.logger.silent:
                futures = {executor.submit(check_subdomain, word): word for word in words}
                for future in tqdm(as_completed(futures), total=len(words), desc="Scanning"):
                    result = future.result()
                    if result:
                        subdomains.append(result)
            else:
                futures = {executor.submit(check_subdomain, word): word for word in words}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        subdomains.append(result)
        
        self.logger.success(f"Found {len(subdomains)} subdomains")
        return subdomains
    
    def get_dns_records(self, domain: str) -> Dict:
        """
        Get all DNS records for a domain
        Returns: Dictionary of record types and their values
        """
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'PTR']
        
        for rtype in record_types:
            try:
                answers = self.resolver.resolve(domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
                self.logger.debug(f"{rtype} records found: {len(records[rtype])}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                records[rtype] = []
            except Exception as e:
                self.logger.debug(f"Error getting {rtype} records: {e}")
                records[rtype] = []
        
        return records
    
    def check_email_security(self, domain: str) -> Dict:
        """
        Check email security records (SPF, DMARC, DKIM)
        Returns: Dictionary with security record status
        """
        security = {
            'spf': {'present': False, 'record': None},
            'dmarc': {'present': False, 'record': None},
            'dkim': {'present': False, 'records': []}
        }
        
        # Check SPF
        try:
            txt_records = self.resolver.resolve(domain, 'TXT')
            for rdata in txt_records:
                txt = str(rdata).strip('"')
                if txt.startswith('v=spf1'):
                    security['spf']['present'] = True
                    security['spf']['record'] = txt
                    self.logger.success(f"SPF record found: {txt[:50]}...")
        except Exception as e:
            self.logger.debug(f"Error checking SPF: {e}")
        
        # Check DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = self.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in txt_records:
                txt = str(rdata).strip('"')
                if txt.startswith('v=DMARC1'):
                    security['dmarc']['present'] = True
                    security['dmarc']['record'] = txt
                    self.logger.success(f"DMARC record found: {txt[:50]}...")
        except Exception as e:
            self.logger.debug(f"Error checking DMARC: {e}")
        
        # Check common DKIM selectors
        dkim_selectors = ['default', 'google', 'k1', 'selector1', 'selector2', 'dkim']
        for selector in dkim_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                txt_records = self.resolver.resolve(dkim_domain, 'TXT')
                for rdata in txt_records:
                    txt = str(rdata).strip('"')
                    if 'p=' in txt:
                        security['dkim']['present'] = True
                        security['dkim']['records'].append({
                            'selector': selector,
                            'record': txt[:100] + '...'
                        })
                        self.logger.success(f"DKIM record found (selector: {selector})")
            except Exception:
                pass
        
        return security
    
    def scan_domain(self, domain: str, check_zone_transfer: bool = True,
                   enumerate_subs: bool = False, wordlist: Optional[str] = None,
                   check_records: bool = True) -> Dict:
        """
        Comprehensive domain scan
        Returns: Dictionary with all scan results
        """
        self.logger.info(f"Starting scan for: {Colors.CYAN}{domain}{Colors.RESET}")
        
        scan_results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'nameservers': [],
            'zone_transfers': [],
            'subdomains': [],
            'dns_records': {},
            'email_security': {},
            'vulnerabilities': []
        }
        
        # Get nameservers
        nameservers = self.get_nameservers(domain)
        if not nameservers:
            self.logger.error(f"No nameservers found for {domain}")
            return scan_results
        
        scan_results['nameservers'] = [{'name': ns, 'ip': ip} for ns, ip in nameservers]
        self.logger.success(f"Found {len(nameservers)} nameserver(s)")
        for ns, ip in nameservers:
            self.logger.info(f"  - {ns} ({ip})")
        
        # Test zone transfer
        if check_zone_transfer:
            self.logger.info("Testing zone transfer vulnerability...")
            for ns_name, ns_ip in nameservers:
                result = self.test_zone_transfer(domain, ns_name, ns_ip)
                scan_results['zone_transfers'].append(result)
                if result['vulnerable']:
                    scan_results['vulnerabilities'].append({
                        'type': 'zone_transfer',
                        'severity': 'high',
                        'nameserver': ns_name
                    })
        
        # Enumerate subdomains
        if enumerate_subs and wordlist:
            _, first_ns_ip = nameservers[0] if nameservers else (None, None)
            subdomains = self.enumerate_subdomains(domain, wordlist, first_ns_ip)
            scan_results['subdomains'] = subdomains
        
        # Get DNS records
        if check_records:
            self.logger.info("Collecting DNS records...")
            scan_results['dns_records'] = self.get_dns_records(domain)
            scan_results['email_security'] = self.check_email_security(domain)
        
        return scan_results

class ReportGenerator:
    """Generate reports in various formats"""
    
    @staticmethod
    def generate_text(results: Dict, filepath: str):
        """Generate text report"""
        with open(filepath, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("DNS RECONNAISSANCE REPORT\n")
            f.write(f"Generated by: DNS Recon Toolkit v{__version__}\n")
            f.write(f"Author: @{__author__}\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Domain: {results['domain']}\n")
            f.write(f"Timestamp: {results['timestamp']}\n\n")
            
            # Nameservers
            f.write("NAMESERVERS:\n")
            for ns in results['nameservers']:
                f.write(f"  - {ns['name']} ({ns['ip']})\n")
            f.write("\n")
            
            # Zone Transfer Results
            f.write("ZONE TRANSFER TESTING:\n")
            vulnerable_count = sum(1 for zt in results['zone_transfers'] if zt['vulnerable'])
            if vulnerable_count > 0:
                f.write(f"[!] VULNERABLE: {vulnerable_count} nameserver(s) allow zone transfer\n\n")
                for zt in results['zone_transfers']:
                    if zt['vulnerable']:
                        f.write(f"  [VULN] {zt['nameserver']} ({zt['ns_ip']})\n")
                        f.write(f"         Records exposed: {zt['record_count']}\n\n")
            else:
                f.write("[+] All nameservers protected against zone transfer\n\n")
            
            # Subdomains
            if results.get('subdomains'):
                f.write(f"SUBDOMAINS DISCOVERED: {len(results['subdomains'])}\n")
                for sub in results['subdomains']:
                    f.write(f"  - {sub['subdomain']}: {', '.join(sub['ips'])}\n")
                f.write("\n")
            
            # DNS Records
            if results.get('dns_records'):
                f.write("DNS RECORDS:\n")
                for rtype, records in results['dns_records'].items():
                    if records:
                        f.write(f"  {rtype}:\n")
                        for record in records:
                            f.write(f"    - {record}\n")
                f.write("\n")
            
            # Email Security
            if results.get('email_security'):
                f.write("EMAIL SECURITY:\n")
                es = results['email_security']
                f.write(f"  SPF: {'✓ Present' if es['spf']['present'] else '✗ Missing'}\n")
                f.write(f"  DMARC: {'✓ Present' if es['dmarc']['present'] else '✗ Missing'}\n")
                f.write(f"  DKIM: {'✓ Present' if es['dkim']['present'] else '✗ Missing'}\n")
                f.write("\n")
            
            f.write("=" * 80 + "\n")
            f.write("End of Report\n")
    
    @staticmethod
    def generate_json(results: Dict, filepath: str):
        """Generate JSON report"""
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
    
    @staticmethod
    def generate_html(results: Dict, filepath: str):
        """Generate HTML report"""
        vulnerable_zt = sum(1 for zt in results['zone_transfers'] if zt['vulnerable'])
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Recon Report - {results['domain']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e27; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #1a1f3a; border-radius: 10px; padding: 30px; box-shadow: 0 10px 40px rgba(0,0,0,0.5); }}
        .header {{ text-align: center; border-bottom: 3px solid #00d9ff; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #00d9ff; font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ color: #888; }}
        .section {{ margin: 30px 0; padding: 20px; background: #252a4a; border-radius: 8px; border-left: 4px solid #00d9ff; }}
        .section h2 {{ color: #00d9ff; margin-bottom: 15px; }}
        .vulnerable {{ background: #ff4444; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .safe {{ background: #44ff44; color: #000; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .info {{ background: #4444ff; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .record {{ background: #2d3555; padding: 10px; margin: 5px 0; border-radius: 4px; }}
        .record-type {{ color: #00d9ff; font-weight: bold; }}
        .subdomain {{ padding: 8px; margin: 5px 0; background: #2d3555; border-radius: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #3d4566; }}
        th {{ background: #2d3555; color: #00d9ff; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #3d4566; color: #888; }}
        .badge {{ display: inline-block; padding: 5px 10px; border-radius: 3px; font-size: 0.9em; margin: 5px; }}
        .badge-high {{ background: #ff4444; }}
        .badge-medium {{ background: #ffaa00; }}
        .badge-low {{ background: #00d9ff; }}
        .badge-safe {{ background: #44ff44; color: #000; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ DNS Reconnaissance Report</h1>
            <p>Generated by DNS Recon Toolkit v{__version__} | Author: @{__author__}</p>
            <p><strong>Domain:</strong> {results['domain']} | <strong>Date:</strong> {results['timestamp']}</p>
        </div>
        
        <div class="section">
            <h2>📊 Summary</h2>
            <p><strong>Nameservers Found:</strong> {len(results['nameservers'])}</p>
            <p><strong>Zone Transfer Vulnerable:</strong> {vulnerable_zt}</p>
            <p><strong>Subdomains Discovered:</strong> {len(results.get('subdomains', []))}</p>
            <p><strong>Total Vulnerabilities:</strong> {len(results.get('vulnerabilities', []))}</p>
        </div>
        
        <div class="section">
            <h2>🌐 Nameservers</h2>
            <table>
                <tr><th>Nameserver</th><th>IP Address</th></tr>
                {''.join(f"<tr><td>{ns['name']}</td><td>{ns['ip']}</td></tr>" for ns in results['nameservers'])}
            </table>
        </div>
        
        <div class="section">
            <h2>🔥 Zone Transfer Vulnerability</h2>
            {f'<div class="vulnerable"><strong>⚠️ VULNERABLE:</strong> {vulnerable_zt} nameserver(s) allow unauthorized zone transfer!</div>' if vulnerable_zt > 0 else '<div class="safe"><strong>✓ SAFE:</strong> All nameservers are protected against zone transfer</div>'}
            {''.join(f'<div class="record"><strong>{zt["nameserver"]}</strong> ({zt["ns_ip"]})<br>Status: <span class="badge badge-high">VULNERABLE</span><br>Records Exposed: {zt["record_count"]}</div>' if zt['vulnerable'] else '' for zt in results['zone_transfers'])}
        </div>
        
        {f'''<div class="section">
            <h2>🔍 Subdomains ({len(results.get('subdomains', []))})</h2>
            {''.join(f'<div class="subdomain"><strong>{sub["subdomain"]}</strong> → {", ".join(sub["ips"])}</div>' for sub in results.get('subdomains', []))}
        </div>''' if results.get('subdomains') else ''}
        
        <div class="footer">
            <p>Made with ❤️ by <strong>notbside</strong></p>
            <p>DNS Recon Toolkit | <a href="https://github.com/notbside" style="color: #00d9ff;">GitHub</a></p>
        </div>
    </div>
</body>
</html>"""
        
        with open(filepath, 'w') as f:
            f.write(html)

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
    sys.exit(0)

def main():
    """Main entry point"""
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="DNS Recon Toolkit - Professional DNS Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s -d example.com --zone-transfer
  %(prog)s -f domains.txt -o results/ -t 20
  %(prog)s -d example.com --all -w wordlist.txt
  %(prog)s -d example.com --format json,html -o report

Author: @{__author__}
Version: {__version__}
License: {__license__}
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-d', '--domain', help='Single domain to scan')
    target_group.add_argument('-f', '--file', help='File containing list of domains')
    
    # Scan options
    parser.add_argument('-zt', '--zone-transfer', action='store_true', 
                       help='Test for zone transfer vulnerability')
    parser.add_argument('-se', '--subdomains', action='store_true',
                       help='Enumerate subdomains')
    parser.add_argument('-w', '--wordlist', 
                       help='Wordlist for subdomain enumeration')
    parser.add_argument('-dr', '--dns-records', action='store_true',
                       help='Collect DNS records')
    parser.add_argument('-a', '--all', action='store_true',
                       help='Run all checks')
    
    # Performance options
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='DNS query timeout in seconds (default: 10)')
    parser.add_argument('-r', '--resolver', 
                       help='Custom DNS resolver IP')
    
    # Output options
    parser.add_argument('-o', '--output', default='dns_recon_report',
                       help='Output file path (without extension)')
    parser.add_argument('--format', default='text,json,html',
                       help='Report format: text,json,html (default: all)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('-s', '--silent', action='store_true',
                       help='Silent mode (minimal output)')
    parser.add_argument('--no-banner', action='store_true',
                       help='Disable banner')
    
    args = parser.parse_args()
    
    # Show banner
    if not args.no_banner and not args.silent:
        Banner.show()
    
    # Initialize logger
    logger = Logger(verbose=args.verbose, silent=args.silent)
    
    # Determine scan options
    if args.all:
        check_zt = True
        enum_subs = True
        check_records = True
        if not args.wordlist:
            logger.warning("No wordlist specified, subdomain enumeration will be skipped")
            enum_subs = False
    else:
        check_zt = args.zone_transfer
        enum_subs = args.subdomains
        check_records = args.dns_records
    
    # Initialize DNS Recon
    recon = DNSRecon(logger, threads=args.threads, timeout=args.timeout, resolver=args.resolver)
    
    # Get domains list
    if args.domain:
        domains = [args.domain]
    else:
        try:
            with open(args.file, 'r') as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            logger.error(f"File not found: {args.file}")
            sys.exit(1)
    
    logger.success(f"Loaded {len(domains)} domain(s) for scanning")
    
    # Scan domains
    all_results = []
    for domain in domains:
        result = recon.scan_domain(
            domain,
            check_zone_transfer=check_zt,
            enumerate_subs=enum_subs,
            wordlist=args.wordlist,
            check_records=check_records
        )
        all_results.append(result)
    
    # Generate reports
    formats = args.format.split(',')
    logger.info("Generating reports...")
    
    for fmt in formats:
        fmt = fmt.strip().lower()
        if fmt == 'text':
            filepath = f"{args.output}.txt"
            ReportGenerator.generate_text(all_results[0], filepath)
            logger.success(f"Text report saved: {filepath}")
        elif fmt == 'json':
            filepath = f"{args.output}.json"
            ReportGenerator.generate_json(all_results[0], filepath)
            logger.success(f"JSON report saved: {filepath}")
        elif fmt == 'html':
            filepath = f"{args.output}.html"
            ReportGenerator.generate_html(all_results[0], filepath)
            logger.success(f"HTML report saved: {filepath}")
    
    logger.success("Scan completed!")

if __name__ == "__main__":
    main()
