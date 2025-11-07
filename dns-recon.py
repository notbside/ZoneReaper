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
                
                self.logger.vuln(f"    [!] VULNERABLE on {nameserver}! {result['record_count']} records exposed")
                self.results['vulnerabilities'].append({
                    'type': 'zone_transfer',
                    'severity': 'high',
                    'domain': domain,
                    'nameserver': nameserver,
                    'details': f"{result['record_count']} DNS records exposed"
                })
        
        except dns.exception.FormError:
            result['error'] = "Transfer refused (FormError)"
            self.logger.success(f"    [✓] Protected on {nameserver}")
        except dns.query.TransferError as e:
            result['error'] = f"Transfer error: {str(e)}"
            self.logger.success(f"    [✓] Protected on {nameserver} - {str(e)}")
        except socket.timeout:
            result['error'] = "Connection timeout"
            self.logger.warning(f"    [?] Timeout on {nameserver}")
        except Exception as e:
            result['error'] = str(e)
            self.logger.debug(f"    [?] Error on {nameserver}: {e}")
        
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
                self.logger.info(f"  Testing: {ns_name}")
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
    def create_report_structure(base_dir: str, vulnerable_domains: list) -> str:
        """
        Create organized report directory structure
        Returns: report directory path
        """
        from datetime import datetime
        import os
        
        # Create timestamped report directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = os.path.join(base_dir, f"scan_report_{timestamp}")
        os.makedirs(report_dir, exist_ok=True)
        
        # Create subdirectories for each vulnerable domain
        for vuln in vulnerable_domains:
            domain_dir = os.path.join(report_dir, vuln['domain'].replace('.', '_'))
            os.makedirs(domain_dir, exist_ok=True)
        
        return report_dir
    
    @staticmethod
    def save_subdomain_list(domain_dir: str, records: list, domain: str):
        """Save subdomain list in TXT format"""
        filepath = os.path.join(domain_dir, "subdomains.txt")
        
        with open(filepath, 'w') as f:
            f.write(f"# Subdomains found via Zone Transfer\n")
            f.write(f"# Domain: {domain}\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total Records: {len(records)}\n")
            f.write("#" + "=" * 60 + "\n\n")
            
            # Group by record type
            a_records = []
            cname_records = []
            mx_records = []
            txt_records = []
            other_records = []
            
            for record in records:
                name = record.get('name', '')
                rtype = record.get('type', '')
                value = record.get('value', '')
                
                if rtype == 'A':
                    a_records.append(f"{name:<50} {value}")
                elif rtype == 'CNAME':
                    cname_records.append(f"{name:<50} -> {value}")
                elif rtype == 'MX':
                    mx_records.append(f"{name:<50} -> {value}")
                elif rtype == 'TXT':
                    txt_records.append(f"{name:<50} = {value}")
                else:
                    other_records.append(f"{name:<50} ({rtype}) {value}")
            
            # Write A records (subdomains with IPs)
            if a_records:
                f.write("# A RECORDS (Subdomains with IP addresses)\n")
                f.write("-" * 80 + "\n")
                for record in sorted(a_records):
                    f.write(record + "\n")
                f.write("\n")
            
            # Write CNAME records
            if cname_records:
                f.write("# CNAME RECORDS (Aliases)\n")
                f.write("-" * 80 + "\n")
                for record in sorted(cname_records):
                    f.write(record + "\n")
                f.write("\n")
            
            # Write MX records
            if mx_records:
                f.write("# MX RECORDS (Mail servers)\n")
                f.write("-" * 80 + "\n")
                for record in sorted(mx_records):
                    f.write(record + "\n")
                f.write("\n")
            
            # Write TXT records
            if txt_records:
                f.write("# TXT RECORDS\n")
                f.write("-" * 80 + "\n")
                for record in txt_records:
                    f.write(record + "\n")
                f.write("\n")
            
            # Write other records
            if other_records:
                f.write("# OTHER RECORDS\n")
                f.write("-" * 80 + "\n")
                for record in sorted(other_records):
                    f.write(record + "\n")
                f.write("\n")
    
    @staticmethod
    def generate_professional_html(domain_dir: str, domain: str, nameserver: str, 
                                   records: list, record_count: int):
        """Generate minimalist professional HTML report with modern design"""
        filepath = os.path.join(domain_dir, "report.html")
        
        # Count record types
        record_types = {}
        for record in records:
            rtype = record.get('type', 'UNKNOWN')
            record_types[rtype] = record_types.get(rtype, 0) + 1
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {domain}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f8f9fa;
            color: #1a1a1a;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            border-radius: 16px;
            padding: 48px;
            margin-bottom: 32px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 400px;
            height: 400px;
            background: radial-gradient(circle, rgba(59, 130, 246, 0.1) 0%, transparent 70%);
        }}
        
        .header-content {{
            position: relative;
            z-index: 1;
        }}
        
        .badge {{
            display: inline-block;
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 16px;
        }}
        
        .header h1 {{
            font-size: 36px;
            font-weight: 700;
            color: white;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }}
        
        .header p {{
            color: #94a3b8;
            font-size: 16px;
            font-weight: 400;
        }}
        
        .alert {{
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            border-left: 4px solid #f59e0b;
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 32px;
            box-shadow: 0 2px 4px rgba(245, 158, 11, 0.1);
        }}
        
        .alert-icon {{
            font-size: 24px;
            margin-bottom: 8px;
        }}
        
        .alert h3 {{
            color: #92400e;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        
        .alert p {{
            color: #78350f;
            font-size: 14px;
            line-height: 1.7;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 24px;
            margin-bottom: 32px;
        }}
        
        .stat-card {{
            background: white;
            border-radius: 12px;
            padding: 28px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
            border: 1px solid #e5e7eb;
            transition: all 0.2s;
        }}
        
        .stat-card:hover {{
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            transform: translateY(-2px);
        }}
        
        .stat-card .label {{
            font-size: 13px;
            font-weight: 500;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }}
        
        .stat-card .value {{
            font-size: 28px;
            font-weight: 700;
            color: #111827;
            word-break: break-all;
        }}
        
        .stat-card .icon {{
            width: 40px;
            height: 40px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            margin-bottom: 16px;
        }}
        
        .icon-primary {{ background: #eff6ff; color: #3b82f6; }}
        .icon-danger {{ background: #fef2f2; color: #ef4444; }}
        .icon-success {{ background: #f0fdf4; color: #10b981; }}
        .icon-warning {{ background: #fffbeb; color: #f59e0b; }}
        
        .section {{
            background: white;
            border-radius: 12px;
            padding: 32px;
            margin-bottom: 32px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
            border: 1px solid #e5e7eb;
        }}
        
        .section-title {{
            font-size: 20px;
            font-weight: 700;
            color: #111827;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .section-title::before {{
            content: '';
            width: 4px;
            height: 24px;
            background: linear-gradient(to bottom, #3b82f6, #2563eb);
            border-radius: 2px;
        }}
        
        .type-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        
        .type-box {{
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            transition: all 0.2s;
        }}
        
        .type-box:hover {{
            background: white;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }}
        
        .type-box .number {{
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 6px;
        }}
        
        .type-box .label {{
            font-size: 12px;
            font-weight: 600;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .type-box.type-a .number {{ color: #10b981; }}
        .type-box.type-cname .number {{ color: #3b82f6; }}
        .type-box.type-mx .number {{ color: #f59e0b; }}
        .type-box.type-txt .number {{ color: #8b5cf6; }}
        .type-box.type-ns .number {{ color: #06b6d4; }}
        .type-box.type-soa .number {{ color: #6366f1; }}
        .type-box.type-default .number {{ color: #6b7280; }}
        
        .table-container {{
            overflow-x: auto;
            border-radius: 8px;
            border: 1px solid #e5e7eb;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}
        
        thead {{
            background: #f9fafb;
            border-bottom: 2px solid #e5e7eb;
        }}
        
        th {{
            padding: 16px;
            text-align: left;
            font-size: 12px;
            font-weight: 600;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        td {{
            padding: 16px;
            border-bottom: 1px solid #f3f4f6;
            color: #374151;
            font-size: 14px;
        }}
        
        tbody tr:hover {{
            background: #f9fafb;
        }}
        
        tbody tr:last-child td {{
            border-bottom: none;
        }}
        
        .record-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.3px;
        }}
        
        .record-badge.A {{ background: #d1fae5; color: #065f46; }}
        .record-badge.CNAME {{ background: #dbeafe; color: #1e40af; }}
        .record-badge.MX {{ background: #fed7aa; color: #92400e; }}
        .record-badge.TXT {{ background: #ede9fe; color: #5b21b6; }}
        .record-badge.NS {{ background: #cffafe; color: #155e75; }}
        .record-badge.SOA {{ background: #e0e7ff; color: #3730a3; }}
        .record-badge.default {{ background: #f3f4f6; color: #374151; }}
        
        .footer {{
            text-align: center;
            padding: 32px;
            color: #6b7280;
            font-size: 14px;
        }}
        
        .footer strong {{
            color: #111827;
        }}
        
        .footer-links {{
            margin-top: 12px;
            display: flex;
            justify-content: center;
            gap: 24px;
        }}
        
        .footer-links a {{
            color: #3b82f6;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s;
        }}
        
        .footer-links a:hover {{
            color: #2563eb;
        }}
        
        @media (max-width: 768px) {{
            .header {{ padding: 32px 24px; }}
            .header h1 {{ font-size: 28px; }}
            .section {{ padding: 24px 20px; }}
            .stats-grid {{ grid-template-columns: 1fr; }}
            .type-stats {{ grid-template-columns: repeat(2, 1fr); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div class="badge">⚠️ Critical Vulnerability</div>
                <h1>DNS Zone Transfer Detected</h1>
                <p>Comprehensive security assessment for {domain}</p>
            </div>
        </div>
        
        <div class="alert">
            <div class="alert-icon">🛡️</div>
            <h3>Security Impact Analysis</h3>
            <p>This nameserver permits unauthorized DNS zone transfers, exposing your complete internal DNS infrastructure. Attackers can leverage this information to map network topology, discover hidden services, identify internal IP addresses, and orchestrate targeted attacks against your infrastructure.</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="icon icon-primary">🌐</div>
                <div class="label">Target Domain</div>
                <div class="value">{domain}</div>
            </div>
            <div class="stat-card">
                <div class="icon icon-danger">🖥️</div>
                <div class="label">Vulnerable Server</div>
                <div class="value" style="font-size: 18px;">{nameserver}</div>
            </div>
            <div class="stat-card">
                <div class="icon icon-warning">📊</div>
                <div class="label">Records Exposed</div>
                <div class="value">{record_count}</div>
            </div>
            <div class="stat-card">
                <div class="icon icon-success">📅</div>
                <div class="label">Scan Date</div>
                <div class="value" style="font-size: 18px;">{datetime.now().strftime('%Y-%m-%d')}</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">📈 Record Distribution</div>
            <div class="type-stats">
"""
        
        # Add record type stats
        for rtype, count in sorted(record_types.items(), key=lambda x: x[1], reverse=True):
            type_class = f"type-{rtype.lower()}" if rtype in ['A', 'CNAME', 'MX', 'TXT', 'NS', 'SOA'] else "type-default"
            html += f"""
                <div class="type-box {type_class}">
                    <div class="number">{count}</div>
                    <div class="label">{rtype}</div>
                </div>
"""
        
        html += """
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">📋 Exposed DNS Records</div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Record Name</th>
                            <th>Value</th>
                            <th>TTL</th>
                        </tr>
                    </thead>
                    <tbody>
"""
        
        # Add records to table
        for record in sorted(records, key=lambda x: (x.get('type', ''), x.get('name', ''))):
            rtype = record.get('type', 'UNKNOWN')
            name = record.get('name', '')
            value = record.get('value', '')
            ttl = record.get('ttl', 0)
            
            badge_class = rtype if rtype in ['A', 'CNAME', 'MX', 'TXT', 'NS', 'SOA'] else "default"
            
            html += f"""
                        <tr>
                            <td><span class="record-badge {badge_class}">{rtype}</span></td>
                            <td style="font-family: 'Monaco', 'Courier New', monospace; font-size: 13px;">{name}</td>
                            <td style="font-family: 'Monaco', 'Courier New', monospace; font-size: 13px; color: #6b7280;">{value}</td>
                            <td style="color: #9ca3af;">{ttl}s</td>
                        </tr>
"""
        
        html += f"""
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>ZoneReaper Security Assessment</strong></p>
            <p>Professional DNS vulnerability scanner by @notbside</p>
            <div class="footer-links">
                <a href="https://github.com/notbside/ZoneReaper">GitHub</a>
                <a href="#">Documentation</a>
                <a href="#">Report Issue</a>
            </div>
            <p style="margin-top: 16px; font-size: 13px; color: #9ca3af;">
                Generated on {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}
            </p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w') as f:
            f.write(html)
    
    @staticmethod
    def generate_index_html(report_dir: str, vulnerable_domains: list, 
                           total_domains: int, protected_count: int, error_count: int):
        """Generate main index.html with modern overview"""
        filepath = os.path.join(report_dir, "index.html")
        
        total_records = sum(v['records'] for v in vulnerable_domains)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Security Scan Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f8f9fa;
            color: #1a1a1a;
            min-height: 100vh;
            padding: 40px 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            margin-bottom: 48px;
        }}
        
        .logo {{
            width: 64px;
            height: 64px;
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            border-radius: 16px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            margin-bottom: 24px;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }}
        
        .header h1 {{
            font-size: 42px;
            font-weight: 700;
            color: #111827;
            margin-bottom: 12px;
            letter-spacing: -1px;
        }}
        
        .header p {{
            font-size: 18px;
            color: #6b7280;
            font-weight: 400;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 24px;
            margin-bottom: 48px;
        }}
        
        .stat-card {{
            background: white;
            border-radius: 16px;
            padding: 32px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
            border: 1px solid #e5e7eb;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--accent-color);
        }}
        
        .stat-card:hover {{
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
            transform: translateY(-4px);
        }}
        
        .stat-card .icon {{
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            margin-bottom: 16px;
        }}
        
        .stat-card .number {{
            font-size: 40px;
            font-weight: 700;
            margin-bottom: 8px;
            color: #111827;
        }}
        
        .stat-card .label {{
            font-size: 14px;
            font-weight: 500;
            color: #6b7280;
        }}
        
        .stat-card.primary {{ --accent-color: #3b82f6; }}
        .stat-card.primary .icon {{ background: #eff6ff; color: #3b82f6; }}
        
        .stat-card.danger {{ --accent-color: #ef4444; }}
        .stat-card.danger .icon {{ background: #fef2f2; color: #ef4444; }}
        .stat-card.danger .number {{ color: #ef4444; }}
        
        .stat-card.success {{ --accent-color: #10b981; }}
        .stat-card.success .icon {{ background: #f0fdf4; color: #10b981; }}
        .stat-card.success .number {{ color: #10b981; }}
        
        .stat-card.warning {{ --accent-color: #f59e0b; }}
        .stat-card.warning .icon {{ background: #fffbeb; color: #f59e0b; }}
        .stat-card.warning .number {{ color: #f59e0b; }}
        
        .section {{
            background: white;
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
            border: 1px solid #e5e7eb;
        }}
        
        .section-header {{
            margin-bottom: 32px;
        }}
        
        .section-header h2 {{
            font-size: 28px;
            font-weight: 700;
            color: #111827;
            margin-bottom: 8px;
        }}
        
        .section-header p {{
            color: #6b7280;
            font-size: 15px;
        }}
        
        .domain-card {{
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-left: 4px solid #ef4444;
            border-radius: 12px;
            padding: 28px;
            margin-bottom: 20px;
            transition: all 0.2s;
        }}
        
        .domain-card:hover {{
            background: white;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);
            transform: translateX(4px);
        }}
        
        .domain-card .domain-name {{
            font-size: 24px;
            font-weight: 700;
            color: #111827;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        .domain-card .domain-name::before {{
            content: '⚠️';
            font-size: 20px;
        }}
        
        .domain-card .meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        
        .meta-item {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px;
            background: white;
            border-radius: 8px;
            border: 1px solid #e5e7eb;
        }}
        
        .meta-item .icon {{
            font-size: 18px;
        }}
        
        .meta-item .text {{
            flex: 1;
        }}
        
        .meta-item .label {{
            font-size: 11px;
            font-weight: 600;
            color: #9ca3af;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: block;
            margin-bottom: 2px;
        }}
        
        .meta-item .value {{
            font-size: 14px;
            font-weight: 600;
            color: #374151;
        }}
        
        .actions {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }}
        
        .btn {{
            padding: 12px 24px;
            border-radius: 10px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: none;
            cursor: pointer;
        }}
        
        .btn-primary {{
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: white;
            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3);
        }}
        
        .btn-primary:hover {{
            box-shadow: 0 4px 16px rgba(59, 130, 246, 0.4);
            transform: translateY(-2px);
        }}
        
        .btn-secondary {{
            background: white;
            color: #3b82f6;
            border: 2px solid #3b82f6;
        }}
        
        .btn-secondary:hover {{
            background: #3b82f6;
            color: white;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 48px;
            padding: 32px;
            color: #6b7280;
            font-size: 14px;
        }}
        
        .footer strong {{
            color: #111827;
        }}
        
        .footer-links {{
            margin-top: 16px;
            display: flex;
            justify-content: center;
            gap: 24px;
        }}
        
        .footer-links a {{
            color: #3b82f6;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s;
        }}
        
        .footer-links a:hover {{
            color: #2563eb;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{ font-size: 32px; }}
            .stats-grid {{ grid-template-columns: 1fr; }}
            .section {{ padding: 24px 20px; }}
            .domain-card {{ padding: 20px; }}
            .domain-card .meta {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️</div>
            <h1>DNS Security Assessment</h1>
            <p>Comprehensive zone transfer vulnerability analysis</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card primary">
                <div class="icon">📊</div>
                <div class="number">{total_domains}</div>
                <div class="label">Total Domains Scanned</div>
            </div>
            
            <div class="stat-card danger">
                <div class="icon">⚠️</div>
                <div class="number">{len(vulnerable_domains)}</div>
                <div class="label">Vulnerable Domains Found</div>
            </div>
            
            <div class="stat-card success">
                <div class="icon">✅</div>
                <div class="number">{protected_count}</div>
                <div class="label">Protected Domains</div>
            </div>
            
            <div class="stat-card warning">
                <div class="icon">📋</div>
                <div class="number">{total_records}</div>
                <div class="label">Total Records Exposed</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <h2>Vulnerable Domains ({len(vulnerable_domains)})</h2>
                <p>Critical security findings requiring immediate attention</p>
            </div>
"""
        
        for vuln in vulnerable_domains:
            domain_folder = vuln['domain'].replace('.', '_')
            html += f"""
            <div class="domain-card">
                <div class="domain-name">{vuln['domain']}</div>
                
                <div class="meta">
                    <div class="meta-item">
                        <div class="icon">🖥️</div>
                        <div class="text">
                            <span class="label">Nameserver</span>
                            <span class="value">{vuln['nameserver']}</span>
                        </div>
                    </div>
                    
                    <div class="meta-item">
                        <div class="icon">📊</div>
                        <div class="text">
                            <span class="label">Records</span>
                            <span class="value">{vuln['records']} exposed</span>
                        </div>
                    </div>
                    
                    <div class="meta-item">
                        <div class="icon">🔴</div>
                        <div class="text">
                            <span class="label">Severity</span>
                            <span class="value">High Risk</span>
                        </div>
                    </div>
                </div>
                
                <div class="actions">
                    <a href="{domain_folder}/report.html" class="btn btn-primary">
                        📄 View Full Report
                    </a>
                    <a href="{domain_folder}/subdomains.txt" class="btn btn-secondary">
                        📥 Download Subdomains
                    </a>
                </div>
            </div>
"""
        
        html += f"""
        </div>
        
        <div class="footer">
            <p><strong>ZoneReaper Security Assessment Toolkit</strong></p>
            <p>Professional DNS vulnerability scanner</p>
            <div class="footer-links">
                <a href="https://github.com/notbside/ZoneReaper">GitHub</a>
                <a href="#">Documentation</a>
                <a href="mailto:notbside@proton.me">Contact</a>
            </div>
            <p style="margin-top: 16px; color: #9ca3af;">
                Generated by @notbside • {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}
            </p>
        </div>
    </div>
</body>
</html>
"""
        
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
        # If no specific options given, default to zone transfer only
        if not args.zone_transfer and not args.subdomains and not args.dns_records:
            check_zt = True  # Default behavior
            enum_subs = False
            check_records = False
            logger.info("No scan type specified, defaulting to zone transfer test")
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
    
    # Calculate statistics
    total_domains = len(all_results)
    vulnerable_domains = []
    protected_domains = []
    error_domains = []
    total_records_exposed = 0
    
    for result in all_results:
        domain_vulnerable = False
        if result.get('zone_transfers'):
            for zt in result['zone_transfers']:
                if zt.get('vulnerable'):
                    domain_vulnerable = True
                    total_records_exposed += zt.get('record_count', 0)
                    if result['domain'] not in vulnerable_domains:
                        vulnerable_domains.append({
                            'domain': result['domain'],
                            'nameserver': zt['nameserver'],
                            'records': zt['record_count']
                        })
        
        if not domain_vulnerable and result.get('nameservers'):
            protected_domains.append(result['domain'])
        elif not result.get('nameservers'):
            error_domains.append(result['domain'])
    
    # Print summary
    print("")
    print("=" * 80)
    logger.info(f"{Colors.CYAN}{Colors.BRIGHT}SCAN SUMMARY{Colors.RESET}")
    print("=" * 80)
    print("")
    logger.info(f"Total domains scanned: {Colors.CYAN}{total_domains}{Colors.RESET}")
    logger.error(f"Vulnerable domains: {Colors.RED}{Colors.BRIGHT}{len(vulnerable_domains)}{Colors.RESET}")
    logger.success(f"Protected domains: {Colors.GREEN}{len(protected_domains)}{Colors.RESET}")
    if error_domains:
        logger.warning(f"Errors/Not found: {Colors.YELLOW}{len(error_domains)}{Colors.RESET}")
    print("")
    
    if vulnerable_domains:
        print("=" * 80)
        logger.vuln(f"{Colors.RED}{Colors.BRIGHT}VULNERABLE DOMAINS FOUND:{Colors.RESET}")
        print("=" * 80)
        for vuln in vulnerable_domains:
            logger.vuln(f"  • {Colors.RED}{vuln['domain']}{Colors.RESET}")
            logger.info(f"    └─ Nameserver: {vuln['nameserver']}")
            logger.info(f"    └─ Records exposed: {Colors.RED}{vuln['records']}{Colors.RESET}")
        print("")
        logger.warning(f"Total records exposed: {Colors.RED}{Colors.BRIGHT}{total_records_exposed}{Colors.RESET}")
        print("")
        print("=" * 80)
        logger.warning(f"{Colors.YELLOW}⚠️  ACTION REQUIRED:{Colors.RESET}")
        print("=" * 80)
        logger.warning("  1. Report to CERT.uz: info@cert.uz")
        logger.warning("  2. Contact domain owners immediately")
        logger.warning("  3. Follow responsible disclosure (90 days)")
        logger.warning("  4. Document all findings")
        
        # Generate professional structured reports
        print("")
        print("=" * 80)
        logger.info(f"{Colors.CYAN}Generating professional reports...{Colors.RESET}")
        print("=" * 80)
        print("")
        
        # Create report structure
        report_dir = ReportGenerator.create_report_structure(args.output if args.output != 'dns_recon_report' else 'reports', vulnerable_domains)
        logger.success(f"Report directory: {Colors.CYAN}{report_dir}{Colors.RESET}")
        print("")
        
        # Generate reports for each vulnerable domain
        for result in all_results:
            if result.get('zone_transfers'):
                for zt in result['zone_transfers']:
                    if zt.get('vulnerable') and zt.get('records'):
                        domain = result['domain']
                        domain_folder = domain.replace('.', '_')
                        domain_dir = os.path.join(report_dir, domain_folder)
                        
                        logger.info(f"Processing: {Colors.CYAN}{domain}{Colors.RESET}")
                        
                        # Save subdomain list (TXT)
                        ReportGenerator.save_subdomain_list(domain_dir, zt['records'], domain)
                        logger.success(f"  ✓ Subdomains list: {domain_folder}/subdomains.txt")
                        
                        # Generate professional HTML report
                        ReportGenerator.generate_professional_html(
                            domain_dir,
                            domain,
                            zt['nameserver'],
                            zt['records'],
                            zt['record_count']
                        )
                        logger.success(f"  ✓ HTML report: {domain_folder}/report.html")
        
        print("")
        
        # Generate main index.html
        ReportGenerator.generate_index_html(
            report_dir,
            vulnerable_domains,
            total_domains,
            len(protected_domains),
            len(error_domains)
        )
        logger.success(f"✓ Main index: {Colors.GREEN}index.html{Colors.RESET}")
        
        print("")
        print("=" * 80)
        logger.success(f"{Colors.GREEN}{Colors.BRIGHT}✓ REPORTS GENERATED SUCCESSFULLY!{Colors.RESET}")
        print("=" * 80)
        print("")
        logger.info(f"Open in browser: {Colors.CYAN}file://{os.path.abspath(report_dir)}/index.html{Colors.RESET}")
        
    else:
        print("=" * 80)
        logger.success(f"{Colors.GREEN}{Colors.BRIGHT}✓ NO VULNERABILITIES FOUND!{Colors.RESET}")
        print("=" * 80)
        logger.success("All tested domains are properly protected against zone transfer attacks.")
    
    print("")
    print("=" * 80)
    logger.success(f"{Colors.GREEN}{Colors.BRIGHT}Scan completed!{Colors.RESET}")
    
    # Exit code based on vulnerabilities
    if vulnerable_domains:
        sys.exit(1)  # Exit with error code if vulnerabilities found
    else:
        sys.exit(0)  # Exit successfully

if __name__ == "__main__":
    main()
