#!/usr/bin/env python3
"""
███████╗███████╗ █████╗ ██████╗ ███████╗██████╗ ██████╗  ██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝
█████╗  █████╗  ███████║██║  ██║█████╗  ██████╔╝██████╔╝██║   ██║███████╗
██╔══╝  ██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗██╔══██╗██║   ██║╚════██║
██║     ███████╗██║  ██║██████╔╝███████╗██║  ██║██║  ██║╚██████╔╝███████║
╚═╝     ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝

HeaderForge Pro - Advanced HTTP Header Security Analyzer
Version: 3.0.0 | Author: Security Research Team
"""

import sys
import time
import json
import csv
import random
import hashlib
import socket
import ssl
import base64
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, quote
from enum import Enum
from pathlib import Path
import re

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from colorama import init, Fore, Back, Style
import dns.resolver
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import urllib3

# Disable warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

class ScanMode(Enum):
    """Scanning modes"""
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"
    STEALTH = "stealth"

class ThreatLevel(Enum):
    """Threat level classification"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class SecurityFinding:
    """Security finding data structure"""
    id: str
    title: str
    description: str
    threat_level: ThreatLevel
    impact: str
    remediation: str
    evidence: str
    cwe: str
    cvss_score: float
    references: List[str]

@dataclass
class HeaderResult:
    """Header test result"""
    header_name: str
    header_value: str
    status_code: int
    response_size: int
    response_time: float
    headers_received: Dict[str, str]
    body_hash: str
    anomalies: List[str]
    redirect_chain: List[str]
    differences: Dict[str, Any]

class WAFDetector:
    """WAF Detection Engine"""
    
    WAF_SIGNATURES = {
        'Cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status', 'server.*cloudflare'],
        'Akamai': ['akamai.*', 'x-akamai-', 'akamaighost'],
        'Imperva': ['incap_ses_', 'visid_incap_'],
        'AWS WAF': ['x-amz-cf-', 'x-amzn-', 'server.*aws'],
        'ModSecurity': ['mod_security', 'nosniff'],
        'F5 BIG-IP': ['BIGipServer', 'F5', 'X-Cnection'],
        'Barracuda': ['barracuda'],
        'Citrix Netscaler': ['ns_afs', 'citrix'],
        'Sucuri': ['sucuri/cloudproxy'],
        'Wordfence': ['wordfence_verifiedhuman'],
    }
    
    @classmethod
    def detect(cls, response_headers: Dict) -> List[str]:
        """Detect WAF from response headers"""
        detected = []
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        
        for waf, signatures in cls.WAF_SIGNATURES.items():
            for sig in signatures:
                sig_lower = sig.lower()
                for header_name, header_value in headers_lower.items():
                    if sig_lower in header_name or sig_lower in header_value:
                        if waf not in detected:
                            detected.append(waf)
        
        return detected

class FingerprintEngine:
    """Application Fingerprinting Engine"""
    
    TECH_SIGNATURES = {
        'PHP': ['x-powered-by.*php', 'phpsessid', 'php'],
        'ASP.NET': ['x-powered-by.*asp.net', 'x-aspnet-version', 'asp.net'],
        'Java': ['jsessionid', 'x-powered-by.*jsp', 'servlet'],
        'Node.js': ['x-powered-by.*express', 'node.js'],
        'Python': ['python', 'django', 'flask', 'wsgi'],
        'Nginx': ['server.*nginx'],
        'Apache': ['server.*apache', 'x-powered-by.*apache'],
        'IIS': ['server.*iis', 'x-powered-by.*iis'],
    }
    
    @classmethod
    def fingerprint(cls, response_headers: Dict, body: str) -> Dict[str, List[str]]:
        """Fingerprint application technology"""
        findings = {}
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        body_lower = body.lower()
        
        for tech, signatures in cls.TECH_SIGNATURES.items():
            tech_findings = []
            
            # Check headers
            for sig in signatures:
                sig_lower = sig.lower()
                for header_name, header_value in headers_lower.items():
                    if re.search(sig_lower, header_name) or re.search(sig_lower, header_value):
                        tech_findings.append(f"Header match: {sig}")
            
            # Check body
            for sig in signatures:
                if re.search(sig.lower(), body_lower):
                    tech_findings.append(f"Body match: {sig}")
            
            if tech_findings:
                findings[tech] = tech_findings
        
        return findings

class PayloadGenerator:
    """Advanced payload generator for header injection"""
    
    @classmethod
    def generate_ip_spoofing_payloads(cls, target_ip: str) -> List[Tuple[str, str]]:
        """Generate IP spoofing payloads"""
        payloads = []
        
        # Basic spoofing
        payloads.extend([
            (target_ip, "Direct IP"),
            ("127.0.0.1", "Localhost"),
            ("0.0.0.0", "Zero IP"),
            ("255.255.255.255", "Broadcast"),
        ])
        
        # Private ranges
        private_ranges = [
            "10.0.0.1",
            "172.16.0.1", 
            "192.168.1.1",
            "169.254.0.1",  # APIPA
        ]
        
        for ip in private_ranges:
            payloads.append((ip, f"Private: {ip}"))
        
        # IPv6
        ipv6_payloads = [
            ("::1", "IPv6 Localhost"),
            ("2001:db8::1", "IPv6 Documentation"),
            ("fe80::1", "IPv6 Link-local"),
        ]
        
        for ip, desc in ipv6_payloads:
            payloads.append((ip, desc))
        
        # Multiple IPs (comma separated)
        payloads.append(("203.0.113.1, 198.51.100.1", "Multiple IPs"))
        
        # Obfuscated IPs
        payloads.extend([
            ("012.034.056.078", "Octal IP"),
            ("3232235521", "Decimal IP (192.168.1.1)"),
            ("0xC0A80101", "Hex IP (192.168.1.1)"),
        ])
        
        return payloads
    
    @classmethod
    def generate_ssti_payloads(cls) -> List[Tuple[str, str]]:
        """Generate SSTI (Server-Side Template Injection) payloads"""
        return [
            ("{{7*7}}", "Basic SSTI"),
            ("${7*7}", "Expression Language"),
            ("<%= 7*7 %>", "ERB Template"),
            ("#{7*7}", "Ruby Template"),
            ("${{7*7}}", "Nested Expression"),
            ("#{system('id')}", "Ruby System Command"),
            ("{{config}}", "Flask Config"),
            ("{{''.__class__}}", "Python Object Chain"),
        ]
    
    @classmethod
    def generate_xss_payloads(cls) -> List[Tuple[str, str]]:
        """Generate XSS payloads for header injection"""
        return [
            ("<script>alert(1)</script>", "Basic XSS"),
            ("\" onload=\"alert(1)", "Event Handler"),
            ("javascript:alert(1)", "JavaScript URI"),
            ("data:text/html,<script>alert(1)</script>", "Data URI"),
            ("<svg onload=alert(1)>", "SVG XSS"),
            ("<img src=x onerror=alert(1)>", "Image Error"),
        ]
    
    @classmethod
    def generate_sqli_payloads(cls) -> List[Tuple[str, str]]:
        """Generate SQL injection payloads"""
        return [
            ("' OR '1'='1", "Basic SQLi"),
            ("' UNION SELECT NULL--", "Union SQLi"),
            ("' AND 1=CONVERT(int, @@version)--", "Error-based"),
            ("' WAITFOR DELAY '0:0:5'--", "Time-based"),
            ("' OR SLEEP(5)--", "MySQL Time-based"),
            ("' OR pg_sleep(5)--", "PostgreSQL Time-based"),
            ("' OR benchmark(1000000,md5('test'))--", "Benchmark SQLi"),
        ]
    
    @classmethod
    def generate_command_injection_payloads(cls) -> List[Tuple[str, str]]:
        """Generate command injection payloads"""
        return [
            ("; id;", "Basic Command"),
            ("| whoami", "Pipe Command"),
            ("`id`", "Backtick Command"),
            ("$(whoami)", "Dollar Command"),
            ("|| ping -c 10 127.0.0.1 ||", "OR Command"),
            ("& dir &", "Background Command"),
        ]

class SSLScanner:
    """SSL/TLS Configuration Scanner"""
    
    @classmethod
    def scan(cls, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Scan SSL/TLS configuration"""
        results = {
            "hostname": hostname,
            "port": port,
            "certificate": {},
            "protocols": [],
            "ciphers": [],
            "vulnerabilities": [],
        }
        
        try:
            # Get certificate
            cert_pem = ssl.get_server_certificate((hostname, port))
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            
            # Certificate details
            results["certificate"] = {
                "subject": str(cert.subject),
                "issuer": str(cert.issuer),
                "serial_number": str(cert.serial_number),
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "signature_hash_algorithm": cert.signature_hash_algorithm.name,
                "version": cert.version.name,
            }
            
            # Check expiry
            expiry_days = (cert.not_valid_after - datetime.now()).days
            if expiry_days < 30:
                results["vulnerabilities"].append(f"Certificate expires in {expiry_days} days")
            
            # Test protocols
            protocols = {
                "SSLv2": ssl.PROTOCOL_SSLv2,
                "SSLv3": ssl.PROTOCOL_SSLv3,
                "TLSv1": ssl.PROTOCOL_TLSv1,
                "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
                "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
                "TLSv1.3": ssl.PROTOCOL_TLS,
            }
            
            for proto_name, proto_const in protocols.items():
                try:
                    context = ssl.SSLContext(proto_const)
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            results["protocols"].append(proto_name)
                except:
                    pass
            
            # Check weak protocols
            weak_protos = ["SSLv2", "SSLv3", "TLSv1"]
            for proto in weak_protos:
                if proto in results["protocols"]:
                    results["vulnerabilities"].append(f"Weak protocol enabled: {proto}")
                    
        except Exception as e:
            results["error"] = str(e)
        
        return results

class DNSEnumerator:
    """DNS Enumeration and Reconnaissance"""
    
    @classmethod
    def enumerate(cls, domain: str) -> Dict[str, List[str]]:
        """Enumerate DNS records"""
        results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results[record_type] = [str(rdata) for rdata in answers]
            except:
                results[record_type] = []
        
        # Try subdomain enumeration
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev']
        results['subdomains'] = []
        
        for sub in common_subdomains:
            full_domain = f"{sub}.{domain}"
            try:
                dns.resolver.resolve(full_domain, 'A')
                results['subdomains'].append(full_domain)
            except:
                pass
        
        return results

class HeaderForgePro:
    """Main HeaderForge Pro Class"""
    
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.protocol = args.protocol
        self.base_url = f"{self.protocol}://{self.target}"
        self.results = []
        self.findings = []
        self.session = self._create_session()
        self.baseline_response = None
        
        # Initialize engines
        self.waf_detector = WAFDetector()
        self.fingerprint_engine = FingerprintEngine()
        self.payload_generator = PayloadGenerator()
        self.ssl_scanner = SSLScanner()
        self.dns_enumerator = DNSEnumerator()
        
        # Headers database
        self.headers_db = self._load_headers_database()
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'security_findings': 0,
            'start_time': None,
            'end_time': None,
        }
    
    def _create_session(self) -> requests.Session:
        """Create HTTP session with advanced configuration"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=100,
            pool_maxsize=100
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configure proxies if provided
        if self.args.proxy:
            session.proxies = {
                'http': self.args.proxy,
                'https': self.args.proxy,
            }
        
        # Set default headers
        session.headers.update({
            'User-Agent': 'HeaderForge-Pro/3.0 (Security Research)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1',
        })
        
        return session
    
    def _load_headers_database(self) -> Dict[str, Dict]:
        """Load headers database from JSON file"""
        headers_db = {
            # IP Spoofing Headers
            'ip_spoofing': {
                'X-Forwarded-For': 'Client IP through proxies',
                'X-Real-IP': 'Real client IP',
                'X-Originating-IP': 'Originating IP',
                'X-Remote-IP': 'Remote client IP',
                'X-Remote-Addr': 'Remote address',
                'X-Client-IP': 'Client IP',
                'True-Client-IP': 'Akamai real client IP',
                'CF-Connecting-IP': 'Cloudflare client IP',
            },
            
            # Host Headers
            'host_injection': {
                'Host': 'Request host',
                'X-Forwarded-Host': 'Original host',
                'X-Original-Host': 'Original host',
                'X-Host': 'Host override',
            },
            
            # Protocol Headers
            'protocol_injection': {
                'X-Forwarded-Proto': 'Original protocol',
                'X-Forwarded-Scheme': 'Original scheme',
                'X-Url-Scheme': 'URL scheme',
            },
            
            # Auth Headers
            'auth_injection': {
                'Authorization': 'Basic/Digest/Bearer auth',
                'X-API-Key': 'API key',
                'X-Auth-Token': 'Auth token',
                'X-CSRF-Token': 'CSRF token',
                'X-Api-Key': 'Alternative API key',
            },
            
            # Security Headers
            'security_headers': {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing',
                'X-XSS-Protection': 'XSS protection',
                'Content-Security-Policy': 'CSP policy',
                'Strict-Transport-Security': 'HSTS policy',
                'Referrer-Policy': 'Referrer policy',
                'Feature-Policy': 'Feature policy',
                'Permissions-Policy': 'Permissions policy',
            },
            
            # Custom Headers (Dangerous)
            'custom_dangerous': {
                'X-Custom-IP-Authorization': 'Custom IP auth',
                'X-ProxyUser-IP': 'Proxy user IP',
                'X-Original-URL': 'Original URL',
                'X-Rewrite-URL': 'Rewrite URL',
                'X-Original-Method': 'Original method',
                'X-HTTP-Method-Override': 'Method override',
                'X-HTTP-Method': 'HTTP method',
            },
        }
        
        return headers_db
    
    def get_baseline(self):
        """Get baseline response without injected headers"""
        try:
            response = self.session.get(
                self.base_url,
                timeout=self.args.timeout,
                verify=not self.args.insecure,
                allow_redirects=self.args.follow_redirects
            )
            
            self.baseline_response = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text,
                'size': len(response.text),
                'time': response.elapsed.total_seconds(),
                'body_hash': hashlib.md5(response.text.encode()).hexdigest(),
            }
            
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to get baseline: {e}{Style.RESET_ALL}")
            return False
    
    def compare_responses(self, response, baseline) -> Dict[str, Any]:
        """Compare response with baseline"""
        differences = {}
        
        # Status code difference
        if response.status_code != baseline['status_code']:
            differences['status_code'] = {
                'baseline': baseline['status_code'],
                'current': response.status_code
            }
        
        # Size difference (more than 10%)
        size_diff = abs(len(response.text) - baseline['size']) / baseline['size'] * 100
        if size_diff > 10:
            differences['size'] = {
                'baseline': baseline['size'],
                'current': len(response.text),
                'difference_percent': round(size_diff, 2)
            }
        
        # Header differences
        new_headers = set(response.headers.keys()) - set(baseline['headers'].keys())
        missing_headers = set(baseline['headers'].keys()) - set(response.headers.keys())
        
        if new_headers:
            differences['new_headers'] = list(new_headers)
        if missing_headers:
            differences['missing_headers'] = list(missing_headers)
        
        # Body hash difference
        current_hash = hashlib.md5(response.text.encode()).hexdigest()
        if current_hash != baseline['body_hash']:
            differences['body_changed'] = True
        
        # Time difference (more than 100%)
        time_diff = abs(response.elapsed.total_seconds() - baseline['time']) / baseline['time'] * 100
        if time_diff > 100:
            differences['time'] = {
                'baseline': baseline['time'],
                'current': response.elapsed.total_seconds(),
                'difference_percent': round(time_diff, 2)
            }
        
        return differences
    
    def test_header(self, header_name: str, header_value: str) -> Optional[HeaderResult]:
        """Test a single header"""
        try:
            # Prepare request
            headers = {header_name: header_value}
            
            # Add delay for stealth mode
            if self.args.stealth:
                time.sleep(random.uniform(0.5, 2.0))
            
            # Send request
            start_time = time.time()
            response = self.session.get(
                self.base_url,
                headers=headers,
                timeout=self.args.timeout,
                verify=not self.args.insecure,
                allow_redirects=self.args.follow_redirects
            )
            response_time = time.time() - start_time
            
            # Track redirect chain
            redirect_chain = []
            if response.history:
                redirect_chain = [resp.url for resp in response.history]
            redirect_chain.append(response.url)
            
            # Analyze response
            anomalies = []
            
            # Check for interesting status codes
            if response.status_code in [400, 403, 500]:
                anomalies.append(f"Interesting status: {response.status_code}")
            
            # Check for WAF
            waf_detected = self.waf_detector.detect(response.headers)
            if waf_detected:
                anomalies.append(f"WAF detected: {', '.join(waf_detected)}")
            
            # Check for technology
            tech_fingerprint = self.fingerprint_engine.fingerprint(response.headers, response.text)
            if tech_fingerprint:
                anomalies.append(f"Tech detected: {', '.join(tech_fingerprint.keys())}")
            
            # Compare with baseline
            differences = {}
            if self.baseline_response:
                differences = self.compare_responses(response, self.baseline_response)
                if differences:
                    anomalies.append("Significant differences from baseline")
            
            # Create result
            result = HeaderResult(
                header_name=header_name,
                header_value=header_value,
                status_code=response.status_code,
                response_size=len(response.text),
                response_time=response_time,
                headers_received=dict(response.headers),
                body_hash=hashlib.md5(response.text.encode()).hexdigest(),
                anomalies=anomalies,
                redirect_chain=redirect_chain,
                differences=differences
            )
            
            return result
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error testing {header_name}: {e}{Style.RESET_ALL}")
            return None
    
    def run_reconnaissance(self):
        """Run reconnaissance phase"""
        print(f"\n{Fore.CYAN}[*] Starting reconnaissance phase...{Style.RESET_ALL}")
        
        # DNS Enumeration
        print(f"{Fore.YELLOW}[*] Performing DNS enumeration...{Style.RESET_ALL}")
        dns_results = self.dns_enumerator.enumerate(self.target)
        
        # SSL/TLS Scanning
        if self.protocol == 'https':
            print(f"{Fore.YELLOW}[*] Scanning SSL/TLS configuration...{Style.RESET_ALL}")
            ssl_results = self.ssl_scanner.scan(self.target)
        
        # Get baseline
        print(f"{Fore.YELLOW}[*] Establishing baseline...{Style.RESET_ALL}")
        self.get_baseline()
        
        return {
            'dns': dns_results,
            'ssl': ssl_results if self.protocol == 'https' else None,
        }
    
    def run_header_tests(self):
        """Run all header tests"""
        print(f"\n{Fore.CYAN}[*] Starting header injection tests...{Style.RESET_ALL}")
        
        all_tests = []
        
        # Generate test cases
        for category, headers in self.headers_db.items():
            if self.args.category and category not in self.args.category.split(','):
                continue
                
            for header_name, description in headers.items():
                # Generate payloads based on header type
                if category == 'ip_spoofing':
                    payloads = self.payload_generator.generate_ip_spoofing_payloads(self.target)
                elif category == 'host_injection':
                    payloads = [(self.target, 'Target host'), ('evil.com', 'Malicious host')]
                else:
                    payloads = [('test', 'Basic test'), ('injection', 'Injection test')]
                
                # Add SSTI/XSS/SQLi payloads for relevant headers
                if category in ['host_injection', 'custom_dangerous']:
                    payloads.extend(self.payload_generator.generate_ssti_payloads())
                    payloads.extend(self.payload_generator.generate_xss_payloads())
                
                for payload_value, payload_desc in payloads:
                    all_tests.append((category, header_name, payload_value, payload_desc))
        
        # Run tests
        total_tests = len(all_tests)
        print(f"{Fore.YELLOW}[*] Running {total_tests} test cases...{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            future_to_test = {}
            
            for test in all_tests:
                category, header_name, payload_value, payload_desc = test
                future = executor.submit(
                    self.test_header, 
                    header_name, 
                    f"{payload_value} ({payload_desc})"
                )
                future_to_test[future] = test
            
            for i, future in enumerate(as_completed(future_to_test), 1):
                test = future_to_test[future]
                category, header_name, payload_value, payload_desc = test
                result = future.result()
                
                if result:
                    self.results.append(result)
                    self._display_result(result, i, total_tests)
    
    def _display_result(self, result: HeaderResult, current: int, total: int):
        """Display test result"""
        progress = f"[{current}/{total}]"
        
        # Determine color based on anomalies
        if result.anomalies:
            color = Fore.RED
            status = "⚠"
        elif result.status_code >= 400:
            color = Fore.YELLOW
            status = "ℹ"
        else:
            color = Fore.GREEN
            status = "✓"
        
        # Build output line
        line = f"{progress} {color}{status}{Style.RESET_ALL} "
        line += f"{result.header_name:25} -> "
        line += f"{result.status_code:3} | "
        line += f"Size: {result.response_size:6} | "
        line += f"Time: {result.response_time:5.2f}s"
        
        # Add redirect info
        if len(result.redirect_chain) > 1:
            line += f" | {Fore.CYAN}Redirects: {len(result.redirect_chain)-1}{Style.RESET_ALL}"
        
        # Add anomaly info
        if result.anomalies:
            line += f" | {Fore.RED}{', '.join(result.anomalies[:2])}{Style.RESET_ALL}"
        
        print(line)
    
    def analyze_results(self):
        """Analyze results and generate findings"""
        print(f"\n{Fore.CYAN}[*] Analyzing results...{Style.RESET_ALL}")
        
        critical_findings = []
        
        for result in self.results:
            # Check for critical findings
            if result.status_code == 200 and "X-Forwarded-For" in result.header_name:
                # Potential IP spoofing
                finding = SecurityFinding(
                    id="HF-001",
                    title="Potential IP Spoofing Vulnerability",
                    description=f"Server accepted {result.header_name} with value {result.header_value}",
                    threat_level=ThreatLevel.HIGH,
                    impact="Attackers can spoof their IP address",
                    remediation="Validate and sanitize all client-supplied IP headers",
                    evidence=f"Header: {result.header_name} = {result.header_value}",
                    cwe="CWE-290",
                    cvss_score=7.5,
                    references=["https://cwe.mitre.org/data/definitions/290.html"]
                )
                critical_findings.append(finding)
            
            # Check for host header injection
            if "Host" in result.header_name and "evil.com" in result.header_value:
                finding = SecurityFinding(
                    id="HF-002",
                    title="Host Header Injection",
                    description="Server processed malicious Host header",
                    threat_level=ThreatLevel.CRITICAL,
                    impact="Cache poisoning, password reset poisoning",
                    remediation="Validate Host header against allowed list",
                    evidence=f"Host header accepted with value: {result.header_value}",
                    cwe="CWE-644",
                    cvss_score=8.2,
                    references=["https://portswigger.net/web-security/host-header"]
                )
                critical_findings.append(finding)
        
        self.findings = critical_findings
        
        return critical_findings
    
    def generate_report(self):
        """Generate comprehensive report"""
        print(f"\n{Fore.CYAN}[*] Generating report...{Style.RESET_ALL}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON Report
        json_report = {
            'metadata': {
                'target': self.target,
                'protocol': self.protocol,
                'timestamp': timestamp,
                'tool': 'HeaderForge Pro 3.0',
                'duration': time.time() - self.stats['start_time'],
            },
            'reconnaissance': self.run_reconnaissance(),
            'results': [asdict(r) for r in self.results],
            'findings': [asdict(f) for f in self.findings],
            'statistics': self.stats,
        }
        
        # Save JSON
        json_file = f"headerforge_{self.target}_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(json_report, f, indent=2, default=str)
        
        # Generate HTML report
        self._generate_html_report(json_report, timestamp)
        
        # Generate CSV summary
        self._generate_csv_summary(timestamp)
        
        print(f"{Fore.GREEN}[+] Reports generated:{Style.RESET_ALL}")
        print(f"  - JSON: {json_file}")
        print(f"  - HTML: headerforge_{self.target}_{timestamp}.html")
        print(f"  - CSV: headerforge_{self.target}_{timestamp}_summary.csv")
    
    def _generate_html_report(self, data: Dict, timestamp: str):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>HeaderForge Pro Report - {target}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 10px 10px 0 0; margin: -30px -30px 30px -30px; }}
                h1 {{ margin: 0; font-size: 2.5em; }}
                .subtitle {{ font-size: 1.2em; opacity: 0.9; }}
                .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }}
                .card {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); border-left: 4px solid #667eea; }}
                .critical {{ border-left-color: #dc3545; }}
                .high {{ border-left-color: #fd7e14; }}
                .medium {{ border-left-color: #ffc107; }}
                .low {{ border-left-color: #28a745; }}
                .finding {{ margin: 15px 0; padding: 15px; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #f8f9fa; font-weight: 600; }}
                tr:hover {{ background: #f8f9fa; }}
                .status-200 {{ color: #28a745; }}
                .status-300 {{ color: #17a2b8; }}
                .status-400 {{ color: #ffc107; }}
                .status-500 {{ color: #dc3545; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 HeaderForge Pro Security Report</h1>
                    <div class="subtitle">
                        <p>Target: <strong>{target}</strong> | Scan Date: {date} | Version: 3.0.0</p>
                    </div>
                </div>
                
                <div class="summary">
                    <div class="card">
                        <h3>📊 Scan Summary</h3>
                        <p>Total Requests: {total_requests}</p>
                        <p>Findings: {total_findings}</p>
                        <p>Duration: {duration:.2f} seconds</p>
                    </div>
                    
                    <div class="card critical">
                        <h3>⚠ Critical Findings</h3>
                        <p style="font-size: 2em; margin: 10px 0;">{critical_count}</p>
                    </div>
                    
                    <div class="card high">
                        <h3>🔴 High Severity</h3>
                        <p style="font-size: 2em; margin: 10px 0;">{high_count}</p>
                    </div>
                    
                    <div class="card">
                        <h3>🎯 Test Coverage</h3>
                        <p>Headers Tested: {headers_tested}</p>
                        <p>Payloads Tested: {payloads_tested}</p>
                    </div>
                </div>
                
                <h2>🔍 Security Findings</h2>
                {findings_html}
                
                <h2>📋 Test Results</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Header</th>
                            <th>Payload</th>
                            <th>Status</th>
                            <th>Size</th>
                            <th>Time</th>
                            <th>Anomalies</th>
                        </tr>
                    </thead>
                    <tbody>
                        {results_html}
                    </tbody>
                </table>
                
                <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em;">
                    <p>Generated by HeaderForge Pro v3.0 | For educational and authorized testing purposes only</p>
                    <p>© {year} Security Research Team | Report ID: {report_id}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Prepare data for HTML template
        findings_html = ""
        for finding in self.findings:
            color_class = finding.threat_level.value.lower()
            findings_html += f"""
            <div class="finding {color_class}">
                <h3>{finding.title} [{finding.threat_level.value}]</h3>
                <p><strong>Description:</strong> {finding.description}</p>
                <p><strong>Impact:</strong> {finding.impact}</p>
                <p><strong>Remediation:</strong> {finding.remediation}</p>
                <p><strong>CVSS Score:</strong> {finding.cvss_score}</p>
                <p><strong>Evidence:</strong> <code>{finding.evidence}</code></p>
            </div>
            """
        
        results_html = ""
        for result in self.results[:100]:  # Limit to 100 results in HTML
            status_class = ""
            if 200 <= result.status_code < 300:
                status_class = "status-200"
            elif 300 <= result.status_code < 400:
                status_class = "status-300"
            elif 400 <= result.status_code < 500:
                status_class = "status-400"
            else:
                status_class = "status-500"
            
            anomalies = ", ".join(result.anomalies[:3]) if result.anomalies else ""
            results_html += f"""
            <tr>
                <td><code>{result.header_name}</code></td>
                <td><code>{result.header_value[:50]}</code></td>
                <td class="{status_class}">{result.status_code}</td>
                <td>{result.response_size}</td>
                <td>{result.response_time:.2f}s</td>
                <td>{anomalies}</td>
            </tr>
            """
        
        # Fill template
        html_content = html_template.format(
            target=self.target,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            year=datetime.now().year,
            report_id=hashlib.md5(self.target.encode()).hexdigest()[:8].upper(),
            total_requests=len(self.results),
            total_findings=len(self.findings),
            critical_count=len([f for f in self.findings if f.threat_level == ThreatLevel.CRITICAL]),
            high_count=len([f for f in self.findings if f.threat_level == ThreatLevel.HIGH]),
            duration=time.time() - self.stats['start_time'],
            headers_tested=len(set(r.header_name for r in self.results)),
            payloads_tested=len(self.results),
            findings_html=findings_html,
            results_html=results_html
        )
        
        html_file = f"headerforge_{self.target}_{timestamp}.html"
        with open(html_file, 'w') as f:
            f.write(html_content)
    
    def _generate_csv_summary(self, timestamp: str):
        """Generate CSV summary report"""
        csv_file = f"headerforge_{self.target}_{timestamp}_summary.csv"
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Header Name', 'Payload', 'Status Code', 
                'Response Size', 'Response Time', 'Anomalies',
                'WAF Detected', 'Redirects', 'Differences'
            ])
            
            # Write data
            for result in self.results:
                writer.writerow([
                    result.header_name,
                    result.header_value[:100],
                    result.status_code,
                    result.response_size,
                    f"{result.response_time:.2f}",
                    "; ".join(result.anomalies),
                    "; ".join(self.waf_detector.detect(result.headers_received)),
                    len(result.redirect_chain) - 1,
                    str(len(result.differences)) if result.differences else "0"
                ])
    
    def run(self):
        """Main execution method"""
        self.stats['start_time'] = time.time()
        
        try:
            # Banner
            self._print_banner()
            
            # Reconnaissance
            recon_data = self.run_reconnaissance()
            
            # Header tests
            self.run_header_tests()
            
            # Analysis
            findings = self.analyze_results()
            
            # Generate report
            self.generate_report()
            
            # Print summary
            self._print_summary()
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Critical error: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
        finally:
            self.stats['end_time'] = time.time()
    
    def _print_banner(self):
        """Print tool banner"""
        banner = f"""
{Fore.CYAN}
███████╗███████╗ █████╗ ██████╗ ███████╗██████╗ ██████╗  ██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝
█████╗  █████╗  ███████║██║  ██║█████╗  ██████╔╝██████╔╝██║   ██║███████╗
██╔══╝  ██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗██╔══██╗██║   ██║╚════██║
██║     ███████╗██║  ██║██████╔╝███████╗██║  ██║██║  ██║╚██████╔╝███████║
╚═╝     ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{Style.RESET_ALL}
{Fore.YELLOW}HeaderForge Pro v3.0 - Advanced HTTP Header Security Analyzer{Style.RESET_ALL}
{Fore.CYAN}Target: {self.target} | Protocol: {self.protocol} | Mode: {self.args.mode}{Style.RESET_ALL}
{'-' * 80}
"""
        print(banner)
    
    def _print_summary(self):
        """Print scan summary"""
        duration = self.stats['end_time'] - self.stats['start_time']
        
        summary = f"""
{Fore.CYAN}{'='*80}{Style.RESET_ALL}
{Fore.YELLOW}SCAN COMPLETED{Style.RESET_ALL}
{Fore.CYAN}{'='*80}{Style.RESET_ALL}

{Fore.GREEN}📊 Statistics:{Style.RESET_ALL}
  • Total Requests: {len(self.results)}
  • Successful: {sum(1 for r in self.results if r.status_code > 0)}
  • Failed: {sum(1 for r in self.results if r.status_code == 0)}
  • Security Findings: {len(self.findings)}
  • Duration: {duration:.2f} seconds
  • Speed: {len(self.results)/duration:.1f} requests/second

{Fore.YELLOW}🔍 Findings Summary:{Style.RESET_ALL}"""
        
        # Group findings by threat level
        by_level = {}
        for finding in self.findings:
            level = finding.threat_level.value
            by_level.setdefault(level, []).append(finding)
        
        for level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.LOW]:
            level_str = level.value
            count = len(by_level.get(level_str, []))
            color = Fore.RED if level == ThreatLevel.CRITICAL else Fore.YELLOW if level == ThreatLevel.HIGH else Fore.BLUE
            print(f"  {color}• {level_str}: {count}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}📁 Reports generated in current directory.{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='HeaderForge Pro - Advanced HTTP Header Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s example.com https
  %(prog)s 192.168.1.1 http --mode aggressive --threads 10
  %(prog)s target.com https --proxy http://127.0.0.1:8080 --output-dir reports
  %(prog)s app.com https --category ip_spoofing,auth_injection --stealth
        '''
    )
    
    # Required arguments
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('protocol', choices=['http', 'https'], help='Protocol to use')
    
    # Scan mode
    parser.add_argument('--mode', choices=['passive', 'active', 'aggressive', 'stealth'],
                       default='active', help='Scanning mode (default: active)')
    
    # Performance
    parser.add_argument('-t', '--threads', type=int, default=5,
                       help='Number of concurrent threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=15,
                       help='Request timeout in seconds (default: 15)')
    
    # Scope
    parser.add_argument('--category', help='Comma-separated list of categories to test')
    parser.add_argument('--max-requests', type=int, default=1000,
                       help='Maximum number of requests (default: 1000)')
    
    # Networking
    parser.add_argument('-p', '--proxy', help='Proxy server (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-k', '--insecure', action='store_true',
                       help='Disable SSL certificate verification')
    parser.add_argument('-r', '--follow-redirects', action='store_true',
                       help='Follow HTTP redirects')
    
    # Stealth options
    parser.add_argument('--stealth', action='store_true',
                       help='Enable stealth mode (random delays)')
    parser.add_argument('--delay', type=float, default=0.5,
                       help='Delay between requests in seconds (default: 0.5)')
    
    # Output
    parser.add_argument('-o', '--output-dir', default='.',
                       help='Output directory for reports (default: current dir)')
    parser.add_argument('--no-html', action='store_true',
                       help='Do not generate HTML report')
    parser.add_argument('--no-csv', action='store_true',
                       help='Do not generate CSV report')
    
    # Advanced
    parser.add_argument('--dns-enum', action='store_true',
                       help='Perform DNS enumeration')
    parser.add_argument('--ssl-scan', action='store_true',
                       help='Perform SSL/TLS scanning')
    parser.add_argument('--fingerprint', action='store_true',
                       help='Perform application fingerprinting')
    
    return parser.parse_args()

def main():
    """Main entry point"""
    try:
        args = parse_arguments()
        
        # Create output directory if needed
        if args.output_dir != '.':
            Path(args.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize scanner
        scanner = HeaderForgePro(args)
        
        # Run scan
        scanner.run()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()