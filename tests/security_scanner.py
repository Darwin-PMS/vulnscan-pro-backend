#!/usr/bin/env python3
"""
Advanced Python Security Testing Toolkit
Comprehensive vulnerability testing for web applications
"""

import requests
import urllib3
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    name: str
    severity: Severity
    url: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None


class SecurityScanner:
    """Main security scanner class"""
    
    def __init__(self, base_url: str, proxies: dict = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.proxies = proxies
        self.vulnerabilities: List[Vulnerability] = []
    
    def scan(self) -> List[Vulnerability]:
        """Run all security tests"""
        self._test_sql_injection()
        self._test_xss()
        self._test_path_traversal()
        self._test_ssrf()
        self._test_command_injection()
        self._test_security_headers()
        return self.vulnerabilities
    
    def _test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
            "' OR 'a'='a"
        ]
        
        test_paths = ['search', 'id', 'user', 'page', 'category', 'product']
        
        for path in test_paths:
            for payload in sql_payloads:
                url = f"{self.base_url}/{path}?q={payload}"
                try:
                    response = self.session.get(url, proxies=self.proxies, timeout=10)
                    if self._detect_sql_error(response.text):
                        self.vulnerabilities.append(Vulnerability(
                            name="SQL Injection",
                            severity=Severity.CRITICAL,
                            url=url,
                            evidence=f"SQL error detected with payload: {payload}",
                            remediation="Use parameterized queries and input validation",
                            cwe_id="CWE-89",
                            owasp_id="A03:2021"
                        ))
                except requests.RequestException:
                    pass
    
    def _test_xss(self):
        """Test for XSS vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src='javascript:alert(1)'>"
        ]
        
        test_paths = ['search', 'q', 'query', 'name', 'comment']
        
        for path in test_paths:
            for payload in xss_payloads:
                url = f"{self.base_url}/{path}?q={payload}"
                try:
                    response = self.session.get(url, proxies=self.proxies, timeout=10)
                    if payload in response.text:
                        self.vulnerabilities.append(Vulnerability(
                            name="Cross-Site Scripting (XSS)",
                            severity=Severity.HIGH,
                            url=url,
                            evidence=f"Reflected XSS detected: {payload}",
                            remediation="Implement output encoding and Content-Security-Policy",
                            cwe_id="CWE-79",
                            owasp_id="A03:2021"
                        ))
                except requests.RequestException:
                    pass
    
    def _test_path_traversal(self):
        """Test for path traversal vulnerabilities"""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        test_paths = ['file', 'path', 'download', 'doc', 'image']
        
        for path in test_paths:
            for payload in traversal_payloads:
                url = f"{self.base_url}/{path}?f={payload}"
                try:
                    response = self.session.get(url, proxies=self.proxies, timeout=10)
                    if 'root:x:' in response.text or '[extensions]' in response.text:
                        self.vulnerabilities.append(Vulnerability(
                            name="Path Traversal",
                            severity=Severity.CRITICAL,
                            url=url,
                            evidence=f"Path traversal detected: {payload}",
                            remediation="Validate and sanitize all file paths",
                            cwe_id="CWE-22",
                            owasp_id="A01:2021"
                        ))
                except requests.RequestException:
                    pass
    
    def _test_ssrf(self):
        """Test for Server-Side Request Forgery"""
        ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/"
        ]
        
        test_paths = ['url', 'uri', 'dest', 'redirect', 'next', 'data']
        
        for path in test_paths:
            for payload in ssrf_payloads:
                url = f"{self.base_url}/{path}?url={payload}"
                try:
                    response = self.session.get(url, proxies=self.proxies, timeout=10)
                    if 'localhost' in response.text.lower() or 'ami-aws' in response.text:
                        self.vulnerabilities.append(Vulnerability(
                            name="Server-Side Request Forgery (SSRF)",
                            severity=Severity.HIGH,
                            url=url,
                            evidence=f"SSRF detected: {payload}",
                            remediation="Use URL allowlists and disable unused URL schemas",
                            cwe_id="CWE-918",
                            owasp_id="A10:2021"
                        ))
                except requests.RequestException:
                    pass
    
    def _test_command_injection(self):
        """Test for command injection"""
        cmd_payloads = [
            "; cat /etc/passwd",
            "| whoami",
            "`id`",
            "$(whoami)",
            "; ls -la"
        ]
        
        test_paths = ['ping', 'host', 'ip', 'domain', 'cmd', 'exec']
        
        for path in test_paths:
            for payload in cmd_payloads:
                url = f"{self.base_url}/{path}?q={payload}"
                try:
                    response = self.session.get(url, proxies=self.proxies, timeout=10)
                    if any(cmd in response.text for cmd in ['root:', 'admin:', 'uid=']):
                        self.vulnerabilities.append(Vulnerability(
                            name="Command Injection",
                            severity=Severity.CRITICAL,
                            url=url,
                            evidence=f"Command injection detected: {payload}",
                            remediation="Avoid OS commands, use parameterized APIs",
                            cwe_id="CWE-78",
                            owasp_id="A03:2021"
                        ))
                except requests.RequestException:
                    pass
    
    def _test_security_headers(self):
        """Test for missing security headers"""
        required_headers = {
            'Strict-Transport-Security': 'HSTS header missing - vulnerable to SSL stripping',
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME sniffing protection missing',
            'Content-Security-Policy': 'CSP missing - XSS risk increased',
            'X-XSS-Protection': 'XSS filter header missing'
        }
        
        try:
            response = self.session.get(self.base_url, proxies=self.proxies, timeout=10)
            
            for header, issue in required_headers.items():
                if header.lower() not in [h.lower() for h in response.headers]:
                    self.vulnerabilities.append(Vulnerability(
                        name=f"Missing {header}",
                        severity=Severity.MEDIUM,
                        url=self.base_url,
                        evidence=issue,
                        remediation=f"Add {header} header to all responses",
                        cwe_id="CWE-693"
                    ))
        except requests.RequestException:
            pass
    
    @staticmethod
    def _detect_sql_error(text: str) -> bool:
        """Detect SQL error messages in response"""
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'ora-', 'postgresql',
            'warning: mysql', 'unclosed quotation', 'sqlite error'
        ]
        text_lower = text.lower()
        return any(err in text_lower for err in sql_errors)


class GHDBDorkScanner:
    """Google Hacking Database (GHDB) dork scanner"""
    
    DORK_CATEGORIES = {
        'backup_files': {
            'ghdb_id': '8361',
            'patterns': [
                'site:{domain} ext:bkf|ext:bkp|ext:bak|ext:old',
                'site:{domain} inurl:backup ext:sql|ext:zip'
            ],
            'severity': Severity.HIGH
        },
        'sensitive_files': {
            'ghdb_id': 'GHDB-CONFIG-001',
            'patterns': [
                'site:{domain} ext:xml|ext:conf|ext:cnf|ext:reg',
                'site:{domain} inurl:wp-config.php|inurl:config.php'
            ],
            'severity': Severity.CRITICAL
        },
        'admin_panels': {
            'ghdb_id': 'GHDB-LOGIN-001',
            'patterns': [
                'site:{domain} inurl:admin|inurl:login|inurl:administrator',
                'site:{domain} intitle:"Admin Login"'
            ],
            'severity': Severity.MEDIUM
        },
        'git_svn': {
            'ghdb_id': 'GHDB-GIT-001',
            'patterns': [
                'site:{domain} inurl:/.git',
                'site:{domain} inurl:/.svn'
            ],
            'severity': Severity.CRITICAL
        },
        'logs': {
            'ghdb_id': 'GHDB-LOG-001',
            'patterns': [
                'site:{domain} ext:log',
                'site:{domain} filetype:log'
            ],
            'severity': Severity.MEDIUM
        }
    }
    
    def __init__(self, domain: str):
        self.domain = domain
    
    def generate_dorks(self) -> Dict[str, List[str]]:
        """Generate all dork queries for the domain"""
        dorks = {}
        for name, config in self.DORK_CATEGORIES.items():
            dorks[name] = []
            for pattern in config['patterns']:
                dorks[name].append(pattern.format(domain=self.domain))
        return dorks
    
    def get_dork_count(self) -> int:
        """Get total number of dork patterns"""
        return sum(len(p['patterns']) for p in self.DORK_CATEGORIES.values())


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"[*] Scanning {target}...")
        
        scanner = SecurityScanner(target)
        results = scanner.scan()
        
        print(f"\n[+] Found {len(results)} vulnerabilities:\n")
        for vuln in results:
            print(f"  [{vuln.severity.value.upper()}] {vuln.name}")
            print(f"    URL: {vuln.url}")
            print(f"    Evidence: {vuln.evidence}")
            if vuln.owasp_id:
                print(f"    OWASP: {vuln.owasp_id}")
            print()
    else:
        print("Usage: python security_scanner.py <target_url>")
