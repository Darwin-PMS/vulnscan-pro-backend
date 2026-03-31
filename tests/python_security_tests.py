#!/usr/bin/env python3
"""
Python Security Testing Module for Web Vulnerability Scanner
Compatible with OWASP Top 10 2021 testing patterns
"""

import unittest
from urllib.parse import urlparse
import re


class TestURLNormalization:
    """Test URL normalization functions"""
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Add https:// prefix if missing and remove trailing slash"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return url


class TestVulnerabilityPatterns:
    """Test vulnerability pattern matching"""
    
    @staticmethod
    def detect_sql_error(response_text: str) -> bool:
        """Detect SQL error messages"""
        sql_errors = [
            'SQL syntax',
            'mysql_fetch',
            'mysql_num_rows',
            'ORA-',
            'PLS-',
            'PostgreSQL',
            'Warning: mysql',
            'unclosed quotation mark',
            'quoted string not properly terminated',
            'Microsoft SQL Native Client error',
            'SQLServer JDBC',
            'ODBC SQL Server',
            'SQLite3::',
            'SQL error'
        ]
        response_lower = response_text.lower()
        return any(err.lower() in response_lower for err in sql_errors)
    
    @staticmethod
    def detect_xss_reflection(payload: str, response_text: str) -> bool:
        """Detect XSS reflection"""
        return payload in response_text
    
    @staticmethod
    def is_git_exposed(response_text: str) -> bool:
        """Detect exposed .git directory"""
        git_indicators = ['[core]', 'repositoryformatversion', 'ref:', 'index']
        return any(indicator in response_text for indicator in git_indicators)
    
    @staticmethod
    def is_config_exposed(response_text: str) -> bool:
        """Detect exposed configuration files"""
        config_indicators = [
            'DB_PASSWORD', 'database', 'password', 'secret',
            'api_key', 'AWS_SECRET', 'PRIVATE_KEY'
        ]
        return any(indicator in response_text for indicator in config_indicators)


class TestDorkPatterns:
    """Test Google Dorking patterns"""
    
    DORK_PATTERNS = {
        'backup_files': {
            'ghdb_id': '8361',
            'pattern': 'site:{domain} ext:bkf|ext:bkp|ext:bak',
            'severity': 'high'
        },
        'sql_injection': {
            'ghdb_id': 'GHDB-SQL-001',
            'pattern': 'site:{domain} inurl:id=|inurl:page=',
            'severity': 'critical'
        },
        'admin_panels': {
            'ghdb_id': 'GHDB-LOGIN-001',
            'pattern': 'site:{domain} inurl:admin|inurl:login',
            'severity': 'medium'
        },
        'git_exposure': {
            'ghdb_id': 'GHDB-GIT-001',
            'pattern': 'site:{domain} inurl:/.git',
            'severity': 'critical'
        },
        'config_exposure': {
            'ghdb_id': 'GHDB-CONFIG-001',
            'pattern': 'site:{domain} inurl:wp-config.php|inurl:config.php',
            'severity': 'critical'
        }
    }
    
    @staticmethod
    def generate_dork(domain: str, dork_type: str) -> list:
        """Generate dork queries for a domain"""
        patterns = TestDorkPatterns.DORK_PATTERNS
        if dork_type in patterns:
            return [p.format(domain=domain) for p in patterns[dork_type]['pattern'].split('|')]
        return []


class TestOWASPTop10:
    """OWASP Top 10 2021 pattern tests"""
    
    @staticmethod
    def test_a01_broken_access_control(url: str) -> dict:
        """Test for Broken Access Control (A01:2021)"""
        return {
            'id': 'A01:2021',
            'test_paths': ['user/1', 'account/1', 'order/1', 'document/1'],
            'severity': 'high'
        }
    
    @staticmethod
    def test_a02_cryptographic_failures(url: str) -> dict:
        """Test for Cryptographic Failures (A02:2021)"""
        return {
            'id': 'A02:2021',
            'test_paths': ['login', 'checkout', 'payment', 'account'],
            'severity': 'critical'
        }
    
    @staticmethod
    def test_a03_injection(url: str) -> dict:
        """Test for Injection (A03:2021)"""
        return {
            'id': 'A03:2021',
            'payloads': [
                "' OR '1'='1",
                "' OR '1'='1'--",
                "admin'--",
                "' UNION SELECT null,null--"
            ],
            'severity': 'critical'
        }
    
    @staticmethod
    def test_a10_ssr(url: str) -> dict:
        """Test for Server-Side Request Forgery (A10:2021)"""
        return {
            'id': 'A10:2021',
            'payloads': [
                'http://localhost',
                'http://127.0.0.1',
                'file:///etc/passwd',
                'http://169.254.169.254'
            ],
            'severity': 'high'
        }


class SecurityTestSuite(unittest.TestCase):
    """Main security testing suite"""
    
    def test_url_normalization(self):
        """Test URL normalization"""
        self.assertEqual(
            TestURLNormalization.normalize_url('example.com'),
            'https://example.com'
        )
        self.assertEqual(
            TestURLNormalization.normalize_url('http://example.com/'),
            'https://example.com'
        )
    
    def test_domain_extraction(self):
        """Test domain extraction"""
        self.assertEqual(
            TestURLNormalization.extract_domain('https://sub.example.com/path'),
            'sub.example.com'
        )
    
    def test_sql_error_detection(self):
        """Test SQL error detection"""
        self.assertTrue(
            TestVulnerabilityPatterns.detect_sql_error('Warning: mysql_fetch_array()')
        )
        self.assertTrue(
            TestVulnerabilityPatterns.detect_sql_error('ORA-00933: SQL command error')
        )
        self.assertFalse(
            TestVulnerabilityPatterns.detect_sql_error('Welcome to our website')
        )
    
    def test_git_exposure_detection(self):
        """Test Git exposure detection"""
        self.assertTrue(
            TestVulnerabilityPatterns.is_git_exposed('[core]\nrepositoryformatversion = 0')
        )
        self.assertFalse(
            TestVulnerabilityPatterns.is_git_exposed('This is a normal HTML page')
        )
    
    def test_config_exposure_detection(self):
        """Test config exposure detection"""
        self.assertTrue(
            TestVulnerabilityPatterns.is_config_exposed('DB_PASSWORD=secret123')
        )
        self.assertTrue(
            TestVulnerabilityPatterns.is_config_exposed('api_key=sk-1234567890')
        )
    
    def test_xss_reflection(self):
        """Test XSS reflection detection"""
        self.assertTrue(
            TestVulnerabilityPatterns.detect_xss_reflection(
                '<script>alert(1)</script>',
                '<script>alert(1)</script> found'
            )
        )
    
    def test_dork_generation(self):
        """Test dork pattern generation"""
        dorks = TestDorkPatterns.generate_dork('example.com', 'backup_files')
        self.assertTrue(any('example.com' in d for d in dorks))
    
    def test_owasp_patterns(self):
        """Test OWASP Top 10 patterns"""
        a03 = TestOWASPTop10.test_a03_injection('https://example.com')
        self.assertIn("' OR '1'='1", a03['payloads'])
        
        a10 = TestOWASPTop10.test_a10_ssr('https://example.com')
        self.assertIn('http://localhost', a10['payloads'])


if __name__ == '__main__':
    unittest.main()
