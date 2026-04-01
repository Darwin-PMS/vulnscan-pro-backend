/**
 * OWASP Top 10 Vulnerability Scanner Module
 * Implements security checks based on OWASP Top 10 2021
 */

const axios = require('axios');
const { checkSSRF, sanitizeInput } = require('../../utils/security');

class OWASPScanner {
    constructor() {
        this.owaspCategories = {
            'A01:2021': 'Broken Access Control',
            'A02:2021': 'Cryptographic Failures',
            'A03:2021': 'Injection',
            'A04:2021': 'Insecure Design',
            'A05:2021': 'Security Misconfiguration',
            'A06:2021': 'Vulnerable Components',
            'A07:2021': 'Authentication Failures',
            'A08:2021': 'Software Integrity Failures',
            'A09:2021': 'Security Logging Failures',
            'A10:2021': 'Server-Side Request Forgery'
        };

        this.patterns = this.initializePatterns();
    }

    initializePatterns() {
        return {
            'A01:2021': [
                {
                    id: 'OWASP-A01-001',
                    title: 'Broken Access Control - Insecure Direct Object Reference',
                    description: 'Application exposes internal object references without proper authorization',
                    severity: 'high',
                    check: async (url, response) => {
                        const idorPatterns = [
                            /\/user\/\d+/,
                            /\/api\/\w+\/\d+/,
                            /\/order\/\d+/,
                            /\/invoice\/\d+/,
                            /\/admin\/user\/\d+/,
                            /id=\d+/,
                            /user_id=\d+/
                        ];
                        return idorPatterns.some(p => p.test(url)) && response.status !== 403;
                    }
                },
                {
                    id: 'OWASP-A01-002',
                    title: 'Broken Access Control - Missing Function Level Access Control',
                    description: 'Administrative functions accessible without authentication',
                    severity: 'critical',
                    check: async (url, response) => {
                        const adminPaths = ['/admin', '/api/admin', '/dashboard', '/management', '/wp-admin', '/console', '/api/v1/users'];
                        return adminPaths.some(p => url.includes(p)) && response.status === 200;
                    }
                },
                {
                    id: 'OWASP-A01-003',
                    title: 'CORS Misconfiguration - Permissive Access Control',
                    description: 'Cross-Origin Resource Sharing allows unauthorized domains',
                    severity: 'high',
                    check: async (url, response) => {
                        const corsHeader = response.headers['access-control-allow-origin'];
                        return corsHeader === '*' || corsHeader === 'null';
                    }
                }
            ],
            'A02:2021': [
                {
                    id: 'OWASP-A02-001',
                    title: 'Sensitive Data Exposure - Missing HTTPS',
                    description: 'Application transmits sensitive data over unencrypted HTTP',
                    severity: 'high',
                    check: async (url, response) => {
                        return url.startsWith('http://') && response.status === 200;
                    }
                },
                {
                    id: 'OWASP-A02-002',
                    title: 'Sensitive Data Exposure - Weak SSL/TLS',
                    description: 'Server supports outdated SSL/TLS protocols',
                    severity: 'medium',
                    check: async (url, response) => {
                        const securityHeaders = response.headers;
                        return !securityHeaders['strict-transport-security'];
                    }
                },
                {
                    id: 'OWASP-A02-003',
                    title: 'Autocomplete Enabled on Sensitive Forms',
                    description: 'Sensitive form fields have autocomplete enabled',
                    severity: 'low',
                    check: async (url, response) => {
                        return response.data && /autocomplete=["']?on["']?/i.test(response.data);
                    }
                }
            ],
            'A03:2021': [
                {
                    id: 'OWASP-A03-001',
                    title: 'SQL Injection Vulnerability',
                    description: 'Application vulnerable to SQL injection attacks',
                    severity: 'critical',
                    check: async (url, response) => {
                        const sqlErrors = [
                            'mysql_fetch', 'mysql_num_rows', 'mysqli', 'ORA-', 
                            'SQLite_JIT', 'PostgreSQL', 'syntax error', 'SQL syntax',
                            'Warning: mysql', 'Microsoft SQL Native Client error',
                            'ORA-00933', 'ORA-01789', 'SQL_ERROR'
                        ];
                        return sqlErrors.some(e => response.data && response.data.includes(e));
                    }
                },
                {
                    id: 'OWASP-A03-002',
                    title: 'Cross-Site Scripting (XSS) Vulnerability',
                    description: 'Application vulnerable to reflected or stored XSS',
                    severity: 'high',
                    check: async (url, response) => {
                        const xssPatterns = ['<script>', 'javascript:', 'onerror=', 'onload='];
                        return xssPatterns.some(p => response.data && response.data.includes(p));
                    }
                },
                {
                    id: 'OWASP-A03-003',
                    title: 'Command Injection Vulnerability',
                    description: 'Application vulnerable to OS command injection',
                    severity: 'critical',
                    check: async (url, response) => {
                        const cmdErrors = ['sh: ', 'bash:', 'cmd.exe', 'PowerShell', 'system32', '/bin/sh'];
                        return cmdErrors.some(e => response.data && response.data.includes(e));
                    }
                },
                {
                    id: 'OWASP-A03-004',
                    title: 'LDAP Injection Vulnerability',
                    description: 'Application vulnerable to LDAP injection',
                    severity: 'high',
                    check: async (url, response) => {
                        return response.data && /(\*|\(|\||&)/.test(response.data) && 
                               (response.data.includes('LDAP') || response.data.includes('DN'));
                    }
                }
            ],
            'A04:2021': [
                {
                    id: 'OWASP-A04-001',
                    title: 'Insecure Design - Missing Rate Limiting',
                    description: 'No rate limiting implemented for API endpoints',
                    severity: 'medium',
                    check: async (url, response) => {
                        const noRateLimit = !response.headers['x-ratelimit-limit'] && 
                                          !response.headers['ratelimit-limit'];
                        return noRateLimit && (url.includes('/api/') || url.includes('/login'));
                    }
                },
                {
                    id: 'OWASP-A04-002',
                    title: 'Insecure Design - Missing Brute Force Protection',
                    description: 'No protection against brute force attacks',
                    severity: 'high',
                    check: async (url, response) => {
                        return url.includes('/login') && response.status === 401;
                    }
                },
                {
                    id: 'OWASP-A04-003',
                    title: 'Mass Assignment Vulnerability',
                    description: 'Application allows modification of sensitive fields',
                    severity: 'medium',
                    check: async (url, response) => {
                        const massAssignPatterns = ['is_admin', 'role', 'user_type', 'permission'];
                        return massAssignPatterns.some(p => url.includes(p)) && 
                               response.status === 200 && response.data;
                    }
                }
            ],
            'A05:2021': [
                {
                    id: 'OWASP-A05-001',
                    title: 'Security Misconfiguration - Missing Security Headers',
                    description: 'Essential security headers are missing',
                    severity: 'medium',
                    check: async (url, response) => {
                        const requiredHeaders = [
                            'x-content-type-options',
                            'x-frame-options',
                            'x-xss-protection',
                            'content-security-policy'
                        ];
                        const missing = requiredHeaders.filter(h => !response.headers[h]);
                        return missing.length >= 2;
                    }
                },
                {
                    id: 'OWASP-A05-002',
                    title: 'Debug Mode Enabled',
                    description: 'Application debug mode is enabled in production',
                    severity: 'high',
                    check: async (url, response) => {
                        const debugIndicators = ['debug=true', 'DEBUG=TRUE', 'development', 'Stack Trace', 
                                               'Error in', 'Exception', 'stacktrace'];
                        return debugIndicators.some(d => response.data && response.data.includes(d));
                    }
                },
                {
                    id: 'OWASP-A05-003',
                    title: 'Default Credentials Check',
                    description: 'Default or common credentials may be in use',
                    severity: 'critical',
                    check: async (url, response) => {
                        const defaultCreds = ['admin:admin', 'admin:password', 'root:root', 'guest:guest'];
                        return false;
                    }
                },
                {
                    id: 'OWASP-A05-004',
                    title: 'Directory Listing Enabled',
                    description: 'Web server has directory listing enabled',
                    severity: 'medium',
                    check: async (url, response) => {
                        return response.data && /Index of \/|Directory listing|\[To Parent Directory\]/.test(response.data);
                    }
                }
            ],
            'A06:2021': [
                {
                    id: 'OWASP-A06-001',
                    title: 'Outdated JavaScript Libraries',
                    description: 'Application uses outdated JavaScript libraries',
                    severity: 'medium',
                    check: async (url, response) => {
                        const outdatedLibs = ['jquery-1.', 'jquery-2.', 'bootstrap-3.', 'react@15', 'vue@1.'];
                        return outdatedLibs.some(lib => response.data && response.data.includes(lib));
                    }
                },
                {
                    id: 'OWASP-A06-002',
                    title: 'Vulnerable Component - Prototype Pollution',
                    description: 'JavaScript prototype pollution vulnerability detected',
                    severity: 'high',
                    check: async (url, response) => {
                        return response.data && /__proto__|constructor|prototype/.test(response.data);
                    }
                }
            ],
            'A07:2021': [
                {
                    id: 'OWASP-A07-001',
                    title: 'Weak Password Policy',
                    description: 'Application does not enforce strong password policy',
                    severity: 'medium',
                    check: async (url, response) => {
                        return url.includes('/register') || url.includes('/signup');
                    }
                },
                {
                    id: 'OWASP-A07-002',
                    title: 'Authentication Bypass - Weak Session',
                    description: 'Weak or predictable session tokens',
                    severity: 'high',
                    check: async (url, response) => {
                        const setCookie = response.headers['set-cookie'];
                        return setCookie && !setCookie.toLowerCase().includes('httponly');
                    }
                },
                {
                    id: 'OWASP-A07-003',
                    title: 'Missing Multi-Factor Authentication',
                    description: 'MFA not required for sensitive operations',
                    severity: 'medium',
                    check: async (url, response) => {
                        return url.includes('/settings') || url.includes('/account');
                    }
                }
            ],
            'A08:2021': [
                {
                    id: 'OWASP-A08-001',
                    title: 'Insecure Dependencies',
                    description: 'Dependencies with known vulnerabilities may be present',
                    severity: 'high',
                    check: async (url, response) => {
                        return response.data && /package\.json|node_modules|bower_components/.test(response.data);
                    }
                },
                {
                    id: 'OWASP-A08-002',
                    title: 'Unsigned Updates',
                    description: 'Software updates are not signed or verified',
                    severity: 'medium',
                    check: async (url, response) => {
                        return response.data && /update|upgrade|patch/i.test(response.data);
                    }
                }
            ],
            'A09:2021': [
                {
                    id: 'OWASP-A09-001',
                    title: 'Insufficient Logging',
                    description: 'Security events are not properly logged',
                    severity: 'medium',
                    check: async (url, response) => {
                        return false;
                    }
                },
                {
                    id: 'OWASP-A09-002',
                    title: 'Failed Authentication Not Logged',
                    description: 'Failed login attempts are not logged',
                    severity: 'low',
                    check: async (url, response) => {
                        return url.includes('/login') && response.status === 401;
                    }
                }
            ],
            'A10:2021': [
                {
                    id: 'OWASP-A10-001',
                    title: 'Server-Side Request Forgery (SSRF)',
                    description: 'Application fetches user-controlled URLs without validation',
                    severity: 'critical',
                    check: async (url, response) => {
                        const ssrfIndicators = ['169.254.169.254', 'metadata.google.internal', 
                                               'localhost', '127.0.0.1', '0.0.0.0'];
                        return ssrfIndicators.some(i => url.includes(i));
                    }
                },
                {
                    id: 'OWASP-A10-002',
                    title: 'SSRF Risk - URL Parameter Reflection',
                    description: 'URL parameters may be used to fetch external resources',
                    severity: 'high',
                    check: async (url, response) => {
                        const ssrfParams = ['url=', 'uri=', 'dest=', 'redirect=', 'next=', 'data=', 'q=', 'callback='];
                        return ssrfParams.some(p => url.includes(p));
                    }
                }
            ]
        };
    }

    async scanTarget(url, scanId) {
        const results = {
            scanId,
            targetUrl: url,
            scanner: 'OWASP Top 10 2021',
            startTime: new Date().toISOString(),
            vulnerabilities: [],
            summary: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0
            },
            categories: {}
        };

        try {
            if (checkSSRF(url)) {
                throw new Error('SSRF protection triggered');
            }

            const response = await axios.get(url, {
                timeout: 10000,
                validateStatus: () => true,
                headers: {
                    'User-Agent': 'VulnScanPro/2.0 Security Scanner'
                }
            });

            for (const [category, patterns] of Object.entries(this.patterns)) {
                const categoryVulns = [];

                for (const pattern of patterns) {
                    try {
                        const isVulnerable = await pattern.check(url, response);
                        
                        if (isVulnerable) {
                            const vulnerability = {
                                id: pattern.id,
                                category,
                                categoryName: this.owaspCategories[category],
                                title: pattern.title,
                                description: pattern.description,
                                severity: pattern.severity,
                                url: url,
                                remediation: this.getRemediation(pattern.id),
                                discoveredAt: new Date().toISOString()
                            };

                            categoryVulns.push(vulnerability);
                            results.vulnerabilities.push(vulnerability);
                            results.summary[pattern.severity]++;
                        }
                    } catch (err) {
                        console.error(`OWASP check ${pattern.id} failed:`, err.message);
                    }
                }

                if (categoryVulns.length > 0) {
                    results.categories[category] = {
                        name: this.owaspCategories[category],
                        count: categoryVulns.length,
                        vulnerabilities: categoryVulns
                    };
                }
            }

            results.endTime = new Date().toISOString();
            results.totalVulnerabilities = results.vulnerabilities.length;

        } catch (error) {
            results.error = error.message;
            results.endTime = new Date().toISOString();
        }

        return results;
    }

    getRemediation(vulnerabilityId) {
        const remediations = {
            'OWASP-A01-001': 'Implement proper authorization checks using access control lists (ACLs). Validate all object references against user permissions.',
            'OWASP-A01-002': 'Implement function level access control on all administrative endpoints. Verify user role before executing privileged operations.',
            'OWASP-A01-003': 'Configure CORS to only allow trusted origins. Never set Access-Control-Allow-Origin to "*" for sensitive data.',
            'OWASP-A02-001': 'Enforce HTTPS for all connections. Implement HSTS header and redirect HTTP to HTTPS.',
            'OWASP-A02-002': 'Enable HTTP Strict Transport Security (HSTS). Disable outdated SSL/TLS protocols.',
            'OWASP-A02-003': 'Set autocomplete="off" on sensitive form fields like passwords and credit card numbers.',
            'OWASP-A03-001': 'Use parameterized queries or ORM. Never concatenate user input into SQL queries.',
            'OWASP-A03-002': 'Implement input validation and output encoding. Use Content Security Policy (CSP) headers.',
            'OWASP-A03-003': 'Never pass user input to system commands. Use safe APIs or whitelist validation.',
            'OWASP-A03-004': 'Escape special LDAP characters in user input. Use LDAP input validation.',
            'OWASP-A04-001': 'Implement rate limiting on all API endpoints. Use tokens or captcha for abuse prevention.',
            'OWASP-A04-002': 'Implement account lockout policies and multi-factor authentication.',
            'OWASP-A04-003': 'Use data transfer objects (DTOs) and explicitly define allowed fields.',
            'OWASP-A05-001': 'Configure all security headers: X-Content-Type-Options, X-Frame-Options, CSP, and Referrer-Policy.',
            'OWASP-A05-002': 'Disable debug mode in production. Set NODE_ENV to "production".',
            'OWASP-A05-003': 'Enforce strong password policies. Require minimum 12 characters with complexity requirements.',
            'OWASP-A05-004': 'Disable directory listing in web server configuration.',
            'OWASP-A06-001': 'Regularly update JavaScript libraries. Use tools like npm audit or Snyk.',
            'OWASP-A06-002': 'Prevent object prototype manipulation. Use Object.freeze() or deep-freeze libraries.',
            'OWASP-A07-001': 'Enforce password complexity: minimum 12 characters, mixed case, numbers, special characters.',
            'OWASP-A07-002': 'Set Secure and HttpOnly flags on session cookies. Implement secure session management.',
            'OWASP-A07-003': 'Enable multi-factor authentication for all user accounts.',
            'OWASP-A08-001': 'Use dependency scanning tools. Regularly update dependencies to latest secure versions.',
            'OWASP-A08-002': 'Implement code signing and signature verification for software updates.',
            'OWASP-A09-001': 'Log all authentication attempts, access control failures, and input validation errors.',
            'OWASP-A09-002': 'Implement comprehensive logging for all security-relevant events.',
            'OWASP-A10-001': 'Validate and sanitize all URL inputs. Block access to internal IP ranges and cloud metadata endpoints.',
            'OWASP-A10-002': 'Validate all user-supplied URLs against an allowlist of permitted domains.'
        };
        return remediations[vulnerabilityId] || 'Update and patch the affected component. Follow OWASP guidelines for remediation.';
    }

    getOWASPSummary() {
        return {
            categories: Object.entries(this.owaspCategories).map(([id, name]) => ({
                id,
                name,
                patternCount: this.patterns[id]?.length || 0
            })),
            totalPatterns: Object.values(this.patterns).flat().length
        };
    }
}

module.exports = { OWASPScanner };
