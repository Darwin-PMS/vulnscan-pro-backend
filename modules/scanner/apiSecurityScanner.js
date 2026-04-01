/**
 * OWASP API Security Top 10 Scanner Module
 * Implements security checks based on OWASP API Security Top 10 2023
 */

const axios = require('axios');
const { checkSSRF, sanitizeInput } = require('../utils/security');

class APISecurityScanner {
    constructor() {
        this.apiCategories = {
            'API1:2023': 'Broken Object Level Authorization',
            'API2:2023': 'Broken Authentication',
            'API3:2023': 'Broken Object Property Level Authorization',
            'API4:2023': 'Unrestricted Resource Consumption',
            'API5:2023': 'Broken Function Level Authorization',
            'API6:2023': 'Unrestricted Access to Sensitive Business Flows',
            'API7:2023': 'Server Side Request Forgery',
            'API8:2023': 'Security Misconfiguration',
            'API9:2023': 'Improper Inventory Management',
            'API10:2023': 'Unsafe Consumption of APIs'
        };

        this.patterns = this.initializePatterns();
    }

    initializePatterns() {
        return {
            'API1:2023': [
                {
                    id: 'API1-001',
                    title: 'Insecure Direct Object Reference (IDOR)',
                    description: 'API exposes endpoints that directly reference internal objects without authorization checks',
                    severity: 'critical',
                    check: async (url, response) => {
                        const idorPatterns = [
                            /\/api\/users\/\d+/,
                            /\/api\/orders\/\d+/,
                            /\/api\/invoices\/\d+/,
                            /\/api\/\w+\/\w+\/\d+/
                        ];
                        return idorPatterns.some(p => p.test(url));
                    }
                },
                {
                    id: 'API1-002',
                    title: 'Missing Object Level Access Control',
                    description: 'API allows access to resources of other users via object ID manipulation',
                    severity: 'high',
                    check: async (url, response) => {
                        return /user_id|userId|account_id|customer_id/i.test(url) && 
                               response.status === 200;
                    }
                }
            ],
            'API2:2023': [
                {
                    id: 'API2-001',
                    title: 'Weak Authentication Mechanism',
                    description: 'API uses weak or no authentication mechanism',
                    severity: 'critical',
                    check: async (url, response) => {
                        const headers = response.headers || {};
                        const authHeaders = ['authorization', 'x-api-key', 'bearer'];
                        const hasAuth = authHeaders.some(h => headers[h]);
                        return !hasAuth && (url.includes('/api/') || url.includes('/v1/') || url.includes('/v2/'));
                    }
                },
                {
                    id: 'API2-002',
                    title: 'Missing API Key Validation',
                    description: 'API accepts requests without validating API keys',
                    severity: 'high',
                    check: async (url, response) => {
                        const keyParams = ['api_key', 'apikey', 'api-key', 'key'];
                        const hasKeyParam = keyParams.some(k => url.includes(k));
                        return hasKeyParam;
                    }
                },
                {
                    id: 'API2-003',
                    title: 'Token Not Invalidated After Password Change',
                    description: 'API does not invalidate tokens when user changes password',
                    severity: 'medium',
                    check: async (url, response) => {
                        return false;
                    }
                }
            ],
            'API3:2023': [
                {
                    id: 'API3-001',
                    title: 'Excessive Data Exposure',
                    description: 'API returns more data than necessary, exposing sensitive fields',
                    severity: 'high',
                    check: async (url, response) => {
                        if (response.data && typeof response.data === 'object') {
                            const sensitiveFields = ['password', 'ssn', 'credit_card', 'secret', 'token'];
                            const jsonStr = JSON.stringify(response.data).toLowerCase();
                            return sensitiveFields.some(f => jsonStr.includes(f));
                        }
                        return false;
                    }
                },
                {
                    id: 'API3-002',
                    title: 'Mass Assignment Vulnerability',
                    description: 'API allows modification of protected fields via mass assignment',
                    severity: 'high',
                    check: async (url, response) => {
                        const sensitiveFields = ['is_admin', 'role', 'permission', 'user_type', 'status'];
                        return sensitiveFields.some(f => url.includes(f) || 
                               (response.data && JSON.stringify(response.data).includes(f)));
                    }
                }
            ],
            'API4:2023': [
                {
                    id: 'API4-001',
                    title: 'No Rate Limiting',
                    description: 'API does not implement rate limiting, allowing DoS attacks',
                    severity: 'high',
                    check: async (url, response) => {
                        const headers = response.headers || {};
                        const rateLimitHeaders = ['x-ratelimit-limit', 'x-rate-limit', 'ratelimit-limit'];
                        const hasRateLimit = rateLimitHeaders.some(h => headers[h]);
                        return !hasRateLimit && (url.includes('/api/') || url.includes('/auth/'));
                    }
                },
                {
                    id: 'API4-002',
                    title: 'Unrestricted File Upload Size',
                    description: 'API allows unlimited file uploads without size restrictions',
                    severity: 'medium',
                    check: async (url, response) => {
                        return url.includes('/upload') || url.includes('/file');
                    }
                }
            ],
            'API5:2023': [
                {
                    id: 'API5-001',
                    title: 'Broken Function Level Authorization',
                    description: 'API allows users to access administrative functions without proper authorization',
                    severity: 'critical',
                    check: async (url, response) => {
                        const adminPaths = ['/admin', '/api/admin', '/manage', '/dashboard', '/configure'];
                        const isAdminPath = adminPaths.some(p => url.includes(p));
                        return isAdminPath && response.status === 200;
                    }
                },
                {
                    id: 'API5-002',
                    title: 'Privilege Escalation via Parameter Manipulation',
                    description: 'API allows privilege escalation through parameter manipulation',
                    severity: 'high',
                    check: async (url, response) => {
                        const privFields = ['role', 'admin', 'permission', 'access_level'];
                        return privFields.some(f => url.includes(f));
                    }
                }
            ],
            'API6:2023': [
                {
                    id: 'API6-001',
                    title: 'Business Logic Abuse',
                    description: 'API allows abuse of business logic without rate limiting',
                    severity: 'medium',
                    check: async (url, response) => {
                        const businessEndpoints = ['/purchase', '/order', '/transfer', '/payment', '/refund'];
                        return businessEndpoints.some(e => url.includes(e));
                    }
                },
                {
                    id: 'API6-002',
                    title: 'Insufficient Flow Controls',
                    description: 'API lacks proper controls for sensitive business operations',
                    severity: 'medium',
                    check: async (url, response) => {
                        return false;
                    }
                }
            ],
            'API7:2023': [
                {
                    id: 'API7-001',
                    title: 'SSRF via URL Parameter',
                    description: 'API fetches user-controlled URLs without proper validation',
                    severity: 'critical',
                    check: async (url, response) => {
                        const ssrfParams = ['url', 'uri', 'dest', 'redirect', 'next', 'data', 'q', 'callback'];
                        return ssrfParams.some(p => url.includes(p + '='));
                    }
                },
                {
                    id: 'API7-002',
                    title: 'SSRF - Internal Service Access',
                    description: 'API can be tricked into accessing internal services',
                    severity: 'critical',
                    check: async (url, response) => {
                        const internalTargets = [
                            '169.254.169.254', 'metadata.google.internal',
                            'localhost', '127.0.0.1', '0.0.0.0',
                            'internal', 'intranet'
                        ];
                        return internalTargets.some(t => url.includes(t));
                    }
                }
            ],
            'API8:2023': [
                {
                    id: 'API8-001',
                    title: 'Missing Security Headers',
                    description: 'API responses missing important security headers',
                    severity: 'medium',
                    check: async (url, response) => {
                        const headers = response.headers || {};
                        const requiredHeaders = ['x-content-type-options', 'x-frame-options'];
                        const missing = requiredHeaders.filter(h => !headers[h]);
                        return missing.length >= 1;
                    }
                },
                {
                    id: 'API8-002',
                    title: 'Verbose Error Messages',
                    description: 'API returns detailed error messages revealing internal information',
                    severity: 'medium',
                    check: async (url, response) => {
                        const verboseErrors = [
                            'stack trace', 'exception', 'error in',
                            'mysql', 'postgresql', 'mongodb', 'oracle',
                            'at com.sun.', 'at java.', 'at org.'
                        ];
                        return verboseErrors.some(e => 
                            response.data && response.data.toLowerCase().includes(e));
                    }
                },
                {
                    id: 'API8-003',
                    title: 'CORS Misconfiguration',
                    description: 'API has improper CORS configuration',
                    severity: 'medium',
                    check: async (url, response) => {
                        const cors = response.headers['access-control-allow-origin'];
                        return cors === '*' || cors === 'null';
                    }
                }
            ],
            'API9:2023': [
                {
                    id: 'API9-001',
                    title: 'Outdated API Documentation',
                    description: 'API documentation is not updated with current endpoints',
                    severity: 'low',
                    check: async (url, response) => {
                        return false;
                    }
                },
                {
                    id: 'API9-002',
                    title: 'Exposed Debug Endpoints',
                    description: 'Debug or test endpoints are exposed in production',
                    severity: 'high',
                    check: async (url, response) => {
                        const debugEndpoints = ['/debug', '/test', '/swagger', '/api-docs', '/health'];
                        return debugEndpoints.some(e => url.includes(e));
                    }
                },
                {
                    id: 'API9-003',
                    title: 'Deprecated API Versions',
                    description: 'Old API versions are still supported without security patches',
                    severity: 'medium',
                    check: async (url, response) => {
                        const oldVersions = ['/v1/', '/v0/', '/api/v1/', '/api/v0/'];
                        return oldVersions.some(v => url.includes(v));
                    }
                }
            ],
            'API10:2023': [
                {
                    id: 'API10-001',
                    title: 'Insufficient Input Validation',
                    description: 'API does not properly validate data from third-party services',
                    severity: 'high',
                    check: async (url, response) => {
                        return response.data && /<script|javascript:|onerror=/i.test(response.data);
                    }
                },
                {
                    id: 'API10-002',
                    title: 'Unsafe Data Serialization',
                    description: 'API uses unsafe data serialization methods',
                    severity: 'high',
                    check: async (url, response) => {
                        const unsafeSerialization = ['pickle', 'yaml.load', 'unserialize', 'eval('];
                        return unsafeSerialization.some(s => 
                            response.data && response.data.includes(s));
                    }
                }
            ]
        };
    }

    async scanTarget(url, scanId) {
        const results = {
            scanId,
            targetUrl: url,
            scanner: 'OWASP API Security Top 10 2023',
            startTime: new Date().toISOString(),
            vulnerabilities: [],
            summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            categories: {}
        };

        try {
            if (checkSSRF(url)) {
                throw new Error('SSRF protection triggered');
            }

            const response = await axios.get(url, {
                timeout: 10000,
                validateStatus: () => true,
                headers: { 'User-Agent': 'VulnScanPro/2.0 Security Scanner' }
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
                                categoryName: this.apiCategories[category],
                                title: pattern.title,
                                description: pattern.description,
                                severity: pattern.severity,
                                url,
                                remediation: this.getRemediation(pattern.id),
                                discoveredAt: new Date().toISOString()
                            };

                            categoryVulns.push(vulnerability);
                            results.vulnerabilities.push(vulnerability);
                            results.summary[pattern.severity]++;
                        }
                    } catch (err) {
                        console.error(`API check ${pattern.id} failed:`, err.message);
                    }
                }

                if (categoryVulns.length > 0) {
                    results.categories[category] = {
                        name: this.apiCategories[category],
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

    getRemediation(id) {
        const remediations = {
            'API1-001': 'Implement object-level authorization checks for all API endpoints. Validate user ownership before returning resources.',
            'API1-002': 'Add proper authorization checks. Verify user has permission to access the requested resource.',
            'API2-001': 'Implement strong authentication mechanisms. Use OAuth 2.0 or JWT with proper validation.',
            'API2-002': 'Validate API keys on every request. Implement key rotation and monitoring.',
            'API2-003': 'Invalidate all tokens when user changes password. Implement token revocation lists.',
            'API3-001': 'Use DTOs to return only necessary fields. Never rely on automatic serialization.',
            'API3-002': 'Implement explicit field allowlists. Never use mass assignment.',
            'API4-001': 'Implement rate limiting on all endpoints. Use sliding window algorithm.',
            'API4-002': 'Set maximum file upload sizes. Validate file types using magic bytes, not extensions.',
            'API5-001': 'Implement function-level access control. Verify user role before executing administrative functions.',
            'API5-002': 'Never trust client-provided role or permission fields. Verify on server side.',
            'API6-001': 'Implement rate limiting for business operations. Add CAPTCHA and confirmation steps.',
            'API6-002': 'Implement flow controls and transaction limits for sensitive operations.',
            'API7-001': 'Validate and sanitize all URL parameters. Use URL allowlists for permitted domains.',
            'API7-002': 'Block access to internal IP ranges and cloud metadata endpoints.',
            'API8-001': 'Add all recommended security headers: X-Content-Type-Options, X-Frame-Options, CSP.',
            'API8-002': 'Return generic error messages to users. Log detailed errors server-side only.',
            'API8-003': 'Configure CORS to only allow trusted origins. Never set Access-Control-Allow-Origin to "*" for APIs.',
            'API9-001': 'Keep API documentation updated. Version control your API spec.',
            'API9-002': 'Remove debug endpoints before deploying to production.',
            'API9-003': 'Deprecate old API versions. Provide migration paths and sunset dates.',
            'API10-001': 'Validate all input data. Use schema validation for request bodies.',
            'API10-002': 'Use safe serialization methods. Avoid eval() and pickle.'
        };
        return remediations[id] || 'Follow OWASP API Security Top 10 guidelines for remediation.';
    }

    getSummary() {
        return {
            categories: Object.entries(this.apiCategories).map(([id, name]) => ({
                id,
                name,
                patternCount: this.patterns[id]?.length || 0
            })),
            totalPatterns: Object.values(this.patterns).flat().length
        };
    }
}

module.exports = { APISecurityScanner };
