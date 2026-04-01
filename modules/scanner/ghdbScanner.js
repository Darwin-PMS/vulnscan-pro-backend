/**
 * Google Hacking Database (GHDB) Scanner Module
 * Implements dork-based vulnerability detection
 */

const axios = require('axios');
const { checkSSRF, sanitizeInput } = require('../utils/security');

class GHDBScanner {
    constructor() {
        this.categories = {
            'Files_Containing_Passwords': { severity: 'critical', description: 'Files that may contain passwords' },
            'Files_Containing_Usernames': { severity: 'high', description: 'Files that may contain usernames' },
            'Sensitive_Directories': { severity: 'medium', description: 'Sensitive directory listings' },
            'Web_Server_Detection': { severity: 'info', description: 'Web server version and config files' },
            'Vulnerable_Files': { severity: 'high', description: 'Files with known vulnerabilities' },
            'Error_Messages': { severity: 'low', description: 'Detailed error message disclosures' },
            'Software_Version': { severity: 'info', description: 'Software version information' },
            'Database_Information': { severity: 'high', description: 'Exposed database information' },
            'Admin_Panels': { severity: 'medium', description: 'Administrative interface discovery' },
            'API_Endpoints': { severity: 'medium', description: 'Exposed API documentation' }
        };

        this.patterns = this.initializeGHDBPatterns();
    }

    initializeGHDBPatterns() {
        return [
            // Files Containing Passwords
            {
                id: 'GHDB-0001',
                category: 'Files_Containing_Passwords',
                title: 'Configuration Files with Passwords',
                dork: 'site:example.com filetype:config password',
                pattern: /password|passwd|pwd|secret|api_key|apikey/i,
                severity: 'critical',
                fileExtensions: ['.conf', '.config', '.cfg', '.ini', '.xml', '.yaml', '.yml', '.json'],
                check: async (url, response) => {
                    const content = response.data || '';
                    const passwordPatterns = [
                        /password\s*=\s*["'][^"']+["']/i,
                        /passwd\s*=\s*["'][^"']+["']/i,
                        /api[_-]?key\s*=\s*["'][^"']+["']/i,
                        /secret\s*=\s*["'][^"']+["']/i
                    ];
                    return passwordPatterns.some(p => p.test(content));
                }
            },
            {
                id: 'GHDB-0002',
                category: 'Files_Containing_Passwords',
                title: 'Database Backup Files',
                dork: 'site:example.com filetype:sql dump',
                pattern: /CREATE TABLE|INSERT INTO|DROP TABLE/i,
                severity: 'critical',
                fileExtensions: ['.sql', '.dump', '.bak', '.backup', '.db'],
                check: async (url, response) => {
                    const content = response.data || '';
                    return /CREATE TABLE|INSERT INTO|DROP TABLE|CREATE DATABASE/i.test(content);
                }
            },
            {
                id: 'GHDB-0003',
                category: 'Files_Containing_Passwords',
                title: 'Excel/CSV Files with Credentials',
                dork: 'site:example.com filetype:xlsx password',
                pattern: /password|username|credential/i,
                severity: 'critical',
                fileExtensions: ['.xlsx', '.xls', '.csv', '.tsv'],
                check: async (url, response) => {
                    return url.match(/\.(xlsx|xls|csv|tsv)$/i) !== null;
                }
            },

            // Files Containing Usernames
            {
                id: 'GHDB-0010',
                category: 'Files_Containing_Usernames',
                title: 'User Lists',
                dork: 'site:example.com filetype:txt "username"',
                pattern: /username|user|email|login|account/i,
                severity: 'high',
                fileExtensions: ['.txt', '.log', '.csv'],
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('username') || content.includes('user');
                }
            },
            {
                id: 'GHDB-0011',
                category: 'Files_Containing_Usernames',
                title: 'Email Lists',
                dork: 'site:example.com filetype:txt "@example.com"',
                pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
                severity: 'medium',
                fileExtensions: ['.txt', '.csv', '.ldif'],
                check: async (url, response) => {
                    const content = response.data || '';
                    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
                    const emails = content.match(emailRegex) || [];
                    return emails.length > 5;
                }
            },

            // Sensitive Directories
            {
                id: 'GHDB-0020',
                category: 'Sensitive_Directories',
                title: 'Git Repository Exposed',
                dork: 'site:example.com intitle:"index of" ".git"',
                pattern: /\.git\/HEAD|\.git\/config|\.git\/objects/i,
                severity: 'critical',
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('.git/HEAD') || content.includes('.git/config') ||
                           url.includes('.git');
                }
            },
            {
                id: 'GHDB-0021',
                category: 'Sensitive_Directories',
                title: 'Environment Files Exposed',
                dork: 'site:example.com filetype:env',
                pattern: /AWS_ACCESS_KEY|DATABASE_URL|SECRET_KEY|PRIVATE_KEY/i,
                severity: 'critical',
                fileExtensions: ['.env', '.env.production', '.env.local'],
                check: async (url, response) => {
                    const content = response.data || '';
                    return /AWS_|DATABASE_|SECRET_|PRIVATE_|API_KEY/.test(content);
                }
            },
            {
                id: 'GHDB-0022',
                category: 'Sensitive_Directories',
                title: 'Backup Directory Exposed',
                dork: 'site:example.com intitle:"index of" "backup"',
                pattern: /backup|bak|old|archive/i,
                severity: 'high',
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('backup') || content.includes('.bak') ||
                           url.includes('/backup');
                }
            },
            {
                id: 'GHDB-0023',
                category: 'Sensitive_Directories',
                title: 'Directory Listing Enabled',
                dork: 'intitle:"Index of" "parent directory"',
                pattern: /\[To Parent Directory\]|<a href="\/[^"]+\/">/i,
                severity: 'medium',
                check: async (url, response) => {
                    const content = response.data || '';
                    return /Index of|Parent Directory|\[To Parent Directory\]|<a href="\/[^"]+\/">/i.test(content);
                }
            },

            // Web Server Detection
            {
                id: 'GHDB-0030',
                category: 'Web_Server_Detection',
                title: 'Apache Server Status Page',
                dork: 'site:example.com "Apache Server Status"',
                pattern: /Server Version|Server Built|Apache|server-status/i,
                severity: 'info',
                check: async (url, response) => {
                    const headers = response.headers;
                    const server = headers['server'] || '';
                    return server.toLowerCase().includes('apache') ||
                           url.includes('server-status');
                }
            },
            {
                id: 'GHDB-0031',
                category: 'Web_Server_Detection',
                title: 'Nginx Configuration Exposed',
                dork: 'site:example.com filetype:conf nginx',
                pattern: /nginx|worker_processes|events \{/i,
                severity: 'low',
                fileExtensions: ['.conf'],
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('nginx') || content.includes('worker_processes');
                }
            },

            // Vulnerable Files
            {
                id: 'GHDB-0040',
                category: 'Vulnerable_Files',
                title: 'phpMyAdmin Access',
                dork: 'site:example.com "phpMyAdmin" "Welcome to phpMyAdmin"',
                pattern: /phpMyAdmin| PMA |pma_/i,
                severity: 'high',
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('phpMyAdmin') || url.includes('phpmyadmin');
                }
            },
            {
                id: 'GHDB-0041',
                category: 'Vulnerable_Files',
                title: 'WordPress Sensitive Files',
                dork: 'site:example.com filetype:log "wordpress" "error"',
                pattern: /wp-config|wp-content|wordpress/i,
                severity: 'high',
                fileExtensions: ['.log', '.txt', '.php'],
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('wp-config.php') || url.includes('wp-config');
                }
            },
            {
                id: 'GHDB-0042',
                category: 'Vulnerable_Files',
                title: 'Admin Login Pages',
                dork: 'site:example.com intitle:"Admin" "Login" "Administration"',
                pattern: /admin|login|authentication/i,
                severity: 'medium',
                check: async (url, response) => {
                    const content = response.data || '';
                    return (url.includes('admin') || url.includes('login')) &&
                           content.includes('password');
                }
            },
            {
                id: 'GHDB-0043',
                category: 'Vulnerable_Files',
                title: 'Laravel .env File',
                dork: 'site:example.com ".env" "APP_KEY"',
                pattern: /APP_KEY|DB_HOST|REDIS_HOST/i,
                severity: 'critical',
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('APP_KEY') || content.includes('DB_HOST');
                }
            },

            // Error Messages
            {
                id: 'GHDB-0050',
                category: 'Error_Messages',
                title: 'SQL Error Disclosure',
                dork: 'site:example.com "SQL syntax" OR "MySQL" OR "PostgreSQL"',
                pattern: /SQL syntax|mysql_fetch|mysqli|ORA-|syntax error/i,
                severity: 'medium',
                check: async (url, response) => {
                    const content = response.data || '';
                    const sqlErrors = [
                        'SQL syntax', 'mysql_fetch', 'mysqli_num', 'ORA-', 
                        'PostgreSQL', 'Microsoft SQL Native Client',
                        'Warning: mysql', 'SQL_ERROR'
                    ];
                    return sqlErrors.some(e => content.includes(e));
                }
            },
            {
                id: 'GHDB-0051',
                category: 'Error_Messages',
                title: 'PHP Error Disclosure',
                dork: 'site:example.com "Warning: include" OR "Fatal error:"',
                pattern: /Warning:|Fatal error:|Parse error:|Notice:/i,
                severity: 'low',
                check: async (url, response) => {
                    const content = response.data || '';
                    return /Warning:|Fatal error:|Parse error:|Notice:/.test(content);
                }
            },
            {
                id: 'GHDB-0052',
                category: 'Error_Messages',
                title: 'Stack Trace Disclosure',
                dork: '"at com.sun." OR "java.lang." OR "Exception in thread"',
                pattern: /Exception in thread|at java\.|at com\.sun\.|Stack trace:/i,
                severity: 'medium',
                check: async (url, response) => {
                    const content = response.data || '';
                    return /Exception in thread|at java\.|Stack trace:/.test(content);
                }
            },

            // Database Information
            {
                id: 'GHDB-0060',
                category: 'Database_Information',
                title: 'Exposed MySQL Data',
                dork: 'site:example.com "MySQL" "Server version"',
                pattern: /MySQL|Database server|Server version/i,
                severity: 'high',
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('MySQL') && content.includes('Server');
                }
            },
            {
                id: 'GHDB-0061',
                category: 'Database_Information',
                title: 'MongoDB Web Interface',
                dork: 'site:example.com "MongoDB" "Administration"',
                pattern: /MongoDB|mongod|__schema/i,
                severity: 'high',
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('MongoDB') || url.includes('mongoclient');
                }
            },

            // Admin Panels
            {
                id: 'GHDB-0070',
                category: 'Admin_Panels',
                title: 'cPanel Access',
                dork: 'site:example.com "cPanel" "Log in"',
                pattern: /cpanel|cPanel|WHM/i,
                severity: 'medium',
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('cPanel') || url.includes('cpanel');
                }
            },
            {
                id: 'GHDB-0071',
                category: 'Admin_Panels',
                title: 'Jenkins CI Access',
                dork: 'site:example.com "Jenkins" "Dashboard"',
                pattern: /Jenkins|Hudson|Build History/i,
                severity: 'high',
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('Jenkins') || url.includes('jenkins');
                }
            },
            {
                id: 'GHDB-0072',
                category: 'Admin_Panels',
                title: 'Kubernetes Dashboard',
                dork: 'site:example.com "Kubernetes Dashboard"',
                pattern: /Kubernetes|kubernetes|k8s/i,
                severity: 'high',
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('Kubernetes') || url.includes('kubernetes');
                }
            },

            // API Endpoints
            {
                id: 'GHDB-0080',
                category: 'API_Endpoints',
                title: 'Swagger/OpenAPI Documentation',
                dork: 'site:example.com "swagger" OR "OpenAPI" OR "api-docs"',
                pattern: /swagger|openapi|api-docs|\/swagger-ui/i,
                severity: 'medium',
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('swagger') || url.includes('swagger') ||
                           url.includes('api-docs');
                }
            },
            {
                id: 'GHDB-0081',
                category: 'API_Endpoints',
                title: 'GraphQL Introspection',
                dork: 'site:example.com graphql "query"',
                pattern: /__schema|__type|IntrospectionQuery/i,
                severity: 'high',
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('__schema') || url.includes('graphql');
                }
            },
            {
                id: 'GHDB-0082',
                category: 'API_Endpoints',
                title: 'GraphQL Playground',
                dork: 'site:example.com "GraphQL Playground"',
                pattern: /GraphQL Playground|playground|GraphiQL/i,
                severity: 'medium',
                check: async (url, response) => {
                    const content = response.data || '';
                    return content.includes('GraphQL Playground') || 
                           url.includes('playground') || url.includes('graphiql');
                }
            }
        ];
    }

    async scanTarget(url, scanId) {
        const results = {
            scanId,
            targetUrl: url,
            scanner: 'Google Hacking Database (GHDB)',
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

            for (const pattern of this.patterns) {
                try {
                    const isVulnerable = await pattern.check(url, response);

                    if (isVulnerable) {
                        const vulnerability = {
                            id: pattern.id,
                            category: pattern.category,
                            categoryName: this.categories[pattern.category]?.description || pattern.category,
                            title: pattern.title,
                            dork: pattern.dork,
                            description: `GHDB pattern detected: ${pattern.title}. This may expose sensitive information.`,
                            severity: pattern.severity,
                            url: url,
                            remediation: this.getRemediation(pattern.id),
                            discoveredAt: new Date().toISOString()
                        };

                        if (!results.categories[pattern.category]) {
                            results.categories[pattern.category] = {
                                name: pattern.category.replace(/_/g, ' '),
                                count: 0,
                                vulnerabilities: []
                            };
                        }

                        results.categories[pattern.category].count++;
                        results.categories[pattern.category].vulnerabilities.push(vulnerability);
                        results.vulnerabilities.push(vulnerability);
                        results.summary[pattern.severity]++;
                    }
                } catch (err) {
                    console.error(`GHDB check ${pattern.id} failed:`, err.message);
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

    async scanWithDorks(targetDomain) {
        const results = {
            domain: targetDomain,
            scanner: 'GHDB Dork Scanner',
            startTime: new Date().toISOString(),
            findings: [],
            summary: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0
            }
        };

        for (const pattern of this.patterns) {
            const dork = pattern.dork.replace('example.com', targetDomain);
            results.findings.push({
                id: pattern.id,
                title: pattern.title,
                category: pattern.category,
                dork: dork,
                severity: pattern.severity,
                description: pattern.title
            });
            results.summary[pattern.severity]++;
        }

        results.endTime = new Date().toISOString();
        return results;
    }

    getRemediation(vulnerabilityId) {
        const remediations = {
            'GHDB-0001': 'Remove configuration files from web root. Store sensitive credentials in environment variables or secure vaults.',
            'GHDB-0002': 'Secure database backup files with encryption. Restrict access to backup files using proper file permissions.',
            'GHDB-0003': 'Remove sensitive data from spreadsheets. Use proper access control and encryption for credential storage.',
            'GHDB-0010': 'Restrict access to user lists. Implement proper access controls and remove public-facing user lists.',
            'GHDB-0011': 'Implement GDPR-compliant email collection. Remove public email lists and use secure contact forms.',
            'GHDB-0020': 'Prevent Git directory exposure by configuring web server to deny access to .git folders. Add .git to web server deny list.',
            'GHDB-0021': 'Move .env files outside web root. Add .env to .gitignore and restrict file permissions.',
            'GHDB-0022': 'Remove or password-protect backup directories. Never expose backups publicly.',
            'GHDB-0023': 'Disable directory listing in web server configuration. Use proper index files.',
            'GHDB-0030': 'Disable server status pages in production. Restrict access to server information.',
            'GHDB-0031': 'Move configuration files outside web root. Secure nginx configuration.',
            'GHDB-0040': 'Password-protect phpMyAdmin. Restrict access by IP. Remove if not needed.',
            'GHDB-0041': 'Move wp-config.php outside web root. Disable directory listing. Remove WordPress version disclosure.',
            'GHDB-0042': 'Implement brute-force protection on login pages. Use CAPTCHA and rate limiting.',
            'GHDB-0043': 'Immediately rotate all exposed keys. Move .env to secure location outside web root.',
            'GHDB-0050': 'Implement custom error pages. Disable detailed SQL errors in production.',
            'GHDB-0051': 'Disable PHP error reporting in production. Set display_errors = Off.',
            'GHDB-0052': 'Configure exception handlers. Never expose stack traces in production.',
            'GHDB-0060': 'Restrict MySQL server access. Use firewall rules. Never expose database directly.',
            'GHDB-0061': 'Enable authentication for MongoDB. Restrict network access. Never expose without auth.',
            'GHDB-0070': 'Enable two-factor authentication for cPanel. Restrict IP access.',
            'GHDB-0071': 'Enable authentication for Jenkins. Restrict access. Never expose without auth.',
            'GHDB-0072': 'Enable RBAC for Kubernetes. Never expose dashboard publicly without auth.',
            'GHDB-0080': 'Disable Swagger UI in production. Protect API documentation with authentication.',
            'GHDB-0081': 'Disable GraphQL introspection in production. Use query depth limiting.',
            'GHDB-0082': 'Disable GraphQL Playground in production. Use production-ready GraphQL clients.'
        };
        return remediations[vulnerabilityId] || 'Remove or restrict access to sensitive information. Follow security best practices.';
    }

    getGHDBSummary() {
        return {
            categories: Object.entries(this.categories).map(([name, info]) => ({
                name: name.replace(/_/g, ' '),
                severity: info.severity,
                description: info.description,
                patternCount: this.patterns.filter(p => p.category === name).length
            })),
            totalPatterns: this.patterns.length
        };
    }
}

module.exports = { GHDBScanner };
