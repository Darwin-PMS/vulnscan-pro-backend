/**
 * Framework Security Scanner
 * Detects Laravel, CodeIgniter, ASP.NET, and other framework-specific vulnerabilities
 */

const { v4: uuidv4 } = require('uuid');

class FrameworkScanner {
    constructor() {
        this.frameworks = {
            laravel: new LaravelScanner(),
            codeigniter: new CodeIgniterScanner(),
            aspnet: new ASPNETScanner(),
            django: new DjangoScanner(),
            spring: new SpringScanner()
        };
    }

    async scanTarget(url, scanId, options = {}) {
        const { framework = 'auto' } = options;
        
        const results = {
            scanId,
            target: url,
            type: 'framework_security',
            startTime: new Date().toISOString(),
            endTime: null,
            vulnerabilities: [],
            summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            detected: {
                framework: null,
                version: null,
                stack: []
            },
            categories: ['Framework Security', 'Misconfiguration', 'Known CVE']
        };

        try {
            const axios = require('axios');
            const response = await axios.get(url, {
                timeout: 10000,
                headers: { 'User-Agent': 'VulnScanPro-Framework/1.0' },
                validateStatus: () => true
            });

            const content = response.data;
            const headers = response.headers;

            if (framework === 'auto' || framework === 'laravel') {
                this.frameworks.laravel.detect(content, headers, results);
            }
            if (framework === 'auto' || framework === 'codeigniter') {
                this.frameworks.codeigniter.detect(content, headers, results);
            }
            if (framework === 'auto' || framework === 'aspnet') {
                this.frameworks.aspnet.detect(content, headers, results);
            }
            if (framework === 'auto' || framework === 'django') {
                this.frameworks.django.detect(content, headers, results);
            }
            if (framework === 'auto' || framework === 'spring') {
                this.frameworks.spring.detect(content, headers, results);
            }

            results.vulnerabilities.forEach(v => {
                if (v.severity === 'critical') results.summary.critical++;
                else if (v.severity === 'high') results.summary.high++;
                else if (v.severity === 'medium') results.summary.medium++;
                else if (v.severity === 'low') results.summary.low++;
                else results.summary.info++;
            });

        } catch (error) {
            console.error('Framework scan error:', error.message);
        }

        results.endTime = new Date().toISOString();
        return results;
    }

    getSummary() {
        return {
            categories: ['Laravel Security', 'CodeIgniter Security', 'ASP.NET Security', 'Django Security', 'Spring Security'],
            features: ['Framework detection', 'Version identification', 'CVE mapping', 'Misconfiguration detection']
        };
    }
}

class LaravelScanner {
    constructor() {
        this.vulnerableVersions = this.initializeVulnerableVersions();
    }

    initializeVulnerableVersions() {
        return {
            '5.0': { cve: ['CVE-2015-6564'], severity: 'critical' },
            '5.1': { cve: ['CVE-2016-6212'], severity: 'high' },
            '5.2': { cve: ['CVE-2017-16894'], severity: 'high' },
            '5.3': { cve: ['CVE-2018-6919'], severity: 'high' },
            '5.4': { cve: ['CVE-2019-6271'], severity: 'medium' },
            '5.5': { cve: ['CVE-2020-15169'], severity: 'high' },
            '5.6': { cve: ['CVE-2021-21263'], severity: 'high' },
            '5.7': { cve: ['CVE-2021-43605'], severity: 'high' },
            '5.8': { cve: ['CVE-2021-32628'], severity: 'critical' },
            '6.x': { cve: ['CVE-2021-32625'], severity: 'high' },
            '7.x': { cve: ['CVE-2021-21263'], severity: 'high' },
            '8.x': { cve: ['CVE-2021-21264'], severity: 'high' }
        };
    }

    detect(content, headers, results) {
        const laravelIndicators = [
            /laravel/i,
            /csrf-token/i,
            /X-CSRF-TOKEN/i,
            /_token/i,
            /vendor\/laravel/i,
            / Illuminate\//i,
            /artisan/i
        ];

        const detected = laravelIndicators.some(p => p.test(content));
        
        if (detected) {
            results.detected.framework = 'Laravel';
            results.detected.stack.push('Laravel');

            const versionMatch = content.match(/Laravel ([\d.]+)/i) || 
                                 headers['x-laravel-version'];
            if (versionMatch) {
                results.detected.version = versionMatch[1] || versionMatch;
                this.checkVulnerableVersion(versionMatch[1] || versionMatch, results);
            }

            this.detectMisconfigurations(content, results);
        }
    }

    checkVulnerableVersion(version, results) {
        const majorMinor = version.split('.').slice(0, 2).join('.');
        const vuln = this.vulnerableVersions[majorMinor];
        
        if (vuln) {
            results.vulnerabilities.push({
                id: `laravel-cve-${uuidv4().substring(0, 6)}`,
                type: 'outdated_framework',
                title: `Outdated Laravel Version: ${version}`,
                severity: vuln.severity,
                description: `Laravel ${version} has known vulnerabilities`,
                category: 'laravel',
                cveIds: vuln.cve,
                remediation: `Upgrade to latest Laravel version`
            });
        }
    }

    detectMisconfigurations(content, results) {
        const patterns = [
            { pattern: /APP_DEBUG\s*=\s*true/i, severity: 'high', title: 'Debug Mode Enabled', desc: 'Laravel debug mode exposes sensitive info' },
            { pattern: /env\(['"](APP_KEY|DB_PASSWORD|SECRET)/i, severity: 'medium', title: 'Hardcoded Secrets in Config', desc: 'Environment variables may be exposed' },
            { pattern: /sql_log\s*=\s*on/i, severity: 'high', title: 'SQL Logging Enabled', desc: 'SQL queries are being logged' },
            { pattern: /display_errors\s*=\s*On/i, severity: 'high', title: 'PHP Display Errors', desc: 'PHP errors are displayed to users' }
        ];

        patterns.forEach(p => {
            if (p.pattern.test(content)) {
                results.vulnerabilities.push({
                    id: `laravel-${uuidv4().substring(0, 6)}`,
                    type: 'misconfiguration',
                    title: p.title,
                    severity: p.severity,
                    description: p.desc,
                    category: 'laravel',
                    remediation: 'Disable in production environment'
                });
            }
        });
    }
}

class CodeIgniterScanner {
    constructor() {
        this.vulnerableVersions = {
            '2.x': { cve: ['CVE-2015-4334'], severity: 'critical' },
            '3.0': { cve: ['CVE-2018-19226'], severity: 'high' },
            '4.0': { cve: ['CVE-2020-24142'], severity: 'high' }
        };
    }

    detect(content, headers, results) {
        const ciIndicators = [
            /CodeIgniter/i,
            /ci_session/i,
            /\/system\/core/i,
            /\/application\/controllers/i,
            /CI_VERSION/i
        ];

        const detected = ciIndicators.some(p => p.test(content));
        
        if (detected) {
            results.detected.framework = 'CodeIgniter';
            results.detected.stack.push('CodeIgniter');

            const versionMatch = content.match(/CodeIgniter ([\d.]+)/i);
            if (versionMatch) {
                results.detected.version = versionMatch[1];
            }

            this.detectMisconfigurations(content, results);
        }
    }

    detectMisconfigurations(content, results) {
        const patterns = [
            { pattern: /enable_query_strings\s*=\s*true/i, severity: 'medium', title: 'Query Strings Enabled', desc: 'Query strings enabled - potential security risk' },
            { pattern: /allow_get_array\s*=\s*true/i, severity: 'low', title: 'GET Array Enabled', desc: 'GET parameters are allowed' },
            { pattern: /CSRF_protection/i, severity: 'low', title: 'Check CSRF Protection', desc: 'Verify CSRF protection is enabled' }
        ];

        patterns.forEach(p => {
            if (p.pattern.test(content)) {
                results.vulnerabilities.push({
                    id: `ci-${uuidv4().substring(0, 6)}`,
                    type: 'misconfiguration',
                    title: p.title,
                    severity: p.severity,
                    description: p.desc,
                    category: 'codeigniter',
                    remediation: 'Configure in application/config/config.php'
                });
            }
        });
    }
}

class ASPNETScanner {
    constructor() {
        this.vulnerableVersions = {
            '4.0': { cve: ['CVE-2020-1147'], severity: 'critical' },
            '3.5': { cve: ['CVE-2020-0688'], severity: 'high' },
            '2.0': { cve: ['CVE-2019-1890'], severity: 'high' }
        };
    }

    detect(content, headers, results) {
        const aspnetIndicators = [
            /__VIEWSTATE/i,
            /__EVENTVALIDATION/i,
            /\.aspx?/i,
            /ASP.NET/i,
            /System\.Web\.UI/i,
            /__doPostBack/i
        ];

        const server = headers['server'] || '';
        
        if (aspnetIndicators.some(p => p.test(content)) || server.includes('ASP.NET')) {
            results.detected.framework = 'ASP.NET';
            results.detected.stack.push('ASP.NET');
            results.detected.stack.push(server);

            const versionMatch = server.match(/ASP.NET ([\d.]+)/i);
            if (versionMatch) {
                results.detected.version = versionMatch[1];
            }

            this.detectMisconfigurations(content, headers, results);
        }
    }

    detectMisconfigurations(content, headers, results) {
        if (headers['x-powered-by']?.includes('ASP.NET')) {
            results.vulnerabilities.push({
                id: `aspnet-001`,
                type: 'information_disclosure',
                title: 'ASP.NET Header Exposed',
                severity: 'low',
                description: 'X-Powered-By header reveals ASP.NET version',
                category: 'aspnet',
                remediation: 'Remove X-Powered-By header in web.config'
            });
        }

        const patterns = [
            { pattern: /customErrors mode\s*=\s*["']Off["']/i, severity: 'high', title: 'Custom Errors Disabled', desc: 'Detailed error messages exposed' },
            { pattern: /trace\s*enabled\s*=\s*true/i, severity: 'high', title: 'Tracing Enabled', desc: 'ASP.NET tracing is enabled' },
            { pattern: /debug\s*=\s*true/i, severity: 'critical', title: 'Debug Mode Enabled', desc: 'Debug mode is enabled in production' }
        ];

        patterns.forEach(p => {
            if (p.pattern.test(content)) {
                results.vulnerabilities.push({
                    id: `aspnet-${uuidv4().substring(0, 6)}`,
                    type: 'misconfiguration',
                    title: p.title,
                    severity: p.severity,
                    description: p.desc,
                    category: 'aspnet',
                    remediation: 'Disable in web.config'
                });
            }
        });
    }
}

class DjangoScanner {
    constructor() {
        this.vulnerableVersions = {
            '2.2': { cve: ['CVE-2021-44420'], severity: 'high' },
            '3.0': { cve: ['CVE-2021-32803'], severity: 'high' },
            '3.1': { cve: ['CVE-2021-35042'], severity: 'high' },
            '3.2': { cve: ['CVE-2022-28346'], severity: 'critical' },
            '4.0': { cve: ['CVE-2023-36069'], severity: 'critical' },
            '4.1': { cve: ['CVE-2023-36069'], severity: 'critical' }
        };
    }

    detect(content, headers, results) {
        const djangoIndicators = [
            /csrfmiddlewaretoken/i,
            /Django/i,
            /__django/i,
            /django-csrf/i,
            /csrf-token/i
        ];

        if (djangoIndicators.some(p => p.test(content))) {
            results.detected.framework = 'Django';
            results.detected.stack.push('Django');
            results.detected.stack.push('Python');

            const versionMatch = content.match(/Django ([\d.]+)/i);
            if (versionMatch) {
                results.detected.version = versionMatch[1];
                this.checkVulnerableVersion(versionMatch[1], results);
            }

            this.detectMisconfigurations(content, results);
        }
    }

    checkVulnerableVersion(version, results) {
        const majorMinor = version.split('.').slice(0, 2).join('.');
        const vuln = this.vulnerableVersions[majorMinor];
        
        if (vuln) {
            results.vulnerabilities.push({
                id: `django-cve-${uuidv4().substring(0, 6)}`,
                type: 'outdated_framework',
                title: `Outdated Django Version: ${version}`,
                severity: vuln.severity,
                description: `Django ${version} has known vulnerabilities`,
                category: 'django',
                cveIds: vuln.cve,
                remediation: 'Upgrade to latest Django version'
            });
        }
    }

    detectMisconfigurations(content, results) {
        if (content.includes('DEBUG = True') || content.includes('DEBUG=True')) {
            results.vulnerabilities.push({
                id: `django-001`,
                type: 'misconfiguration',
                title: 'Django Debug Mode Enabled',
                severity: 'critical',
                description: 'Debug mode exposes sensitive configuration',
                category: 'django',
                remediation: 'Set DEBUG=False in settings.py'
            });
        }
    }
}

class SpringScanner {
    constructor() {
        this.vulnerableVersions = {
            '2.0.x': { cve: ['CVE-2022-22965'], severity: 'critical' },
            '2.1.x': { cve: ['CVE-2022-22965'], severity: 'critical' },
            '2.5.x': { cve: ['CVE-2022-22965'], severity: 'critical' },
            '2.6.x': { cve: ['CVE-2022-22965'], severity: 'critical' },
            '3.0.x': { cve: ['CVE-2022-22965'], severity: 'critical' },
            '3.1.x': { cve: ['CVE-2022-22965'], severity: 'critical' },
            '3.2.x': { cve: ['CVE-2022-22965'], severity: 'critical' },
            '5.2.x': { cve: ['CVE-2022-22965'], severity: 'critical' },
            '5.3.x': { cve: ['CVE-2022-22965'], severity: 'critical' }
        };
    }

    detect(content, headers, results) {
        const springIndicators = [
            /Spring/i,
            /springframework/i,
            /Thymeleaf/i,
            /org\.springframework/i,
            /_csrf/i,
            /csrf token/i
        ];

        if (springIndicators.some(p => p.test(content))) {
            results.detected.framework = 'Spring Framework';
            results.detected.stack.push('Spring');
            results.detected.stack.push('Java');

            const versionMatch = content.match(/Spring ([\d.]+)/i);
            if (versionMatch) {
                results.detected.version = versionMatch[1];
            }

            this.detectVulnerabilities(results);
        }
    }

    detectVulnerabilities(results) {
        results.vulnerabilities.push({
            id: `spring-001`,
            type: 'potential_vulnerability',
            title: 'Spring Framework Detected',
            severity: 'medium',
            description: 'Ensure Spring is patched against CVE-2022-22965 (Spring4Shell)',
            category: 'spring',
            cveIds: ['CVE-2022-22965'],
            remediation: 'Apply Spring Framework patches immediately'
        });
    }
}

module.exports = { FrameworkScanner };