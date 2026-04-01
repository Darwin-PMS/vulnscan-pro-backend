/**
 * WordPress & PHP Security Scanner
 * Specialized scanner for WordPress and PHP-based applications
 * Detects common WordPress vulnerabilities, plugin issues, and PHP vulnerabilities
 */

const { v4: uuidv4 } = require('uuid');

class WordPressScanner {
    constructor() {
        this.commonPlugins = this.initializePluginList();
        this.vulnerablePatterns = this.initializeVulnerablePatterns();
        this.wpVersions = this.initializeWPVersions();
    }

    initializePluginList() {
        return {
            'contact-form-7': { severity: 'low', category: 'plugin' },
            'elementor': { severity: 'medium', category: 'page-builder' },
            'woocommerce': { severity: 'medium', category: 'ecommerce' },
            'wordfence': { severity: 'low', category: 'security' },
            'all-in-one-seo': { severity: 'low', category: 'seo' },
            'jetpack': { severity: 'low', category: 'security' },
            'akismet': { severity: 'low', category: 'spam' },
            'wp-super-cache': { severity: 'medium', category: 'cache' },
            'w3-total-cache': { severity: 'medium', category: 'cache' },
            'revolution-slider': { severity: 'critical', cve: ['CVE-2014-9139'] },
            'slider-revolution': { severity: 'critical', cve: ['CVE-2014-9139'] },
            'revslider': { severity: 'critical', cve: ['CVE-2014-9139'] },
            'gravity-forms': { severity: 'medium', category: 'forms' },
            'gravityforms': { severity: 'medium', category: 'forms' },
            'contact-form-7': { severity: 'low', category: 'forms' },
            ' Ninja Forms': { severity: 'medium', category: 'forms' },
            'ninja-forms': { severity: 'medium', category: 'forms' },
            'woocommerce': { severity: 'medium', category: 'ecommerce' },
            'magnus': { severity: 'critical', cve: ['CVE-2015-2678'] },
            'popup-builder': { severity: 'high', cve: ['CVE-2020-28130'] },
            'wp-file-manager': { severity: 'critical', cve: ['CVE-2020-25213'] },
            'easy-wp-smtp': { severity: 'high', cve: ['CVE-2020-32626'] },
            'duplicate-page': { severity: 'low', category: 'utility' },
            'siteorigin-panels': { severity: 'medium', category: 'page-builder' },
            'beaver-builder': { severity: 'medium', category: 'page-builder' }
        };
    }

    initializeVulnerablePatterns() {
        return [
            {
                id: 'WP-001',
                name: 'XML-RPC Enabled',
                severity: 'high',
                pattern: /xmlrpc\.php/,
                description: 'XML-RPC is enabled and can be used for brute force attacks',
                remediation: 'Disable XML-RPC if not needed using .htaccess or a security plugin'
            },
            {
                id: 'WP-002',
                name: 'User Enumeration',
                severity: 'medium',
                pattern: /\?author=\d+/,
                description: 'User enumeration is possible via URL parameter',
                remediation: 'Block author parameter scanning in .htaccess'
            },
            {
                id: 'WP-003',
                name: 'WordPress Version Disclosure',
                severity: 'low',
                pattern: /<meta name="generator" content="WordPress/i,
                description: 'WordPress version is disclosed in meta tags',
                remediation: 'Remove version generator tag via functions.php or security plugin'
            },
            {
                id: 'WP-004',
                name: 'wp-config.php Accessible',
                severity: 'critical',
                pattern: /wp-config\.php/,
                description: 'Configuration file may be accessible',
                remediation: 'Move wp-config.php outside web root or block via .htaccess'
            },
            {
                id: 'WP-005',
                name: 'Directory Listing Enabled',
                severity: 'medium',
                pattern: /Index of \/wp-content\/plugins/,
                description: 'Directory listing is enabled for plugins',
                remediation: 'Disable directory listing in .htaccess'
            },
            {
                id: 'WP-006',
                name: 'Debug Mode Enabled',
                severity: 'high',
                pattern: /define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*true/i,
                description: 'WordPress debug mode is enabled - exposes sensitive info',
                remediation: 'Set WP_DEBUG to false in wp-config.php'
            },
            {
                id: 'WP-007',
                name: 'SQL Error Exposure',
                severity: 'high',
                pattern: /SQL syntax|MySQL server version|mysql_fetch/i,
                description: 'SQL errors are being displayed',
                remediation: 'Disable error display in PHP config or wp-config.php'
            },
            {
                id: 'WP-008',
                name: 'Plugin Directory Detection',
                severity: 'medium',
                pattern: /\/wp-content\/plugins\/([a-zA-Z0-9-_]+)/,
                description: 'Plugin directory structure exposed',
                remediation: 'Disable directory listing'
            },
            {
                id: 'WP-009',
                name: 'Theme Detection',
                severity: 'low',
                pattern: /\/wp-content\/themes\/([a-zA-Z0-9-_]+)/,
                description: 'Theme directory structure exposed',
                remediation: 'Disable directory listing'
            },
            {
                id: 'WP-010',
                name: 'REST API Enabled',
                severity: 'low',
                pattern: /\/wp-json\/wp\/v2/,
                description: 'REST API is enabled - verify this is intended',
                remediation: 'Restrict REST API access if not needed using security plugin'
            },
            {
                id: 'WP-011',
                name: 'Login Page Exposed',
                severity: 'low',
                pattern: /wp-login\.php|wp-admin/,
                description: 'WordPress login page is accessible',
                remediation: 'Consider using a custom login URL plugin'
            },
            {
                id: 'WP-012',
                name: 'Timthumb Vulnerability',
                severity: 'high',
                pattern: /timthumb\.php|thumb\.php/,
                description: 'Timthumb script detected - known RCE vulnerability',
                remediation: 'Update timthumb or remove if not needed'
            },
            {
                id: 'WP-013',
                name: 'Legacy PHP Version',
                severity: 'critical',
                pattern: /PHP\/(5\.[0-5]|7\.[0-2])/,
                description: 'Running unsupported PHP version',
                remediation: 'Upgrade to PHP 7.4 or higher'
            },
            {
                id: 'WP-014',
                name: 'XML External Entity (XXE)',
                severity: 'high',
                pattern: /<!ENTITY|SYSTEM\s+["']file:/i,
                description: 'Possible XXE vulnerability in XML parser',
                remediation: 'Disable external entity loading in PHP config'
            },
            {
                id: 'WP-015',
                name: 'LFI via Path Traversal',
                severity: 'critical',
                pattern: /\.\.\/|\.\.\\/,
                description: 'Path traversal detected',
                remediation: 'Sanitize all file inputs and use realpath()'
            }
        ];
    }

    initializeWPVersions() {
        return {
            '6.4': { supported: true, eol: '2024-12-31' },
            '6.3': { supported: true, eol: '2024-08-31' },
            '6.2': { supported: false, eol: '2024-04-30' },
            '6.1': { supported: false, eol: '2024-01-31' },
            '6.0': { supported: false, eol: '2023-11-30' },
            '5.9': { supported: false, eol: '2023-08-31' },
            '5.8': { supported: false, eol: '2023-06-30' },
            '5.7': { supported: false, eol: '2023-04-30' }
        };
    }

    async scanTarget(url, scanId, options = {}) {
        const results = {
            scanId,
            target: url,
            type: 'wordpress_php',
            startTime: new Date().toISOString(),
            endTime: null,
            vulnerabilities: [],
            summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            detected: {
                cms: null,
                version: null,
                plugins: [],
                theme: null,
                server: null
            },
            categories: ['WordPress Security', 'PHP Vulnerabilities', 'Plugin Analysis']
        };

        try {
            const axios = require('axios');
            const response = await axios.get(url, {
                timeout: 10000,
                headers: {
                    'User-Agent': 'VulnScanPro-WPScanner/1.0'
                },
                validateStatus: () => true
            });

            const content = response.data;
            const headers = response.headers;

            this.detectWordPress(content, headers, results);
            this.detectPlugins(content, results);
            this.detectTheme(content, results);
            this.scanPatterns(content, results);
            this.checkServerInfo(headers, results);
            this.checkPHPVersion(headers, results);

            results.vulnerabilities.forEach(v => {
                if (v.severity === 'critical') results.summary.critical++;
                else if (v.severity === 'high') results.summary.high++;
                else if (v.severity === 'medium') results.summary.medium++;
                else if (v.severity === 'low') results.summary.low++;
                else results.summary.info++;
            });

        } catch (error) {
            console.error('WordPress scan error:', error.message);
        }

        results.endTime = new Date().toISOString();
        return results;
    }

    detectWordPress(content, headers, results) {
        const wpIndicators = [
            { pattern: /wp-content/i, type: 'plugin path' },
            { pattern: /wp-includes/i, type: 'core path' },
            { pattern: /wordpress/i, type: 'generator meta' },
            { pattern: /wp-embed/i, type: 'embed script' }
        ];

        const server = headers['server'] || '';
        const xpoweredby = headers['x-powered-by'] || '';
        
        if (server.toLowerCase().includes('wordpress') || 
            content.includes('wp-content') || 
            content.includes('wp-includes')) {
            
            results.detected.cms = 'WordPress';
            
            const versionMatch = content.match(/<meta name="generator" content="WordPress ([\d.]+)"/i) ||
                                  content.match(/wp-includes\/version\.php.*?\$wp_version = ['"]([^'"]+)/i);
            
            if (versionMatch) {
                results.detected.version = versionMatch[1];
            }
        }

        if (headers['x-generator']) {
            const wpVersion = headers['x-generator'].match(/WordPress ([\d.]+)/i);
            if (wpVersion) {
                results.detected.version = wpVersion[1];
            }
        }
    }

    detectPlugins(content, results) {
        const pluginPattern = /\/wp-content\/plugins\/([a-zA-Z0-9-_]+)/gi;
        let match;
        const foundPlugins = new Set();

        while ((match = pluginPattern.exec(content)) !== null) {
            const pluginName = match[1].toLowerCase();
            foundPlugins.add(match[1]);

            const pluginInfo = this.commonPlugins[pluginName];
            if (pluginInfo) {
                if (pluginInfo.cve) {
                    results.vulnerabilities.push({
                        id: `wp-plugin-${uuidv4().substring(0, 6)}`,
                        type: 'vulnerable_plugin',
                        title: `Vulnerable Plugin: ${match[1]}`,
                        severity: pluginInfo.severity,
                        description: `Known vulnerable plugin - CVE: ${pluginInfo.cve.join(', ')}`,
                        category: 'plugin',
                        plugin: match[1],
                        cveIds: pluginInfo.cve,
                        remediation: 'Update plugin to latest version or remove if not needed',
                        url: results.target
                    });
                }
            }
        }

        results.detected.plugins = Array.from(foundPlugins);
    }

    detectTheme(content, results) {
        const themePattern = /\/wp-content\/themes\/([a-zA-Z0-9-_]+)/i;
        const match = content.match(themePattern);
        
        if (match) {
            results.detected.theme = match[1];
        }
    }

    scanPatterns(content, results) {
        for (const pattern of this.vulnerablePatterns) {
            try {
                if (pattern.pattern.test(content)) {
                    results.vulnerabilities.push({
                        id: `wp-${pattern.id}`,
                        type: 'security_issue',
                        title: pattern.name,
                        severity: pattern.severity,
                        description: pattern.description,
                        category: 'wordpress',
                        remediation: pattern.remediation,
                        cwe: pattern.id === 'WP-014' ? 'CWE-611' : pattern.id === 'WP-015' ? 'CWE-22' : null,
                        references: this.getReferences(pattern.id)
                    });
                }
            } catch (e) {
                continue;
            }
        }
    }

    checkServerInfo(headers, results) {
        const server = headers['server'] || '';
        const xpoweredby = headers['x-powered-by'] || '';
        
        results.detected.server = server || xpoweredby || 'Unknown';

        if (server.includes('Apache') && !headers['server']?.includes('nginx')) {
            results.vulnerabilities.push({
                id: 'php-001',
                type: 'server_config',
                title: 'Apache Server Banner',
                severity: 'low',
                description: 'Server type is exposed in headers',
                category: 'information_disclosure',
                remediation: 'Hide server banner in Apache config'
            });
        }
    }

    checkPHPVersion(headers, results) {
        const xpoweredby = headers['x-powered-by'] || '';
        const phpVersionMatch = xpoweredby.match(/PHP\/([\d.]+)/i);
        
        if (phpVersionMatch) {
            const version = phpVersionMatch[1];
            const majorMinor = version.split('.').slice(0, 2).join('.');
            
            if (this.wpVersions[majorMinor] && !this.wpVersions[majorMinor].supported) {
                results.vulnerabilities.push({
                    id: 'php-version-001',
                    type: 'outdated_software',
                    title: 'End-of-Life PHP Version',
                    severity: 'critical',
                    description: `PHP version ${version} is no longer supported`,
                    category: 'php',
                    remediation: 'Upgrade to PHP 7.4 or higher (8.0+ recommended)'
                });
            }
        }
    }

    getReferences(patternId) {
        const references = {
            'WP-001': ['https://www.wordfence.com/help/advanced/xml-rpc/'],
            'WP-004': ['https://wordpress.org/support/article/hardening-wordpress/'],
            'WP-006': ['https://wordpress.org/support/article/debugging-in-wordpress/'],
            'WP-012': ['https://blog.sucuri.net/2014/08/understanding-the-timthumb-vulnerability.html'],
            'WP-014': ['https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing'],
            'WP-015': ['https://www.owasp.org/index.php/Path_Traversal']
        };
        return references[patternId] || [];
    }

    getSummary() {
        return {
            categories: [
                'WordPress Core Vulnerabilities',
                'Plugin Security Issues',
                'Theme Vulnerabilities',
                'PHP Security Issues',
                'Server Misconfigurations',
                'Information Disclosure'
            ],
            features: [
                'WordPress version detection',
                'Plugin enumeration',
                'Theme detection',
                'Vulnerable plugin identification',
                'PHP version checking',
                'Common WordPress misconfigurations'
            ]
        };
    }
}

module.exports = { WordPressScanner };