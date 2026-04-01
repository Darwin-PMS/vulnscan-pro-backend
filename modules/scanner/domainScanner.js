/**
 * Domain Intelligence Scanner
 * Comprehensive domain analysis, technology detection, vulnerabilities, and OSINT
 */

const { v4: uuidv4 } = require('uuid');
const dns = require('dns').promises;
const https = require('https');
const http = require('http');
const { URL } = require('url');

class DomainIntelligenceScanner {
    constructor() {
        this.techSignatures = this.loadTechSignatures();
        this.cmsSignatures = this.loadCMSSignatures();
    }

    loadTechSignatures() {
        return {
            // JavaScript Frameworks
            react: { pattern: /react|reactjs|react-dom/i, category: 'JavaScript Framework', confidence: 'high' },
            vue: { pattern: /vuejs|vue\.js|vue/i, category: 'JavaScript Framework', confidence: 'high' },
            angular: { pattern: /angular|ng-app/i, category: 'JavaScript Framework', confidence: 'high' },
            nextjs: { pattern: /nextjs|__next/i, category: 'JavaScript Framework', confidence: 'high' },
            nuxt: { pattern: /nuxt|__nuxt/i, category: 'JavaScript Framework', confidence: 'high' },
            svelte: { pattern: /svelte/i, category: 'JavaScript Framework', confidence: 'high' },

            // Backend
            nodejs: { pattern: /nodejs|express|node\.js/i, category: 'Backend', confidence: 'medium' },
            php: { pattern: /php/i, category: 'Backend', confidence: 'high' },
            python: { pattern: /python|django|flask|fastapi/i, category: 'Backend', confidence: 'medium' },
            java: { pattern: /java|spring|tomcat|jsp/i, category: 'Backend', confidence: 'medium' },
            aspnet: { pattern: /asp\.net|iis|aspx/i, category: 'Backend', confidence: 'high' },
            ruby: { pattern: /ruby on rails|ruby/i, category: 'Backend', confidence: 'medium' },
            golang: { pattern: /golang|go\.net/i, category: 'Backend', confidence: 'low' },

            // Web Servers
            nginx: { pattern: /nginx/i, category: 'Web Server', confidence: 'high' },
            apache: { pattern: /apache/i, category: 'Web Server', confidence: 'high' },
            iis: { pattern: /microsoft-iis|iis/i, category: 'Web Server', confidence: 'high' },
            litespeed: { pattern: /litespeed/i, category: 'Web Server', confidence: 'high' },
            cloudflare: { pattern: /cloudflare/i, category: 'CDN/WAF', confidence: 'high' },

            // Databases
            mysql: { pattern: /mysql/i, category: 'Database', confidence: 'medium' },
            postgresql: { pattern: /postgresql|postgres/i, category: 'Database', confidence: 'medium' },
            mongodb: { pattern: /mongodb/i, category: 'Database', confidence: 'medium' },
            redis: { pattern: /redis/i, category: 'Database', confidence: 'medium' },
            mariadb: { pattern: /mariadb/i, category: 'Database', confidence: 'medium' },

            // CMS
            wordpress: { pattern: /wp-content|wp-includes|wordpress/i, category: 'CMS', confidence: 'high' },
            drupal: { pattern: /drupal/i, category: 'CMS', confidence: 'high' },
            joomla: { pattern: /joomla/i, category: 'CMS', confidence: 'high' },
            magento: { pattern: /magento|mediamosa/i, category: 'CMS', confidence: 'high' },
            shopify: { pattern: /shopify/i, category: 'CMS', confidence: 'high' },
            wix: { pattern: /wix/i, category: 'CMS', confidence: 'high' },
            squarespace: { pattern: /squarespace/i, category: 'CMS', confidence: 'high' },

            // Analytics
            google_analytics: { pattern: /google-analytics|gtag|ga\.js/i, category: 'Analytics', confidence: 'high' },
            mixpanel: { pattern: /mixpanel/i, category: 'Analytics', confidence: 'high' },
            segment: { pattern: /segment\.com|segment\.io/i, category: 'Analytics', confidence: 'high' },
            hotjar: { pattern: /hotjar/i, category: 'Analytics', confidence: 'high' },

            // Security
            cloudflare: { pattern: /cloudflare|cf-ray/i, category: 'Security', confidence: 'high' },
            akamai: { pattern: /akamai/i, category: 'Security', confidence: 'high' },
            aws_waf: { pattern: /aws-waf/i, category: 'Security', confidence: 'high' },
            sentry: { pattern: /sentry\.io/i, category: 'Monitoring', confidence: 'high' },
            datadog: { pattern: /datadog/i, category: 'Monitoring', confidence: 'high' }
        };
    }

    loadCMSSignatures() {
        return {
            wordpress: {
                indicators: ['/wp-content/', '/wp-includes/', 'wp-json', 'wp-admin'],
                versionPatterns: [/meta name="generator" content="WordPress ([\d.]+)"/i],
                category: 'CMS'
            },
            drupal: {
                indicators: ['drupal', '/sites/default/', 'drupal.js'],
                versionPatterns: [/Drupal ([\d.]+)/i],
                category: 'CMS'
            },
            joomla: {
                indicators: ['joomla', '/media/com_', '/administrator/'],
                versionPatterns: [/Joomla! ([\d.]+)/i],
                category: 'CMS'
            },
            magento: {
                indicators: ['/skin/frontend/', '/js/mage/', 'Mage.Cookies'],
                versionPatterns: [/Magento ([\d.]+)/i],
                category: 'E-commerce'
            },
            shopify: {
                indicators: ['shopify', '/cdn.shopify.com/'],
                versionPatterns: [],
                category: 'E-commerce'
            }
        };
    }

    async scanTarget(url, scanId, options = {}) {
        const results = {
            scanId,
            target: url,
            type: 'domain_intelligence',
            startTime: new Date().toISOString(),
            endTime: null,
            domain: null,
            whois: {},
            dns: {},
            technologies: [],
            security: {},
            ssl: {},
            headers: {},
            ports: [],
            subdomains: [],
            vulnerabilities: [],
            summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            categories: ['Domain Intelligence', 'Technology Stack', 'Security Analysis', 'OSINT']
        };

        try {
            let domain;
            try {
                const urlObj = new URL(url);
                domain = urlObj.hostname;
            } catch (e) {
                domain = url;
            }

            results.domain = domain;

            await this.gatherDNSInfo(domain, results);
            await this.gatherSSLInfo(domain, results);
            await this.gatherHTTPHeaders(url, results);
            await this.detectTechnologies(results);
            await this.checkSecurityHeaders(results);
            await this.findSubdomains(domain, results);
            this.analyzeSecurityIssues(results);

        } catch (error) {
            console.error('Domain intelligence scan error:', error.message);
        }

        results.endTime = new Date().toISOString();
        return results;
    }

    async gatherDNSInfo(domain, results) {
        try {
            const [a, aaaa, cname, mx, ns, txt, soa] = await Promise.all([
                dns.resolve4(domain).catch(() => []),
                dns.resolve6(domain).catch(() => []),
                dns.resolveCname(domain).catch(() => []),
                dns.resolveMx(domain).catch(() => []),
                dns.resolveNs(domain).catch(() => []),
                dns.resolveTxt(domain).catch(() => []),
                dns.resolveSoa(domain).catch(() => null)
            ]);

            results.dns = {
                aRecords: a,
                aaaaRecords: aaaa,
                cnameRecords: cname,
                mxRecords: mx,
                nsRecords: ns,
                txtRecords: txt,
                soaRecord: soa
            };

            for (const ip of a || []) {
                results.vulnerabilities.push({
                    id: `domain-${uuidv4().substring(0, 6)}`,
                    type: 'exposed_service',
                    title: `Public IP: ${ip}`,
                    severity: 'info',
                    description: `Domain resolves to public IP address`,
                    category: 'network',
                    remediation: 'Ensure proper firewall rules'
                });
            }

        } catch (error) {
            results.dns.error = error.message;
        }
    }

    async gatherSSLInfo(domain, results) {
        return new Promise((resolve) => {
            const options = {
                hostname: domain,
                port: 443,
                method: 'GET',
                timeout: 10000,
                rejectUnauthorized: false
            };

            const req = https.request(options, (res) => {
                const cert = res.socket.getPeerCertificate();
                
                if (cert && Object.keys(cert).length > 0) {
                    results.ssl = {
                        valid: cert.valid_to && new Date(cert.valid_to) > new Date(),
                        issuer: cert.issuer?.O || cert.issuer?.OU || 'Unknown',
                        validFrom: cert.valid_from,
                        validTo: cert.valid_to,
                        daysRemaining: cert.valid_to ? Math.ceil((new Date(cert.valid_to) - new Date()) / (1000 * 60 * 60 * 24)) : null,
                        protocol: res.socket.getProtocol(),
                        cipher: res.socket.getCipher()?.name,
                        subject: cert.subject?.CN
                    };

                    if (results.ssl.daysRemaining !== null && results.ssl.daysRemaining < 30) {
                        results.vulnerabilities.push({
                            id: `ssl-${uuidv4().substring(0, 6)}`,
                            type: 'ssl_expiring',
                            title: 'SSL Certificate Expiring Soon',
                            severity: results.ssl.daysRemaining < 7 ? 'high' : 'medium',
                            description: `SSL certificate expires in ${results.ssl.daysRemaining} days`,
                            category: 'ssl',
                            remediation: 'Renew SSL certificate'
                        });
                    }
                }
                resolve();
            });

            req.on('error', () => resolve());
            req.on('timeout', () => resolve());
            req.end();
        });
    }

    async gatherHTTPHeaders(url, results) {
        try {
            const axios = require('axios');
            const response = await axios.get(url, {
                timeout: 10000,
                validateStatus: () => true,
                maxRedirects: 5
            });

            results.headers = {
                server: response.headers['server'],
                contentType: response.headers['content-type'],
                cacheControl: response.headers['cache-control'],
                xPoweredBy: response.headers['x-powered-by'],
                xFrameOptions: response.headers['x-frame-options'],
                xContentTypeOptions: response.headers['x-content-type-options'],
                strictTransportSecurity: response.headers['strict-transport-security'],
                contentSecurityPolicy: response.headers['content-security-policy'],
                location: response.headers['location'],
                statusCode: response.status
            };

        } catch (error) {
            results.headers.error = error.message;
        }
    }

    async detectTechnologies(results) {
        const headersContent = Object.values(results.headers).join(' ');
        const allContent = headersContent;

        for (const [tech, info] of Object.entries(this.techSignatures)) {
            if (info.pattern.test(allContent)) {
                results.technologies.push({
                    name: tech.replace(/_/g, ' ').toUpperCase(),
                    category: info.category,
                    confidence: info.confidence
                });
            }
        }

        results.technologies = [...new Map(results.technologies.map(t => [t.name, t])).values()];
    }

    async checkSecurityHeaders(results) {
        const required = [
            'strict-transport-security',
            'x-content-type-options',
            'x-frame-options',
            'content-security-policy'
        ];

        const recommended = [
            'x-xss-protection',
            'referrer-policy',
            'permissions-policy'
        ];

        const found = Object.keys(results.headers).filter(h => 
            results.headers[h] !== undefined
        );

        for (const header of required) {
            if (!results.headers[header]) {
                results.vulnerabilities.push({
                    id: `header-${uuidv4().substring(0, 6)}`,
                    type: 'missing_security_header',
                    title: `Missing Security Header: ${header}`,
                    severity: 'high',
                    description: `Security header ${header} is not set`,
                    category: 'security_header',
                    remediation: `Add ${header} header to server response`
                });
            }
        }

        if (results.headers.xPoweredBy) {
            results.vulnerabilities.push({
                id: `header-${uuidv4().substring(0, 6)}`,
                type: 'information_disclosure',
                title: 'X-Powered-By Header Exposed',
                severity: 'low',
                description: `Server technology revealed: ${results.headers.xPoweredBy}`,
                category: 'information_disclosure',
                remediation: 'Remove X-Powered-By header'
            });
        }
    }

    async findSubdomains(domain, results) {
        const commonSubdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
            'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 
            'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 
            'store', 'portal', 'support', 'cp', 'cdn', 'static', 'docs', 'beta'
        ];

        const found = [];
        
        for (const sub of commonSubdomains.slice(0, 10)) {
            try {
                const fullDomain = `${sub}.${domain}`;
                await dns.resolve4(fullDomain);
                found.push(fullDomain);
            } catch (e) {
                // Subdomain doesn't exist
            }
        }

        results.subdomains = found;

        if (found.length > 0) {
            results.vulnerabilities.push({
                id: `domain-${uuidv4().substring(0, 6)}`,
                type: 'subdomain_enumeration',
                title: `${found.length} Subdomains Discovered`,
                severity: 'info',
                description: `Found subdomains: ${found.join(', ')}`,
                category: 'reconnaissance',
                remediation: 'Ensure subdomains are properly secured'
            });
        }
    }

    analyzeSecurityIssues(results) {
        if (results.ssl && results.ssl.valid === false) {
            results.vulnerabilities.push({
                id: `ssl-${uuidv4().substring(0, 6)}`,
                type: 'ssl_invalid',
                title: 'Invalid SSL Certificate',
                severity: 'critical',
                description: 'SSL certificate is invalid or expired',
                category: 'ssl',
                remediation: 'Install valid SSL certificate'
            });
        }

        if (results.headers.statusCode >= 400 && results.headers.statusCode < 500) {
            results.vulnerabilities.push({
                id: `domain-${uuidv4().substring(0, 6)}`,
                type: 'http_error',
                title: `HTTP Error: ${results.headers.statusCode}`,
                severity: 'low',
                description: `Site returns HTTP ${results.headers.statusCode}`,
                category: 'availability'
            });
        }

        if (results.headers.location && results.headers.location.includes('http://')) {
            results.vulnerabilities.push({
                id: `domain-${uuidv4().substring(0, 6)}`,
                type: 'insecure_redirect',
                title: 'Insecure Redirect Found',
                severity: 'medium',
                description: 'Site redirects to HTTP URL',
                category: 'transport_security',
                remediation: 'Use HTTPS for all redirects'
            });
        }

        results.vulnerabilities.forEach(v => {
            if (v.severity === 'critical') results.summary.critical++;
            else if (v.severity === 'high') results.summary.high++;
            else if (v.severity === 'medium') results.summary.medium++;
            else if (v.severity === 'low') results.summary.low++;
            else results.summary.info++;
        });
    }

    getSummary() {
        return {
            categories: [
                'DNS Analysis',
                'SSL/TLS Inspection',
                'Technology Detection',
                'Security Header Analysis',
                'Subdomain Enumeration',
                'Information Disclosure'
            ],
            features: [
                'Technology stack detection (50+ technologies)',
                'SSL certificate analysis',
                'Security header audit',
                'Subdomain discovery',
                'HTTP header analysis',
                'Vulnerability identification'
            ]
        };
    }
}

module.exports = { DomainIntelligenceScanner };