/**
 * Secret Scanner - Advanced Secret Detection
 * Detects exposed credentials, API keys, tokens, and sensitive data
 * Supports multiple pattern types and entropy detection
 */

const crypto = require('crypto');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

class SecretScanner {
    constructor() {
        this.secretPatterns = this.initializePatterns();
        this.entropyThreshold = 4.5;
        this.excludedPaths = [
            'node_modules', '.git', 'dist', 'build', 'vendor',
            '.env.example', '.env.sample', 'package-lock.json'
        ];
        this.confidenceWeights = {
            high: 0.9,
            medium: 0.6,
            low: 0.3
        };
    }

    initializePatterns() {
        return {
            aws: {
                pattern: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
                type: 'AWS Access Key',
                severity: 'critical',
                entropy: false,
                description: 'AWS Access Key ID - Immediate rotation required'
            },
            awsSecret: {
                pattern: /(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)[\s]*[=:][\s]*["']?([a-zA-Z0-9/+=]{40})["']?/g,
                type: 'AWS Secret Key',
                severity: 'critical',
                entropy: true,
                description: 'AWS Secret Access Key - Full AWS access compromise'
            },
            github: {
                pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}/g,
                type: 'GitHub Token',
                severity: 'critical',
                entropy: false,
                description: 'GitHub Personal Access Token - Repository access'
            },
            gitlab: {
                pattern: /glpat-[0-9a-zA-Z\-]{20}/g,
                type: 'GitLab Token',
                severity: 'critical',
                entropy: false,
                description: 'GitLab Personal Access Token'
            },
            bitbucket: {
                pattern: /BB[a-zA-Z0-9]{32}/g,
                type: 'Bitbucket Token',
                severity: 'critical',
                entropy: false,
                description: 'Bitbucket App Password'
            },
            jwt: {
                pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
                type: 'JWT Token',
                severity: 'high',
                entropy: false,
                description: 'JSON Web Token - Potential session hijacking'
            },
            azure: {
                pattern: /[a-zA-Z0-9+/]{86}==/g,
                type: 'Azure Key',
                severity: 'critical',
                entropy: true,
                description: 'Azure Storage Account Key'
            },
            azureToken: {
                pattern: /(?:Bearer\s+)?[a-zA-Z0-9\-\._~+/]+=*(?:\s|$)/g,
                type: 'Azure AD Token',
                severity: 'high',
                entropy: true,
                description: 'Azure Active Directory Token'
            },
            gcp: {
                pattern: /AIza[0-9A-Za-z\-_]{35}/g,
                type: 'Google API Key',
                severity: 'critical',
                entropy: false,
                description: 'Google API Key - Cloud platform access'
            },
            gcpService: {
                pattern: /-----BEGIN PRIVATE KEY-----[\s\S]*-----END PRIVATE KEY-----/g,
                type: 'GCP Service Account',
                severity: 'critical',
                entropy: false,
                description: 'Google Cloud Service Account Private Key'
            },
            stripe: {
                pattern: /(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}/g,
                type: 'Stripe API Key',
                severity: 'critical',
                entropy: false,
                description: 'Stripe API Key - Payment processing access'
            },
            slack: {
                pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
                type: 'Slack Token',
                severity: 'high',
                entropy: false,
                description: 'Slack Token - Workspace access'
            },
            sendgrid: {
                pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
                type: 'SendGrid API Key',
                severity: 'critical',
                entropy: false,
                description: 'SendGrid API Key - Email sending capability'
            },
            twilio: {
                pattern: /SK[a-zA-Z0-9]{32}/g,
                type: 'Twilio API Key',
                severity: 'high',
                entropy: false,
                description: 'Twilio API Key - SMS/Call capabilities'
            },
            mailgun: {
                pattern: /key-[0-9a-zA-Z]{32}/g,
                type: 'Mailgun API Key',
                severity: 'high',
                entropy: false,
                description: 'Mailgun API Key - Email service'
            },
            database: {
                pattern: /(?i)(?:mysql|postgres|mongodb|redis|mariadb)[\s:]+(?:[\w-]+)[\s:]+([\w!@#$%^&*()]+)/g,
                type: 'Database Connection String',
                severity: 'critical',
                entropy: true,
                description: 'Database credentials - Full database access'
            },
            password: {
                pattern: /(?i)(?:password|passwd|pwd|secret|api_key|apikey|auth_token)[\s]*[=:][\s]*["']?([^\s'"]{8,})["']?/g,
                type: 'Password/Secret',
                severity: 'high',
                entropy: true,
                description: 'Generic password or secret field'
            },
            privateKey: {
                pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
                type: 'Private Key',
                severity: 'critical',
                entropy: false,
                description: 'Private Key - Identity compromise'
            },
            sshKey: {
                pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
                type: 'SSH Private Key',
                severity: 'critical',
                entropy: false,
                description: 'SSH Private Key - Server access'
            },
            apiKey: {
                pattern: /(?i)(?:api[_-]?key|apikey)[\s]*[=:][\s]*["']?([a-zA-Z0-9]{20,64})["']?/g,
                type: 'Generic API Key',
                severity: 'high',
                entropy: true,
                description: 'Generic API Key - Various services'
            },
            bearerToken: {
                pattern: /(?i)Bearer\s+[a-zA-Z0-9\-_.~+/]+=*/g,
                type: 'Bearer Token',
                severity: 'high',
                entropy: true,
                description: 'Bearer Token - Authentication token'
            },
            authorization: {
                pattern: /(?i)Authorization:\s*(?:Basic|Bearer)\s+[a-zA-Z0-9+/=]+/g,
                type: 'Authorization Header',
                severity: 'high',
                entropy: false,
                description: 'Authorization header with credentials'
            },
            firebase: {
                pattern: /AAAA[a-zA-Z0-9_-]{22}:[a-zA-Z0-9_-]{140}/g,
                type: 'Firebase Cloud Messaging',
                severity: 'high',
                entropy: false,
                description: 'Firebase Cloud Messaging key'
            },
            heroku: {
                pattern: /[hH]eroku[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}/g,
                type: 'Heroku API Key',
                severity: 'critical',
                entropy: false,
                description: 'Heroku API Key - Cloud platform access'
            },
            npm: {
                pattern: /npm_[a-zA-Z0-9]{36}/g,
                type: 'NPM Token',
                severity: 'high',
                entropy: false,
                description: 'NPM Access Token - Package publishing'
            },
            datadog: {
                pattern: /[a-zA-Z0-9]{32}/g,
                type: 'Datadog API Key',
                severity: 'high',
                entropy: true,
                description: 'Datadog API Key - Monitoring'
            },
            newrelic: {
                pattern: /NR[a-zA-Z0-9]{32}/g,
                type: 'New Relic Key',
                severity: 'high',
                entropy: false,
                description: 'New Relic License Key - APM'
            },
            cloudflare: {
                pattern: /[a-zA-Z0-9]{37}/g,
                type: 'Cloudflare API Key',
                severity: 'critical',
                entropy: true,
                description: 'Cloudflare API Key - DNS and security'
            },
            pgp: {
                pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
                type: 'PGP Private Key',
                severity: 'critical',
                entropy: false,
                description: 'PGP Private Key - Encryption identity'
            }
        };
    }

    calculateEntropy(text) {
        if (!text || text.length < 8) return 0;
        
        const frequencies = {};
        for (const char of text) {
            frequencies[char] = (frequencies[char] || 0) + 1;
        }
        
        let entropy = 0;
        const len = text.length;
        
        for (const char in frequencies) {
            const freq = frequencies[char] / len;
            entropy -= freq * Math.log2(freq);
        }
        
        return entropy;
    }

    isHighEntropy(value) {
        if (value.length < 20) return false;
        return this.calculateEntropy(value) >= this.entropyThreshold;
    }

    shouldExclude(filePath) {
        const lowerPath = filePath.toLowerCase();
        return this.excludedPaths.some(excluded => 
            lowerPath.includes(excluded.toLowerCase())
        );
    }

    async scanContent(content, filePath = null) {
        const findings = [];
        
        if (filePath && this.shouldExclude(filePath)) {
            return findings;
        }
        
        for (const [name, config] of Object.entries(this.secretPatterns)) {
            const regex = new RegExp(config.pattern.source, config.pattern.flags || 'g');
            let match;
            
            while ((match = regex.exec(content)) !== null) {
                const value = match[1] || match[0];
                
                if (config.entropy && !this.isHighEntropy(value)) {
                    continue;
                }
                
                const lineNumber = content.substring(0, match.index).split('\n').length;
                const context = this.getContext(content, match.index, 3);
                
                let confidence = this.confidenceWeights[config.entropy ? 'high' : 'high'];
                
                if (config.entropy && this.isHighEntropy(value)) {
                    confidence = this.confidenceWeights.high;
                }
                
                findings.push({
                    id: `secret-${uuidv4().substring(0, 8)}`,
                    type: config.type,
                    severity: config.severity,
                    confidence: confidence.toFixed(2),
                    value: this.maskSecret(value),
                    matchedPattern: name,
                    filePath: filePath,
                    lineNumber,
                    context: {
                        before: context.before,
                        match: context.match,
                        after: context.after
                    },
                    description: config.description,
                    remediation: this.getRemediation(config.type),
                    references: this.getReferences(config.type),
                    category: 'secret',
                    entropy: this.calculateEntropy(value).toFixed(2)
                });
            }
        }
        
        return this.deduplicateFindings(findings);
    }

    getContext(content, matchIndex, lines = 3) {
        const lines = content.split('\n');
        let currentLine = 0;
        let charCount = 0;
        
        for (let i = 0; i < lines.length; i++) {
            if (charCount + lines[i].length >= matchIndex) {
                currentLine = i;
                break;
            }
            charCount += lines[i].length + 1;
        }
        
        const start = Math.max(0, currentLine - lines);
        const end = Math.min(lines.length, currentLine + lines + 1);
        
        return {
            before: lines.slice(start, currentLine).join('\n'),
            match: lines[currentLine],
            after: lines.slice(currentLine + 1, end).join('\n')
        };
    }

    maskSecret(secret) {
        if (!secret || secret.length < 8) return '***';
        
        const visible = Math.min(4, Math.floor(secret.length / 4));
        return secret.substring(0, visible) + '*'.repeat(secret.length - visible * 2) + secret.substring(secret.length - visible);
    }

    deduplicateFindings(findings) {
        const seen = new Map();
        
        for (const finding of findings) {
            const key = `${finding.type}-${finding.filePath}-${finding.lineNumber}`;
            
            if (!seen.has(key)) {
                seen.set(key, finding);
            } else if (this.severityScore(finding.severity) > this.severityScore(seen.get(key).severity)) {
                seen.set(key, finding);
            }
        }
        
        return Array.from(seen.values());
    }

    severityScore(severity) {
        const scores = { critical: 4, high: 3, medium: 2, low: 1 };
        return scores[severity] || 0;
    }

    getRemediation(type) {
        const remediations = {
            'AWS Access Key': 'Immediately rotate the access key in AWS IAM. Check CloudTrail for unauthorized usage.',
            'GitHub Token': 'Revoke the token in GitHub Settings > Developer Settings > Personal access tokens.',
            'Database Connection String': 'Rotate database credentials immediately. Review access logs.',
            'Private Key': 'Generate new key pair. Revoke compromised key from authorized stores.',
            'JWT Token': 'Invalidate the token and implement token rotation. Review user sessions.',
            default: 'Remove the secret from code. Rotate credentials. Review access logs for compromise.'
        };
        
        return remediations[type] || remediations.default;
    }

    getReferences(type) {
        return [
            'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
            'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'
        ];
    }

    async scanFiles(filePaths) {
        const allFindings = [];
        
        for (const filePath of filePaths) {
            try {
                const content = fs.readFileSync(filePath, 'utf8');
                const findings = await this.scanContent(content, filePath);
                allFindings.push(...findings);
            } catch (error) {
                console.error(`Error scanning ${filePath}:`, error.message);
            }
        }
        
        return allFindings;
    }

    getSummary() {
        return {
            categories: [
                'Cloud Provider Credentials',
                'API Keys',
                'Authentication Tokens',
                'Private Keys',
                'Database Credentials',
                'Service Tokens'
            ],
            patterns: Object.keys(this.secretPatterns).length,
            features: [
                'Multi-pattern detection',
                'Entropy analysis',
                'Context extraction',
                'Confidence scoring',
                'Exclusion patterns',
                'False positive reduction'
            ]
        };
    }

    async scanTarget(target, scanId, options = {}) {
        const results = {
            scanId,
            target,
            type: 'secret_scanning',
            startTime: new Date().toISOString(),
            endTime: null,
            vulnerabilities: [],
            summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            categories: ['Secret Scanning', 'Credential Exposure', 'API Key Detection'],
            patternsScanned: Object.keys(this.secretPatterns).length
        };
        
        if (options.content) {
            const findings = await this.scanContent(options.content, options.filePath);
            results.vulnerabilities = findings;
            
            findings.forEach(v => {
                if (v.severity === 'critical') results.summary.critical++;
                else if (v.severity === 'high') results.summary.high++;
                else if (v.severity === 'medium') results.summary.medium++;
                else if (v.severity === 'low') results.summary.low++;
                else results.summary.info++;
            });
        }
        
        results.endTime = new Date().toISOString();
        return results;
    }
}

module.exports = { SecretScanner };