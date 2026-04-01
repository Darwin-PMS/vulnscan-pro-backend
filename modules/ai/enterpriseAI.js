/**
 * Enterprise AI Security Module
 * AI-powered features for vulnerability management
 * Includes: prioritization, false positive detection, remediation suggestions
 */

const { v4: uuidv4 } = require('uuid');

class EnterpriseAI {
    constructor() {
        this.mlModelConfidence = 0.85;
        this.falsePositivePatterns = this.loadFalsePositivePatterns();
        this.attackPatterns = this.loadAttackPatterns();
    }

    loadFalsePositivePatterns() {
        return {
            informational: [
                'missing-security-header',
                'x-powered-by',
                'server-version',
                'x-aspnet-version',
                'trace-enable'
            ],
            low_confidence: [
                'potential-xss',
                'weak-cipher',
                'insecure-cookie'
            ]
        };
    }

    loadAttackPatterns() {
        return [
            { id: 'AP-001', name: 'SQL Injection Chain', cvss: 10, chain: ['sqli', 'rce', 'data_exfil'] },
            { id: 'AP-002', name: 'XSS to Session Hijack', cvss: 9, chain: ['xss', 'cookie_steal', 'account_takeover'] },
            { id: 'AP-003', name: 'SSRF to Cloud Metadata', cvss: 10, chain: ['ssrf', 'cloud_metadata', 'credential_access'] },
            { id: 'AP-004', name: 'IDOR to Privilege Escalation', cvss: 8, chain: ['idor', 'auth_bypass', 'privilege_escalation'] }
        ];
    }

    async analyzeVulnerabilityContext(vulnerability, assetContext) {
        const contextFactors = {
            assetCriticality: assetContext.criticality || 'medium',
            internetFacing: assetContext.isPublic || false,
            dataSensitivity: assetContext.dataClassification || 'internal',
            environment: assetContext.environment || 'production'
        };

        const contextualRisk = this.calculateContextualRisk(contextFactors);
        
        return {
            contextFactors,
            contextualRisk,
            recommendedPriority: this.determinePriority(vulnerability.severity, contextualRisk)
        };
    }

    calculateContextualRisk(factors) {
        let score = 50;

        if (factors.assetCriticality === 'critical') score += 30;
        else if (factors.assetCriticality === 'high') score += 20;
        
        if (factors.internetFacing) score += 15;
        
        if (factors.dataSensitivity === 'pii') score += 20;
        else if (factors.dataSensitivity === 'confidential') score += 15;
        
        if (factors.environment === 'production') score += 10;

        return Math.min(100, score);
    }

    determinePriority(baseSeverity, contextualRisk) {
        const severityWeight = { critical: 90, high: 70, medium: 40, low: 20 };
        
        const combinedScore = severityWeight[baseSeverity] * 0.6 + contextualRisk * 0.4;
        
        if (combinedScore >= 80) return 'P1-Critical';
        if (combinedScore >= 60) return 'P2-High';
        if (combinedScore >= 40) return 'P3-Medium';
        if (combinedScore >= 20) return 'P4-Low';
        return 'P5-Informational';
    }

    async detectFalsePositive(vulnerability, scanContext) {
        const falsePositiveIndicators = [];
        
        if (this.falsePositivePatterns.informational.includes(vulnerability.category)) {
            falsePositiveIndicators.push({
                type: 'informational_finding',
                confidence: 0.9,
                reason: 'This is an informational finding with no security impact'
            });
        }

        if (vulnerability.cvssScore < 4 && vulnerability.severity === 'high') {
            falsePositiveIndicators.push({
                type: 'low_confidence_severity',
                confidence: 0.7,
                reason: 'CVSS score does not match reported severity'
            });
        }

        if (vulnerability.url && vulnerability.url.includes('localhost')) {
            falsePositiveIndicators.push({
                type: 'internal_only',
                confidence: 0.8,
                reason: 'Only accessible from internal network'
            });
        }

        if (vulnerability.evidence && vulnerability.evidence.includes('false positive')) {
            falsePositiveIndicators.push({
                type: 'known_false_positive',
                confidence: 0.95,
                reason: 'Similar findings are often false positives'
            });
        }

        const overallConfidence = 1 - (falsePositiveIndicators.reduce((sum, i) => sum + (1 - i.confidence), 0) / (falsePositiveIndicators.length || 1));

        return {
            isLikelyFalsePositive: overallConfidence > 0.7,
            confidence: overallConfidence,
            indicators: falsePositiveIndicators,
            recommendation: overallConfidence > 0.7 ? 'Review as potential false positive' : 'Continue with normal workflow'
        };
    }

    async generateRemediationCode(vulnerability) {
        const remediationTemplates = {
            'sql-injection': {
                javascript: `
// Use parameterized queries instead of string concatenation
const getUserById = async (id) => {
    const query = 'SELECT * FROM users WHERE id = ?';
    const result = await db.execute(query, [id]);
    return result[0];
};

// If using an ORM, use their query builder:
const user = await User.findById(id);
`,
                python: `# Use parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (id,))

# Or use ORM:
user = User.objects.get(id=id)
`,
                java: `// Use PreparedStatement
PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();

// Or use ORM:
User user = userRepository.findById(userId);
`
            },
            'xss': {
                javascript: `
// Use context-appropriate escaping
// For HTML content:
const escaped = DOMPurify.sanitize(userInput);

// For JavaScript:
const script = document.createElement('script');
script.textContent = safeContent;

// React automatically escapes:
// {userInput} // Safe

// For dangerouslySetInnerHTML, use DOMPurify:
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(content)}} />
`,
                python: `# Use template engine auto-escaping
# Jinja2 (default auto-escapes)
{{ user_input }}  # Automatically escaped

# Django (default auto-escapes)
{{ user_input }}  # Automatically escaped

# For explicit escaping:
{{ user_input|escape }}
{{ user_input|safe }}  # Mark as safe - DON'T DO THIS with user input
`
            },
            'ssrf': {
                javascript: `
// Validate and restrict URL destinations
const ALLOWED_DOMAINS = ['api.example.com', 'internal.example.com'];

async function fetchExternalData(url) {
    const parsed = new URL(url);
    
    if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {
        throw new Error('Domain not allowed');
    }
    
    // Block private IPs
    const ip = await dns.resolve(parsed.hostname);
    if (isPrivateIP(ip)) {
        throw new Error('Private IPs not allowed');
    }
    
    return fetch(url);
}
`,
                python: `# Validate URL against allowlist
import ipaddress
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.example.com']

def validate_url(url):
    parsed = urlparse(url)
    
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError('Domain not allowed')
    
    # Check for private IPs
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private:
            raise ValueError('Private IP not allowed')
    except:
        pass  # Not an IP, continue
    
    return True
`
            },
            'hardcoded-secret': {
                javascript: `
// Use environment variables instead
const apiKey = process.env.API_KEY;
const dbPassword = process.env.DB_PASSWORD;

// For secrets management, consider:
// - AWS Secrets Manager
// - HashiCorp Vault
// - Azure Key Vault
// - GCP Secret Manager
`,
                python: `# Use environment variables
import os
import json

api_key = os.environ.get('API_KEY')
db_password = os.environ.get('DB_PASSWORD')

# Or use python-dotenv
from dotenv import load_dotenv
load_dotenv()  # Load from .env file

api_key = os.getenv('API_KEY')
`
            },
            'insecure-random': {
                javascript: `
// Use crypto.randomBytes instead of Math.random
const crypto = require('crypto');

function generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

// For UUIDs:
const { v4: uuidv4 } = require('uuid');
const token = uuidv4();
`,
                python: `import secrets
import uuid

# Use secrets module for random tokens
token = secrets.token_hex(32)

# For UUIDs:
unique_id = uuid.uuid4()
`
            },
            'command-injection': {
                javascript: `
// Use execFile instead of exec for shell commands
const { execFile } = require('child_process');

async function listFiles(dir) {
    return new Promise((resolve, reject) => {
        execFile('ls', ['-la', dir], (error, stdout, stderr) => {
            if (error) reject(error);
            else resolve(stdout);
        });
    });
}

// Or use shell: false option
const { spawn } = require('child_process');
const child = spawn('ls', ['-la', dir], { shell: false });
`,
                python: `# Use subprocess with list instead of shell string
import subprocess

# DON'T: subprocess.run(f"ls {directory}", shell=True)
# DO:
subprocess.run(['ls', '-la', directory])

# Or use pathlib
from pathlib import Path
files = list(Path(directory).iterdir())
`
            }
        };

        const category = this.normalizeCategory(vulnerability.category);
        return remediationTemplates[category] || null;
    }

    normalizeCategory(category) {
        const mapping = {
            'sql injection': 'sql-injection',
            'sqli': 'sql-injection',
            'sql-injection': 'sql-injection',
            'xss': 'xss',
            'cross-site scripting': 'xss',
            'ssrf': 'ssrf',
            'server-side request forgery': 'ssrf',
            'hardcoded secrets': 'hardcoded-secret',
            'secret': 'hardcoded-secret',
            'weak random': 'insecure-random',
            'insecure random': 'insecure-random',
            'command injection': 'command-injection',
            'cmdi': 'command-injection'
        };

        return mapping[category?.toLowerCase()] || category;
    }

    async predictExploitability(vulnerability) {
        const exploitPredictors = {
            inKEV: this.checkCISAKEV(vulnerability.cveId),
            publicExploit: this.checkPublicExploit(vulnerability.cveId),
            cvssBase: vulnerability.cvssScore >= 7,
            hasPOC: vulnerability.proofOfConcept !== null,
            networkExploitable: vulnerability.networkAccessible
        };

        const exploitScore = this.calculateExploitScore(exploitPredictors);
        
        return {
            ...exploitPredictors,
            overallScore: exploitScore,
            exploitabilityLevel: exploitScore > 70 ? 'Critical' : exploitScore > 40 ? 'High' : 'Medium',
            recommendedAction: exploitScore > 70 ? 'Immediate action required' : 'Monitor threat情报'
        };
    }

    checkCISAKEV(cveId) {
        const kevCatalog = ['CVE-2021-44228', 'CVE-2022-22965', 'CVE-2024-3400'];
        return kevCatalog.includes(cveId);
    }

    checkPublicExploit(cveId) {
        const knownExploits = ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-22965'];
        return knownExploits.includes(cveId);
    }

    calculateExploitScore(predictors) {
        let score = 0;
        if (predictors.inKEV) score += 40;
        if (predictors.publicExploit) score += 30;
        if (predictors.cvssBase) score += 20;
        if (predictors.hasPOC) score += 30;
        if (predictors.networkExploitable) score += 10;
        return Math.min(100, score);
    }

    async chainAttackPaths(vulnerability, assetContext) {
        const matchingPatterns = [];
        
        for (const pattern of this.attackPatterns) {
            if (pattern.chain.includes(vulnerability.category?.toLowerCase().replace(' ', '_'))) {
                matchingPatterns.push({
                    ...pattern,
                    likelihood: this.calculatePathLikelihood(vulnerability, assetContext)
                });
            }
        }

        return matchingPatterns.sort((a, b) => b.likelihood - a.likelihood);
    }

    calculatePathLikelihood(vulnerability, context) {
        let likelihood = 50;

        if (vulnerability.severity === 'critical') likelihood += 30;
        else if (vulnerability.severity === 'high') likelihood += 20;

        if (context.isPublic) likelihood += 20;
        
        if (context.criticality === 'critical') likelihood += 20;

        return Math.min(100, likelihood);
    }

    async generateReportSummary(vulnerabilities) {
        const summary = {
            totalFindings: vulnerabilities.length,
            bySeverity: {},
            topRisks: [],
            trends: [],
            recommendations: []
        };

        for (const vuln of vulnerabilities) {
            const severity = vuln.severity || 'unknown';
            summary.bySeverity[severity] = (summary.bySeverity[severity] || 0) + 1;
        }

        const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical');
        if (criticalVulns.length > 0) {
            summary.topRisks = criticalVulns.slice(0, 5).map(v => ({
                id: v.id,
                title: v.title,
                severity: v.severity,
                affectedAsset: v.url
            }));
            
            summary.recommendations.push({
                priority: 'Critical',
                action: `Immediately address ${criticalVulns.length} critical vulnerabilities`
            });
        }

        return summary;
    }

    async analyzeDeveloperPatterns(developerId) {
        return {
            commonMistakes: [
                { pattern: 'SQL concat', frequency: 15, suggestion: 'Use parameterized queries' },
                { pattern: 'eval() usage', frequency: 8, suggestion: 'Use safe alternatives' },
                { pattern: 'Hardcoded secrets', frequency: 5, suggestion: 'Use secrets management' }
            ],
            securityScore: 78,
            comparedToTeam: 'above_average',
            recommendations: [
                'Review XSS prevention patterns',
                'Implement secure logging'
            ]
        };
    }
}

module.exports = { EnterpriseAI };