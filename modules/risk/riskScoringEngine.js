/**
 * Enterprise Risk Scoring Engine
 * Multi-factor risk prioritization with AI/ML capabilities
 * Combines CVSS, business context, exploitability, and threat intelligence
 */

const { v4: uuidv4 } = require('uuid');

class RiskScoringEngine {
    constructor() {
        this.cvssWeights = {
            CVSS_Base: 0.25,
            Business_Criticality: 0.20,
            Internet_Exposure: 0.15,
            Exploitability: 0.15,
            CISA_KEV: 0.10,
            PII_Exposure: 0.10,
            Environment: 0.05
        };
        
        this.cisaKEV = this.loadCISAKEV();
        this.exploitSources = this.loadExploitSources();
        this.assetCriticality = new Map();
    }

    loadCISAKEV() {
        return {
            'CVE-2021-44228': { known: true, name: 'Log4Shell', severity: 'critical', epss: 0.99 },
            'CVE-2021-45046': { known: true, name: 'Log4j DoS', severity: 'high', epss: 0.95 },
            'CVE-2022-22965': { known: true, name: 'Spring4Shell', severity: 'critical', epss: 0.97 },
            'CVE-2022-0847': { known: true, name: 'Dirty Pipe', severity: 'high', epss: 0.90 },
            'CVE-2021-34527': { known: true, name: 'PrintNightmare', severity: 'critical', epss: 0.95 },
            'CVE-2021-43297': { known: true, name: 'Apache Log4j RCE', severity: 'critical', epss: 0.98 },
            'CVE-2023-46805': { known: true, name: 'Ivanti Connect Secure', severity: 'high', epss: 0.85 },
            'CVE-2024-1709': { known: true, name: 'ConnectWise ScreenConnect', severity: 'critical', epss: 0.95 },
            'CVE-2024-3400': { known: true, name: 'Palo Alto PAN-OS', severity: 'critical', epss: 0.92 },
            'CVE-2024-27198': { known: true, name: 'JetBrains TeamCity', severity: 'critical', epss: 0.94 }
        };
    }

    loadExploitSources() {
        return {
            'exploit-db': { weight: 0.8, latency: 'low' },
            'metasploit': { weight: 0.9, latency: 'low' },
            'cisa': { weight: 1.0, latency: 'low' },
            'packetstorm': { weight: 0.7, latency: 'medium' },
            'github': { weight: 0.6, latency: 'high' },
            'social': { weight: 0.3, latency: 'high' }
        };
    }

    async calculateRiskScore(vulnerability, assetContext = {}) {
        const factors = {
            cvss: this.calculateCVSSScore(vulnerability),
            businessCriticality: this.calculateBusinessCriticality(assetContext),
            internetExposure: this.calculateInternetExposure(assetContext),
            exploitability: await this.calculateExploitability(vulnerability),
            cisaKEV: this.calculateCISAKEVScore(vulnerability),
            piiExposure: this.calculatePIIExposure(assetContext),
            environment: this.calculateEnvironmentScore(assetContext)
        };

        const weightedScore = Object.entries(factors).reduce((total, [factor, score]) => {
            return total + (score * (this.cvssWeights[factor] || 0));
        }, 0);

        const finalScore = Math.min(100, Math.round(weightedScore * 10) / 10);
        const severity = this.determineSeverity(finalScore);

        return {
            riskScore: finalScore,
            severity,
            factors,
            priority: this.determinePriority(severity, factors),
            remediationEffort: this.estimateRemediationEffort(vulnerability, factors),
            slaDueDate: this.calculateSLADueDate(severity),
            recommendations: this.generateRecommendations(severity, factors, vulnerability)
        };
    }

    calculateCVSSScore(vulnerability) {
        const cvssVector = vulnerability.cvss_vector || vulnerability.cvssScore;
        
        if (typeof cvssVector === 'number') {
            return cvssVector;
        }
        
        if (cvssVector && typeof cvssVector === 'string') {
            const baseScore = cvssVector.match(/CVSS:3.1\/AV:[NALA]\/AC:[LH]\/PR:[NH]\/UI:[NR]\/S:[UC]\/C:[NH]\/I:[NH]\/A:[NH]/);
            return baseScore ? 8.0 : 5.0;
        }

        const severityScores = {
            critical: 9.5,
            high: 7.5,
            medium: 5.0,
            low: 2.5,
            informational: 0
        };
        
        return severityScores[vulnerability.severity?.toLowerCase()] || 5.0;
    }

    calculateBusinessCriticality(assetContext = {}) {
        const criticalityMap = {
            'production_critical': 10,
            'production': 8,
            'staging': 5,
            'development': 3,
            'internal': 6,
            'external': 7,
            'customer_facing': 9,
            'backoffice': 4
        };

        return criticalityMap[assetContext.criticality] || 5;
    }

    calculateInternetExposure(assetContext = {}) {
        if (assetContext.isPublic === true) return 10;
        if (assetContext.exposure === 'internet-facing') return 10;
        if (assetContext.exposure === 'internal') return 3;
        if (assetContext.exposure === 'dmz') return 7;
        
        return assetContext.isExposed ? 8 : 4;
    }

    async calculateExploitability(vulnerability) {
        const cveId = vulnerability.cve_id || vulnerability.cveIds?.[0];
        
        if (cveId && this.exploitSources[cveId]) {
            return 10;
        }

        const exploitsAvailable = await this.checkExploitAvailability(vulnerability);
        
        if (exploitsAvailable.confirmed) return 10;
        if (exploitsAvailable.possible) return 6;
        
        return 3;
    }

    async checkExploitAvailability(vulnerability) {
        const cveId = vulnerability.cve_id;
        
        if (!cveId) {
            return { confirmed: false, possible: true, sources: [] };
        }

        const sources = [];
        
        if (this.cisaKEV[cveId]) {
            sources.push({ source: 'CISA KEV', confidence: 1.0 });
            return { confirmed: true, possible: true, sources };
        }

        return { confirmed: false, possible: false, sources };
    }

    calculateCISAKEVScore(vulnerability) {
        const cveId = vulnerability.cve_id || vulnerability.cveIds?.[0];
        
        if (!cveId) return 0;
        
        const kevEntry = this.cisaKEV[cveId];
        
        if (kevEntry) {
            return kevEntry.severity === 'critical' ? 10 : 8;
        }
        
        return 0;
    }

    calculatePIIExposure(assetContext = {}) {
        if (assetContext.dataClassification === 'pii') return 10;
        if (assetContext.dataClassification === 'sensitive') return 7;
        if (assetContext.dataClassification === 'confidential') return 5;
        if (assetContext.dataClassification === 'internal') return 3;
        
        return assetContext.containsPII ? 8 : 0;
    }

    calculateEnvironmentScore(assetContext = {}) {
        const envScores = {
            'production': 10,
            'prod': 10,
            'staging': 6,
            'stage': 6,
            'development': 3,
            'dev': 3,
            'test': 4,
            'qa': 4
        };

        return envScores[assetContext.environment?.toLowerCase()] || 5;
    }

    determineSeverity(score) {
        if (score >= 90) return 'critical';
        if (score >= 70) return 'high';
        if (score >= 40) return 'medium';
        if (score >= 20) return 'low';
        return 'informational';
    }

    determinePriority(severity, factors) {
        const priority = {
            critical: 'P1 - Critical',
            high: 'P2 - High',
            medium: 'P3 - Medium',
            low: 'P4 - Low',
            informational: 'P5 - Info'
        };

        if (factors.cisaKEV >= 8 && factors.exploitability >= 8) {
            return `${priority[severity]} - ACTIVE EXPLOIT`;
        }

        return priority[severity];
    }

    estimateRemediationEffort(vulnerability, factors) {
        const baseEffort = 3;
        
        if (factors.cvss >= 9) return { level: 'high', hours: 16 };
        if (factors.cvss >= 7) return { level: 'medium', hours: 8 };
        if (factors.cvss >= 4) return { level: 'low', hours: 4 };
        
        return { level: 'low', hours: 2 };
    }

    calculateSLADueDate(severity) {
        const now = new Date();
        const slaHours = {
            critical: 24,
            high: 168,
            medium: 720,
            low: 2160
        };

        const hours = slaHours[severity] || 2160;
        const dueDate = new Date(now.getTime() + hours * 60 * 60 * 1000);

        return {
            hours,
            dueDate: dueDate.toISOString(),
            severity
        };
    }

    generateRecommendations(severity, factors, vulnerability) {
        const recommendations = [];
        
        if (factors.cisaKEV >= 8) {
            recommendations.push({
                type: 'urgent',
                message: 'CISA KEV - Apply immediate mitigations or patch',
                reference: 'https://www.cisa.gov/known-exploited-vulnerabilities'
            });
        }
        
        if (factors.exploitability >= 8) {
            recommendations.push({
                type: 'high',
                message: 'Exploits available - Prioritize remediation',
                reference: 'Check exploit-db, metasploit, or similar sources'
            });
        }
        
        if (factors.internetExposure >= 8 && severity !== 'informational') {
            recommendations.push({
                type: 'network',
                message: 'Internet-facing system - Consider WAF rules or temporary blocking'
            });
        }
        
        if (factors.piiExposure >= 8) {
            recommendations.push({
                type: 'compliance',
                message: 'PII exposure detected - May trigger GDPR/CCPA notification requirements'
            });
        }

        if (severity === 'critical' || severity === 'high') {
            recommendations.push({
                type: 'process',
                message: 'Schedule immediate security review meeting'
            });
        }

        return recommendations;
    }

    async batchScore(vulnerabilities, assetContextMap = {}) {
        const results = [];
        
        for (const vuln of vulnerabilities) {
            const assetCtx = assetContextMap[vuln.asset_id] || {};
            const scored = await this.calculateRiskScore(vuln, assetCtx);
            results.push({
                vulnerabilityId: vuln.id,
                ...scored
            });
        }
        
        return results.sort((a, b) => b.riskScore - a.riskScore);
    }

    getDashboardMetrics(vulnerabilities) {
        const total = vulnerabilities.length;
        const bySeverity = vulnerabilities.reduce((acc, v) => {
            acc[v.severity] = (acc[v.severity] || 0) + 1;
            return acc;
        }, {});

        const avgScore = vulnerabilities.reduce((sum, v) => sum + (v.riskScore || 0), 0) / (total || 1);
        
        return {
            total,
            critical: bySeverity.critical || 0,
            high: bySeverity.high || 0,
            medium: bySeverity.medium || 0,
            low: bySeverity.low || 0,
            informational: bySeverity.informational || 0,
            averageRiskScore: Math.round(avgScore * 10) / 10,
            exposedToInternet: vulnerabilities.filter(v => v.isPublic).length,
            withExploits: vulnerabilities.filter(v => v.exploitAvailable).length,
            inKEV: vulnerabilities.filter(v => v.inKEVCatalog).length
        };
    }
}

module.exports = { RiskScoringEngine };