/**
 * Scanner Module Index
 * Exports all vulnerability scanner modules
 */

const { OWASPScanner } = require('./owaspScanner');
const { GHDBScanner } = require('./ghdbScanner');
const { APISecurityScanner } = require('./apiSecurityScanner');
const { CloudSecurityScanner } = require('./cloudSecurityScanner');
const { CICDSecurityScanner } = require('./cicdSecurityScanner');
const { MobileSecurityScanner } = require('./mobileSecurityScanner');
const { LLMSecurityScanner } = require('./llmSecurityScanner');
const { ContainerSecurityScanner } = require('./containerSecurityScanner');

const scannerInstances = {
    owasp: new OWASPScanner(),
    ghdb: new GHDBScanner(),
    api: new APISecurityScanner(),
    cloud: new CloudSecurityScanner(),
    cicd: new CICDSecurityScanner(),
    mobile: new MobileSecurityScanner(),
    llm: new LLMSecurityScanner(),
    container: new ContainerSecurityScanner()
};

module.exports = {
    OWASPScanner,
    GHDBScanner,
    APISecurityScanner,
    CloudSecurityScanner,
    CICDSecurityScanner,
    MobileSecurityScanner,
    LLMSecurityScanner,
    ContainerSecurityScanner,
    scannerInstances,
    
    getAvailableScanners: () => ({
        owasp: {
            id: 'owasp',
            name: 'OWASP Top 10 2021',
            description: 'Comprehensive security scanner based on OWASP Top 10 2021 vulnerabilities',
            icon: 'shield',
            color: '#6366f1',
            categories: scannerInstances.owasp.getOWASPSummary()
        },
        ghdb: {
            id: 'ghdb',
            name: 'Google Hacking Database',
            description: 'Dork-based vulnerability detection for exposed sensitive information',
            icon: 'database',
            color: '#10b981',
            categories: scannerInstances.ghdb.getGHDBSummary()
        },
        api: {
            id: 'api',
            name: 'OWASP API Security Top 10',
            description: 'Security scanner for API vulnerabilities based on OWASP API Security Top 10 2023',
            icon: 'code',
            color: '#f59e0b',
            categories: scannerInstances.api.getSummary()
        },
        cloud: {
            id: 'cloud',
            name: 'Cloud Security',
            description: 'Detect misconfigurations in AWS, GCP, and Azure cloud environments',
            icon: 'cloud',
            color: '#3b82f6',
            categories: scannerInstances.cloud.getSummary()
        },
        cicd: {
            id: 'cicd',
            name: 'CI/CD Pipeline Security',
            description: 'Security scanner for CI/CD pipelines (GitHub, GitLab, Jenkins, Azure DevOps)',
            icon: 'git-branch',
            color: '#ec4899',
            categories: scannerInstances.cicd.getSummary()
        },
        mobile: {
            id: 'mobile',
            name: 'Mobile App Security',
            description: 'Security scanner for Android and iOS applications',
            icon: 'smartphone',
            color: '#8b5cf6',
            categories: scannerInstances.mobile.getSummary()
        },
        llm: {
            id: 'llm',
            name: 'LLM/AI Security',
            description: 'Detect prompt injection, hallucinations, and AI-specific vulnerabilities',
            icon: 'bot',
            color: '#06b6d4',
            categories: scannerInstances.llm.getSummary()
        },
        container: {
            id: 'container',
            name: 'Container Security',
            description: 'Security scanner for Docker, Kubernetes, and container deployments',
            icon: 'container',
            color: '#14b8a6',
            categories: scannerInstances.container.getSummary()
        }
    }),
    
    scanWithModule: async (module, url, scanId, options = {}) => {
        const scanner = scannerInstances[module];
        
        if (!scanner) {
            if (module === 'all') {
                const results = {};
                const allVulns = [];
                let summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
                
                for (const [name, instance] of Object.entries(scannerInstances)) {
                    try {
                        const result = await instance.scanTarget(url, `${scanId}_${name}`, options);
                        results[name] = result;
                        allVulns.push(...result.vulnerabilities);
                        Object.keys(summary).forEach(k => {
                            summary[k] += result.summary[k];
                        });
                    } catch (err) {
                        console.error(`Module ${name} failed:`, err.message);
                    }
                }
                
                return {
                    scanId,
                    targetUrl: url,
                    modules: Object.keys(scannerInstances),
                    startTime: new Date().toISOString(),
                    endTime: new Date().toISOString(),
                    vulnerabilities: allVulns,
                    summary,
                    results
                };
            }
            throw new Error(`Unknown scanner module: ${module}`);
        }
        
        return await scanner.scanTarget(url, scanId, options);
    },
    
    scanMultipleModules: async (modules, url, scanId, options = {}) => {
        const results = {};
        const allVulns = [];
        let summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        
        for (const module of modules) {
            const scanner = scannerInstances[module];
            if (scanner) {
                try {
                    const result = await scanner.scanTarget(url, `${scanId}_${module}`, options);
                    results[module] = result;
                    allVulns.push(...result.vulnerabilities);
                    Object.keys(summary).forEach(k => {
                        summary[k] += result.summary[k];
                    });
                } catch (err) {
                    console.error(`Module ${module} failed:`, err.message);
                }
            }
        }
        
        return {
            scanId,
            targetUrl: url,
            modules,
            startTime: new Date().toISOString(),
            endTime: new Date().toISOString(),
            vulnerabilities: allVulns,
            summary,
            results
        };
    }
};
