/**
 * CI/CD Pipeline Security Scanner Module
 * Detects vulnerabilities in CI/CD pipelines and DevOps configurations
 */

const axios = require('axios');
const { checkSSRF } = require('../../utils/security');

class CICDSecurityScanner {
    constructor() {
        this.pipelineTypes = {
            github: 'GitHub Actions',
            gitlab: 'GitLab CI/CD',
            jenkins: 'Jenkins',
            azure: 'Azure DevOps',
            circleci: 'CircleCI'
        };

        this.patterns = this.initializePatterns();
    }

    initializePatterns() {
        return {
            github: [
                {
                    id: 'CI-GH-001',
                    title: 'Exposed GitHub Secrets in Logs',
                    description: 'GitHub Actions workflow may expose secrets in logs',
                    severity: 'high',
                    check: async (url, response) => {
                        return url.includes('.github/workflows');
                    }
                },
                {
                    id: 'CI-GH-002',
                    title: 'Workflow with write Permissions',
                    description: 'GitHub Actions workflow has excessive write permissions',
                    severity: 'medium',
                    check: async (url, response) => {
                        if (response.data) {
                            return JSON.stringify(response.data).includes('permissions:') &&
                                   JSON.stringify(response.data).includes('contents: write');
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GH-003',
                    title: 'Unpinned Action Versions',
                    description: 'GitHub Actions use @master or @main instead of SHA',
                    severity: 'medium',
                    check: async (url, response) => {
                        if (response.data) {
                            return /@[a-z0-9]+$/i.test(response.data) ||
                                   /@master\b/i.test(response.data) ||
                                   /@main\b/i.test(response.data);
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GH-004',
                    title: 'Untrusted Code in PR Workflows',
                    description: 'Workflow runs on pull request from forks',
                    severity: 'high',
                    check: async (url, response) => {
                        if (response.data) {
                            return JSON.stringify(response.data).includes('pull_request_target');
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GH-005',
                    title: 'Missing Security Scan Steps',
                    description: 'Pipeline lacks SAST or dependency scanning',
                    severity: 'low',
                    check: async (url, response) => {
                        if (response.data) {
                            const hasSecurityTools = /trivy|snyk|semgrep|owasp|sonarqube/i.test(response.data);
                            return !hasSecurityTools;
                        }
                        return false;
                    }
                }
            ],
            gitlab: [
                {
                    id: 'CI-GL-001',
                    title: 'Exposed CI/CD Variables',
                    description: 'GitLab CI/CD has exposed environment variables',
                    severity: 'high',
                    check: async (url, response) => {
                        return url.includes('.gitlab-ci.yml') || url.includes('gitlab-ci');
                    }
                },
                {
                    id: 'CI-GL-002',
                    title: 'Unrestricted Pipeline Triggers',
                    description: 'GitLab pipeline allows manual triggers from MRs',
                    severity: 'medium',
                    check: async (url, response) => {
                        if (response.data) {
                            return JSON.stringify(response.data).includes('trigger:');
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GL-003',
                    title: 'Missing Dependency Scanning',
                    description: 'GitLab CI/CD lacks dependency scanning job',
                    severity: 'low',
                    check: async (url, response) => {
                        if (response.data) {
                            return !/dependency_scanning|gemnasium|snyk/i.test(response.data);
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GL-004',
                    title: 'Insecure Image Pull Policy',
                    description: 'Pipeline uses :latest tag or always pull policy',
                    severity: 'medium',
                    check: async (url, response) => {
                        if (response.data) {
                            return /image:.*:latest|:main|:master/i.test(response.data) ||
                                   /pull_policy:\s*always/i.test(response.data);
                        }
                        return false;
                    }
                }
            ],
            jenkins: [
                {
                    id: 'CI-JK-001',
                    title: 'Jenkins Without CSRF Protection',
                    description: 'Jenkins may have CSRF protection disabled',
                    severity: 'high',
                    check: async (url, response) => {
                        return url.includes('jenkins') || url.includes('Jenkins');
                    }
                },
                {
                    id: 'CI-JK-002',
                    title: 'Exposed Jenkins Credentials',
                    description: 'Jenkins credentials may be exposed in configuration',
                    severity: 'critical',
                    check: async (url, response) => {
                        return url.includes('/credentials') || url.includes('/config.xml');
                    }
                },
                {
                    id: 'CI-JK-003',
                    title: 'Jenkins Without Authentication',
                    description: 'Jenkins instance allows anonymous access',
                    severity: 'critical',
                    check: async (url, response) => {
                        if (response.data) {
                            return response.data.includes('Sign in to Jenkins') &&
                                   response.status === 200;
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-JK-004',
                    title: 'Script Console Enabled',
                    description: 'Jenkins script console may be accessible',
                    severity: 'high',
                    check: async (url, response) => {
                        return url.includes('script');
                    }
                }
            ],
            azure: [
                {
                    id: 'CI-AZ-001',
                    title: 'Exposed Azure Pipeline Secrets',
                    description: 'Azure DevOps pipeline exposes secrets',
                    severity: 'high',
                    check: async (url, response) => {
                        return url.includes('azure-pipelines') || url.includes('azure-pipeline');
                    }
                },
                {
                    id: 'CI-AZ-002',
                    title: 'Insecure Agent Configuration',
                    description: 'Azure DevOps uses self-hosted agent without security',
                    severity: 'medium',
                    check: async (url, response) => {
                        if (response.data) {
                            return /pool:|agent:/i.test(response.data) &&
                                   !/vmImage|container/i.test(response.data);
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-AZ-003',
                    title: 'Missing Security Gates',
                    description: 'Azure pipeline lacks security approval gates',
                    severity: 'low',
                    check: async (url, response) => {
                        if (response.data) {
                            return !/security|approval|check/i.test(response.data);
                        }
                        return false;
                    }
                }
            ],
            general: [
                {
                    id: 'CI-GEN-001',
                    title: 'Hardcoded Credentials in Config',
                    description: 'Pipeline configuration contains hardcoded credentials',
                    severity: 'critical',
                    check: async (url, response) => {
                        if (response.data) {
                            const credPatterns = [
                                /password\s*[=:]\s*["'][^"']+["']/i,
                                /api[_-]?key\s*[=:]\s*["'][^"']+["']/i,
                                /secret\s*[=:]\s*["'][^"']+["']/i,
                                /token\s*[=:]\s*["'][A-Za-z0-9+/=]{20,}["']/i
                            ];
                            return credPatterns.some(p => p.test(response.data));
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GEN-002',
                    title: 'Insecure Variable Declaration',
                    description: 'Pipeline uses variables with sensitive data',
                    severity: 'high',
                    check: async (url, response) => {
                        if (response.data) {
                            return /\$\{\{.*(password|secret|key|token)/i.test(response.data) ||
                                   /\$\{.*\}/.test(response.data);
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GEN-003',
                    title: 'Unverified Third-Party Actions',
                    description: 'Pipeline uses unverified or community actions',
                    severity: 'medium',
                    check: async (url, response) => {
                        if (response.data) {
                            return /uses:\s+[a-z0-9-]+\/[a-z0-9-]+@[a-z0-9.]+$/im.test(response.data);
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GEN-004',
                    title: 'Missing Cache Security',
                    description: 'Pipeline cache not encrypted or secured',
                    severity: 'medium',
                    check: async (url, response) => {
                        if (response.data) {
                            return /cache:|restore-cache|save-cache/i.test(response.data);
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GEN-005',
                    title: 'Docker-in-Docker Security Risk',
                    description: 'Pipeline runs Docker without proper isolation',
                    severity: 'high',
                    check: async (url, response) => {
                        if (response.data) {
                            return /docker: docker|dind|privileged.*true/i.test(response.data);
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GEN-006',
                    title: 'SSH Key in Pipeline',
                    description: 'Pipeline configuration contains SSH keys',
                    severity: 'critical',
                    check: async (url, response) => {
                        if (response.data) {
                            return /ssh-rsa|ssh-dss|ssh-ed25519|-----BEGIN.*PRIVATE KEY-----/i.test(response.data);
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GEN-007',
                    title: 'Missing Timeout Configuration',
                    description: 'Pipeline steps lack timeout limits',
                    severity: 'low',
                    check: async (url, response) => {
                        if (response.data) {
                            return !/timeout/i.test(response.data);
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GEN-008',
                    title: 'Debug Mode Enabled',
                    description: 'Pipeline runs with debug mode enabled',
                    severity: 'medium',
                    check: async (url, response) => {
                        if (response.data) {
                            return /debug\s*[=:]\s*true/i.test(response.data) ||
                                   /ACTIONS_STEP_DEBUG\s*=\s*true/i.test(response.data);
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GEN-009',
                    title: 'Missing Artifact Signing',
                    description: 'Build artifacts are not signed or verified',
                    severity: 'medium',
                    check: async (url, response) => {
                        if (response.data) {
                            return /artifact|build.*output|package/i.test(response.data);
                        }
                        return false;
                    }
                },
                {
                    id: 'CI-GEN-010',
                    title: 'Insecure Base Image',
                    description: 'Pipeline uses outdated or insecure base image',
                    severity: 'high',
                    check: async (url, response) => {
                        if (response.data) {
                            const oldImages = [
                                /ubuntu:16/i, /ubuntu:18/i,
                                /node:10/i, /node:12/i,
                                /python:2/i, /python:3.6/i,
                                /alpine:3\.[0-9]/i
                            ];
                            return oldImages.some(p => p.test(response.data));
                        }
                        return false;
                    }
                }
            ]
        };
    }

    async scanTarget(url, scanId) {
        const results = {
            scanId,
            targetUrl: url,
            scanner: 'CI/CD Pipeline Security Scanner',
            startTime: new Date().toISOString(),
            vulnerabilities: [],
            summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            pipelines: {}
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

            const detectedPipelines = this.detectPipelineType(url, response.data);

            for (const pipelineType of detectedPipelines) {
                const patterns = this.patterns[pipelineType] || [];
                
                for (const pattern of patterns) {
                    try {
                        const isVulnerable = await pattern.check(url, response);

                        if (isVulnerable) {
                            const vulnerability = {
                                id: pattern.id,
                                pipelineType: this.pipelineTypes[pipelineType] || pipelineType,
                                title: pattern.title,
                                description: pattern.description,
                                severity: pattern.severity,
                                url,
                                remediation: this.getRemediation(pattern.id),
                                discoveredAt: new Date().toISOString()
                            };

                            if (!results.pipelines[pipelineType]) {
                                results.pipelines[pipelineType] = [];
                            }
                            results.pipelines[pipelineType].push(vulnerability);
                            results.vulnerabilities.push(vulnerability);
                            results.summary[pattern.severity]++;
                        }
                    } catch (err) {
                        console.error(`CI/CD check ${pattern.id} failed:`, err.message);
                    }
                }
            }

            for (const pattern of this.patterns.general) {
                try {
                    const isVulnerable = await pattern.check(url, response);

                    if (isVulnerable) {
                        const vulnerability = {
                            id: pattern.id,
                            pipelineType: 'General',
                            title: pattern.title,
                            description: pattern.description,
                            severity: pattern.severity,
                            url,
                            remediation: this.getRemediation(pattern.id),
                            discoveredAt: new Date().toISOString()
                        };

                        if (!results.pipelines.general) {
                            results.pipelines.general = [];
                        }
                        results.pipelines.general.push(vulnerability);
                        results.vulnerabilities.push(vulnerability);
                        results.summary[pattern.severity]++;
                    }
                } catch (err) {
                    console.error(`CI/CD check ${pattern.id} failed:`, err.message);
                }
            }

            results.endTime = new Date().toISOString();
            results.totalVulnerabilities = results.vulnerabilities.length;
            results.detectedPipelines = detectedPipelines;

        } catch (error) {
            results.error = error.message;
            results.endTime = new Date().toISOString();
        }

        return results;
    }

    detectPipelineType(url, content) {
        const pipelines = [];
        const urlLower = url.toLowerCase();
        const contentStr = typeof content === 'string' ? content : JSON.stringify(content || '');

        if (urlLower.includes('.github/workflows') || urlLower.includes('.yml') || 
            urlLower.includes('github')) {
            pipelines.push('github');
        }
        if (urlLower.includes('gitlab-ci') || urlLower.includes('.gitlab-ci.yml')) {
            pipelines.push('gitlab');
        }
        if (urlLower.includes('jenkins') || urlLower.includes('jenkinsfile')) {
            pipelines.push('jenkins');
        }
        if (urlLower.includes('azure-pipelines') || urlLower.includes('azure-devops')) {
            pipelines.push('azure');
        }

        return pipelines.length > 0 ? pipelines : ['general'];
    }

    getRemediation(id) {
        const remediations = {
            'CI-GH-001': 'Use secrets masking with ##[ secrets.MASK]##. Never echo secrets.',
            'CI-GH-002': 'Use minimal permissions. Default to read-only for most workflows.',
            'CI-GH-003': 'Pin actions to full SHA commit hash for security.',
            'CI-GH-004': 'Use pull_request event instead of pull_request_target. Clone fork safely.',
            'CI-GH-005': 'Add security scanning steps: SAST, dependency check, container scan.',
            'CI-GL-001': 'Use masked variables for secrets. Set CI/CD variables as protected.',
            'CI-GL-002': 'Limit pipeline triggers. Use protected branches for sensitive pipelines.',
            'CI-GL-003': 'Enable GitLab dependency scanning and container scanning.',
            'CI-GL-004': 'Pin image tags to specific versions. Use SHA digests for production.',
            'CI-JK-001': 'Enable CSRF protection in Jenkins configuration.',
            'CI-JK-002': 'Use Jenkins credentials store. Never store credentials in config files.',
            'CI-JK-003': 'Enable Jenkins security. Configure authentication and authorization.',
            'CI-JK-004': 'Restrict script console access. Use Role-Based Access Control.',
            'CI-AZ-001': 'Use Azure Key Vault for secrets. Never hardcode credentials.',
            'CI-AZ-002': 'Use Microsoft-hosted agents for better isolation. If self-hosted, secure the agent.',
            'CI-AZ-003': 'Add security gates using OWASP ZAP, WhiteSource, or Defender.',
            'CI-GEN-001': 'Remove all hardcoded credentials. Use secret management tools.',
            'CI-GEN-002': 'Store sensitive values in encrypted secrets. Never log secret values.',
            'CI-GEN-003': 'Verify third-party actions. Use SHA pinning and review permissions.',
            'CI-GEN-004': 'Enable cache encryption. Use unique cache keys per branch.',
            'CI-GEN-005': 'Use Docker socket mounting only when necessary. Consider Kaniko instead.',
            'CI-GEN-006': 'Use service accounts instead of SSH keys. Rotate keys regularly.',
            'CI-GEN-007': 'Set reasonable timeouts for all pipeline steps. Prevent stuck jobs.',
            'CI-GEN-008': 'Disable debug mode in production pipelines. Use conditional debug only.',
            'CI-GEN-009': 'Sign build artifacts. Use checksum verification and artifact attestation.',
            'CI-GEN-010': 'Use minimal, up-to-date base images. Scan images for vulnerabilities.'
        };
        return remediations[id] || 'Follow CI/CD security best practices and DevSecOps guidelines.';
    }

    getSummary() {
        return {
            pipelineTypes: Object.entries(this.pipelineTypes).map(([key, name]) => ({
                id: key,
                name,
                patternCount: this.patterns[key]?.length || 0
            })),
            generalPatternCount: this.patterns.general.length,
            totalPatterns: Object.values(this.patterns).flat().length
        };
    }
}

module.exports = { CICDSecurityScanner };
