/**
 * Cloud Security Scanner Module
 * Detects misconfigurations in AWS, GCP, and Azure environments
 */

const axios = require('axios');
const { checkSSRF } = require('../utils/security');

class CloudSecurityScanner {
    constructor() {
        this.cloudProviders = {
            aws: 'Amazon Web Services',
            gcp: 'Google Cloud Platform',
            azure: 'Microsoft Azure'
        };

        this.patterns = this.initializePatterns();
    }

    initializePatterns() {
        return {
            aws: [
                {
                    id: 'CLOUD-AWS-001',
                    title: 'Public S3 Bucket',
                    description: 'S3 bucket is configured with public access',
                    severity: 'critical',
                    check: async (url, response) => {
                        const isS3 = url.includes('.s3.') || url.includes('s3.amazonaws.com');
                        if (isS3) {
                            return response.status === 200 && 
                                   !response.headers['x-amz-acl']?.includes('private');
                        }
                        return false;
                    }
                },
                {
                    id: 'CLOUD-AWS-002',
                    title: 'Exposed AWS Metadata',
                    description: 'AWS EC2 metadata service accessible',
                    severity: 'high',
                    check: async (url, response) => {
                        return url.includes('169.254.169.254') || 
                               url.includes('metadata.aws');
                    }
                },
                {
                    id: 'CLOUD-AWS-003',
                    title: 'Weak S3 Bucket Policy',
                    description: 'S3 bucket policy allows wildcard principals',
                    severity: 'high',
                    check: async (url, response) => {
                        if (response.data) {
                            return JSON.stringify(response.data).includes('"*": "*"') ||
                                   JSON.stringify(response.data).includes('"Principal": "*"');
                        }
                        return false;
                    }
                },
                {
                    id: 'CLOUD-AWS-004',
                    title: 'Unencrypted EBS Volume',
                    description: 'EBS volume without encryption at rest',
                    severity: 'medium',
                    check: async (url, response) => {
                        return false;
                    }
                },
                {
                    id: 'CLOUD-AWS-005',
                    title: 'Open Security Group',
                    description: 'Security group allows traffic from 0.0.0.0/0',
                    severity: 'high',
                    check: async (url, response) => {
                        if (response.data) {
                            return JSON.stringify(response.data).includes('0.0.0.0/0');
                        }
                        return false;
                    }
                },
                {
                    id: 'CLOUD-AWS-006',
                    title: 'Root Account in Use',
                    description: 'AWS root account is being used directly',
                    severity: 'critical',
                    check: async (url, response) => {
                        return false;
                    }
                },
                {
                    id: 'CLOUD-AWS-007',
                    title: 'Missing CloudTrail Logging',
                    description: 'CloudTrail logging is not enabled',
                    severity: 'medium',
                    check: async (url, response) => {
                        return false;
                    }
                },
                {
                    id: 'CLOUD-AWS-008',
                    title: 'Public RDS Instance',
                    description: 'RDS database is publicly accessible',
                    severity: 'critical',
                    check: async (url, response) => {
                        return url.includes('rds.') || url.includes('.db.');
                    }
                }
            ],
            gcp: [
                {
                    id: 'CLOUD-GCP-001',
                    title: 'Public GCS Bucket',
                    description: 'Google Cloud Storage bucket is publicly accessible',
                    severity: 'critical',
                    check: async (url, response) => {
                        const isGCS = url.includes('storage.googleapis.com') ||
                                     url.includes('.storage.googleapis.com');
                        if (isGCS) {
                            return response.status === 200;
                        }
                        return false;
                    }
                },
                {
                    id: 'CLOUD-GCP-002',
                    title: 'Exposed GCP Metadata',
                    description: 'GCP metadata endpoint is accessible',
                    severity: 'high',
                    check: async (url, response) => {
                        return url.includes('metadata.google.internal') ||
                               url.includes('169.254.169.254');
                    }
                },
                {
                    id: 'CLOUD-GCP-003',
                    title: 'Missing VPC Firewall Rules',
                    description: 'No firewall rules configured for VPC',
                    severity: 'medium',
                    check: async (url, response) => {
                        return false;
                    }
                },
                {
                    id: 'CLOUD-GCP-004',
                    title: 'Default Service Account in Use',
                    description: 'Application using default GCP service account',
                    severity: 'high',
                    check: async (url, response) => {
                        return url.includes('compute.googleapis.com');
                    }
                },
                {
                    id: 'CLOUD-GCP-005',
                    title: 'SQL Instance with Public IP',
                    description: 'Cloud SQL instance has public IP enabled',
                    severity: 'high',
                    check: async (url, response) => {
                        return url.includes('cloudsql.') || url.includes('sql.goog');
                    }
                }
            ],
            azure: [
                {
                    id: 'CLOUD-AZURE-001',
                    title: 'Public Blob Storage',
                    description: 'Azure Blob Storage is publicly accessible',
                    severity: 'critical',
                    check: async (url, response) => {
                        const isBlob = url.includes('.blob.core.windows.net');
                        if (isBlob) {
                            return response.status === 200;
                        }
                        return false;
                    }
                },
                {
                    id: 'CLOUD-AZURE-002',
                    title: 'Exposed Azure Metadata',
                    description: 'Azure instance metadata service accessible',
                    severity: 'high',
                    check: async (url, response) => {
                        return url.includes('169.254.169.254') ||
                               url.includes('metadata.azure.com');
                    }
                },
                {
                    id: 'CLOUD-AZURE-003',
                    title: 'Network Security Group with Open Ports',
                    description: 'NSG allows unrestricted inbound traffic',
                    severity: 'high',
                    check: async (url, response) => {
                        return false;
                    }
                },
                {
                    id: 'CLOUD-AZURE-004',
                    title: 'SQL Server Without Firewall',
                    description: 'Azure SQL Server without proper firewall rules',
                    severity: 'critical',
                    check: async (url, response) => {
                        return url.includes('.database.windows.net');
                    }
                },
                {
                    id: 'CLOUD-AZURE-005',
                    title: 'Storage Account with Shared Key',
                    description: 'Storage account using shared key authentication',
                    severity: 'medium',
                    check: async (url, response) => {
                        return false;
                    }
                }
            ],
            general: [
                {
                    id: 'CLOUD-GEN-001',
                    title: 'Exposed .git Directory',
                    description: 'Cloud storage contains exposed .git directory',
                    severity: 'critical',
                    check: async (url, response) => {
                        return url.includes('.git') || 
                               (response.data && response.data.includes('.git/HEAD'));
                    }
                },
                {
                    id: 'CLOUD-GEN-002',
                    title: 'Exposed .env File',
                    description: 'Environment file with secrets exposed publicly',
                    severity: 'critical',
                    check: async (url, response) => {
                        if (response.data) {
                            return response.data.includes('AWS_') ||
                                   response.data.includes('DATABASE_URL') ||
                                   response.data.includes('SECRET_KEY') ||
                                   response.data.includes('API_KEY');
                        }
                        return false;
                    }
                },
                {
                    id: 'CLOUD-GEN-003',
                    title: 'Debug Mode Enabled',
                    description: 'Application debug mode is enabled in cloud environment',
                    severity: 'high',
                    check: async (url, response) => {
                        if (response.data) {
                            const debugIndicators = ['debug=true', 'DEBUG=TRUE', 'debug: true', 'development'];
                            return debugIndicators.some(d => response.data.includes(d));
                        }
                        return false;
                    }
                },
                {
                    id: 'CLOUD-GEN-004',
                    title: 'Default Credentials Possible',
                    description: 'Application may be using default credentials',
                    severity: 'high',
                    check: async (url, response) => {
                        return false;
                    }
                },
                {
                    id: 'CLOUD-GEN-005',
                    title: 'Missing HTTPS Redirect',
                    description: 'Cloud service does not enforce HTTPS',
                    severity: 'medium',
                    check: async (url, response) => {
                        return url.startsWith('http://') && response.status === 200;
                    }
                },
                {
                    id: 'CLOUD-GEN-006',
                    title: 'Missing WAF Protection',
                    description: 'Web application firewall not detected',
                    severity: 'medium',
                    check: async (url, response) => {
                        const wafHeaders = ['x-cdn', 'x-sucuri', 'x-akamai', 'x-ddos'];
                        const headers = response.headers || {};
                        return !wafHeaders.some(h => headers[h]);
                    }
                },
                {
                    id: 'CLOUD-GEN-007',
                    title: 'Exposed Admin Console',
                    description: 'Cloud provider admin console is accessible',
                    severity: 'high',
                    check: async (url, response) => {
                        const adminUrls = ['/admin', '/console', '/management', '/dashboard'];
                        return adminUrls.some(a => url.includes(a));
                    }
                },
                {
                    id: 'CLOUD-GEN-008',
                    title: 'Missing Access Logging',
                    description: 'Access logs are not being collected',
                    severity: 'medium',
                    check: async (url, response) => {
                        return false;
                    }
                },
                {
                    id: 'CLOUD-GEN-009',
                    title: 'Unrestricted CORS Policy',
                    description: 'CORS allows all origins',
                    severity: 'medium',
                    check: async (url, response) => {
                        const cors = response.headers?.['access-control-allow-origin'];
                        return cors === '*' || cors === 'null';
                    }
                },
                {
                    id: 'CLOUD-GEN-010',
                    title: 'Backup Without Encryption',
                    description: 'Data backups are not encrypted',
                    severity: 'high',
                    check: async (url, response) => {
                        const backupExtensions = ['.bak', '.backup', '.dump', '.sql'];
                        return backupExtensions.some(ext => url.includes(ext));
                    }
                }
            ]
        };
    }

    async scanTarget(url, scanId) {
        const results = {
            scanId,
            targetUrl: url,
            scanner: 'Cloud Security Scanner',
            startTime: new Date().toISOString(),
            vulnerabilities: [],
            summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            providers: { aws: [], gcp: [], azure: [], general: [] }
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

            const detectedProviders = this.detectProviders(url);
            
            for (const provider of detectedProviders) {
                const patterns = this.patterns[provider] || [];
                
                for (const pattern of patterns) {
                    try {
                        const isVulnerable = await pattern.check(url, response);

                        if (isVulnerable) {
                            const vulnerability = {
                                id: pattern.id,
                                provider: provider.toUpperCase(),
                                title: pattern.title,
                                description: pattern.description,
                                severity: pattern.severity,
                                url,
                                remediation: this.getRemediation(pattern.id),
                                discoveredAt: new Date().toISOString()
                            };

                            results.providers[provider].push(vulnerability);
                            results.vulnerabilities.push(vulnerability);
                            results.summary[pattern.severity]++;
                        }
                    } catch (err) {
                        console.error(`Cloud check ${pattern.id} failed:`, err.message);
                    }
                }
            }

            for (const pattern of this.patterns.general) {
                try {
                    const isVulnerable = await pattern.check(url, response);

                    if (isVulnerable) {
                        const vulnerability = {
                            id: pattern.id,
                            provider: 'MULTI',
                            title: pattern.title,
                            description: pattern.description,
                            severity: pattern.severity,
                            url,
                            remediation: this.getRemediation(pattern.id),
                            discoveredAt: new Date().toISOString()
                        };

                        results.providers.general.push(vulnerability);
                        results.vulnerabilities.push(vulnerability);
                        results.summary[pattern.severity]++;
                    }
                } catch (err) {
                    console.error(`Cloud check ${pattern.id} failed:`, err.message);
                }
            }

            results.endTime = new Date().toISOString();
            results.totalVulnerabilities = results.vulnerabilities.length;
            results.detectedProviders = detectedProviders;

        } catch (error) {
            results.error = error.message;
            results.endTime = new Date().toISOString();
        }

        return results;
    }

    detectProviders(url) {
        const providers = [];
        const urlLower = url.toLowerCase();

        if (urlLower.includes('s3.') || urlLower.includes('aws') || 
            urlLower.includes('amazon') || urlLower.includes('cloudfront')) {
            providers.push('aws');
        }
        if (urlLower.includes('storage.googleapis') || urlLower.includes('cloud.google') ||
            urlLower.includes('googleapis') || urlLower.includes('gcp')) {
            providers.push('gcp');
        }
        if (urlLower.includes('blob.core.windows') || urlLower.includes('azure') ||
            urlLower.includes('azurewebsites') || urlLower.includes('cloudapp.azure')) {
            providers.push('azure');
        }

        return providers.length > 0 ? providers : ['general'];
    }

    getRemediation(id) {
        const remediations = {
            'CLOUD-AWS-001': 'Enable S3 block public access. Review bucket policies and ACLs. Use IAM roles instead of bucket policies.',
            'CLOUD-AWS-002': 'Disable IMDSv2 or add token requirement. Use security groups to block metadata access.',
            'CLOUD-AWS-003': 'Restrict bucket policies to specific IAM principals. Remove wildcard (*) permissions.',
            'CLOUD-AWS-004': 'Enable encryption at rest for EBS volumes. Use AWS KMS for key management.',
            'CLOUD-AWS-005': 'Restrict security group rules to specific IP ranges. Remove 0.0.0.0/0 for sensitive ports.',
            'CLOUD-AWS-006': 'Use IAM roles instead of root account. Enable MFA for root account.',
            'CLOUD-AWS-007': 'Enable CloudTrail in all regions. Configure log validation and centralized logging.',
            'CLOUD-AWS-008': 'Disable public accessibility for RDS instances. Use VPC and private subnets.',
            'CLOUD-GCP-001': 'Set bucket uniform access control. Enable bucket policy only mode.',
            'CLOUD-GCP-002': 'Disable metadata API or require tokens. Use VPC firewall rules.',
            'CLOUD-GCP-003': 'Configure VPC firewall rules. Use service accounts with minimal permissions.',
            'CLOUD-GCP-004': 'Create dedicated service accounts. Use Workload Identity for GKE.',
            'CLOUD-GCP-005': 'Disable public IP for Cloud SQL. Use Cloud SQL Proxy or private IP.',
            'CLOUD-AZURE-001': 'Enable secure transfer required. Set blob container public access to private.',
            'CLOUD-AZURE-002': 'Disable Azure instance metadata service access via network configuration.',
            'CLOUD-AZURE-003': 'Configure NSG rules to restrict traffic. Remove any any rules for inbound.',
            'CLOUD-AZURE-004': 'Enable Azure Defender for SQL. Configure firewall rules to allow only necessary IPs.',
            'CLOUD-AZURE-005': 'Migrate to Azure AD authentication. Disable shared key access.',
            'CLOUD-GEN-001': 'Block .git access via web server config. Remove .git directories from web root.',
            'CLOUD-GEN-002': 'Move .env files outside web root. Add to .gitignore. Rotate any exposed secrets.',
            'CLOUD-GEN-003': 'Disable debug mode in production. Use environment variables to control.',
            'CLOUD-GEN-004': 'Change all default credentials. Use secrets management services.',
            'CLOUD-GEN-005': 'Enforce HTTPS redirect. Enable HSTS preload.',
            'CLOUD-GEN-006': 'Enable WAF service (AWS WAF, Cloudflare, etc.). Configure OWASP rule set.',
            'CLOUD-GEN-007': 'Restrict admin console access by IP. Enable MFA for administrative access.',
            'CLOUD-GEN-008': 'Enable access logging for all services. Send logs to centralized SIEM.',
            'CLOUD-GEN-009': 'Configure CORS to only allow specific origins. Never set Access-Control-Allow-Origin to "*".',
            'CLOUD-GEN-010': 'Enable encryption for all backups. Use cloud provider encryption services.'
        };
        return remediations[id] || 'Follow cloud security best practices for the affected service.';
    }

    getSummary() {
        return {
            providers: Object.entries(this.cloudProviders).map(([key, name]) => ({
                id: key,
                name,
                patternCount: this.patterns[key]?.length || 0
            })),
            generalPatternCount: this.patterns.general.length,
            totalPatterns: Object.values(this.patterns).flat().length
        };
    }
}

module.exports = { CloudSecurityScanner };
