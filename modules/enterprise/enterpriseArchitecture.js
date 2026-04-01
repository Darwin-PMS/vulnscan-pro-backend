/**
 * Enterprise System Architecture
 * VulnScan Pro - Enterprise-Grade Vulnerability Management Platform
 * 
 * Architecture Overview:
 * - Microservice-ready design
 * - Queue-based scan engine
 * - Multi-tenant RBAC
 * - AI-powered prioritization
 * - Compliance-ready
 */

const fs = require('fs');
const path = require('path');

const ENTERPRISE_ARCHITECTURE = {
    name: 'VulnScan Pro Enterprise',
    version: '2.0.0',
    architecture: {
        pattern: 'Microservices with Event-Driven Design',
        layers: [
            'API Gateway (Authentication, Rate Limiting, Load Balancing)',
            'Application Layer (Business Logic, RBAC, Workflows)',
            'Scan Engine Layer (Queue-based, Async Workers)',
            'Data Layer (MySQL, Redis, Elasticsearch)',
            'Security Layer (WAF, Zero Trust, Encryption)'
        ]
    },
    
    components: {
        scanEngine: {
            type: 'Queue-based async processing',
            queueSystem: 'Bull with Redis',
            workers: {
                dast: 'DAST Scanner Worker',
                sast: 'SAST Scanner Worker', 
                sca: 'Dependency Scanner Worker',
                api: 'API Security Worker',
                cloud: 'Cloud Config Worker',
                container: 'Container Security Worker',
                secret: 'Secret Detection Worker',
                malware: 'Malware Analysis Worker'
            },
            scaling: 'Horizontal pod autoscaling (HPA)',
            concurrency: 'Per-worker configurable (default: 5)'
        },
        
        dataStorage: {
            primary: 'MySQL 8.0 (transactional data)',
            cache: 'Redis (sessions, rates, queue)',
            search: 'Elasticsearch (audit logs, findings)',
            objectStorage: 'S3/MinIO (reports, SBOMs)',
            encryption: {
                atRest: 'AES-256-GCM',
                inTransit: 'TLS 1.3',
                fieldLevel: 'Per-column encryption for PII'
            }
        },
        
        messaging: {
            internal: 'Redis Pub/Sub',
            external: 'Webhook dispatch (Slack, Teams, Jira)',
            events: [
                'scan.completed',
                'vulnerability.found',
                'vulnerability.resolved',
                'sla.breached',
                'compliance.failed'
            ]
        }
    },
    
    security: {
        zeroTrust: {
            identityVerification: 'Identity proofing on signup',
            mfaRequired: 'TOTP/SMS/Email for all users',
            sessionManagement: 'JWT with short expiry, refresh tokens',
            deviceTrust: 'Device fingerprinting + behavioral analysis',
            networkContext: 'Geo-location, VPN/Tor detection',
            adaptiveAuth: 'Risk-based authentication level'
        },
        
        tenantIsolation: {
            schema: 'Database per tenant (optional)',
            rowLevel: 'tenant_id column on all tables',
            network: 'VPC isolation per tenant',
            storage: 'S3 bucket per tenant with bucket policies'
        },
        
        auditCompliance: {
            tamperProof: 'Immutability via blockchain/hash chain',
            retention: '7 years (configurable)',
            export: 'SIEM integration (Splunk, ELK)',
            standards: ['NIST CSF 2.0', 'ISO 27001', 'SOC2 Type II']
        }
    },
    
    scanningModules: {
        dast: {
            name: 'Dynamic Application Security Testing',
            capabilities: [
                'OWASP Top 10 2021',
                'XSS, SQLi, SSRF, RCE, IDOR',
                'Auth bypass, CSRF',
                'Security headers analysis',
                'TLS/SSL configuration checks',
                'JavaScript SPA analysis'
            ],
            tools: ['OWASP ZAP', 'Nuclei', 'Custom patterns']
        },
        
        sast: {
            name: 'Static Application Security Testing',
            capabilities: [
                'Insecure coding patterns',
                'Dangerous function detection',
                'SQL injection (code level)',
                'Command injection',
                'Hardcoded secrets',
                'Crypto weakness detection'
            ],
            languages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'Go']
        },
        
        sca: {
            name: 'Software Composition Analysis',
            capabilities: [
                'npm, pip, composer, maven dependencies',
                'CVE mapping and prioritization',
                'Exploit maturity assessment',
                'License compliance',
                'SBOM generation (SPDX, CycloneDX)',
                'Supply chain risk detection'
            ]
        },
        
        apiSecurity: {
            name: 'API Security Testing',
            capabilities: [
                'OpenAPI/Swagger import',
                'BOLA/BFLA detection',
                'Auth token fuzzing',
                'Rate limit bypass',
                'JWT weakness analysis',
                'GraphQL security'
            ]
        },
        
        cloudSecurity: {
            name: 'Cloud Infrastructure Security',
            capabilities: [
                'AWS misconfigurations (IAM, S3, EC2)',
                'Azure RBAC issues',
                'GCP open storage',
                'Kubernetes CIS benchmark',
                'Infrastructure as Code scanning'
            ]
        },
        
        containerSecurity: {
            name: 'Container Security',
            capabilities: [
                'Docker image scanning',
                'Kubernetes manifest analysis',
                'CIS Docker benchmark',
                'Vulnerable base images',
                'Exposed secrets in containers'
            ]
        },
        
        secretScanning: {
            name: 'Secret Detection',
            capabilities: [
                'AWS access keys',
                'Azure service principals',
                'JWT tokens',
                'Database passwords',
                'SSH private keys',
                'API keys (generic)'
            ]
        },
        
        malwareDetection: {
            name: 'Malware Upload Analysis',
            capabilities: [
                'File signature analysis',
                'YARA rule matching',
                'Sandbox execution',
                'ClamAV integration',
                'Behavioral analysis'
            ]
        },
        
        complianceScanning: {
            name: 'Compliance Posture Scanning',
            frameworks: ['NIST CSF', 'ISO 27001', 'SOC2', 'PCI-DSS', 'HIPAA', 'GDPR']
        }
    },
    
    riskEngine: {
        factors: {
            cvss: { weight: 0.25, source: 'NVD CVSS 3.1' },
            businessCriticality: { weight: 0.20, source: 'Asset classification' },
            internetExposure: { weight: 0.15, source: 'Asset tags' },
            exploitability: { weight: 0.15, source: 'CISA KEV, exploit-db' },
            cisaKEVVuln: { weight: 0.10, source: 'CISA KEV catalog' },
            piiExposure: { weight: 0.10, source: 'Data classification' },
            environment: { weight: 0.05, source: 'prod/stage/dev' }
        },
        
        outputLevels: ['critical', 'high', 'medium', 'low', 'informational'],
        
        mlModel: {
            enabled: true,
            features: ['false positive reduction', 'attack path prediction', 'duplicate clustering']
        }
    },
    
    workflowLifecycle: {
        states: [
            { id: 'open', label: 'Open', color: '#ef4444' },
            { id: 'triaged', label: 'Triaged', color: '#f97316' },
            { id: 'assigned', label: 'Assigned', color: '#eab308' },
            { id: 'in_progress', label: 'In Progress', color: '#3b82f6' },
            { id: 'fixed', label: 'Fixed', color: '#22c55e' },
            { id: 'rescan_pending', label: 'Rescan Pending', color: '#a855f7' },
            { id: 'verified', label: 'Verified', color: '#10b981' },
            { id: 'closed', label: 'Closed', color: '#6b7280' }
        ],
        
        specialStatuses: [
            { id: 'false_positive', label: 'False Positive', color: '#9ca3af' },
            { id: 'risk_accepted', label: 'Risk Accepted', color: '#d97706' },
            { id: 'duplicate', label: 'Duplicate', color: '#9ca3af' },
            { id: 'suppressed', label: 'Suppressed', color: '#6b7280' },
            { id: 'wont_fix', label: "Won't Fix", color: '#9ca3af' },
            { id: 'sla_breached', label: 'SLA Breached', color: '#dc2626' }
        ]
    },
    
    rbac: {
        roles: {
            SUPER_ADMIN: {
                level: 1,
                scope: 'global',
                description: 'Platform-wide administration'
            },
            ADMIN: {
                level: 2,
                scope: 'tenant',
                description: 'Tenant administration'
            },
            APP_SUPERVISOR: {
                level: 3,
                scope: 'project',
                description: 'Project oversight and validation'
            },
            USER: {
                level: 4,
                scope: 'self',
                description: 'Standard user access'
            }
        },
        
        permissions: [
            'scan:create', 'scan:read', 'scan:update', 'scan:delete', 'scan:export',
            'vuln:read', 'vuln:update', 'vuln:verify', 'vuln:false_positive',
            'asset:create', 'asset:read', 'asset:update', 'asset:delete',
            'user:create', 'user:read', 'user:update', 'user:delete',
            'role:assign', 'compliance:read', 'compliance:generate',
            'audit:read', 'report:generate', 'integration:manage'
        ]
    },
    
    integrations: {
        scm: ['GitHub', 'GitLab', 'Bitbucket', 'Azure DevOps'],
        ticketing: ['Jira', 'ServiceNow', 'Linear', 'Asana'],
        messaging: ['Slack', 'Microsoft Teams', 'Discord'],
        siem: ['Splunk', 'ELK Stack', 'Wazuh', 'AWS Security Hub'],
        scanners: ['OWASP ZAP', 'Nuclei', 'Nessus', 'OpenVAS', 'SonarQube', 'Snyk'],
        compliance: ['DefectDojo', 'Recordit', 'Drata', 'Vanta']
    },
    
    aiFeatures: {
        enabled: true,
        features: [
            'AI risk prioritization (CVSS + ML)',
            'False positive detection',
            'Remediation code suggestions',
            'Exploitability prediction',
            'Attack path chaining',
            'Duplicate finding clustering',
            'Natural language report generation',
            'Secure coding hints',
            'Security chatbot'
        ],
        governance: {
            promptInjectionProtection: true,
            outputValidation: true,
            auditLogging: true,
            humanInLoop: true
        }
    },
    
    dashboards: {
        executive: {
            metrics: [
                'Total Assets', 'Critical Vulnerabilities', 'MTTR',
                'SLA Compliance', 'Scan Coverage %', 'False Positive %',
                'Compliance Readiness %', 'OWASP Top 10 Trends'
            ]
        },
        operational: {
            metrics: [
                'Active Scans', 'Queued Jobs', 'Worker Health',
                'Scanner Status', 'API Usage', 'Error Rates'
            ]
        },
        security: {
            metrics: [
                'Vulnerability Breakdown', 'Top Affected Apps',
                'Developer Remediation Score', 'Department Risk',
                'CVE Trend', 'Exploit Availability'
            ]
        }
    },
    
    sla: {
        responseTime: {
            critical: '1 hour',
            high: '4 hours',
            medium: '24 hours',
            low: '7 days'
        },
        resolutionTime: {
            critical: '24 hours',
            high: '7 days',
            medium: '30 days',
            low: '90 days'
        }
    }
};

module.exports = { ENTERPRISE_ARCHITECTURE };