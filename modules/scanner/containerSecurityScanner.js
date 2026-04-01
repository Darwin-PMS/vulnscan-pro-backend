/**
 * Container Security Scanner Module
 * Detects vulnerabilities in Docker images, Kubernetes configurations, and container deployments
 */

const axios = require('axios');

class ContainerSecurityScanner {
    constructor() {
        this.checkTypes = {
            docker: 'Docker',
            kubernetes: 'Kubernetes',
            docker_compose: 'Docker Compose',
            general: 'Container Security'
        };

        this.patterns = this.initializePatterns();
    }

    initializePatterns() {
        return {
            docker: [
                {
                    id: 'CONT-DK-001',
                    title: 'Running as Root User',
                    description: 'Container runs as root user, increasing attack surface',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /USER\s+root/i.test(content) ||
                                   (!/USER\s+[a-z]/i.test(content) && /FROM\s+/i.test(content));
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DK-002',
                    title: 'Latest Tag Usage',
                    description: 'Docker image uses :latest tag which may cause inconsistent deployments',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /FROM\s+[^:]*:latest/i.test(content) ||
                                   /image:.*:latest/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DK-003',
                    title: 'Missing Health Check',
                    description: 'Docker image lacks HEALTHCHECK instruction',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return !/HEALTHCHECK\s+/i.test(content) && /FROM\s+/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DK-004',
                    title: 'Exposed Secrets in Dockerfile',
                    description: 'Hardcoded secrets or credentials in Dockerfile',
                    severity: 'critical',
                    check: async (content) => {
                        if (content) {
                            const secretPatterns = [
                                /password\s*[=:]/i,
                                /api_key\s*[=:]/i,
                                /secret\s*[=:]/i,
                                /ENV\s+\w*_PASS/i,
                                /ENV\s+\w*_KEY/i,
                                /ARG\s+\w*_SECRET/i
                            ];
                            return secretPatterns.some(p => p.test(content));
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DK-005',
                    title: 'Sensitive Data in ENV',
                    description: 'Environment variables may contain sensitive data',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /ENV\s+\w*=\s*["'][^"']{20,}/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DK-006',
                    title: 'Missing Package Update',
                    description: 'Dockerfile does not update packages before installing',
                    severity: 'low',
                    check: async (content) => {
                        if (content) {
                            return /apt-get\s+install/i.test(content) && 
                                   !/apt-get\s+update/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DK-007',
                    title: 'No Pin Package Version',
                    description: 'Packages installed without specific versions',
                    severity: 'low',
                    check: async (content) => {
                        if (content) {
                            return /apt-get\s+install\s+\w+\s+&&/i.test(content) ||
                                   /pip\s+install\s+\w+$/im.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DK-008',
                    title: 'COPY Instead of ADD',
                    description: 'Using ADD instead of COPY for file copying',
                    severity: 'info',
                    check: async (content) => {
                        if (content) {
                            return /ADD\s+[^$]+\/.*$/m.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DK-009',
                    title: 'No Multi-Stage Build',
                    description: 'Dockerfile not using multi-stage builds for smaller images',
                    severity: 'low',
                    check: async (content) => {
                        if (content) {
                            const lines = content.split('\n');
                            const fromCount = (content.match(/^FROM\s+/gmi) || []).length;
                            return fromCount <= 1 && /go\s+build|gradle\s+build|maven\s+package|npm\s+build/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DK-010',
                    title: 'Privileged Container Risk',
                    description: 'Container may run with excessive privileges',
                    severity: 'critical',
                    check: async (content) => {
                        if (content) {
                            return /--privileged/i.test(content) ||
                                   /--cap-add\s+ALL/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DK-011',
                    title: 'Sensitive Mount Points',
                    description: 'Container mounts sensitive host directories',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            const sensitiveMounts = ['/var/run/docker.sock', '/etc', '/root', '/var/log'];
                            return sensitiveMounts.some(m => content.includes(m));
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DK-012',
                    title: 'Insecure Base Image',
                    description: 'Using untrusted or unofficial base image',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /FROM\s+scratch/i.test(content) ||
                                   /FROM\s+ubuntu$/i.test(content) ||
                                   /FROM\s+centos$/i.test(content);
                        }
                        return false;
                    }
                }
            ],
            kubernetes: [
                {
                    id: 'CONT-K8-001',
                    title: 'Running as Root',
                    description: 'Pod runs containers as root user',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return !/runAsNonRoot:\s*true/i.test(content) &&
                                   /securityContext:/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-002',
                    title: 'Missing Pod Security Policy',
                    description: 'No PodSecurityPolicy or PodSecurityContext defined',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return !/securityContext:/i.test(content) && /kind:\s*Pod/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-003',
                    title: 'Privileged Container',
                    description: 'Container runs in privileged mode',
                    severity: 'critical',
                    check: async (content) => {
                        if (content) {
                            return /privileged:\s*true/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-004',
                    title: 'Host Network Access',
                    description: 'Pod accesses host network namespace',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /hostNetwork:\s*true/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-005',
                    title: 'Host PID/IPC Access',
                    description: 'Pod accesses host PID or IPC namespace',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /hostPID:\s*true/i.test(content) ||
                                   /hostIPC:\s*true/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-006',
                    title: 'Allow Privilege Escalation',
                    description: 'Container allows privilege escalation',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /allowPrivilegeEscalation:\s*true/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-007',
                    title: 'Missing Resource Limits',
                    description: 'Container does not specify resource limits',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return !/resources:/i.test(content) && /containers:/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-008',
                    title: 'Missing Liveness/Readiness Probes',
                    description: 'Container lacks health check configuration',
                    severity: 'low',
                    check: async (content) => {
                        if (content) {
                            return !/livenessProbe:|readinessProbe:/i.test(content) && 
                                   /containers:/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-009',
                    title: 'Insecure Image Reference',
                    description: 'Container image uses :latest tag or unverified registry',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /image:\s*[^:]*$/m.test(content) ||
                                   /image:\s*[^:]+\s*$/m.test(content) ||
                                   /image:\s+[^/]+\/[^/]+\/[^:]+$/m.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-010',
                    title: 'Exposed Secrets as Environment',
                    description: 'Sensitive data stored as environment variables',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /env:/.test(content) && 
                                   /secretKeyRef|name:\s*[^$]+\$/(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-011',
                    title: 'Empty Security Context',
                    description: 'Security context defined but empty',
                    severity: 'low',
                    check: async (content) => {
                        if (content) {
                            return /securityContext:\s*\{\s*\}/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-012',
                    title: 'Host Path Volume Mount',
                    description: 'Pod mounts host filesystem',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /hostPath:|mountPath:\s*\//i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-013',
                    title: 'NET_RAW Capability Granted',
                    description: 'Container has NET_RAW capability which can be abused',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /NET_RAW/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-K8-014',
                    title: 'Service Account Token Auto-Mount',
                    description: 'Service account token mounted unnecessarily',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return !/automountServiceAccountToken:\s*false/i.test(content);
                        }
                        return false;
                    }
                }
            ],
            docker_compose: [
                {
                    id: 'CONT-DC-001',
                    title: 'Privileged Mode in Compose',
                    description: 'Service runs in privileged mode',
                    severity: 'critical',
                    check: async (content) => {
                        if (content) {
                            return /privileged:\s*true/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DC-002',
                    title: 'Network Mode Host',
                    description: 'Service uses host network mode',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /network_mode:\s*["']?host["']?/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DC-003',
                    title: 'Sensitive Volume Mounts',
                    description: 'Sensitive host paths mounted in container',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            const sensitivePaths = ['/var/run/docker.sock', '/etc/passwd', '/root/.ssh'];
                            return sensitivePaths.some(p => content.includes(p));
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DC-004',
                    title: 'Environment Variables with Secrets',
                    description: 'Sensitive data in environment variables',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            const secretVars = ['PASSWORD', 'SECRET', 'API_KEY', 'TOKEN', 'PRIVATE'];
                            return secretVars.some(v => 
                                content.includes(`-${v}`) || content.includes(`_${v}`));
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-DC-005',
                    title: 'Latest Tag Usage',
                    description: 'Image uses :latest tag',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /image:\s*[^:\n]+$/m.test(content);
                        }
                        return false;
                    }
                }
            ],
            general: [
                {
                    id: 'CONT-GN-001',
                    title: 'No Read-Only Root Filesystem',
                    description: 'Container root filesystem is writable',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return !/readOnlyRootFilesystem:\s*true/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-GN-002',
                    title: 'Dropped Capabilities Missing',
                    description: 'Container does not drop unnecessary capabilities',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return !/capabilities:\s*drop/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-GN-003',
                    title: 'Docker Socket Not Mounted',
                    description: 'Docker socket should not be mounted in containers',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /docker\.sock|\.sock["']?\s*:/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-GN-004',
                    title: 'Sensitive Ports Exposed',
                    description: 'Sensitive ports exposed to network',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            const sensitivePorts = ['3306', '5432', '27017', '6379', '9200'];
                            return sensitivePorts.some(p => 
                                new RegExp(`-${p}:|-${p}\\s|ports:.*${p}`).test(content));
                        }
                        return false;
                    }
                },
                {
                    id: 'CONT-GN-005',
                    title: 'No User Namespace Remapping',
                    description: 'Container not using user namespace remapping',
                    severity: 'low',
                    check: async (content) => {
                        if (content) {
                            return !/usernsMode:/i.test(content);
                        }
                        return false;
                    }
                }
            ]
        };
    }

    async scanTarget(url, scanId, options = {}) {
        const { content, type } = options;

        const results = {
            scanId,
            targetUrl: url,
            scanner: 'Container Security Scanner',
            startTime: new Date().toISOString(),
            vulnerabilities: [],
            summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            containerTypes: {}
        };

        try {
            let scanContent = content;

            if (!scanContent && url) {
                try {
                    const response = await axios.get(url, {
                        timeout: 10000,
                        validateStatus: () => true,
                        headers: { 'User-Agent': 'VulnScanPro/2.0 Security Scanner' }
                    });
                    scanContent = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                } catch (err) {
                    console.log('Could not fetch URL content');
                }
            }

            const typesToCheck = type ? [type] : ['docker', 'kubernetes', 'docker_compose', 'general'];

            for (const containerType of typesToCheck) {
                const patterns = this.patterns[containerType] || [];

                for (const pattern of patterns) {
                    try {
                        const isVulnerable = await pattern.check(scanContent);

                        if (isVulnerable) {
                            const vulnerability = {
                                id: pattern.id,
                                containerType: this.checkTypes[containerType] || containerType,
                                title: pattern.title,
                                description: pattern.description,
                                severity: pattern.severity,
                                remediation: this.getRemediation(pattern.id),
                                discoveredAt: new Date().toISOString()
                            };

                            if (!results.containerTypes[containerType]) {
                                results.containerTypes[containerType] = [];
                            }
                            results.containerTypes[containerType].push(vulnerability);
                            results.vulnerabilities.push(vulnerability);
                            results.summary[pattern.severity]++;
                        }
                    } catch (err) {
                        console.error(`Container check ${pattern.id} failed:`, err.message);
                    }
                }
            }

            results.endTime = new Date().toISOString();
            results.totalVulnerabilities = results.vulnerabilities.length;

        } catch (error) {
            results.error = error.message;
            results.endTime = new Date().toISOString();
        }

        return results;
    }

    getRemediation(id) {
        const remediations = {
            'CONT-DK-001': 'Create a non-root user in Dockerfile with USER instruction. Use numeric UID for consistency.',
            'CONT-DK-002': 'Always use specific version tags (e.g., node:18-alpine3.17) instead of :latest.',
            'CONT-DK-003': 'Add HEALTHCHECK instruction to Dockerfile for container health monitoring.',
            'CONT-DK-004': 'Never hardcode secrets in Dockerfile. Use Docker secrets or environment variables at runtime.',
            'CONT-DK-005': 'Avoid storing sensitive data in ENV variables. Use secrets management or volume mounts.',
            'CONT-DK-006': 'Always run apt-get update before apt-get install to ensure latest packages.',
            'CONT-DK-007': 'Pin package versions (e.g., apt-get install curl=7.88.1) for reproducibility.',
            'CONT-DK-008': 'Use COPY instead of ADD unless you specifically need ADD features (like tar extraction).',
            'CONT-DK-009': 'Use multi-stage builds to separate build-time and runtime dependencies.',
            'CONT-DK-010': 'Avoid --privileged and --cap-add flags. Use specific capability requirements instead.',
            'CONT-DK-011': 'Avoid mounting sensitive host directories. Use Docker volumes for persistent data.',
            'CONT-DK-012': 'Use official, verified base images. Prefer minimal images like alpine or distroless.',
            'CONT-K8-001': 'Set runAsNonRoot: true and runAsUser to non-zero value in PodSecurityContext.',
            'CONT-K8-002': 'Define PodSecurityPolicy or use Pod Security Standards.',
            'CONT-K8-003': 'Set privileged: false in container security context. Remove unnecessary capabilities.',
            'CONT-K8-004': 'Avoid hostNetwork unless necessary. Use ClusterIP or Ingress for service communication.',
            'CONT-K8-005': 'Avoid hostPID and hostIPC unless required. Isolate pods using namespaces.',
            'CONT-K8-006': 'Set allowPrivilegeEscalation: false in security context.',
            'CONT-K8-007': 'Define resource limits and requests for CPU and memory in container spec.',
            'CONT-K8-008': 'Add livenessProbe and readinessProbe for application health monitoring.',
            'CONT-K8-009': 'Use specific image tags. Pin to SHA digests for production.',
            'CONT-K8-010': 'Use Kubernetes secrets with proper RBAC. Prefer Vault or external secrets management.',
            'CONT-K8-011': 'Remove empty security contexts or add meaningful security settings.',
            'CONT-K8-012': 'Avoid hostPath volumes. Use PersistentVolumeClaims or emptyDir for temporary storage.',
            'CONT-K8-013': 'Remove NET_RAW capability. Add explicit list of required capabilities.',
            'CONT-K8-014': 'Set automountServiceAccountToken: false for pods that dont need service account access.',
            'CONT-DC-001': 'Remove privileged: true from docker-compose.yml service definitions.',
            'CONT-DC-002': 'Use bridge network mode instead of host mode for better isolation.',
            'CONT-DC-003': 'Remove sensitive host path mounts. Use named volumes instead.',
            'CONT-DC-004': 'Use .env file for secrets or Docker secrets for sensitive environment variables.',
            'CONT-DC-005': 'Pin image versions in docker-compose.yml. Use SHA digests for production.',
            'CONT-GN-001': 'Set readOnlyRootFilesystem: true in security context.',
            'CONT-GN-002': 'Add securityContext.capabilities.drop: [ALL] to drop all capabilities.',
            'CONT-GN-003': 'Do not mount Docker socket inside containers. Use Docker-in-Docker alternatives.',
            'CONT-GN-004': 'Use internal networks for database services. Expose only necessary ports.',
            'CONT-GN-005': 'Consider using userns remapping for additional isolation.'
        };
        return remediations[id] || 'Follow container security best practices.';
    }

    getSummary() {
        return {
            types: Object.entries(this.checkTypes).map(([key, name]) => ({
                id: key,
                name,
                patternCount: this.patterns[key]?.length || 0
            })),
            totalPatterns: Object.values(this.patterns).flat().length
        };
    }
}

module.exports = { ContainerSecurityScanner };
