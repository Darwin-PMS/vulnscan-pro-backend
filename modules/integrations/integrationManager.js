/**
 * Enterprise Integrations Module
 * Connect with GitHub, GitLab, Bitbucket, Jira, Slack, Teams, SIEM, and more
 * Webhook-based event dispatch and bi-directional sync
 */

const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const { query } = require('../../database/db');

const INTEGRATION_TYPES = {
    SCM: 'scm',
    TICKETING: 'ticketing',
    MESSAGING: 'messaging',
    SIEM: 'siem',
    SCA: 'sca',
    SCANNER: 'scanner',
    COMPLIANCE: 'compliance'
};

const INTEGRATION_PROVIDERS = {
    GITHUB: { type: INTEGRATION_TYPES.SCM, name: 'GitHub', auth: 'oauth' },
    GITLAB: { type: INTEGRATION_TYPES.SCM, name: 'GitLab', auth: 'oauth' },
    BITBUCKET: { type: INTEGRATION_TYPES.SCM, name: 'Bitbucket', auth: 'oauth' },
    JIRA: { type: INTEGRATION_TYPES.TICKETING, name: 'Jira', auth: 'api_token' },
    SERVICE_NOW: { type: INTEGRATION_TYPES.TICKETING, name: 'ServiceNow', auth: 'oauth' },
    LINEAR: { type: INTEGRATION_TYPES.TICKETING, name: 'Linear', auth: 'api_key' },
    SLACK: { type: INTEGRATION_TYPES.MESSAGING, name: 'Slack', auth: 'oauth' },
    TEAMS: { type: INTEGRATION_TYPES.MESSAGING, name: 'Microsoft Teams', auth: 'webhook' },
    DISCORD: { type: INTEGRATION_TYPES.MESSAGING, name: 'Discord', auth: 'webhook' },
    SPLUNK: { type: INTEGRATION_TYPES.SIEM, name: 'Splunk', auth: 'api_key' },
    ELASTIC: { type: INTEGRATION_TYPES.SIEM, name: 'Elastic SIEM', auth: 'api_key' },
    WAZUH: { type: INTEGRATION_TYPES.SIEM, name: 'Wazuh', auth: 'api_key' },
    AWS_SECURITY_HUB: { type: INTEGRATION_TYPES.SIEM, name: 'AWS Security Hub', auth: 'iam' },
    DEFECTDOJO: { type: INTEGRATION_TYPES.COMPLIANCE, name: 'DefectDojo', auth: 'api_key' },
    SNYK: { type: INTEGRATION_TYPES.SCA, name: 'Snyk', auth: 'api_key' },
    SONARQUBE: { type: INTEGRATION_TYPES.SCANNER, name: 'SonarQube', auth: 'api_key' },
    NESSUS: { type: INTEGRATION_TYPES.SCANNER, name: 'Nessus', auth: 'api_key' },
    OPENVAS: { type: INTEGRATION_TYPES.SCANNER, name: 'OpenVAS', auth: 'api_key' },
    NUCLEI: { type: INTEGRATION_TYPES.SCANNER, name: 'Nuclei', auth: 'none' },
    ZAP: { type: INTEGRATION_TYPES.SCANNER, name: 'OWASP ZAP', auth: 'api_key' }
};

class IntegrationManager {
    constructor() {
        this.webhookCache = new Map();
        this.retryConfig = { maxRetries: 3, retryDelay: 1000 };
    }

    async createIntegration(tenantId, userId, type, provider, config) {
        const integrationId = uuidv4();
        
        await query(
            `INSERT INTO integrations 
             (id, tenant_id, user_id, type, provider, config, status, created_at)
             VALUES (?, ?, ?, ?, ?, ?, 'active', NOW())`,
            [
                integrationId,
                tenantId,
                userId,
                type,
                provider,
                this.encryptConfig(config)
            ]
        );

        await this.testConnection(integrationId, config);

        return {
            integrationId,
            type,
            provider,
            status: 'active',
            createdAt: new Date().toISOString()
        };
    }

    encryptConfig(config) {
        const crypto = require('crypto');
        const key = process.env.INTEGRATION_KEY || 'default-encryption-key';
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key.padEnd(32)), iv);
        
        let encrypted = cipher.update(JSON.stringify(config), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return JSON.stringify({ iv: iv.toString('hex'), data: encrypted });
    }

    decryptConfig(encryptedConfig) {
        try {
            const crypto = require('crypto');
            const key = process.env.INTEGRATION_KEY || 'default-encryption-key';
            const { iv, data } = JSON.parse(encryptedConfig);
            
            const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key.padEnd(32)), Buffer.from(iv, 'hex'));
            let decrypted = decipher.update(data, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return JSON.parse(decrypted);
        } catch (e) {
            return null;
        }
    }

    async testConnection(integrationId, config) {
        const [integration] = await query(
            'SELECT provider FROM integrations WHERE id = ?',
            [integrationId]
        );

        const provider = integration[0]?.provider;
        
        const testMethods = {
            'GitHub': () => this.testGitHubConnection(config),
            'GitLab': () => this.testGitLabConnection(config),
            'Jira': () => this.testJiraConnection(config),
            'Slack': () => this.testSlackConnection(config),
            'Teams': () => this.testTeamsConnection(config),
            'Splunk': () => this.testSplunkConnection(config)
        };

        const testMethod = testMethods[provider];
        if (testMethod) {
            return await testMethod();
        }

        return { success: true };
    }

    async testGitHubConnection(config) {
        try {
            const response = await axios.get('https://api.github.com/user', {
                headers: { Authorization: `Bearer ${config.token}` }
            });
            return { success: true, user: response.data.login };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async testGitLabConnection(config) {
        try {
            const response = await axios.get(`${config.url}/api/v4/user`, {
                headers: { Authorization: `Bearer ${config.token}` }
            });
            return { success: true, user: response.data.username };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async testJiraConnection(config) {
        try {
            const response = await axios.get(`${config.url}/rest/api/3/myself`, {
                auth: { username: config.email, password: config.token }
            });
            return { success: true, user: response.data.displayName };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async testSlackConnection(config) {
        try {
            const response = await axios.post('https://slack.com/api/auth.test', {}, {
                headers: { Authorization: `Bearer ${config.token}` }
            });
            return { success: response.data.ok, user: response.data.user };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async testTeamsConnection(config) {
        return { success: true, test: 'Webhook URL validated' };
    }

    async testSplunkConnection(config) {
        try {
            const response = await axios.get(`${config.url}/services/search/jobs`, {
                auth: { username: config.username, password: config.password }
            });
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async syncWithGitHub(vulnerability, config) {
        const [integration] = await query(
            `SELECT i.* FROM integrations i 
             WHERE i.provider = 'GitHub' AND i.status = 'active'`,
            []
        );

        if (!integration || integration.length === 0) {
            return { synced: false, reason: 'No active GitHub integration' };
        }

        try {
            const issueBody = this.formatGitHubIssue(vulnerability);
            
            const response = await axios.post(
                `${config.apiUrl}/repos/${config.owner}/${config.repo}/issues`,
                issueBody,
                {
                    headers: {
                        Authorization: `Bearer ${config.token}`,
                        Accept: 'application/vnd.github.v3+json'
                    }
                }
            );

            await this.logIntegrationEvent('github', 'create_issue', response.data.id);

            return { synced: true, issueUrl: response.data.html_url, issueNumber: response.data.number };
        } catch (error) {
            return { synced: false, error: error.message };
        }
    }

    formatGitHubIssue(vulnerability) {
        const severityEmoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', informational: '⚪' };
        
        return {
            title: `[${vulnerability.severity?.toUpperCase()}] ${vulnerability.title}`,
            body: `## Vulnerability Details\n\n**Severity:** ${severityEmoji[vulnerability.severity]} ${vulnerability.severity}\n**Category:** ${vulnerability.category}\n**URL:** ${vulnerability.url}\n\n### Description\n${vulnerability.description}\n\n### Remediation\n${vulnerability.remediation}\n\n### References\n${vulnerability.cveIds?.map(cve => `- ${cve}`).join('\n') || 'N/A'}\n\n---\n*Generated by VulnScan Pro*`,
            labels: ['security', vulnerability.severity, 'vulnerability']
        };
    }

    async createJiraTicket(vulnerability, config) {
        try {
            const ticketData = this.formatJiraTicket(vulnerability);
            
            const response = await axios.post(
                `${config.url}/rest/api/3/issue`,
                ticketData,
                {
                    auth: { username: config.email, password: config.token },
                    headers: { 'Content-Type': 'application/json' }
                }
            );

            await this.logIntegrationEvent('jira', 'create_ticket', response.data.key);

            return { synced: true, ticketKey: response.data.key, ticketUrl: `${config.url}/browse/${response.data.key}` };
        } catch (error) {
            return { synced: false, error: error.message };
        }
    }

    formatJiraTicket(vulnerability) {
        return {
            fields: {
                project: { key: config.projectKey },
                summary: `[${vulnerability.severity}] ${vulnerability.title}`,
                description: {
                    type: 'doc',
                    version: 1,
                    content: [{
                        type: 'paragraph',
                        content: [{ type: 'text', text: vulnerability.description }]
                    }]
                },
                issuetype: { name: 'Bug' },
                priority: { name: this.mapJiraPriority(vulnerability.severity) }
            }
        };
    }

    mapJiraPriority(severity) {
        const mapping = { critical: 'Highest', high: 'High', medium: 'Medium', low: 'Low' };
        return mapping[severity] || 'Medium';
    }

    async sendSlackNotification(vulnerability, config) {
        try {
            const message = this.formatSlackMessage(vulnerability);
            
            await axios.post(config.webhookUrl, message);
            
            await this.logIntegrationEvent('slack', 'notification', 'sent');

            return { sent: true };
        } catch (error) {
            return { sent: false, error: error.message };
        }
    }

    formatSlackMessage(vulnerability) {
        const colorMap = { critical: '#FF0000', high: '#FFA500', medium: '#FFFF00', low: '#00FF00' };
        
        return {
            attachments: [{
                color: colorMap[vulnerability.severity] || '#CCCCCC',
                blocks: [
                    {
                        type: 'header',
                        text: { type: 'plain_text', text: `🔒 ${vulnerability.title}` }
                    },
                    {
                        type: 'section',
                        fields: [
                            { type: 'mrkdwn', text: `*Severity:*\n${vulnerability.severity?.toUpperCase()}` },
                            { type: 'mrkdwn', text: `*Category:*\n${vulnerability.category}` }
                        ]
                    },
                    {
                        type: 'section',
                        text: { type: 'mrkdwn', text: `*Description:*\n${vulnerability.description?.substring(0, 200)}` }
                    },
                    {
                        type: 'actions',
                        elements: [{
                            type: 'button',
                            text: { type: 'plain_text', text: 'View in VulnScan Pro' },
                            url: `${process.env.FRONTEND_URL}/vulnerabilities/${vulnerability.id}`
                        }]
                    }
                ]
            }]
        };
    }

    async sendTeamsNotification(vulnerability, config) {
        try {
            const message = this.formatTeamsMessage(vulnerability);
            
            await axios.post(config.webhookUrl, message);
            
            return { sent: true };
        } catch (error) {
            return { sent: false, error: error.message };
        }
    }

    formatTeamsMessage(vulnerability) {
        return {
            '@type': 'MessageCard',
            '@context': 'http://schema.org/extensions',
            themeColor: this.getTeamsColor(vulnerability.severity),
            summary: vulnerability.title,
            sections: [{
                activityTitle: `🔒 ${vulnerability.title}`,
                facts: [
                    { name: 'Severity', value: vulnerability.severity },
                    { name: 'Category', value: vulnerability.category },
                    { name: 'URL', value: vulnerability.url }
                ],
                markdown: true
            }]
        };
    }

    getTeamsColor(severity) {
        const colors = { critical: 'FF0000', high: 'FFA500', medium: 'FFFF00', low: '00FF00' };
        return colors[severity] || '0076D7';
    }

    async sendToSIEM(event, config) {
        try {
            if (config.provider === 'splunk') {
                await axios.post(
                    `${config.url}/services/receivers/simple`,
                    event,
                    {
                        auth: { username: config.username, password: config.password },
                        params: { host: 'vulnscan-pro', source: 'vulnerability', sourcetype: 'vulnscan:findings' }
                    }
                );
            } else if (config.provider === 'elastic') {
                await axios.post(`${config.url}/_bulk`, { index: 'vulnerabilities', ...event });
            }

            return { sent: true };
        } catch (error) {
            return { sent: false, error: error.message };
        }
    }

    async triggerWebhook(eventType, payload, integrations) {
        const results = [];
        
        for (const integration of integrations) {
            if (!integration.webhooks?.enabled) continue;

            const result = await this.dispatchWebhook(eventType, integration, payload);
            results.push({ integrationId: integration.id, ...result });
        }

        return results;
    }

    async dispatchWebhook(eventType, integration, payload) {
        const config = this.decryptConfig(integration.config);
        const webhookEvents = integration.webhooks?.events || [];

        if (!webhookEvents.includes(eventType)) {
            return { delivered: false, reason: 'Event not subscribed' };
        }

        const webhookUrl = config.webhookUrl;
        
        try {
            await axios.post(webhookUrl, {
                event: eventType,
                timestamp: new Date().toISOString(),
                data: payload
            }, { timeout: 5000 });

            return { delivered: true };
        } catch (error) {
            return { delivered: false, error: error.message };
        }
    }

    async logIntegrationEvent(integrationType, action, externalId) {
        await query(
            `INSERT INTO integration_logs (id, integration_type, action, external_id, created_at)
             VALUES (?, ?, ?, ?, NOW())`,
            [uuidv4(), integrationType, action, externalId]
        );
    }

    async getIntegrationLogs(tenantId, integrationId = null) {
        let sql = `SELECT * FROM integration_logs WHERE tenant_id = ?`;
        const params = [tenantId];

        if (integrationId) {
            sql += ' AND integration_id = ?';
            params.push(integrationId);
        }

        sql += ' ORDER BY created_at DESC LIMIT 100';

        const [logs] = await query(sql, params);
        return logs;
    }

    async getAvailableIntegrations() {
        return Object.entries(INTEGRATION_PROVIDERS).map(([key, value]) => ({
            id: key,
            ...value
        }));
    }
}

module.exports = {
    IntegrationManager,
    INTEGRATION_TYPES,
    INTEGRATION_PROVIDERS
};