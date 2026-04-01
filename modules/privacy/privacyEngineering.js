/**
 * Privacy Engineering Module
 * Based on NIST Privacy Framework & GDPR/DPDP compliance
 * Reference: https://csrc.nist.gov/projects/privacy-framework
 */

const { v4: uuidv4 } = require('uuid');
const { query } = require('../../database/db');

const CONSENT_TYPES = {
    MARKETING: 'marketing',
    ANALYTICS: 'analytics',
    FUNCTIONAL: 'functional',
    ESSENTIAL: 'essential'
};

const CONSENT_STATUS = {
    GRANTED: 'granted',
    DENIED: 'denied',
    WITHDRAWN: 'withdrawn',
    PENDING: 'pending'
};

const DATA_CATEGORIES = {
    PII: 'personally_identifiable',
    SENSITIVE: 'sensitive',
    HEALTH: 'health',
    FINANCIAL: 'financial',
    BIOMETRIC: 'biometric',
    LOCATION: 'location',
    BEHAVIORAL: 'behavioral',
    TECHNICAL: 'technical'
};

class PrivacyEngineering {
    constructor() {
        this.retentionPolicies = {
            logs: { duration: 90, unit: 'days' },
            scanData: { duration: 365, unit: 'days' },
            userData: { duration: -1, unit: 'indefinite' },
            auditLogs: { duration: 2555, unit: 'days' },
            apiLogs: { duration: 30, unit: 'days' }
        };
    }

    // ==================== CONSENT MANAGEMENT ====================

    async createConsentRecord(userId, consentData) {
        const {
            type,
            purpose,
            granted,
            method = 'explicit',
            ipAddress,
            userAgent
        } = consentData;

        const consent = {
            id: uuidv4(),
            userId,
            type,
            purpose,
            status: granted ? CONSENT_STATUS.GRANTED : CONSENT_STATUS.DENIED,
            method,
            grantedAt: granted ? new Date().toISOString() : null,
            withdrawnAt: null,
            ipAddress: this.hashIP(ipAddress),
            userAgent,
            version: '1.0',
            createdAt: new Date().toISOString()
        };

        await query(`
            INSERT INTO consent_records 
            (consent_id, user_id, type, purpose, status, method, 
             granted_at, ip_address, user_agent, version, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            consent.id,
            consent.userId,
            consent.type,
            consent.purpose,
            consent.status,
            consent.method,
            consent.grantedAt,
            consent.ipAddress,
            consent.userAgent,
            consent.version,
            consent.createdAt
        ]);

        return consent;
    }

    async getUserConsents(userId) {
        const [consents] = await query(`
            SELECT * FROM consent_records 
            WHERE user_id = ?
            ORDER BY created_at DESC
        `, [userId]);

        const consentSummary = {
            marketing: false,
            analytics: false,
            functional: true,
            essential: true
        };

        for (const consent of consents) {
            if (consent.status === CONSENT_STATUS.GRANTED) {
                if (consent.type === CONSENT_TYPES.MARKETING) consentSummary.marketing = true;
                if (consent.type === CONSENT_TYPES.ANALYTICS) consentSummary.analytics = true;
                if (consent.type === CONSENT_TYPES.FUNCTIONAL) consentSummary.functional = true;
            }
        }

        return {
            consents,
            summary: consentSummary,
            lastUpdated: consents[0]?.created_at
        };
    }

    async withdrawConsent(userId, consentType) {
        await query(`
            UPDATE consent_records 
            SET status = ?, withdrawn_at = ?
            WHERE user_id = ? AND type = ?
            AND status = ?
        `, [
            CONSENT_STATUS.WITHDRAWN,
            new Date().toISOString(),
            userId,
            consentType,
            CONSENT_STATUS.GRANTED
        ]);

        await this.logConsentEvent('CONSENT_WITHDRAWN', { userId, consentType });

        return { success: true, consentType, withdrawnAt: new Date().toISOString() };
    }

    async checkConsent(userId, consentType) {
        const [consent] = await query(`
            SELECT status FROM consent_records 
            WHERE user_id = ? AND type = ?
            ORDER BY created_at DESC
            LIMIT 1
        `, [userId, consentType]);

        if (!consent) {
            if (consentType === CONSENT_TYPES.ESSENTIAL) return true;
            if (consentType === CONSENT_TYPES.FUNCTIONAL) return true;
            return false;
        }

        return consent.status === CONSENT_STATUS.GRANTED;
    }

    // ==================== DATA MINIMIZATION ====================

    minimizeData(data, purpose) {
        const minimizationRules = {
            user_registration: ['id', 'username', 'email', 'password_hash'],
            marketing: ['id', 'email', 'marketing_preferences'],
            analytics: ['id', 'usage_patterns', 'timestamp'],
            support: ['id', 'username', 'email', 'support_tickets']
        };

        const allowedFields = minimizationRules[purpose] || Object.keys(data);
        const minimized = {};

        for (const field of allowedFields) {
            if (data[field] !== undefined) {
                minimized[field] = data[field];
            }
        }

        return minimized;
    }

    async auditDataCollection(userId) {
        const [userData] = await query(`
            SELECT * FROM users WHERE id = ?
        `, [userId]);

        const [consentRecords] = await query(`
            SELECT type, status, purpose FROM consent_records WHERE user_id = ?
        `, [userId]);

        const dataInventory = [];

        const piiFields = ['email', 'username', 'full_name'];
        for (const field of piiFields) {
            if (userData[0] && userData[0][field]) {
                dataInventory.push({
                    field,
                    category: DATA_CATEGORIES.PII,
                    value: this.maskPII(userData[0][field], field),
                    collectedWithConsent: this.hasConsent(consentRecords, field)
                });
            }
        }

        return {
            userId,
            dataInventory,
            collectionPoints: this.identifyCollectionPoints(userData[0]),
            generatedAt: new Date().toISOString()
        };
    }

    identifyCollectionPoints(userData) {
        const points = [];

        if (userData?.email) points.push({ point: 'registration', type: 'direct' });
        if (userData?.last_login) points.push({ point: 'authentication', type: 'automated' });
        if (userData?.created_at) points.push({ point: 'signup', type: 'direct' });

        return points;
    }

    hasConsent(consentRecords, field) {
        return consentRecords.some(r => r.status === CONSENT_STATUS.GRANTED);
    }

    // ==================== PII MASKING ====================

    maskPII(value, type) {
        if (!value) return null;

        switch (type) {
            case 'email':
                const [local, domain] = value.split('@');
                return `${local.substring(0, 2)}***@${domain}`;

            case 'username':
                return value.substring(0, 2) + '***' + value.substring(value.length - 1);

            case 'full_name':
                return value.split(' ').map(n => n[0] + '***').join(' ');

            case 'phone':
                return value.replace(/\d(?=\d{4})/g, '*');

            case 'ip_address':
                return value.replace(/\.\d+$/, '.***');

            default:
                return value.substring(0, 3) + '***';
        }
    }

    maskSensitiveData(data, fieldsToMask) {
        const masked = { ...data };

        for (const field of fieldsToMask) {
            if (masked[field]) {
                masked[field] = this.maskPII(masked[field], field);
            }
        }

        return masked;
    }

    // ==================== DATA ANONYMIZATION ====================

    anonymizeUserData(userId, options = {}) {
        const {
            preserveScans = false,
            anonymizeHistory = true
        } = options;

        const anonymizedFields = {
            username: `anon_${uuidv4().substring(0, 8)}`,
            email: `anon_${uuidv4()}@anonymized.local`,
            full_name: null,
            password_hash: 'ANONYMIZED',
            last_login: null
        };

        const updates = Object.entries(anonymizedFields).map(([k, v]) => `${k} = ?`);
        const values = Object.values(anonymizedFields);

        if (!preserveScans) {
            updates.push('is_active = FALSE');
        }

        return {
            userId,
            anonymizedFields: Object.keys(anonymizedFields),
            sql: `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
            values: [...values, userId]
        };
    }

    async applyDataRetentionPolicy() {
        const results = [];

        for (const [dataType, policy] of Object.entries(this.retentionPolicies)) {
            if (policy.duration === -1) continue;

            const result = await this.applyRetentionToDataType(dataType, policy);
            results.push(result);
        }

        await this.logPrivacyEvent('RETENTION_POLICY_APPLIED', { results });

        return {
            appliedPolicies: results.length,
            results,
            appliedAt: new Date().toISOString()
        };
    }

    async applyRetentionToDataType(dataType, policy) {
        let table, dateColumn;

        switch (dataType) {
            case 'logs':
                table = 'audit_logs';
                dateColumn = 'created_at';
                break;
            case 'scanData':
                table = 'scans';
                dateColumn = 'created_at';
                break;
            case 'apiLogs':
                table = 'api_usage_logs';
                dateColumn = 'created_at';
                break;
            default:
                return { dataType, status: 'skipped', reason: 'Unknown data type' };
        }

        try {
            const [result] = await query(`
                DELETE FROM ${table} 
                WHERE ${dateColumn} < DATE_SUB(NOW(), INTERVAL ? DAY)
            `, [policy.duration]);

            return {
                dataType,
                table,
                recordsDeleted: result.affectedRows,
                retentionDays: policy.duration,
                status: 'completed'
            };
        } catch (error) {
            return {
                dataType,
                table,
                status: 'failed',
                error: error.message
            };
        }
    }

    // ==================== USER DATA RIGHTS ====================

    async processDataExport(userId) {
        const exportData = {
            profile: await this.exportUserProfile(userId),
            scans: await this.exportUserScans(userId),
            subscriptions: await this.exportUserSubscriptions(userId),
            activity: await this.exportUserActivity(userId),
            consents: await this.exportUserConsents(userId)
        };

        const exportId = uuidv4();
        const exportFile = {
            id: exportId,
            userId,
            format: 'json',
            data: exportData,
            generatedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
        };

        await query(`
            INSERT INTO data_export_requests 
            (request_id, user_id, status, requested_at, completed_at)
            VALUES (?, ?, 'completed', ?, ?)
        `, [exportId, userId, new Date().toISOString(), new Date().toISOString()]);

        return exportFile;
    }

    async exportUserProfile(userId) {
        const [user] = await query(`
            SELECT id, username, email, full_name, role, created_at, last_login
            FROM users WHERE id = ?
        `, [userId]);

        return user[0] || null;
    }

    async exportUserScans(userId) {
        const [scans] = await query(`
            SELECT scan_id, target_url, status, total_vulnerabilities, created_at
            FROM scans WHERE user_id = ?
        `, [userId]);

        return scans;
    }

    async exportUserSubscriptions(userId) {
        const [subs] = await query(`
            SELECT tier_id, status, billing_cycle, start_date, end_date
            FROM user_subscriptions WHERE user_id = ?
        `, [userId]);

        return subs;
    }

    async exportUserActivity(userId) {
        const [activity] = await query(`
            SELECT action, details, created_at
            FROM audit_logs WHERE user_id = ?
            ORDER BY created_at DESC LIMIT 1000
        `, [userId]);

        return activity;
    }

    async exportUserConsents(userId) {
        const [consents] = await query(`
            SELECT type, purpose, status, granted_at, withdrawn_at
            FROM consent_records WHERE user_id = ?
        `, [userId]);

        return consents;
    }

    async processDataDeletion(userId, options = {}) {
        // const {
        //     softDelete = true,
        //     deleteScans = false,
        //     deleteSubscription = false,
        //     anonymize = true
        // } = options;
        const softDelete = await this.processDataDeletion(userId, {
            softDelete: true,
            anonymize: deleteOptions.anonymize || true,
            deleteScans: false,
            deleteSubscription: false
        });

        const deletionId = uuidv4();

        await query(`
            INSERT INTO data_deletion_requests 
            (request_id, user_id, status, type, requested_at)
            VALUES (?, ?, 'processing', ?, NOW())
        `, [deletionId, userId, softDelete ? 'soft' : 'hard']);



        await query(`
            UPDATE data_deletion_requests 
            SET status = 'completed', completed_at = NOW()
            WHERE request_id = ?
        `, [deletionId]);

        await this.logPrivacyEvent('DATA_DELETION_COMPLETED', {
            deletionId,
            userId,
            softDelete: true,
            anonymize: deleteOptions.anonymize || true
        });

        return {
            deletionId,
            status: 'completed',
            completedAt: new Date().toISOString(),
            message: 'User data anonymized - preserved for audit trail'
        };
    }

    // ==================== PRIVACY RISK ASSESSMENT ====================

    async generatePrivacyRiskHeatmap(userId) {
        const consents = await this.getUserConsents(userId);
        const dataInventory = await this.auditDataCollection(userId);

        const risks = [];

        const unconsentedData = dataInventory.dataInventory.filter(d => !d.collectedWithConsent);
        if (unconsentedData.length > 0) {
            risks.push({
                category: 'CONSENT',
                level: 'HIGH',
                description: 'Data collected without consent',
                dataFields: unconsentedData.map(d => d.field)
            });
        }

        const sensitiveData = dataInventory.dataInventory.filter(d =>
            [DATA_CATEGORIES.PII, DATA_CATEGORIES.SENSITIVE].includes(d.category)
        );
        if (sensitiveData.length > 3) {
            risks.push({
                category: 'DATA_VOLUME',
                level: 'MEDIUM',
                description: 'Large volume of sensitive PII collected'
            });
        }

        return {
            userId,
            overallRisk: risks.length > 0 ? 'MEDIUM' : 'LOW',
            risks,
            dataInventory: dataInventory.dataInventory,
            consentStatus: consents.summary,
            generatedAt: new Date().toISOString()
        };
    }

    // ==================== AUDIT & LOGGING ====================

    async logConsentEvent(action, details) {
        await query(`
            INSERT INTO privacy_audit_logs 
            (id, action, details, created_at)
            VALUES (?, ?, ?, NOW())
        `, [uuidv4(), action, JSON.stringify(details)]);
    }

    async logPrivacyEvent(eventType, data) {
        await query(`
            INSERT INTO privacy_audit_logs 
            (id, event_type, data, created_at)
            VALUES (?, ?, ?, NOW())
        `, [uuidv4(), eventType, JSON.stringify(data)]);
    }

    hashIP(ip) {
        const crypto = require('crypto');
        return crypto.createHash('sha256').update(ip || 'unknown').digest('hex').substring(0, 16);
    }

    async getConsentAuditTrail(userId) {
        const [logs] = await query(`
            SELECT * FROM privacy_audit_logs 
            WHERE JSON_EXTRACT(data, '$.userId') = ?
            OR JSON_EXTRACT(details, '$.userId') = ?
            ORDER BY created_at DESC
            LIMIT 100
        `, [userId, userId]);

        return {
            userId,
            logs,
            generatedAt: new Date().toISOString()
        };
    }
}

module.exports = {
    PrivacyEngineering,
    CONSENT_TYPES,
    CONSENT_STATUS,
    DATA_CATEGORIES
};
