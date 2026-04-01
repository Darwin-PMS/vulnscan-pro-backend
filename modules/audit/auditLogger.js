/**
 * Audit Logging Module
 * Comprehensive activity tracking for compliance
 */

const { v4: uuidv4 } = require('uuid');
const { query } = require('../../database/db');

const AUDIT_ACTIONS = {
    AUTH: {
        LOGIN: 'auth.login',
        LOGOUT: 'auth.logout',
        LOGIN_FAILED: 'auth.login_failed',
        PASSWORD_CHANGE: 'auth.password_change',
        PASSWORD_RESET: 'auth.password_reset'
    },
    USER: {
        CREATE: 'user.create',
        UPDATE: 'user.update',
        DELETE: 'user.delete',
        ROLE_CHANGE: 'user.role_change',
        STATUS_CHANGE: 'user.status_change'
    },
    SCAN: {
        START: 'scan.start',
        COMPLETE: 'scan.complete',
        FAIL: 'scan.fail',
        DELETE: 'scan.delete',
        EXPORT: 'scan.export'
    },
    SUBSCRIPTION: {
        CREATE: 'subscription.create',
        UPGRADE: 'subscription.upgrade',
        DOWNGRADE: 'subscription.downgrade',
        CANCEL: 'subscription.cancel'
    },
    ADMIN: {
        USER_MANAGE: 'admin.user_manage',
        SYSTEM_CONFIG: 'admin.system_config',
        EXPORT_DATA: 'admin.export_data'
    },
    SECURITY: {
        MFA_ENABLE: 'security.mfa_enable',
        MFA_DISABLE: 'security.mfa_disable',
        SESSION_REVOKE: 'security.session_revoke',
        SUSPICIOUS_ACTIVITY: 'security.suspicious_activity'
    },
    PRIVACY: {
        CONSENT_GRANT: 'privacy.consent_grant',
        CONSENT_WITHDRAW: 'privacy.consent_withdraw',
        DATA_EXPORT: 'privacy.data_export',
        DATA_DELETE: 'privacy.data_delete'
    }
};

const RISK_LEVELS = {
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    CRITICAL: 'critical'
};

class AuditLogger {
    async log(action, details = {}) {
        const {
            userId = null,
            resourceType = null,
            resourceId = null,
            ipAddress = null,
            userAgent = null,
            status = 'success',
            riskLevel = RISK_LEVELS.LOW,
            metadata = null,
            sessionId = null
        } = details;

        const auditEntry = {
            id: uuidv4(),
            userId,
            action,
            resourceType,
            resourceId,
            ipAddress: this.hashIP(ipAddress),
            userAgent: userAgent?.substring(0, 500),
            status,
            riskLevel,
            metadata: metadata ? JSON.stringify(metadata) : null,
            sessionId,
            createdAt: new Date().toISOString()
        };

        try {
            await query(`
                INSERT INTO audit_logs 
                (id, user_id, action, resource_type, resource_id, ip_address, 
                 user_agent, status, risk_level, metadata, session_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, [
                auditEntry.id,
                auditEntry.userId,
                auditEntry.action,
                auditEntry.resourceType,
                auditEntry.resourceId,
                auditEntry.ipAddress,
                auditEntry.userAgent,
                auditEntry.status,
                auditEntry.riskLevel,
                auditEntry.metadata,
                auditEntry.sessionId,
                auditEntry.createdAt
            ]);
        } catch (error) {
            console.error('Audit log error:', error.message);
        }

        return auditEntry;
    }

    async logAuth(userId, action, details = {}) {
        return this.log(AUDIT_ACTIONS.AUTH[action], {
            userId,
            resourceType: 'session',
            ...details
        });
    }

    async logUserAction(adminUserId, targetUserId, action, details = {}) {
        return this.log(AUDIT_ACTIONS.USER[action], {
            userId: adminUserId,
            resourceType: 'user',
            resourceId: targetUserId,
            riskLevel: RISK_LEVELS.HIGH,
            ...details
        });
    }

    async logScan(userId, scanId, action, details = {}) {
        return this.log(AUDIT_ACTIONS.SCAN[action], {
            userId,
            resourceType: 'scan',
            resourceId: scanId,
            ...details
        });
    }

    async logSecurity(userId, action, details = {}) {
        return this.log(AUDIT_ACTIONS.SECURITY[action], {
            userId,
            resourceType: 'security',
            riskLevel: RISK_LEVELS.HIGH,
            ...details
        });
    }

    async logPrivacy(userId, action, details = {}) {
        return this.log(AUDIT_ACTIONS.PRIVACY[action], {
            userId,
            resourceType: 'privacy',
            riskLevel: RISK_LEVELS.MEDIUM,
            ...details
        });
    }

    async getAuditLogs(filters = {}) {
        const {
            userId,
            action,
            startDate,
            endDate,
            riskLevel,
            page = 1,
            limit = 50
        } = filters;

        let whereClause = '1=1';
        const params = [];

        if (userId) {
            whereClause += ' AND user_id = ?';
            params.push(userId);
        }
        if (action) {
            whereClause += ' AND action LIKE ?';
            params.push(`%${action}%`);
        }
        if (startDate) {
            whereClause += ' AND created_at >= ?';
            params.push(startDate);
        }
        if (endDate) {
            whereClause += ' AND created_at <= ?';
            params.push(endDate);
        }
        if (riskLevel) {
            whereClause += ' AND risk_level = ?';
            params.push(riskLevel);
        }

        const offset = (parseInt(page) - 1) * parseInt(limit);

        const [logs] = await query(`
            SELECT al.*, u.username, u.email
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            WHERE ${whereClause}
            ORDER BY al.created_at DESC
            LIMIT ? OFFSET ?
        `, [...params, parseInt(limit), offset]);

        const [countResult] = await query(`
            SELECT COUNT(*) as total FROM audit_logs WHERE ${whereClause}
        `, params);

        return {
            logs,
            total: countResult[0]?.total || 0,
            page: parseInt(page),
            totalPages: Math.ceil((countResult[0]?.total || 0) / parseInt(limit))
        };
    }

    async getUserActivity(userId, days = 30) {
        const [activities] = await query(`
            SELECT action, COUNT(*) as count, 
                   MAX(created_at) as last_occurrence
            FROM audit_logs
            WHERE user_id = ?
            AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
            GROUP BY action
            ORDER BY count DESC
        `, [userId, days]);

        const [recentActions] = await query(`
            SELECT * FROM audit_logs
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 20
        `, [userId]);

        return { activities, recentActions };
    }

    async getSecurityEvents(filters = {}) {
        const { severity, startDate, endDate, status } = filters;

        let whereClause = "action LIKE 'security.%' OR action LIKE 'auth.%'";
        const params = [];

        if (severity) {
            whereClause += ' AND risk_level = ?';
            params.push(severity);
        }
        if (status) {
            whereClause += ' AND status = ?';
            params.push(status);
        }
        if (startDate) {
            whereClause += ' AND created_at >= ?';
            params.push(startDate);
        }
        if (endDate) {
            whereClause += ' AND created_at <= ?';
            params.push(endDate);
        }

        const [events] = await query(`
            SELECT * FROM audit_logs
            WHERE ${whereClause}
            ORDER BY created_at DESC
            LIMIT 100
        `, params);

        return { events };
    }

    async getComplianceReport(startDate, endDate) {
        const [summary] = await query(`
            SELECT 
                action,
                COUNT(*) as total_count,
                SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success_count,
                SUM(CASE WHEN status = 'failure' THEN 1 ELSE 0 END) as failure_count,
                SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) as critical_count,
                SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high_count
            FROM audit_logs
            WHERE created_at BETWEEN ? AND ?
            GROUP BY action
            ORDER BY total_count DESC
        `, [startDate, endDate]);

        const [userStats] = await query(`
            SELECT 
                u.username,
                COUNT(*) as action_count,
                MAX(al.created_at) as last_activity
            FROM audit_logs al
            JOIN users u ON al.user_id = u.id
            WHERE al.created_at BETWEEN ? AND ?
            GROUP BY u.id, u.username
            ORDER BY action_count DESC
            LIMIT 20
        `, [startDate, endDate]);

        return { summary, userStats };
    }

    async searchLogs(searchTerm, filters = {}) {
        const { page = 1, limit = 50 } = filters;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const [logs] = await query(`
            SELECT al.*, u.username, u.email
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            WHERE al.action LIKE ? 
               OR al.metadata LIKE ?
               OR u.username LIKE ?
            ORDER BY al.created_at DESC
            LIMIT ? OFFSET ?
        `, [`%${searchTerm}%`, `%${searchTerm}%`, `%${searchTerm}%`, parseInt(limit), offset]);

        const [countResult] = await query(`
            SELECT COUNT(*) as total
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            WHERE al.action LIKE ? 
               OR al.metadata LIKE ?
               OR u.username LIKE ?
        `, [`%${searchTerm}%`, `%${searchTerm}%`, `%${searchTerm}%`]);

        return {
            logs,
            total: countResult[0]?.total || 0,
            page: parseInt(page),
            totalPages: Math.ceil((countResult[0]?.total || 0) / parseInt(limit))
        };
    }

    async getAnomalies() {
        const [failedLogins] = await query(`
            SELECT user_id, ip_address, COUNT(*) as attempts,
                   MAX(created_at) as last_attempt
            FROM audit_logs
            WHERE action = 'auth.login_failed'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY user_id, ip_address
            HAVING COUNT(*) > 3
        `);

        const [rapidActions] = await query(`
            SELECT user_id, action, COUNT(*) as count,
                   MIN(created_at) as first_action,
                   MAX(created_at) as last_action
            FROM audit_logs
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
            GROUP BY user_id, action
            HAVING COUNT(*) > 10
        `);

        const [newLocations] = await query(`
            SELECT al.user_id, al.ip_address, al.created_at
            FROM audit_logs al
            WHERE al.action = 'auth.login'
            AND al.created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY al.user_id, al.ip_address
            HAVING COUNT(*) = 1
        `);

        return {
            failedLogins,
            rapidActions,
            newLocations,
            timestamp: new Date().toISOString()
        };
    }

    hashIP(ip) {
        if (!ip) return null;
        const crypto = require('crypto');
        return crypto.createHash('sha256').update(ip).digest('hex').substring(0, 32);
    }
}

module.exports = {
    AuditLogger,
    AUDIT_ACTIONS,
    RISK_LEVELS
};
