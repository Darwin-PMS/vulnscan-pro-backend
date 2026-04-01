/**
 * Enterprise API Routes
 * NIST CSF, Compliance, Audit, MFA, RBAC
 */

const express = require('express');
const router = express.Router();
const { authenticateToken, optionalAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');

// Import modules
const { NISTFramework } = require('../modules/nist/nistFramework');
const { AIGovernance } = require('../modules/ai_governance/aiGovernance');
const { PrivacyEngineering } = require('../modules/privacy/privacyEngineering');
const { ZeroTrustIAM } = require('../modules/zero_trust/zeroTrustIAM');
const { AuditLogger, AUDIT_ACTIONS } = require('../modules/audit/auditLogger');
const { RBACModule, ROLES, PERMISSIONS } = require('../modules/rbac/rbacModule');

const nistFramework = new NISTFramework();
const aiGovernance = new AIGovernance();
const privacyEngineering = new PrivacyEngineering();
const zeroTrustIAM = new ZeroTrustIAM();
const auditLogger = new AuditLogger();
const rbacModule = new RBACModule();

// ============================================
// NIST CSF COMPLIANCE ROUTES
// ============================================

router.get('/nist/compliance', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const dashboard = await nistFramework.getComplianceDashboard();
        res.json(dashboard);
    } catch (error) {
        console.error('NIST compliance error:', error);
        res.status(500).json({ error: 'Failed to get compliance data' });
    }
});

router.get('/nist/identify', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const assetMap = await nistFramework.generateAssetMap();
        res.json(assetMap);
    } catch (error) {
        console.error('NIST identify error:', error);
        res.status(500).json({ error: 'Failed to identify assets' });
    }
});

router.get('/nist/protect', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const accessControl = await nistFramework.getAccessControlStatus();
        const dataProtection = await nistFramework.getDataProtectionStatus();
        res.json({ accessControl, dataProtection });
    } catch (error) {
        console.error('NIST protect error:', error);
        res.status(500).json({ error: 'Failed to get protection status' });
    }
});

router.get('/nist/detect', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.query;
        const anomalies = await nistFramework.detectAnomalies(userId);
        res.json(anomalies);
    } catch (error) {
        console.error('NIST detect error:', error);
        res.status(500).json({ error: 'Failed to detect anomalies' });
    }
});

router.get('/nist/risk-register', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const riskRegister = await nistFramework.generateRiskRegister();
        res.json(riskRegister);
    } catch (error) {
        console.error('Risk register error:', error);
        res.status(500).json({ error: 'Failed to generate risk register' });
    }
});

// ============================================
// INCIDENT MANAGEMENT ROUTES
// ============================================

router.post('/incidents', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { type, severity, userId, description } = req.body;
        
        const incident = await nistFramework.createIncidentTicket({
            type,
            severity,
            userId,
            description,
            source: 'api'
        });

        await auditLogger.log(AUDIT_ACTIONS.ADMIN.USER_MANAGE, {
            userId: req.user.userId,
            resourceType: 'incident',
            resourceId: incident.id,
            metadata: { type, severity }
        });

        res.status(201).json(incident);
    } catch (error) {
        console.error('Create incident error:', error);
        res.status(500).json({ error: 'Failed to create incident' });
    }
});

router.get('/incidents', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status, severity, page = 1, limit = 20 } = req.query;
        
        const [incidents] = await require('../database/db').query(`
            SELECT * FROM incident_tickets
            WHERE 1=1
            ${status ? ' AND status = ?' : ''}
            ${severity ? ' AND severity = ?' : ''}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        `, [
            ...(status ? [status] : []),
            ...(severity ? [severity] : []),
            parseInt(limit),
            (parseInt(page) - 1) * parseInt(limit)
        ]);

        res.json({ incidents });
    } catch (error) {
        console.error('Get incidents error:', error);
        res.status(500).json({ error: 'Failed to get incidents' });
    }
});

router.put('/incidents/:ticketId/escalate', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { ticketId } = req.params;
        const { level, reason } = req.body;

        const escalation = await nistFramework.escalateIncident(ticketId, level, reason);
        res.json(escalation);
    } catch (error) {
        console.error('Escalate incident error:', error);
        res.status(500).json({ error: 'Failed to escalate incident' });
    }
});

// ============================================
// AUDIT LOGGING ROUTES
// ============================================

router.get('/audit/logs', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId, action, startDate, endDate, riskLevel, page, limit } = req.query;
        
        const logs = await auditLogger.getAuditLogs({
            userId, action, startDate, endDate, riskLevel, page, limit
        });

        res.json(logs);
    } catch (error) {
        console.error('Get audit logs error:', error);
        res.status(500).json({ error: 'Failed to get audit logs' });
    }
});

router.get('/audit/search', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { q, page, limit } = req.query;
        
        const results = await auditLogger.searchLogs(q, { page, limit });
        res.json(results);
    } catch (error) {
        console.error('Search audit logs error:', error);
        res.status(500).json({ error: 'Failed to search audit logs' });
    }
});

router.get('/audit/security-events', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { severity, startDate, endDate, status } = req.query;
        
        const events = await auditLogger.getSecurityEvents({ severity, startDate, endDate, status });
        res.json(events);
    } catch (error) {
        console.error('Get security events error:', error);
        res.status(500).json({ error: 'Failed to get security events' });
    }
});

router.get('/audit/anomalies', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const anomalies = await auditLogger.getAnomalies();
        res.json(anomalies);
    } catch (error) {
        console.error('Get anomalies error:', error);
        res.status(500).json({ error: 'Failed to get anomalies' });
    }
});

router.get('/audit/compliance-report', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        
        const report = await auditLogger.getComplianceReport(
            startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
            endDate || new Date()
        );
        
        res.json(report);
    } catch (error) {
        console.error('Get compliance report error:', error);
        res.status(500).json({ error: 'Failed to get compliance report' });
    }
});

// ============================================
// MFA ROUTES
// ============================================

router.post('/mfa/setup', authenticateToken, async (req, res) => {
    try {
        const { method = 'totp' } = req.body;
        const userId = req.user.userId;

        const mfa = require('../modules/mfa/mfaModule');
        const result = await mfa.setupMFA(userId, method);

        await auditLogger.logSecurity(userId, 'MFA_ENABLE', {
            metadata: { method }
        });

        res.json(result);
    } catch (error) {
        console.error('MFA setup error:', error);
        res.status(500).json({ error: 'Failed to setup MFA' });
    }
});

router.post('/mfa/verify', authenticateToken, async (req, res) => {
    try {
        const { code } = req.body;
        const userId = req.user.userId;

        const mfa = require('../modules/mfa/mfaModule');
        const result = await mfa.verifyTOTP(
            (await require('../database/db').query(
                'SELECT secret FROM mfa_configurations WHERE user_id = ? AND is_active = FALSE',
                [userId]
            ))[0]?.[0]?.secret,
            code
        );

        if (result.valid) {
            await mfa.completeMFAEnable(userId, code);
        }

        res.json(result);
    } catch (error) {
        console.error('MFA verify error:', error);
        res.status(500).json({ error: 'Failed to verify MFA' });
    }
});

router.get('/mfa/status', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const mfa = require('../modules/mfa/mfaModule');
        const status = await mfa.getMFAStatus(userId);
        res.json(status);
    } catch (error) {
        console.error('MFA status error:', error);
        res.status(500).json({ error: 'Failed to get MFA status' });
    }
});

router.delete('/mfa/disable', authenticateToken, async (req, res) => {
    try {
        const { code } = req.body;
        const userId = req.user.userId;

        const mfa = require('../modules/mfa/mfaModule');
        const result = await mfa.disableMFA(userId, code);

        if (result.success) {
            await auditLogger.logSecurity(userId, 'MFA_DISABLE');
        }

        res.json(result);
    } catch (error) {
        console.error('MFA disable error:', error);
        res.status(500).json({ error: 'Failed to disable MFA' });
    }
});

// ============================================
// RBAC ROUTES
// ============================================

router.get('/rbac/permissions', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const permissions = await rbacModule.getUserPermissions(userId);
        res.json(permissions);
    } catch (error) {
        console.error('Get permissions error:', error);
        res.status(500).json({ error: 'Failed to get permissions' });
    }
});

router.get('/rbac/roles', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const roles = await rbacModule.getAllRoles();
        res.json({ roles });
    } catch (error) {
        console.error('Get roles error:', error);
        res.status(500).json({ error: 'Failed to get roles' });
    }
});

router.put('/rbac/users/:userId/role', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { role } = req.body;

        const result = await rbacModule.assignRole(userId, role, req.user.userId);

        await auditLogger.logUserAction(req.user.userId, userId, 'ROLE_CHANGE', {
            metadata: { oldRole: result.oldRole, newRole: role }
        });

        res.json(result);
    } catch (error) {
        console.error('Assign role error:', error);
        res.status(500).json({ error: error.message || 'Failed to assign role' });
    }
});

router.get('/rbac/audit', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId, startDate, endDate } = req.query;
        const changes = await rbacModule.auditPermissionChanges(userId, { startDate, endDate });
        res.json(changes);
    } catch (error) {
        console.error('Audit permission changes error:', error);
        res.status(500).json({ error: 'Failed to audit permission changes' });
    }
});

// ============================================
// PRIVACY ROUTES
// ============================================

router.get('/privacy/consents', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const consents = await privacyEngineering.getUserConsents(userId);
        res.json(consents);
    } catch (error) {
        console.error('Get consents error:', error);
        res.status(500).json({ error: 'Failed to get consents' });
    }
});

router.post('/privacy/consent', authenticateToken, async (req, res) => {
    try {
        const { type, purpose, granted } = req.body;
        const userId = req.user.userId;

        const consent = await privacyEngineering.createConsentRecord(userId, {
            type,
            purpose,
            granted,
            ipAddress: req.ip
        });

        await auditLogger.logPrivacy(userId, granted ? 'CONSENT_GRANT' : 'CONSENT_WITHDRAW', {
            metadata: { type }
        });

        res.json(consent);
    } catch (error) {
        console.error('Create consent error:', error);
        res.status(500).json({ error: 'Failed to create consent' });
    }
});

router.delete('/privacy/consent/:type', authenticateToken, async (req, res) => {
    try {
        const { type } = req.params;
        const userId = req.user.userId;

        const result = await privacyEngineering.withdrawConsent(userId, type);
        res.json(result);
    } catch (error) {
        console.error('Withdraw consent error:', error);
        res.status(500).json({ error: 'Failed to withdraw consent' });
    }
});

router.post('/privacy/export', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const exportData = await privacyEngineering.processDataExport(userId);

        await auditLogger.logPrivacy(userId, 'DATA_EXPORT');

        res.json(exportData);
    } catch (error) {
        console.error('Data export error:', error);
        res.status(500).json({ error: 'Failed to export data' });
    }
});

router.post('/privacy/delete', authenticateToken, async (req, res) => {
    try {
        const { softDelete = true, anonymize = true } = req.body;
        const userId = req.user.userId;

        const result = await privacyEngineering.processDataDeletion(userId, {
            softDelete,
            anonymize
        });

        await auditLogger.logPrivacy(userId, 'DATA_DELETE', {
            metadata: { softDelete, anonymize }
        });

        res.json(result);
    } catch (error) {
        console.error('Data delete error:', error);
        res.status(500).json({ error: 'Failed to delete data' });
    }
});

// ============================================
// ZERO TRUST ROUTES
// ============================================

router.post('/zero-trust/session-trust', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { deviceFingerprint, ipAddress, geoLocation } = req.body;

        const trustScore = await zeroTrustIAM.calculateSessionTrust(userId, {
            deviceFingerprint,
            ipAddress,
            geoLocation
        });

        res.json(trustScore);
    } catch (error) {
        console.error('Session trust error:', error);
        res.status(500).json({ error: 'Failed to calculate trust score' });
    }
});

router.post('/zero-trust/device', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const deviceInfo = req.body;

        const result = await zeroTrustIAM.registerTrustedDevice(userId, {
            ...deviceInfo,
            ipAddress: req.ip
        });

        res.json(result);
    } catch (error) {
        console.error('Register device error:', error);
        res.status(500).json({ error: 'Failed to register device' });
    }
});

// ============================================
// AI GOVERNANCE ROUTES
// ============================================

router.post('/ai/validate', authenticateToken, async (req, res) => {
    try {
        const { prompt } = req.body;
        
        const validation = aiGovernance.validatePrompt(prompt);
        
        res.json(validation);
    } catch (error) {
        console.error('AI validate error:', error);
        res.status(500).json({ error: 'Failed to validate prompt' });
    }
});

router.post('/ai/trust-score', authenticateToken, async (req, res) => {
    try {
        const { response, context } = req.body;
        
        const trustScore = aiGovernance.calculateTrustScore(response, context);
        
        res.json(trustScore);
    } catch (error) {
        console.error('AI trust score error:', error);
        res.status(500).json({ error: 'Failed to calculate trust score' });
    }
});

router.get('/ai/usage-analytics', authenticateToken, async (req, res) => {
    try {
        const { range = '7d' } = req.query;
        const userId = req.user.userId;

        const analytics = await aiGovernance.getAIUsageAnalytics(range);
        
        res.json(analytics);
    } catch (error) {
        console.error('AI analytics error:', error);
        res.status(500).json({ error: 'Failed to get AI analytics' });
    }
});

// ============================================
// ENTERPRISE STATS ROUTE
// ============================================

router.get('/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { query } = require('../database/db');
        
        const [userStats] = await query(`
            SELECT 
                COUNT(*) as total_users,
                SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_users,
                SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admins
            FROM users
        `);

        const [scanStats] = await query(`
            SELECT 
                COUNT(*) as total_scans,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_scans,
                SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running_scans
            FROM scans
        `);

        const [vulnStats] = await query(`
            SELECT 
                COUNT(*) as total_vulns,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
            FROM vulnerabilities
        `);

        const [incidentStats] = await query(`
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_incidents,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_incidents
            FROM incident_tickets
        `);

        const nistCompliance = await nistFramework.getComplianceDashboard();

        res.json({
            users: userStats[0],
            scans: scanStats[0],
            vulnerabilities: vulnStats[0],
            incidents: incidentStats[0],
            securityScore: nistCompliance.overallScore,
            nistScores: nistCompliance.nistCompliance,
            threatsBlocked: 0,
            lastUpdated: new Date().toISOString()
        });
    } catch (error) {
        console.error('Enterprise stats error:', error);
        res.status(500).json({ error: 'Failed to get enterprise stats' });
    }
});

router.get('/alerts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { query } = require('../database/db');
        
        const [alerts] = await query(`
            SELECT * FROM security_events 
            WHERE status = 'new'
            ORDER BY created_at DESC
            LIMIT 10
        `);

        res.json({ alerts });
    } catch (error) {
        console.error('Get alerts error:', error);
        res.status(500).json({ error: 'Failed to get alerts' });
    }
});

module.exports = router;
