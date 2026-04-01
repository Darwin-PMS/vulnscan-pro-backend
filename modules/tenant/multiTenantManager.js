/**
 * Multi-Tenant Architecture Module
 * Tenant isolation, row-level security, and namespace management
 * Supports both schema-level and row-level tenant isolation
 */

const { v4: uuidv4 } = require('uuid');
const { query } = require('../../database/db');

class MultiTenantManager {
    constructor() {
        this.isolationLevel = process.env.TENANT_ISOLATION || 'row_level';
    }

    async createTenant(name, plan = 'basic', settings = {}) {
        const tenantId = uuidv4();
        const namespace = this.generateNamespace(name);
        
        await query(
            `INSERT INTO tenants (id, name, namespace, plan, settings, created_at)
             VALUES (?, ?, ?, ?, ?, NOW())`,
            [tenantId, name, namespace, plan, JSON.stringify(settings)]
        );

        await this.createTenantResources(tenantId, plan);

        return {
            tenantId,
            name,
            namespace,
            plan,
            createdAt: new Date().toISOString()
        };
    }

    generateNamespace(name) {
        const base = name.toLowerCase().replace(/[^a-z0-9]/g, '-');
        const unique = Date.now().toString(36);
        return `${base}-${unique.substring(0, 8)}`;
    }

    async createTenantResources(tenantId, plan) {
        const resourceLimits = this.getResourceLimits(plan);
        
        await query(
            `INSERT INTO tenant_resources (tenant_id, resource_type, limit, current_usage)
             VALUES (?, ?, ?, ?)`,
            [tenantId, 'projects', resourceLimits.projects, 0]
        );
        await query(
            `INSERT INTO tenant_resources (tenant_id, resource_type, limit, current_usage)
             VALUES (?, ?, ?, ?)`,
            [tenantId, 'users', resourceLimits.users, 0]
        );
        await query(
            `INSERT INTO tenant_resources (tenant_id, resource_type, limit, current_usage)
             VALUES (?, ?, ?, ?)`,
            [tenantId, 'scans', resourceLimits.scans, 0]
        );
        await query(
            `INSERT INTO tenant_resources (tenant_id, resource_type, limit, current_usage)
             VALUES (?, ?, ?, ?)`,
            [tenantId, 'storage_mb', resourceLimits.storage, 0]
        );
    }

    getResourceLimits(plan) {
        const plans = {
            free: { projects: 1, users: 3, scans: 10, storage: 100 },
            basic: { projects: 5, users: 10, scans: 100, storage: 1000 },
            pro: { projects: 20, users: 50, scans: 500, storage: 5000 },
            enterprise: { projects: -1, users: -1, scans: -1, storage: -1 }
        };

        return plans[plan] || plans.basic;
    }

    async getTenant(tenantId) {
        const [tenants] = await query(
            'SELECT * FROM tenants WHERE id = ?',
            [tenantId]
        );

        if (!tenants || tenants.length === 0) {
            return null;
        }

        const [resources] = await query(
            'SELECT * FROM tenant_resources WHERE tenant_id = ?',
            [tenantId]
        );

        return {
            ...tenants[0],
            resources: resources.reduce((acc, r) => {
                acc[r.resource_type] = { limit: r.limit, usage: r.current_usage };
                return acc;
            }, {})
        };
    }

    async getTenantByNamespace(namespace) {
        const [tenants] = await query(
            'SELECT * FROM tenants WHERE namespace = ?',
            [namespace]
        );

        return tenants[0] || null;
    }

    middleware(forceTenantCheck = false) {
        return async (req, res, next) => {
            try {
                const userId = req.user?.userId;
                const tenantIdFromHeader = req.headers['x-tenant-id'];
                const tenantIdFromToken = req.user?.tenantId;

                if (!userId) {
                    return res.status(401).json({ error: 'Authentication required' });
                }

                let tenantId = tenantIdFromToken;

                if (forceTenantCheck && tenantIdFromHeader) {
                    if (tenantIdFromHeader !== tenantIdFromToken && req.user.role !== 'super_admin') {
                        return res.status(403).json({ error: 'Tenant access denied' });
                    }
                    tenantId = tenantIdFromHeader;
                }

                req.tenantId = tenantId;

                if (tenantId) {
                    const tenant = await this.getTenant(tenantId);
                    if (!tenant) {
                        return res.status(404).json({ error: 'Tenant not found' });
                    }
                    req.tenant = tenant;
                }

                next();
            } catch (error) {
                console.error('Tenant middleware error:', error);
                res.status(500).json({ error: 'Tenant validation failed' });
            }
        };
    }

    async checkResourceLimit(tenantId, resourceType) {
        const [resource] = await query(
            `SELECT * FROM tenant_resources 
             WHERE tenant_id = ? AND resource_type = ?`,
            [tenantId, resourceType]
        );

        if (!resource || !resource[0]) {
            return { allowed: true };
        }

        const { limit, current_usage } = resource[0];
        
        if (limit === -1) {
            return { allowed: true };
        }

        return {
            allowed: current_usage < limit,
            limit,
            usage: current_usage,
            remaining: limit - current_usage
        };
    }

    async incrementResource(tenantId, resourceType, amount = 1) {
        await query(
            `UPDATE tenant_resources 
             SET current_usage = current_usage + ?
             WHERE tenant_id = ? AND resource_type = ?`,
            [amount, tenantId, resourceType]
        );
    }

    async decrementResource(tenantId, resourceType, amount = 1) {
        await query(
            `UPDATE tenant_resources 
             SET current_usage = GREATEST(0, current_usage - ?)
             WHERE tenant_id = ? AND resource_type = ?`,
            [amount, tenantId, resourceType]
        );
    }

    async updateTenantSettings(tenantId, settings) {
        const [tenant] = await query(
            'SELECT settings FROM tenants WHERE id = ?',
            [tenantId]
        );

        if (!tenant || !tenant[0]) {
            throw new Error('Tenant not found');
        }

        const currentSettings = JSON.parse(tenant[0].settings || '{}');
        const updatedSettings = { ...currentSettings, ...settings };

        await query(
            'UPDATE tenants SET settings = ? WHERE id = ?',
            [JSON.stringify(updatedSettings), tenantId]
        );

        return updatedSettings;
    }

    async getTenantUsers(tenantId) {
        const [users] = await query(
            `SELECT u.id, u.username, u.email, u.role, u.is_active, u.created_at
             FROM users u
             JOIN user_tenants ut ON u.id = ut.user_id
             WHERE ut.tenant_id = ?`,
            [tenantId]
        );

        return users;
    }

    async addUserToTenant(userId, tenantId, role = 'user') {
        await query(
            `INSERT INTO user_tenants (id, user_id, tenant_id, role, joined_at)
             VALUES (?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE role = ?`,
            [uuidv4(), userId, tenantId, role, role]
        );
    }

    async removeUserFromTenant(userId, tenantId) {
        await query(
            'UPDATE user_tenants SET role = ?, removed_at = NOW() WHERE user_id = ? AND tenant_id = ?',
            ['removed', userId, tenantId]
        );
    }

    async getTenantProjects(tenantId) {
        const [projects] = await query(
            `SELECT * FROM projects WHERE tenant_id = ?`,
            [tenantId]
        );

        return projects;
    }

    async getTenantScans(tenantId, filters = {}) {
        let sql = `
            SELECT s.* FROM scans s
            JOIN projects p ON s.project_id = p.id
            WHERE p.tenant_id = ?
        `;
        const params = [tenantId];

        if (filters.status) {
            sql += ' AND s.status = ?';
            params.push(filters.status);
        }

        if (filters.fromDate) {
            sql += ' AND s.created_at >= ?';
            params.push(filters.fromDate);
        }

        sql += ' ORDER BY s.created_at DESC LIMIT ?';
        params.push(filters.limit || 50);

        const [scans] = await query(sql, params);
        return scans;
    }

    async getTenantStats(tenantId) {
        const [projectCount] = await query(
            'SELECT COUNT(*) as count FROM projects WHERE tenant_id = ?',
            [tenantId]
        );

        const [userCount] = await query(
            'SELECT COUNT(*) as count FROM user_tenants WHERE tenant_id = ?',
            [tenantId]
        );

        const [scanCount] = await query(
            `SELECT COUNT(*) as count FROM scans s
             JOIN projects p ON s.project_id = p.id
             WHERE p.tenant_id = ?`,
            [tenantId]
        );

        const [vulnCount] = await query(
            `SELECT COUNT(*) as count FROM vulnerabilities v
             JOIN scans s ON v.scan_id = s.scan_id
             JOIN projects p ON s.project_id = p.id
             WHERE p.tenant_id = ?`,
            [tenantId]
        );

        return {
            projects: projectCount[0]?.count || 0,
            users: userCount[0]?.count || 0,
            scans: scanCount[0]?.count || 0,
            vulnerabilities: vulnCount[0]?.count || 0
        };
    }

    buildTenantWhereClause(tableAlias = '') {
        const prefix = tableAlias ? `${tableAlias}.` : '';
        return `${prefix}tenant_id = ?`;
    }

    getTenantFilterParams(tenantId) {
        return [tenantId];
    }
}

module.exports = { MultiTenantManager };