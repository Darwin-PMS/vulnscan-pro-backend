/**
 * Enhanced RBAC Module
 * 4-Tier Role System with Project Ownership
 * Enterprise-grade permissions for VulnScan Pro
 */

const { v4: uuidv4 } = require('uuid');
const { query } = require('../../database/db');

const ROLES = {
    SUPER_ADMIN: 'super_admin',
    ADMIN: 'admin',
    APP_SUPERVISOR: 'app_supervisor',
    USER: 'user'
};

const ROLE_LEVELS = {
    [ROLES.SUPER_ADMIN]: 1,
    [ROLES.ADMIN]: 2,
    [ROLES.APP_SUPERVISOR]: 3,
    [ROLES.USER]: 4
};

const PERMISSION_CATEGORIES = {
    SCAN: 'scan',
    VULNERABILITY: 'vuln',
    ASSET: 'asset',
    USER: 'user',
    ROLE: 'role',
    COMPLIANCE: 'compliance',
    AUDIT: 'audit',
    REPORT: 'report',
    INTEGRATION: 'integration',
    BILLING: 'billing',
    ADMIN: 'admin',
    PROJECT: 'project'
};

const PERMISSIONS = {
    // Scan Permissions
    'scan:create': { category: PERMISSION_CATEGORIES.SCAN, description: 'Start new scans' },
    'scan:read': { category: PERMISSION_CATEGORIES.SCAN, description: 'View scan results' },
    'scan:read_all': { category: PERMISSION_CATEGORIES.SCAN, description: 'View all tenant scans' },
    'scan:update': { category: PERMISSION_CATEGORIES.SCAN, description: 'Modify scan configurations' },
    'scan:delete': { category: PERMISSION_CATEGORIES.SCAN, description: 'Delete scans' },
    'scan:export': { category: PERMISSION_CATEGORIES.SCAN, description: 'Export scan reports' },
    'scan:schedule': { category: PERMISSION_CATEGORIES.SCAN, description: 'Create scheduled scans' },
    'scan:cancel': { category: PERMISSION_CATEGORIES.SCAN, description: 'Cancel running scans' },
    'scan:priority': { category: PERMISSION_CATEGORIES.SCAN, description: 'Set scan priority' },

    // Vulnerability Permissions
    'vuln:read': { category: PERMISSION_CATEGORIES.VULNERABILITY, description: 'View vulnerabilities' },
    'vuln:read_all': { category: PERMISSION_CATEGORIES.VULNERABILITY, description: 'View all project vulnerabilities' },
    'vuln:update': { category: PERMISSION_CATEGORIES.VULNERABILITY, description: 'Update vulnerability status' },
    'vuln:assign': { category: PERMISSION_CATEGORIES.VULNERABILITY, description: 'Assign vulnerabilities' },
    'vuln:verify': { category: PERMISSION_CATEGORIES.VULNERABILITY, description: 'Verify fixes' },
    'vuln:false_positive': { category: PERMISSION_CATEGORIES.VULNERABILITY, description: 'Mark as false positive' },
    'vuln:risk_accept': { category: PERMISSION_CATEGORIES.VULNERABILITY, description: 'Accept risk' },
    'vuln:bulk_update': { category: PERMISSION_CATEGORIES.VULNERABILITY, description: 'Bulk update vulnerabilities' },
    'vuln:comment': { category: PERMISSION_CATEGORIES.VULNERABILITY, description: 'Add comments' },

    // Asset Permissions
    'asset:create': { category: PERMISSION_CATEGORIES.ASSET, description: 'Create new assets' },
    'asset:read': { category: PERMISSION_CATEGORIES.ASSET, description: 'View assets' },
    'asset:read_all': { category: PERMISSION_CATEGORIES.ASSET, description: 'View all tenant assets' },
    'asset:update': { category: PERMISSION_CATEGORIES.ASSET, description: 'Update assets' },
    'asset:delete': { category: PERMISSION_CATEGORIES.ASSET, description: 'Delete assets' },
    'asset:tag': { category: PERMISSION_CATEGORIES.ASSET, description: 'Tag assets' },

    // User Management
    'user:create': { category: PERMISSION_CATEGORIES.USER, description: 'Create new users' },
    'user:read': { category: PERMISSION_CATEGORIES.USER, description: 'View user profiles' },
    'user:read_all': { category: PERMISSION_CATEGORIES.USER, description: 'View all users' },
    'user:update': { category: PERMISSION_CATEGORIES.USER, description: 'Update user information' },
    'user:delete': { category: PERMISSION_CATEGORIES.USER, description: 'Delete users' },
    'user:suspend': { category: PERMISSION_CATEGORIES.USER, description: 'Suspend users' },
    'user:invite': { category: PERMISSION_CATEGORIES.USER, description: 'Invite new users' },

    // Role Management
    'role:read': { category: PERMISSION_CATEGORIES.ROLE, description: 'View roles' },
    'role:assign': { category: PERMISSION_CATEGORIES.ROLE, description: 'Assign roles' },
    'role:create': { category: PERMISSION_CATEGORIES.ROLE, description: 'Create custom roles' },
    'role:delete': { category: PERMISSION_CATEGORIES.ROLE, description: 'Delete custom roles' },

    // Compliance
    'compliance:read': { category: PERMISSION_CATEGORIES.COMPLIANCE, description: 'View compliance reports' },
    'compliance:generate': { category: PERMISSION_CATEGORIES.COMPLIANCE, description: 'Generate reports' },
    'compliance:export': { category: PERMISSION_CATEGORIES.COMPLIANCE, description: 'Export compliance data' },
    'compliance:controls': { category: PERMISSION_CATEGORIES.COMPLIANCE, description: 'Manage controls' },

    // Audit
    'audit:read': { category: PERMISSION_CATEGORIES.AUDIT, description: 'View audit logs' },
    'audit:export': { category: PERMISSION_CATEGORIES.AUDIT, description: 'Export audit logs' },
    'audit:search': { category: PERMISSION_CATEGORIES.AUDIT, description: 'Search audit logs' },

    // Reports
    'report:generate': { category: PERMISSION_CATEGORIES.REPORT, description: 'Generate reports' },
    'report:export': { category: PERMISSION_CATEGORIES.REPORT, description: 'Export reports' },
    'report:schedule': { category: PERMISSION_CATEGORIES.REPORT, description: 'Schedule reports' },

    // Integrations
    'integration:create': { category: PERMISSION_CATEGORIES.INTEGRATION, description: 'Create integrations' },
    'integration:read': { category: PERMISSION_CATEGORIES.INTEGRATION, description: 'View integrations' },
    'integration:update': { category: PERMISSION_CATEGORIES.INTEGRATION, description: 'Update integrations' },
    'integration:delete': { category: PERMISSION_CATEGORIES.INTEGRATION, description: 'Delete integrations' },
    'integration:webhook': { category: PERMISSION_CATEGORIES.INTEGRATION, description: 'Manage webhooks' },

    // Billing (Admin only)
    'billing:read': { category: PERMISSION_CATEGORIES.BILLING, description: 'View billing' },
    'billing:update': { category: PERMISSION_CATEGORIES.BILLING, description: 'Update billing' },

    // Project Management
    'project:create': { category: PERMISSION_CATEGORIES.PROJECT, description: 'Create projects' },
    'project:read': { category: PERMISSION_CATEGORIES.PROJECT, description: 'View projects' },
    'project:read_all': { category: PERMISSION_CATEGORIES.PROJECT, description: 'View all projects' },
    'project:update': { category: PERMISSION_CATEGORIES.PROJECT, description: 'Update projects' },
    'project:delete': { category: PERMISSION_CATEGORIES.PROJECT, description: 'Delete projects' },
    'project:member': { category: PERMISSION_CATEGORIES.PROJECT, description: 'Manage project members' },

    // Admin Functions
    'admin:settings': { category: PERMISSION_CATEGORIES.ADMIN, description: 'System settings' },
    'admin:system': { category: PERMISSION_CATEGORIES.ADMIN, description: 'System configuration' },
    'admin:api_keys': { category: PERMISSION_CATEGORIES.ADMIN, description: 'Manage API keys' },
    'admin:ip_whitelist': { category: PERMISSION_CATEGORIES.ADMIN, description: 'IP allowlisting' }
};

const ROLE_PERMISSIONS = {
    [ROLES.SUPER_ADMIN]: Object.keys(PERMISSIONS),
    
    [ROLES.ADMIN]: [
        'scan:create', 'scan:read', 'scan:read_all', 'scan:update', 'scan:delete', 'scan:export', 'scan:schedule', 'scan:cancel',
        'vuln:read', 'vuln:read_all', 'vuln:update', 'vuln:assign', 'vuln:verify', 'vuln:false_positive', 'vuln:risk_accept', 'vuln:bulk_update', 'vuln:comment',
        'asset:create', 'asset:read', 'asset:read_all', 'asset:update', 'asset:delete', 'asset:tag',
        'user:create', 'user:read', 'user:read_all', 'user:update', 'user:delete', 'user:suspend', 'user:invite',
        'role:read', 'role:assign',
        'compliance:read', 'compliance:generate', 'compliance:export', 'compliance:controls',
        'audit:read', 'audit:export', 'audit:search',
        'report:generate', 'report:export', 'report:schedule',
        'integration:create', 'integration:read', 'integration:update', 'integration:delete', 'integration:webhook',
        'billing:read', 'billing:update',
        'project:create', 'project:read', 'project:read_all', 'project:update', 'project:delete', 'project:member'
    ],
    
    [ROLES.APP_SUPERVISOR]: [
        'scan:create', 'scan:read', 'scan:update', 'scan:export', 'scan:schedule', 'scan:cancel',
        'vuln:read', 'vuln:read_all', 'vuln:update', 'vuln:assign', 'vuln:verify', 'vuln:false_positive', 'vuln:risk_accept', 'vuln:comment',
        'asset:create', 'asset:read', 'asset:update', 'asset:tag',
        'user:read',
        'compliance:read',
        'audit:read',
        'report:generate', 'report:export',
        'integration:read',
        'project:read', 'project:read_all', 'project:update', 'project:member'
    ],
    
    [ROLES.USER]: [
        'scan:create', 'scan:read', 'scan:export',
        'vuln:read', 'vuln:update', 'vuln:comment',
        'asset:create', 'asset:read', 'asset:update',
        'user:read',
        'compliance:read',
        'report:generate',
        'integration:read',
        'project:read'
    ]
};

class EnterpriseRBAC {
    async hasPermission(userId, permission, projectId = null) {
        const [user] = await query(
            `SELECT u.role, p.owner_id as project_owner 
             FROM users u 
             LEFT JOIN projects p ON p.id = ? 
             WHERE u.id = ? AND u.is_active = TRUE`,
            [projectId, userId]
        );

        if (!user) return false;

        const rolePermissions = ROLE_PERMISSIONS[user.role] || [];
        
        if (rolePermissions.includes(permission)) {
            if (projectId && user.role === ROLES.USER) {
                const [member] = await query(
                    'SELECT * FROM project_members WHERE user_id = ? AND project_id = ?',
                    [userId, projectId]
                );
                return member.length > 0;
            }
            return true;
        }
        
        return false;
    }

    async hasAnyPermission(userId, permissions, projectId = null) {
        for (const permission of permissions) {
            if (await this.hasPermission(userId, permission, projectId)) {
                return true;
            }
        }
        return false;
    }

    async hasAllPermissions(userId, permissions, projectId = null) {
        for (const permission of permissions) {
            if (!await this.hasPermission(userId, permission, projectId)) {
                return false;
            }
        }
        return true;
    }

    async getUserPermissions(userId) {
        const [user] = await query('SELECT role FROM users WHERE id = ?', [userId]);
        if (!user) return { role: null, permissions: [] };

        const permissions = ROLE_PERMISSIONS[user.role] || [];

        return {
            role: user.role,
            roleLevel: ROLE_LEVELS[user.role],
            permissions: permissions.map(p => ({
                key: p,
                ...PERMISSIONS[p]
            }))
        };
    }

    async getUserProjects(userId) {
        const [user] = await query('SELECT role FROM users WHERE id = ?', [userId]);
        
        if (!user) return [];
        
        let projects;
        
        if (user.role === ROLES.SUPER_ADMIN || user.role === ROLES.ADMIN) {
            [projects] = await query(
                `SELECT p.*, t.name as tenant_name 
                 FROM projects p 
                 LEFT JOIN tenants t ON p.tenant_id = t.id`
            );
        } else if (user.role === ROLES.APP_SUPERVISOR) {
            [projects] = await query(
                `SELECT p.* FROM projects p 
                 WHERE p.owner_id = ? OR p.id IN (
                     SELECT project_id FROM project_members WHERE user_id = ?
                 )`,
                [userId, userId]
            );
        } else {
            [projects] = await query(
                `SELECT p.* FROM projects p 
                 WHERE p.id IN (
                     SELECT project_id FROM project_members WHERE user_id = ?
                 )`,
                [userId]
            );
        }
        
        return projects;
    }

    async assignRole(userId, newRole, assignedBy, tenantId = null) {
        if (!ROLE_PERMISSIONS[newRole]) {
            throw new Error('Invalid role');
        }

        const [user] = await query('SELECT role FROM users WHERE id = ?', [userId]);
        if (!user) throw new Error('User not found');

        const oldRole = user.role;

        await query(
            'UPDATE users SET role = ? WHERE id = ?',
            [newRole, userId]
        );

        await query(
            `INSERT INTO permission_changes 
             (id, user_id, old_role, new_role, changed_by, tenant_id, changed_at)
             VALUES (?, ?, ?, ?, ?, ?, NOW())`,
            [uuidv4(), userId, oldRole, newRole, assignedBy, tenantId]
        );

        return { oldRole, newRole };
    }

    async createProject(name, description, userId, tenantId = null) {
        const projectId = uuidv4();
        
        await query(
            `INSERT INTO projects (id, name, description, owner_id, tenant_id, created_at)
             VALUES (?, ?, ?, ?, ?, NOW())`,
            [projectId, name, description, userId, tenantId]
        );

        await query(
            `INSERT INTO project_members (id, project_id, user_id, role, joined_at)
             VALUES (?, ?, ?, 'owner', NOW())`,
            [uuidv4(), projectId, userId]
        );

        return { projectId, name };
    }

    async addProjectMember(projectId, userId, role, addedBy) {
        const [existing] = await query(
            'SELECT * FROM project_members WHERE project_id = ? AND user_id = ?',
            [projectId, userId]
        );

        if (existing.length > 0) {
            await query(
                'UPDATE project_members SET role = ? WHERE project_id = ? AND user_id = ?',
                [role, projectId, userId]
            );
        } else {
            await query(
                `INSERT INTO project_members (id, project_id, user_id, role, joined_at)
                 VALUES (?, ?, ?, ?, NOW())`,
                [uuidv4(), projectId, userId, role]
            );
        }

        return { projectId, userId, role };
    }

    async getProjectMembers(projectId) {
        const [members] = await query(
            `SELECT pm.*, u.username, u.email, u.role as user_role
             FROM project_members pm
             JOIN users u ON pm.user_id = u.id
             WHERE pm.project_id = ?`,
            [projectId]
        );
        return members;
    }

    async getRoleHierarchy() {
        return {
            levels: Object.entries(ROLE_LEVELS).map(([role, level]) => ({
                level,
                role,
                title: role.replace('_', ' ').toUpperCase(),
                permissionCount: ROLE_PERMISSIONS[role].length
            })).sort((a, b) => a.level - b.level)
        };
    }

    middleware(permission, projectOptional = false) {
        return async (req, res, next) => {
            try {
                const userId = req.user?.userId;
                const projectId = req.params.projectId || req.body.projectId || req.query.projectId;

                if (!userId) {
                    return res.status(401).json({ error: 'Authentication required' });
                }

                const hasPermission = await this.hasPermission(userId, permission, projectId);
                
                if (!hasPermission) {
                    return res.status(403).json({
                        error: 'Access denied',
                        requiredPermission: permission
                    });
                }

                next();
            } catch (error) {
                console.error('RBAC middleware error:', error);
                res.status(500).json({ error: 'Authorization check failed' });
            }
        };
    }

    checkPermissionMiddleware(requiredPermissions, requireAll = false) {
        return async (req, res, next) => {
            try {
                const userId = req.user?.userId;
                const projectId = req.params.projectId || req.body.projectId;

                if (!userId) {
                    return res.status(401).json({ error: 'Authentication required' });
                }

                let hasPermission;
                if (requireAll) {
                    hasPermission = await this.hasAllPermissions(userId, requiredPermissions, projectId);
                } else {
                    hasPermission = await this.hasAnyPermission(userId, requiredPermissions, projectId);
                }
                
                if (!hasPermission) {
                    return res.status(403).json({
                        error: 'Access denied',
                        requiredPermissions
                    });
                }

                next();
            } catch (error) {
                console.error('RBAC middleware error:', error);
                res.status(500).json({ error: 'Authorization check failed' });
            }
        };
    }
}

module.exports = {
    EnterpriseRBAC,
    ROLES,
    ROLE_LEVELS,
    PERMISSIONS,
    PERMISSION_CATEGORIES,
    ROLE_PERMISSIONS
};