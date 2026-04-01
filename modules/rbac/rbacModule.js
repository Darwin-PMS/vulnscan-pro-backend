/**
 * RBAC - Role-Based Access Control Module
 * Fine-grained permissions system
 */

const { v4: uuidv4 } = require('uuid');
const { query } = require('../../database/db');

const ROLES = {
    SUPER_ADMIN: 'super_admin',
    ADMIN: 'admin',
    SECURITY_ANALYST: 'security_analyst',
    USER: 'user',
    GUEST: 'guest'
};

const PERMISSIONS = {
    // User Management
    'user:read': 'View user profiles',
    'user:create': 'Create new users',
    'user:update': 'Update user information',
    'user:delete': 'Delete users',
    'user:role': 'Change user roles',
    'user:status': 'Enable/disable users',

    // Scan Management
    'scan:read': 'View scan results',
    'scan:create': 'Start new scans',
    'scan:update': 'Modify scan configurations',
    'scan:delete': 'Delete scans',
    'scan:export': 'Export scan reports',
    'scan:scheduled': 'Create scheduled scans',

    // Vulnerability Management
    'vuln:read': 'View vulnerabilities',
    'vuln:verify': 'Mark vulnerabilities as verified',
    'vuln:false_positive': 'Mark as false positive',
    'vuln:mitigate': 'Mark as mitigated',

    // Subscription Management
    'subscription:read': 'View subscription details',
    'subscription:create': 'Create subscriptions',
    'subscription:update': 'Update subscriptions',
    'subscription:cancel': 'Cancel subscriptions',
    'subscription:pricing': 'Modify pricing tiers',

    // Admin Functions
    'admin:dashboard': 'Access admin dashboard',
    'admin:users': 'Manage all users',
    'admin:system': 'System configuration',
    'admin:audit': 'View audit logs',
    'admin:export': 'Export system data',

    // AI Features
    'ai:chat': 'Use AI assistant',
    'ai:advanced': 'Use advanced AI features',
    'ai:export': 'Export AI analysis',

    // Compliance
    'compliance:read': 'View compliance reports',
    'compliance:generate': 'Generate compliance reports',
    'compliance:export': 'Export compliance data',

    // Privacy
    'privacy:manage': 'Manage consent records',
    'privacy:export': 'Export user data',
    'privacy:delete': 'Delete user data'
};

const ROLE_PERMISSIONS = {
    [ROLES.SUPER_ADMIN]: Object.keys(PERMISSIONS),
    [ROLES.ADMIN]: [
        'user:read', 'user:update', 'user:status',
        'scan:read', 'scan:create', 'scan:update', 'scan:delete', 'scan:export', 'scan:scheduled',
        'vuln:read', 'vuln:verify', 'vuln:false_positive', 'vuln:mitigate',
        'subscription:read', 'subscription:update',
        'admin:dashboard', 'admin:users', 'admin:audit', 'admin:export',
        'ai:chat', 'ai:advanced', 'ai:export',
        'compliance:read', 'compliance:generate', 'compliance:export',
        'privacy:manage', 'privacy:export'
    ],
    [ROLES.SECURITY_ANALYST]: [
        'scan:read', 'scan:create', 'scan:export',
        'vuln:read', 'vuln:verify', 'vuln:false_positive',
        'admin:audit',
        'ai:chat', 'ai:export',
        'compliance:read'
    ],
    [ROLES.USER]: [
        'scan:read', 'scan:create',
        'vuln:read',
        'subscription:read',
        'ai:chat',
        'compliance:read'
    ],
    [ROLES.GUEST]: [
        'scan:read',
        'vuln:read'
    ]
};

class RBACModule {
    async hasPermission(userId, permission) {
        const [user] = await query(
            'SELECT role FROM users WHERE id = ? AND is_active = TRUE',
            [userId]
        );

        if (!user) return false;

        const rolePermissions = ROLE_PERMISSIONS[user.role] || [];
        return rolePermissions.includes(permission);
    }

    async hasAnyPermission(userId, permissions) {
        for (const permission of permissions) {
            if (await this.hasPermission(userId, permission)) {
                return true;
            }
        }
        return false;
    }

    async hasAllPermissions(userId, permissions) {
        for (const permission of permissions) {
            if (!await this.hasPermission(userId, permission)) {
                return false;
            }
        }
        return true;
    }

    async getUserPermissions(userId) {
        const [user] = await query(
            'SELECT role FROM users WHERE id = ?',
            [userId]
        );

        if (!user) return { role: null, permissions: [] };

        const permissions = ROLE_PERMISSIONS[user.role] || [];

        return {
            role: user.role,
            permissions,
            permissionDetails: permissions.map(p => ({
                key: p,
                description: PERMISSIONS[p]
            }))
        };
    }

    async checkPermission(userId, permission) {
        const hasPermission = await this.hasPermission(userId, permission);
        
        return {
            allowed: hasPermission,
            permission,
            userId,
            checkedAt: new Date().toISOString()
        };
    }

    async requirePermission(userId, permission) {
        const hasPermission = await this.hasPermission(userId, permission);
        
        if (!hasPermission) {
            const error = new Error('Access denied: Insufficient permissions');
            error.code = 'INSUFFICIENT_PERMISSIONS';
            error.requiredPermission = permission;
            throw error;
        }
        
        return true;
    }

    async getRolePermissions(role) {
        const permissions = ROLE_PERMISSIONS[role] || [];
        
        return {
            role,
            permissions,
            count: permissions.length,
            details: permissions.map(p => ({
                key: p,
                description: PERMISSIONS[p]
            }))
        };
    }

    async getAllRoles() {
        return Object.entries(ROLE_PERMISSIONS).map(([role, permissions]) => ({
            role,
            permissionsCount: permissions.length,
            permissions: permissions.map(p => ({
                key: p,
                description: PERMISSIONS[p]
            }))
        }));
    }

    async assignRole(userId, newRole, assignedBy) {
        if (!ROLE_PERMISSIONS[newRole]) {
            throw new Error('Invalid role');
        }

        const [user] = await query('SELECT role FROM users WHERE id = ?', [userId]);
        if (!user) {
            throw new Error('User not found');
        }

        const oldRole = user.role;

        await query(
            'UPDATE users SET role = ? WHERE id = ?',
            [newRole, userId]
        );

        await query(`
            INSERT INTO permission_changes 
            (id, user_id, old_role, new_role, changed_by, changed_at)
            VALUES (?, ?, ?, ?, ?, NOW())
        `, [uuidv4(), userId, oldRole, newRole, assignedBy]);

        return { oldRole, newRole };
    }

    async getRoleHierarchy() {
        return {
            levels: [
                { level: 1, role: ROLES.SUPER_ADMIN, title: 'Super Administrator' },
                { level: 2, role: ROLES.ADMIN, title: 'Administrator' },
                { level: 3, role: ROLES.SECURITY_ANALYST, title: 'Security Analyst' },
                { level: 4, role: ROLES.USER, title: 'Standard User' },
                { level: 5, role: ROLES.GUEST, title: 'Guest' }
            ],
            permissionCounts: Object.entries(ROLE_PERMISSIONS).reduce((acc, [role, perms]) => {
                acc[role] = perms.length;
                return acc;
            }, {})
        };
    }

    async createCustomRole(roleName, permissions, createdBy) {
        const roleId = uuidv4();

        await query(`
            INSERT INTO custom_roles (id, name, permissions, created_by, created_at)
            VALUES (?, ?, ?, ?, NOW())
        `, [roleId, roleName, JSON.stringify(permissions), createdBy]);

        return { roleId, roleName, permissions };
    }

    async getCustomRoles() {
        const [roles] = await query('SELECT * FROM custom_roles WHERE is_active = TRUE');
        return roles.map(r => ({
            ...r,
            permissions: JSON.parse(r.permissions)
        }));
    }

    async auditPermissionChanges(userId, filters = {}) {
        const { startDate, endDate } = filters;
        
        let whereClause = '1=1';
        const params = [];

        if (userId) {
            whereClause += ' AND user_id = ?';
            params.push(userId);
        }
        if (startDate) {
            whereClause += ' AND changed_at >= ?';
            params.push(startDate);
        }
        if (endDate) {
            whereClause += ' AND changed_at <= ?';
            params.push(endDate);
        }

        const [changes] = await query(`
            SELECT pc.*, 
                   u1.username as user_name,
                   u2.username as changed_by_name
            FROM permission_changes pc
            JOIN users u1 ON pc.user_id = u1.id
            JOIN users u2 ON pc.changed_by = u2.id
            WHERE ${whereClause}
            ORDER BY pc.changed_at DESC
        `, params);

        return { changes };
    }

    middleware(requiredPermission) {
        return async (req, res, next) => {
            try {
                const userId = req.user?.userId;
                
                if (!userId) {
                    return res.status(401).json({ error: 'Authentication required' });
                }

                const hasPermission = await this.hasPermission(userId, requiredPermission);
                
                if (!hasPermission) {
                    return res.status(403).json({ 
                        error: 'Access denied',
                        requiredPermission,
                        message: 'You do not have permission to perform this action'
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
                
                if (!userId) {
                    return res.status(401).json({ error: 'Authentication required' });
                }

                let hasPermission;
                if (requireAll) {
                    hasPermission = await this.hasAllPermissions(userId, requiredPermissions);
                } else {
                    hasPermission = await this.hasAnyPermission(userId, requiredPermissions);
                }
                
                if (!hasPermission) {
                    return res.status(403).json({ 
                        error: 'Access denied',
                        requiredPermissions,
                        message: requireAll 
                            ? 'All required permissions needed'
                            : 'One of the required permissions needed'
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
    RBACModule,
    ROLES,
    PERMISSIONS,
    ROLE_PERMISSIONS
};
