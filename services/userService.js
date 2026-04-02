const { query } = require('../database/db');
const { sanitizeSearchInput } = require('../utils/security');

const ALLOWED_USER_UPDATE_FIELDS = ['username', 'email', 'fullName'];
const ADMIN_USER_UPDATE_FIELDS = ['username', 'email', 'fullName', 'role', 'isActive'];
const ALLOWED_CREATE_FIELDS = ['username', 'email', 'password', 'fullName', 'role'];

const sanitizeUserUpdate = (data, isAdmin = false) => {
    const allowed = isAdmin ? ADMIN_USER_UPDATE_FIELDS : ALLOWED_USER_UPDATE_FIELDS;
    const sanitized = {};
    
    for (const key of allowed) {
        if (data[key] !== undefined) {
            sanitized[key] = data[key];
        }
    }
    
    return sanitized;
};

const sanitizeSearch = (search) => {
    if (!search) return '';
    return sanitizeSearchInput(search);
};

const userService = {
    async getAllUsers({ page = 1, limit = 20, search = '', role = '', status = '' }) {
        const offset = (parseInt(page) - 1) * parseInt(limit);
        const safeSearch = sanitizeSearch(search);
        
        let whereClause = '1=1';
        const params = [];

        if (safeSearch) {
            whereClause += ' AND (u.username LIKE ? OR u.email LIKE ?)';
            params.push(`%${safeSearch}%`, `%${safeSearch}%`);
        }

        if (role && ['user', 'admin'].includes(role)) {
            whereClause += ' AND u.role = ?';
            params.push(role);
        }

        if (status) {
            whereClause += ' AND u.is_active = ?';
            params.push(status === 'active');
        }

        const baseParams = [...params];
        const countParams = [...params];

        const users = await query(`
            SELECT 
                u.id, 
                u.username, 
                u.email, 
                u.full_name, 
                u.role, 
                u.is_active, 
                u.created_at, 
                u.last_login,
                COALESCE(scan_counts.scan_count, 0) as scans_count,
                sub_info.tier_name,
                sub_info.sub_status
            FROM users u
            LEFT JOIN (
                SELECT user_id, COUNT(*) as scan_count 
                FROM scans 
                GROUP BY user_id
            ) scan_counts ON u.id = scan_counts.user_id
            LEFT JOIN (
                SELECT 
                    us.user_id, 
                    st.name as tier_name, 
                    us.status as sub_status
                FROM user_subscriptions us
                JOIN subscription_tiers st ON us.tier_id = st.tier
                WHERE us.status IN ('active', 'trial')
            ) sub_info ON u.id = sub_info.user_id
            WHERE ${whereClause} 
            ORDER BY u.created_at DESC 
            LIMIT ? OFFSET ?
        `, [...baseParams, parseInt(limit), offset]);

        const countResult = await query(
            `SELECT COUNT(*) as total FROM users u WHERE ${whereClause}`,
            countParams
        );

        const formattedUsers = users.map(user => ({
            id: user.id,
            username: user.username,
            email: user.email,
            full_name: user.full_name,
            role: user.role,
            is_active: user.is_active,
            created_at: user.created_at,
            last_login: user.last_login,
            scans_count: user.scans_count,
            subscription: user.tier_name ? {
                tier_name: user.tier_name,
                status: user.sub_status
            } : null
        }));

        return {
            users: formattedUsers,
            total: countResult[0]?.total || 0,
            page: parseInt(page),
            totalPages: Math.ceil((countResult[0]?.total || 0) / parseInt(limit))
        };
    },

    async getUserById(userId) {
        const userIdNum = parseInt(userId);
        if (isNaN(userIdNum) || userIdNum <= 0) {
            throw new Error('Invalid user ID');
        }

        const [users] = await query(`
            SELECT 
                u.id, 
                u.username, 
                u.email, 
                u.full_name, 
                u.role, 
                u.is_active, 
                u.created_at, 
                u.last_login
            FROM users u 
            WHERE u.id = ?
        `, [userIdNum]);

        if (!users || users.length === 0) {
            return null;
        }

        const [subscription] = await query(`
            SELECT us.*, st.name as tier_name, st.features
            FROM user_subscriptions us
            JOIN subscription_tiers st ON us.tier_id = st.tier
            WHERE us.user_id = ? AND us.status IN ('active', 'trial')
        `, [userIdNum]);

        const [scans] = await query(`
            SELECT scan_id, target_url, status, created_at, total_vulnerabilities
            FROM scans 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 10
        `, [userIdNum]);

        return {
            user: users[0],
            subscription: subscription[0] || null,
            recentScans: scans
        };
    },

    async updateUser(userId, updates, requestingUserId, requestingUserRole) {
        const userIdNum = parseInt(userId);
        if (isNaN(userIdNum) || userIdNum <= 0) {
            throw new Error('Invalid user ID');
        }

        const requestingUserIdNum = parseInt(requestingUserId);
        const isAdmin = requestingUserRole === 'admin';
        const isSelfUpdate = requestingUserIdNum === userIdNum;

        const sanitized = sanitizeUserUpdate(updates, isAdmin);

        if (Object.keys(sanitized).length === 0) {
            throw new Error('No valid fields to update');
        }

        const { username, email, fullName, role, isActive } = sanitized;
        const updateFields = [];
        const params = [];

        if (username !== undefined) {
            if (username.length < 3 || username.length > 50) {
                throw new Error('Username must be between 3 and 50 characters');
            }
            if (!/^[a-zA-Z0-9_]+$/.test(username)) {
                throw new Error('Username can only contain letters, numbers, and underscores');
            }
            updateFields.push('username = ?');
            params.push(username);
        }
        
        if (email !== undefined) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                throw new Error('Valid email is required');
            }
            updateFields.push('email = ?');
            params.push(email);
        }
        
        if (fullName !== undefined) {
            updateFields.push('full_name = ?');
            params.push(fullName);
        }

        if (role !== undefined) {
            if (!isAdmin) {
                throw new Error('Only admins can change roles');
            }
            if (!['user', 'admin'].includes(role)) {
                throw new Error('Invalid role');
            }
            updateFields.push('role = ?');
            params.push(role);
        }

        if (isActive !== undefined) {
            if (!isAdmin) {
                throw new Error('Only admins can change user status');
            }
            updateFields.push('is_active = ?');
            params.push(isActive);
        }

        if (updateFields.length > 0) {
            params.push(userIdNum);
            await query(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`, params);
        }

        const [updated] = await query(
            'SELECT id, username, email, full_name, role, is_active FROM users WHERE id = ?',
            [userIdNum]
        );

        return updated[0];
    },

    async createUser(userData) {
        const sanitized = {};
        for (const key of ALLOWED_CREATE_FIELDS) {
            if (userData[key] !== undefined) {
                sanitized[key] = userData[key];
            }
        }

        const { username, email, password, fullName, role = 'user' } = sanitized;

        if (!username || !email || !password) {
            throw new Error('Username, email, and password are required');
        }

        const bcrypt = require('bcryptjs');
        const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;
        
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

        const [result] = await query(
            'INSERT INTO users (username, email, password_hash, full_name, role) VALUES (?, ?, ?, ?, ?)',
            [username, email, passwordHash, fullName || null, role]
        );

        const [newUser] = await query(
            'SELECT id, username, email, full_name, role, is_active, created_at FROM users WHERE id = ?',
            [result.insertId]
        );

        return newUser[0];
    },

    async deleteUser(userId, currentUserId) {
        const userIdNum = parseInt(userId);
        const currentUserIdNum = parseInt(currentUserId);

        if (isNaN(userIdNum) || userIdNum <= 0) {
            throw new Error('Invalid user ID');
        }

        if (userIdNum === currentUserIdNum) {
            throw new Error('Cannot delete your own account');
        }

        const [existing] = await query('SELECT id, role FROM users WHERE id = ?', [userIdNum]);
        
        if (!existing || existing.length === 0) {
            throw new Error('User not found');
        }

        if (existing[0].role === 'admin') {
            throw new Error('Cannot delete admin accounts');
        }

        await query('UPDATE users SET is_active = FALSE, deleted_at = NOW() WHERE id = ?', [userIdNum]);
        return { deleted: true, message: 'User soft deleted - data preserved for audit' };
    }
};

module.exports = userService;
