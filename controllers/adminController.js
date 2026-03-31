const { query } = require('../database/db');
const userService = require('../services/userService');
const subscriptionService = require('../services/subscriptionService');
const scanService = require('../services/scanService');
const { getAdminStats } = require('../middleware/admin');
const { validatePasswordStrength, sanitizeSearchInput } = require('../utils/security');

const validateUserInput = (data, isUpdate = false) => {
    const errors = [];
    
    if (!isUpdate) {
        if (!data.username || data.username.trim().length < 3) {
            errors.push('Username must be at least 3 characters');
        }
        if (data.username && !/^[a-zA-Z0-9_]+$/.test(data.username)) {
            errors.push('Username can only contain letters, numbers, and underscores');
        }
        if (!data.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
            errors.push('Valid email is required');
        }
        if (!data.password) {
            errors.push('Password is required');
        } else {
            const passwordCheck = validatePasswordStrength(data.password);
            if (!passwordCheck.valid) {
                errors.push(...passwordCheck.errors);
            }
        }
    } else {
        if (data.username && data.username.trim().length < 3) {
            errors.push('Username must be at least 3 characters');
        }
        if (data.username && !/^[a-zA-Z0-9_]+$/.test(data.username)) {
            errors.push('Username can only contain letters, numbers, and underscores');
        }
        if (data.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
            errors.push('Valid email is required');
        }
        if (data.password) {
            const passwordCheck = validatePasswordStrength(data.password);
            if (!passwordCheck.valid) {
                errors.push(...passwordCheck.errors);
            }
        }
    }

    if (data.role && !['user', 'admin'].includes(data.role)) {
        errors.push('Role must be either user or admin');
    }

    return errors;
};

const adminController = {
    async getDashboardStats(req, res) {
        try {
            const stats = await getAdminStats();
            res.json(stats);
        } catch (error) {
            console.error('Error fetching admin stats:', error.message);
            res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
        }
    },

    async getAllUsers(req, res) {
        try {
            const { page, limit, search, role, status } = req.query;
            const result = await userService.getAllUsers({ page, limit, search, role, status });
            res.json(result);
        } catch (error) {
            console.error('Error fetching users:', error.message);
            res.status(500).json({ error: 'Failed to fetch users' });
        }
    },

    async getUserById(req, res) {
        try {
            const { userId } = req.params;
            const result = await userService.getUserById(userId);
            
            if (!result) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            res.json(result);
        } catch (error) {
            console.error('Error fetching user:', error.message);
            res.status(500).json({ error: 'Failed to fetch user details' });
        }
    },

    async updateUser(req, res) {
        try {
            const { userId } = req.params;
            const { username, email, fullName, role, isActive, password } = req.body;

            const errors = validateUserInput(req.body, true);
            if (errors.length > 0) {
                return res.status(400).json({ error: errors.join('. ') });
            }

            const updates = { username, email, fullName, role, isActive, password };
            const updated = await userService.updateUser(
                userId,
                updates,
                req.user.userId,
                req.user.role
            );
            
            res.json({ success: true, user: updated });
        } catch (error) {
            console.error('Error updating user:', error.message);
            const status = error.message.includes('Invalid') || error.message.includes('Only') ? 400 : 500;
            res.status(status).json({ error: error.message || 'Failed to update user' });
        }
    },

    async deleteUser(req, res) {
        try {
            const { userId } = req.params;
            await userService.deleteUser(userId, req.user.userId);
            res.json({ success: true, message: 'User deleted successfully' });
        } catch (error) {
            console.error('Error deleting user:', error.message);
            const status = error.message.includes('Cannot') || error.message.includes('Invalid') ? 400 : 500;
            res.status(status).json({ error: error.message || 'Failed to delete user' });
        }
    },

    async getAllSubscriptions(req, res) {
        try {
            const { page, limit, tier, status } = req.query;
            const result = await subscriptionService.getAllSubscriptions({ page, limit, tier, status });
            res.json(result);
        } catch (error) {
            console.error('Error fetching subscriptions:', error.message);
            res.status(500).json({ error: 'Failed to fetch subscriptions' });
        }
    },

    async updateSubscription(req, res) {
        try {
            const { subId } = req.params;
            const { status, tierId, autoRenew, scansUsedThisMonth } = req.body;
            
            if (status && !['active', 'cancelled', 'expired', 'trial'].includes(status)) {
                return res.status(400).json({ error: 'Invalid subscription status' });
            }
            
            const updated = await subscriptionService.updateSubscription(subId, {
                status,
                tierId,
                autoRenew,
                scansUsedThisMonth
            });
            
            res.json({ success: true, subscription: updated });
        } catch (error) {
            console.error('Error updating subscription:', error.message);
            res.status(500).json({ error: 'Failed to update subscription' });
        }
    },

    async createUser(req, res) {
        try {
            const { username, email, password, fullName, role } = req.body;

            const errors = validateUserInput(req.body);
            if (errors.length > 0) {
                return res.status(400).json({ error: errors.join('. ') });
            }

            const existing = await query('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
            if (existing.length > 0) {
                return res.status(409).json({ error: 'Username or email already exists' });
            }

            const newUser = await userService.createUser({ username, email, password, fullName, role });
            res.status(201).json({ success: true, user: newUser });
        } catch (error) {
            console.error('Error creating user:', error.message);
            res.status(500).json({ error: error.message || 'Failed to create user' });
        }
    },

    async getSubscriptionTiers(req, res) {
        try {
            const tiers = await subscriptionService.getSubscriptionTiers();
            res.json({ tiers });
        } catch (error) {
            console.error('Error fetching tiers:', error.message);
            res.status(500).json({ error: 'Failed to fetch subscription tiers' });
        }
    },

    async updateSubscriptionTier(req, res) {
        try {
            const { tierId } = req.params;
            const updates = req.body;
            const updated = await subscriptionService.updateSubscriptionTier(tierId, updates);
            res.json({ success: true, tier: updated });
        } catch (error) {
            console.error('Error updating tier:', error.message);
            res.status(500).json({ error: 'Failed to update subscription tier' });
        }
    },

    async getAllScans(req, res) {
        try {
            const { page, limit, status, search } = req.query;
            const safeSearch = sanitizeSearchInput(search || '');
            const result = await scanService.getAllScans({ page, limit, status, search: safeSearch });
            res.json(result);
        } catch (error) {
            console.error('Error fetching scans:', error.message);
            res.status(500).json({ error: 'Failed to fetch scans' });
        }
    },

    async deleteScan(req, res) {
        try {
            const { scanId } = req.params;
            if (!scanId || scanId.length < 10) {
                return res.status(400).json({ error: 'Invalid scan ID' });
            }
            await scanService.deleteScan(scanId);
            res.json({ success: true, message: 'Scan deleted successfully' });
        } catch (error) {
            console.error('Error deleting scan:', error.message);
            res.status(500).json({ error: 'Failed to delete scan' });
        }
    }
};

module.exports = adminController;
