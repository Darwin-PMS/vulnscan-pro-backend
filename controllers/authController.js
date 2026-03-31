const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { query } = require('../database/db');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    throw new Error('CRITICAL: JWT_SECRET environment variable is required');
}

const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;

const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;

const validatePassword = (password) => {
    const errors = [];
    if (password.length < 12) {
        errors.push('Password must be at least 12 characters');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    if (!/[0-9]/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }
    return errors;
};

const getClientIP = (req) => {
    return req.ip || req.headers['x-forwarded-for']?.split(',')[0] || req.connection?.remoteAddress || 'unknown';
};

const register = async (req, res) => {
    try {
        const { username, email, password, fullName } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password are required' });
        }

        if (username.length < 3 || username.length > 50) {
            return res.status(400).json({ error: 'Username must be between 3 and 50 characters' });
        }

        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores' });
        }

        const passwordErrors = validatePassword(password);
        if (passwordErrors.length > 0) {
            return res.status(400).json({ error: passwordErrors.join('. ') });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Please enter a valid email address' });
        }

        const existingUser = await query('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
        if (existingUser.length > 0) {
            return res.status(409).json({ error: 'Username or email already exists' });
        }

        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

        const result = await query(
            'INSERT INTO users (username, email, password_hash, full_name) VALUES (?, ?, ?, ?)',
            [username, email, passwordHash, fullName || null]
        );

        const token = jwt.sign(
            { userId: result.insertId, username, email, role: 'user' },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );

        await query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [result.insertId]);

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000
        });

        res.status(201).json({
            message: 'Registration successful',
            token,
            user: {
                id: result.insertId,
                username,
                email,
                fullName
            }
        });
    } catch (error) {
        console.error('Registration error:', error.message);
        res.status(500).json({ error: 'Registration failed' });
    }
};

const login = async (req, res) => {
    try {
        const { username, password } = req.body;
        const clientIP = getClientIP(req);
        const loginKey = `${clientIP}:${username}`;
        const attempts = loginAttempts.get(loginKey);

        if (attempts && attempts.count >= MAX_LOGIN_ATTEMPTS && Date.now() - attempts.lastAttempt < LOCKOUT_DURATION) {
            const remainingTime = Math.ceil((LOCKOUT_DURATION - (Date.now() - attempts.lastAttempt)) / 1000 / 60);
            return res.status(429).json({
                error: `Too many login attempts. Please try again in ${remainingTime} minutes.`
            });
        }

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const users = await query('SELECT * FROM users WHERE username = ? OR email = ?', [username, username]);
        const user = users[0];

        if (!user) {
            recordFailedAttempt(loginKey);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (!user.is_active) {
            return res.status(403).json({ error: 'Account is deactivated' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
            recordFailedAttempt(loginKey);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        loginAttempts.delete(loginKey);

        const token = jwt.sign(
            { userId: user.id, username: user.username, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );

        await query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000
        });

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                fullName: user.full_name
            }
        });
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({ error: 'Login failed' });
    }
};

const recordFailedAttempt = (loginKey) => {
    const attempts = loginAttempts.get(loginKey) || { count: 0, lastAttempt: 0 };
    attempts.count++;
    attempts.lastAttempt = Date.now();
    loginAttempts.set(loginKey, attempts);
};

const logout = async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (token) {
            loginAttempts.delete(getClientIP(req));
        }

        res.clearCookie('token');
        res.json({ message: 'Logout successful' });
    } catch (error) {
        console.error('Logout error:', error.message);
        res.status(500).json({ error: 'Logout failed' });
    }
};

const getCurrentUser = async (req, res) => {
    try {
        const users = await query(
            'SELECT id, username, email, full_name, role, created_at, last_login FROM users WHERE id = ?',
            [req.user.userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = users[0];
        res.json({
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                fullName: user.full_name,
                role: user.role,
                createdAt: user.created_at,
                lastLogin: user.last_login
            }
        });
    } catch (error) {
        console.error('Get current user error:', error.message);
        res.status(500).json({ error: 'Failed to get user data' });
    }
};

const updateProfile = async (req, res) => {
    try {
        const userId = req.user.userId;
        const { fullName, email, currentPassword, newPassword } = req.body;

        const updates = [];
        const params = [];

        if (fullName !== undefined) {
            updates.push('full_name = ?');
            params.push(fullName);
        }

        if (email !== undefined) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.status(400).json({ error: 'Please enter a valid email address' });
            }

            const existing = await query('SELECT id FROM users WHERE email = ? AND id != ?', [email, userId]);
            if (existing.length > 0) {
                return res.status(409).json({ error: 'Email already in use' });
            }

            updates.push('email = ?');
            params.push(email);
        }

        if (newPassword) {
            if (!currentPassword) {
                return res.status(400).json({ error: 'Current password is required to change password' });
            }

            const [users] = await query('SELECT password_hash FROM users WHERE id = ?', [userId]);
            const isValid = await bcrypt.compare(currentPassword, users[0].password_hash);
            if (!isValid) {
                return res.status(401).json({ error: 'Current password is incorrect' });
            }

            const passwordErrors = validatePassword(newPassword);
            if (passwordErrors.length > 0) {
                return res.status(400).json({ error: passwordErrors.join('. ') });
            }

            const newHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
            updates.push('password_hash = ?');
            params.push(newHash);
        }

        if (updates.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }

        params.push(userId);
        await query(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params);

        const [updatedUser] = await query(
            'SELECT id, username, email, full_name, role, created_at, last_login FROM users WHERE id = ?',
            [userId]
        );

        res.json({
            message: 'Profile updated successfully',
            user: {
                id: updatedUser.id,
                username: updatedUser.username,
                email: updatedUser.email,
                fullName: updatedUser.full_name,
                role: updatedUser.role,
                createdAt: updatedUser.created_at,
                lastLogin: updatedUser.last_login
            }
        });
    } catch (error) {
        console.error('Update profile error:', error.message);
        res.status(500).json({ error: 'Failed to update profile' });
    }
};

module.exports = {
    register,
    login,
    logout,
    getCurrentUser,
    updateProfile
};
