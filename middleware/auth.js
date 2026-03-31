const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    throw new Error('CRITICAL: JWT_SECRET environment variable is required. Set it in .env file.');
}

if (JWT_SECRET.length < 32) {
    console.warn('WARNING: JWT_SECRET should be at least 32 characters for security.');
}

const tokenBlacklist = new Set();

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    if (tokenBlacklist.has(token)) {
        return res.status(401).json({ error: 'Token has been revoked' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        return res.status(403).json({ error: 'Invalid token' });
    }
};

const optionalAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        if (tokenBlacklist.has(token)) {
            req.user = null;
            return next();
        }
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
        } catch (error) {
            req.user = null;
        }
    } else {
        req.user = null;
    }
    next();
};

const revokeToken = (token) => {
    tokenBlacklist.add(token);
};

const isTokenRevoked = (token) => {
    return tokenBlacklist.has(token);
};

const generateToken = (payload) => {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '24h' });
};

const verifyToken = (token) => {
    return jwt.verify(token, JWT_SECRET);
};

const LOG_LEVEL = process.env.LOG_LEVEL || 'error';
const log = {
    error: (...args) => {
        if (LOG_LEVEL === 'error' || LOG_LEVEL === 'debug') {
            console.error(`[ERROR]`, ...args.map(sanitizeLog));
        }
    },
    info: (...args) => {
        if (LOG_LEVEL === 'info' || LOG_LEVEL === 'debug') {
            console.log(`[INFO]`, ...args.map(sanitizeLog));
        }
    },
    debug: (...args) => {
        if (LOG_LEVEL === 'debug') {
            console.log(`[DEBUG]`, ...args.map(sanitizeLog));
        }
    }
};

const sanitizeLog = (arg) => {
    if (typeof arg === 'object' && arg !== null) {
        const sanitized = { ...arg };
        delete sanitized.password;
        delete sanitized.password_hash;
        delete sanitized.token;
        delete sanitized.Authorization;
        return sanitized;
    }
    return arg;
};

module.exports = {
    authenticateToken,
    optionalAuth,
    revokeToken,
    isTokenRevoked,
    generateToken,
    verifyToken,
    log
};
