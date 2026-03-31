const BLOCKED_HOSTS = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '::1',
    '169.254.169.254',
    'metadata.google.internal',
    'metadata.aws',
    'metadata.azure.com'
];

const BLOCKED_PROTOCOLS = ['file:', 'ftp:', 'gopher:', 'mailto:', 'tel:', 'data:', 'javascript:'];

const PRIVATE_IP_RANGES = [
    /^10\.\d+\.\d+\.\d+$/,
    /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
    /^192\.168\.\d+\.\d+$/,
    /^169\.254\.\d+\.\d+$/,
    /^127\.\d+\.\d+\.\d+$/,
    /^fc00:/i,
    /^fe80:/i,
    /^::1$/i
];

const sanitizeSearchInput = (input) => {
    if (typeof input !== 'string') return '';
    return input.replace(/[%_\\]/g, '\\$&').substring(0, 200);
};

const validateScanURL = (url) => {
    if (!url || typeof url !== 'string') {
        throw new Error('URL is required');
    }

    const trimmedUrl = url.trim();

    if (trimmedUrl.length > 2048) {
        throw new Error('URL exceeds maximum length');
    }

    let parsed;
    try {
        parsed = new URL(trimmedUrl);
    } catch {
        throw new Error('Invalid URL format');
    }

    if (BLOCKED_PROTOCOLS.includes(parsed.protocol)) {
        throw new Error('This protocol is not allowed for security reasons');
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('Only HTTP and HTTPS protocols are allowed');
    }

    const hostname = parsed.hostname.toLowerCase();

    if (BLOCKED_HOSTS.includes(hostname)) {
        throw new Error('This target host is not allowed');
    }

    for (const range of PRIVATE_IP_RANGES) {
        if (range.test(hostname)) {
            throw new Error('Private IP addresses are not allowed');
        }
    }

    if (hostname.match(/^[a-f0-9:]+$/i) && hostname.includes(':')) {
        throw new Error('IPv6 addresses are not allowed');
    }

    const urlObj = new URL(trimmedUrl);
    if (urlObj.username || urlObj.password) {
        throw new Error('URLs with credentials are not allowed');
    }

    return true;
};

const validateEmail = (email) => {
    if (!email || typeof email !== 'string') return false;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 254;
};

const validateUsername = (username) => {
    if (!username || typeof username !== 'string') return false;
    return /^[a-zA-Z0-9_]{3,50}$/.test(username);
};

const validatePasswordStrength = (password) => {
    if (!password || typeof password !== 'string') {
        return { valid: false, errors: ['Password is required'] };
    }

    const errors = [];

    if (password.length < 12) {
        errors.push('Password must be at least 12 characters');
    }
    if (password.length > 128) {
        errors.push('Password must not exceed 128 characters');
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
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }

    const commonPasswords = [
        'password', 'password123', '123456', '123456789', 'qwerty',
        'admin', 'admin123', 'letmein', 'welcome', 'monkey'
    ];
    if (commonPasswords.some(cp => password.toLowerCase().includes(cp))) {
        errors.push('Password is too common');
    }

    return {
        valid: errors.length === 0,
        errors
    };
};

const sanitizeObject = (obj, allowedFields) => {
    if (!obj || typeof obj !== 'object') return {};
    const sanitized = {};
    for (const key of allowedFields) {
        if (obj[key] !== undefined) {
            sanitized[key] = obj[key];
        }
    }
    return sanitized;
};

const validatePagination = (page, limit, maxLimit = 100) => {
    const pageNum = parseInt(page) || 1;
    const limitNum = parseInt(limit) || 20;

    return {
        page: Math.max(1, Math.min(pageNum, 1000)),
        limit: Math.max(1, Math.min(limitNum, maxLimit))
    };
};

const generateSecureId = () => {
    const crypto = require('crypto');
    return crypto.randomBytes(16).toString('hex');
};

module.exports = {
    validateScanURL,
    validateEmail,
    validateUsername,
    validatePasswordStrength,
    sanitizeSearchInput,
    sanitizeObject,
    validatePagination,
    generateSecureId,
    BLOCKED_HOSTS,
    BLOCKED_PROTOCOLS
};
