const rateLimit = new Map();

const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const MAX_REQUESTS = 100;

const rateLimiter = (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    
    const record = rateLimit.get(ip);
    
    if (record) {
        const expiresAt = record.timestamp + RATE_LIMIT_WINDOW;
        
        if (now < expiresAt) {
            if (record.count >= MAX_REQUESTS) {
                const resetTime = Math.ceil((expiresAt - now) / 1000);
                return res.status(429).json({
                    error: 'Too many requests',
                    retryAfter: resetTime
                });
            }
            record.count++;
        } else {
            rateLimit.set(ip, { count: 1, timestamp: now });
        }
    } else {
        rateLimit.set(ip, { count: 1, timestamp: now });
    }
    
    next();
};

const adminRateLimiter = (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    
    const key = `admin:${ip}`;
    const record = rateLimit.get(key);
    
    const MAX_ADMIN_REQUESTS = 60;
    
    if (record) {
        const expiresAt = record.timestamp + RATE_LIMIT_WINDOW;
        
        if (now < expiresAt) {
            if (record.count >= MAX_ADMIN_REQUESTS) {
                const resetTime = Math.ceil((expiresAt - now) / 1000);
                return res.status(429).json({
                    error: 'Too many admin requests',
                    retryAfter: resetTime
                });
            }
            record.count++;
        } else {
            rateLimit.set(key, { count: 1, timestamp: now });
        }
    } else {
        rateLimit.set(key, { count: 1, timestamp: now });
    }
    
    next();
};

setInterval(() => {
    const now = Date.now();
    for (const [key, record] of rateLimit.entries()) {
        if (now > record.timestamp + RATE_LIMIT_WINDOW) {
            rateLimit.delete(key);
        }
    }
}, RATE_LIMIT_WINDOW);

module.exports = { rateLimiter, adminRateLimiter };
