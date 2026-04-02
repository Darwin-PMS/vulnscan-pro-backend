const fs = require('fs');
const path = require('path');

const LOG_DIR = path.join(__dirname, '..', 'logs');
const REQUEST_LOG_FILE = path.join(LOG_DIR, 'api-requests.log');
const ERROR_LOG_FILE = path.join(LOG_DIR, 'errors.log');
const AUDIT_LOG_FILE = path.join(LOG_DIR, 'audit.log');

if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

const formatDate = () => new Date().toISOString();

const formatRequest = (req, res, duration) => {
    const userId = req.user?.id || 'anonymous';
    return {
        timestamp: formatDate(),
        method: req.method,
        url: req.originalUrl,
        path: req.path,
        query: req.query,
        params: req.params,
        headers: {
            'content-type': req.headers['content-type'],
            'user-agent': req.headers['user-agent'],
            'authorization': req.headers['authorization'] ? '[REDACTED]' : null,
            'x-request-id': req.headers['x-request-id']
        },
        body: req.body,
        user: {
            id: userId,
            email: req.user?.email || null,
            role: req.user?.role || null
        },
        response: {
            status: res.statusCode,
            duration: `${duration}ms`
        }
    };
};

const formatError = (error, req) => {
    return {
        timestamp: formatDate(),
        error: {
            name: error.name,
            message: error.message,
            stack: error.stack
        },
        request: {
            method: req.method,
            url: req.originalUrl,
            body: req.body,
            params: req.params
        },
        user: {
            id: req.user?.id || 'anonymous',
            email: req.user?.email || null
        }
    };
};

const requestLogger = (req, res, next) => {
    const startTime = Date.now();
    const requestId = req.id || 'unknown';

    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const logEntry = formatRequest(req, res, duration);

        const logLine = JSON.stringify(logEntry);

        fs.appendFile(REQUEST_LOG_FILE, logLine + '\n', (err) => {
            if (err) console.error('Failed to write request log:', err);
        });

        if (process.env.LOG_LEVEL === 'debug') {
            console.log(`[${requestId}] ${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
        }
    });

    next();
};

const errorLogger = (err, req, res, next) => {
    const logEntry = formatError(err, req);
    const requestId = req.id || 'unknown';

    console.error(`[${requestId}] Error:`, err.message);

    fs.appendFile(ERROR_LOG_FILE, JSON.stringify(logEntry) + '\n', (writeErr) => {
        if (writeErr) console.error('Failed to write error log:', writeErr);
    });

    next(err);
};

const auditLogger = (action) => {
    return (req, res, next) => {
        const auditEntry = {
            timestamp: formatDate(),
            action: action,
            user: {
                id: req.user?.id || 'anonymous',
                email: req.user?.email || null,
                role: req.user?.role || null
            },
            request: {
                method: req.method,
                url: req.originalUrl,
                ip: req.ip || req.connection.remoteAddress
            },
            resource: {
                type: req.params.resourceType || null,
                id: req.params.resourceId || null
            }
        };

        fs.appendFile(AUDIT_LOG_FILE, JSON.stringify(auditEntry) + '\n', (err) => {
            if (err) console.error('Failed to write audit log:', err);
        });

        next();
    };
};

const getLogs = (type = 'requests', limit = 100) => {
    return new Promise((resolve, reject) => {
        let file;
        switch (type) {
            case 'errors':
                file = ERROR_LOG_FILE;
                break;
            case 'audit':
                file = AUDIT_LOG_FILE;
                break;
            default:
                file = REQUEST_LOG_FILE;
        }

        fs.readFile(file, 'utf8', (err, data) => {
            if (err) {
                if (err.code === 'ENOENT') {
                    resolve([]);
                } else {
                    reject(err);
                }
                return;
            }

            const lines = data.split('\n').filter(line => line.trim());
            const logs = lines.slice(-limit).map(line => {
                try {
                    return JSON.parse(line);
                } catch {
                    return { raw: line };
                }
            }).reverse();

            resolve(logs);
        });
    });
};

const clearLogs = (type = 'requests') => {
    return new Promise((resolve, reject) => {
        let file;
        switch (type) {
            case 'errors':
                file = ERROR_LOG_FILE;
                break;
            case 'audit':
                file = AUDIT_LOG_FILE;
                break;
            default:
                file = REQUEST_LOG_FILE;
        }

        fs.writeFile(file, '', (err) => {
            if (err) reject(err);
            else resolve();
        });
    });
};

const getLogStats = () => {
    return new Promise((resolve) => {
        const getFileStats = (file) => {
            return new Promise((res) => {
                fs.stat(file, (err, stats) => {
                    if (err || !stats) {
                        res({ exists: false, size: 0, lines: 0 });
                    } else {
                        fs.readFile(file, 'utf8', (rErr, data) => {
                            if (rErr) {
                                res({ exists: true, size: stats.size, lines: 0 });
                            } else {
                                const lines = data.split('\n').filter(l => l.trim());
                                res({ exists: true, size: stats.size, lines: lines.length });
                            }
                        });
                    }
                });
            });
        };

        Promise.all([
            getFileStats(REQUEST_LOG_FILE),
            getFileStats(ERROR_LOG_FILE),
            getFileStats(AUDIT_LOG_FILE)
        ]).then(([requests, errors, audit]) => {
            resolve({
                requests,
                errors,
                audit,
                timestamp: formatDate()
            });
        });
    });
};

module.exports = {
    requestLogger,
    errorLogger,
    auditLogger,
    getLogs,
    clearLogs,
    getLogStats
};
