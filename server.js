const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');
const { v4: uuidv4 } = require('uuid');

dotenv.config();

const { initializeDatabase } = require('./database/db');
const { rateLimiter, adminRateLimiter } = require('./middleware/rateLimiter');
const { requestLogger, errorLogger } = require('./middleware/apiLogger');
const scanner = require('./services/vulnerabilityScanner');

const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:3000', 'http://localhost:3001'];

app.set('trust proxy', 1);

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https:"],
            fontSrc: ["'self'", "data:"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"],
            baseUri: ["'self'"],
            upgradeInsecureRequests: NODE_ENV === 'production' ? [] : null
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "same-origin" },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: "none" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    xssFilter: true
}));

app.use(cors({
    origin: (origin, callback) => {
        if (NODE_ENV === 'development' || !origin) {
            return callback(null, true);
        }
        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['X-Request-Id'],
    maxAge: 86400
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(rateLimiter);

app.use((req, res, next) => {
    req.id = uuidv4();
    res.setHeader('X-Request-Id', req.id);
    next();
});

app.use(requestLogger);

const scanRoutes = require('./routes/scanRoutes');
const dorkRoutes = require('./routes/dorkRoutes');
const aiRoutes = require('./routes/aiRoutes');
const authRoutes = require('./routes/authRoutes');
const mobileRoutes = require('./routes/mobileRoutes');
const subscriptionRoutes = require('./routes/subscriptionRoutes');
const adminRoutes = require('./routes/adminRoutes');
const enterpriseRoutes = require('./routes/enterpriseRoutes');
const scanModulesRoutes = require('./routes/scanModules');
const logRoutes = require('./routes/logRoutes');

app.use('/api/scans', scanRoutes);
app.use('/api/dorks', dorkRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/mobile', mobileRoutes);
app.use('/api/subscriptions', subscriptionRoutes);
app.use('/api/admin', adminRateLimiter, adminRoutes);
app.use('/api/enterprise', enterpriseRoutes);
app.use('/api/scan-modules', scanModulesRoutes);
app.use('/api/logs', logRoutes);

app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        service: 'VulnScan Pro - Web & Mobile Security Scanner',
        version: process.env.APP_VERSION || '1.0.0'
    });
});

app.use((err, req, res, next) => {
    errorLogger(err, req, res, next);
    const errorId = req.id;
    console.error(`[${errorId}] Error:`, err.message);

    if (err.message === 'Not allowed by CORS') {
        return res.status(403).json({
            error: 'CORS policy violation'
        });
    }

    if (NODE_ENV === 'production') {
        return res.status(err.status || 500).json({
            error: 'An unexpected error occurred',
            reference: errorId
        });
    }

    res.status(err.status || 500).json({
        error: err.message || 'Internal server error',
        reference: errorId,
        path: req.path
    });
});

app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        path: req.path
    });
});

const startServer = async () => {
    try {
        if (!process.env.JWT_SECRET) {
            throw new Error('JWT_SECRET environment variable is required. Add it to your .env file.');
        }

        await initializeDatabase();
        await scanner.initializeDorkPatterns();

        console.log(`
========================================
  VulnScan Pro - Security Scanner API
  Environment: ${NODE_ENV}
  Port: ${PORT}
  CORS Origins: ${allowedOrigins.join(', ')}
========================================
        `);

        app.listen(PORT, () => {
            console.log(`🚀 Server running on http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error.message);
        process.exit(1);
    }
};

startServer();
