const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { initializeDatabase } = require('./database/db');
const scanner = require('./services/vulnerabilityScanner');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
const scanRoutes = require('./routes/scanRoutes');
const dorkRoutes = require('./routes/dorkRoutes');
const aiRoutes = require('./routes/aiRoutes');

app.use('/api/scans', scanRoutes);
app.use('/api/dorks', dorkRoutes);
app.use('/api/ai', aiRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        service: 'Web Vulnerability Scanner API'
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: err.message
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Initialize database and start server
const startServer = async () => {
    try {
        await initializeDatabase();
        await scanner.initializeDorkPatterns();

        app.listen(PORT, () => {
            console.log(`
========================================
  Web Vulnerability Scanner API
  Server running on port ${PORT}
========================================
      `);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
};

startServer();