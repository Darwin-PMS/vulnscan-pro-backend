const express = require('express');
const router = express.Router();
const { getLogs, clearLogs, getLogStats } = require('../middleware/apiLogger');
const { authenticateToken } = require('../middleware/auth');

router.use(authenticateToken);

router.get('/stats', async (req, res) => {
    try {
        const stats = await getLogStats();
        res.json({
            success: true,
            data: stats
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.get('/requests', async (req, res) => {
    try {
        const { limit = 100, type = 'requests' } = req.query;
        const logs = await getLogs(type, parseInt(limit));
        res.json({
            success: true,
            count: logs.length,
            data: logs
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.get('/errors', async (req, res) => {
    try {
        const { limit = 100 } = req.query;
        const logs = await getLogs('errors', parseInt(limit));
        res.json({
            success: true,
            count: logs.length,
            data: logs
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.get('/audit', async (req, res) => {
    try {
        const { limit = 100 } = req.query;
        const logs = await getLogs('audit', parseInt(limit));
        res.json({
            success: true,
            count: logs.length,
            data: logs
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.delete('/clear', async (req, res) => {
    try {
        const { type = 'all' } = req.body;
        
        if (type === 'all' || type === 'requests') {
            await clearLogs('requests');
        }
        if (type === 'all' || type === 'errors') {
            await clearLogs('errors');
        }
        if (type === 'all' || type === 'audit') {
            await clearLogs('audit');
        }
        
        res.json({
            success: true,
            message: `Logs cleared: ${type}`
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
