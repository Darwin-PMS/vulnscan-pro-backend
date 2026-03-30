const express = require('express');
const router = express.Router();
const { pool } = require('../database/db');

// Get all dork patterns
router.get('/', async (req, res) => {
    try {
        const [patterns] = await pool.query(
            'SELECT * FROM dork_patterns WHERE is_active = TRUE ORDER BY severity DESC'
        );
        res.json({ patterns });
    } catch (error) {
        console.error('Error fetching dork patterns:', error);
        res.status(500).json({ error: 'Failed to fetch dork patterns' });
    }
});

// Get dork patterns by category
router.get('/category/:category', async (req, res) => {
    try {
        const { category } = req.params;
        const [patterns] = await pool.query(
            'SELECT * FROM dork_patterns WHERE category = ? AND is_active = TRUE',
            [category]
        );
        res.json({ patterns });
    } catch (error) {
        console.error('Error fetching dork patterns:', error);
        res.status(500).json({ error: 'Failed to fetch dork patterns' });
    }
});

// Get dork pattern by GHDB ID
router.get('/ghdb/:ghdbId', async (req, res) => {
    try {
        const { ghdbId } = req.params;
        const [patterns] = await pool.query(
            'SELECT * FROM dork_patterns WHERE ghdb_id = ?',
            [ghdbId]
        );

        if (patterns.length === 0) {
            return res.status(404).json({ error: 'Dork pattern not found' });
        }

        res.json({ pattern: patterns[0] });
    } catch (error) {
        console.error('Error fetching dork pattern:', error);
        res.status(500).json({ error: 'Failed to fetch dork pattern' });
    }
});

module.exports = router;