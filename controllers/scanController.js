const { pool } = require('../database/db');
const scanner = require('../services/vulnerabilityScanner');
const { v4: uuidv4 } = require('uuid');
const subscriptionController = require('./subscriptionController');
const { validateScanURL } = require('../utils/security');

const scanController = {
    async startScan(req, res) {
        try {
            const { url } = req.body;
            const userId = req.user?.userId || null;

            if (!url) {
                return res.status(400).json({ error: 'URL is required' });
            }

            try {
                validateScanURL(url);
            } catch (validationError) {
                return res.status(400).json({ error: validationError.message });
            }

            const scanId = uuidv4();

            // Create scan record with optional user_id
            await pool.query(
                'INSERT INTO scans (scan_id, user_id, target_url, status) VALUES (?, ?, ?, ?)',
                [scanId, userId, url, 'pending']
            );

            // Log start
            await pool.query(
                'INSERT INTO scan_history (scan_id, action, details) VALUES (?, ?, ?)',
                [scanId, 'scan_started', `Scan initiated for ${url}`]
            );

            // Update status to running
            await pool.query(
                'UPDATE scans SET status = ? WHERE scan_id = ?',
                ['running', scanId]
            );

            // Increment scan count for authenticated users
            if (userId) {
                await subscriptionController.incrementScanCount(userId);
            }

            // Start scan in background
            runScan(scanId, url);

            res.json({
                success: true,
                scanId,
                message: 'Scan started successfully',
                url
            });
        } catch (error) {
            console.error('Error starting scan:', error);
            res.status(500).json({ error: 'Failed to start scan' });
        }
    },

    // Get scan status
    async getScanStatus(req, res) {
        try {
            const { scanId } = req.params;

            const [scans] = await pool.query(
                'SELECT * FROM scans WHERE scan_id = ?',
                [scanId]
            );

            if (scans.length === 0) {
                return res.status(404).json({ error: 'Scan not found' });
            }

            const scan = scans[0];

            // Get vulnerability summary
            const [vulnSummary] = await pool.query(
                `SELECT severity, COUNT(*) as count 
         FROM vulnerabilities 
         WHERE scan_id = ? 
         GROUP BY severity`,
                [scanId]
            );

            res.json({
                scanId: scan.scan_id,
                url: scan.target_url,
                status: scan.status,
                createdAt: scan.created_at,
                completedAt: scan.completed_at,
                summary: vulnSummary
            });
        } catch (error) {
            console.error('Error getting scan status:', error);
            res.status(500).json({ error: 'Failed to get scan status' });
        }
    },

    // Get scan results
    async getScanResults(req, res) {
        try {
            const { scanId } = req.params;
            const { severity, limit = 100, offset = 0 } = req.query;

            // Verify scan exists
            const [scans] = await pool.query(
                'SELECT * FROM scans WHERE scan_id = ?',
                [scanId]
            );

            if (scans.length === 0) {
                return res.status(404).json({ error: 'Scan not found' });
            }

            let query = 'SELECT * FROM vulnerabilities WHERE scan_id = ?';
            const params = [scanId];

            if (severity) {
                query += ' AND severity = ?';
                params.push(severity);
            }

            query += ' ORDER BY FIELD(severity, "critical", "high", "medium", "low", "info"), discovered_at DESC';
            query += ' LIMIT ? OFFSET ?';
            params.push(parseInt(limit), parseInt(offset));

            const [vulnerabilities] = await pool.query(query, params);

            // Get counts by severity
            const [counts] = await pool.query(
                `SELECT severity, COUNT(*) as count 
         FROM vulnerabilities 
         WHERE scan_id = ? 
         GROUP BY severity`,
                [scanId]
            );

            const summary = {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0
            };

            counts.forEach(row => {
                summary[row.severity] = row.count;
            });

            res.json({
                scanId,
                scan: scans[0],
                summary,
                vulnerabilities,
                total: vulnerabilities.length
            });
        } catch (error) {
            console.error('Error getting scan results:', error);
            res.status(500).json({ error: 'Failed to get scan results' });
        }
    },

    // Get all scans
    async getAllScans(req, res) {
        try {
            const { limit = 20, offset = 0 } = req.query;
            const userId = req.user?.userId || null;

            let query;
            let params;

            if (userId) {
                // Authenticated users see their own scans
                query = `
                    SELECT s.*, 
                    COUNT(v.id) as total_vulnerabilities,
                    SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high_count
                   FROM scans s
                   LEFT JOIN vulnerabilities v ON s.scan_id = v.scan_id
                   WHERE s.user_id = ?
                   GROUP BY s.id
                   ORDER BY s.created_at DESC
                   LIMIT ? OFFSET ?`;
                params = [userId, parseInt(limit), parseInt(offset)];
            } else {
                // Anonymous users see all scans (shared scanner)
                query = `
                    SELECT s.*, 
                    COUNT(v.id) as total_vulnerabilities,
                    SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high_count
                   FROM scans s
                   LEFT JOIN vulnerabilities v ON s.scan_id = v.scan_id
                   GROUP BY s.id
                   ORDER BY s.created_at DESC
                   LIMIT ? OFFSET ?`;
                params = [parseInt(limit), parseInt(offset)];
            }

            const [scans] = await pool.query(query, params);

            res.json({
                scans,
                total: scans.length
            });
        } catch (error) {
            console.error('Error getting scans:', error);
            res.status(500).json({ error: 'Failed to get scans' });
        }
    },

    // Get scan history
    async getScanHistory(req, res) {
        try {
            const { scanId } = req.params;

            const [history] = await pool.query(
                'SELECT * FROM scan_history WHERE scan_id = ? ORDER BY timestamp DESC',
                [scanId]
            );

            res.json({ scanId, history });
        } catch (error) {
            console.error('Error getting scan history:', error);
            res.status(500).json({ error: 'Failed to get scan history' });
        }
    },

    // Delete scan (soft delete - preserve for audit)
    async deleteScan(req, res) {
        try {
            const { scanId } = req.params;

            await pool.query('UPDATE scans SET status = ?, deleted_at = NOW() WHERE scan_id = ?', ['deleted', scanId]);

            res.json({ success: true, message: 'Scan soft deleted - preserved for audit trail' });
        } catch (error) {
            console.error('Error deleting scan:', error);
            res.status(500).json({ error: 'Failed to delete scan' });
        }
    },

    // Get dashboard stats
    async getDashboardStats(req, res) {
        try {
            const userId = req.user?.userId || null;
            console.log('getDashboardStats called with userId:', userId);

            let scanCondition = '';
            let params = [];

            if (userId) {
                scanCondition = 'WHERE user_id = ?';
                params.push(userId);
            }

            // Total scans
            const [totalScans] = await pool.query(`SELECT COUNT(*) as count FROM scans ${scanCondition}`, params);
            console.log('Total scans for userId', userId, ':', totalScans[0].count);

            // Total vulnerabilities (only from user's scans if authenticated)
            let vulnQuery;
            let vulnParams;
            if (userId) {
                vulnQuery = `SELECT COUNT(*) as count FROM vulnerabilities v JOIN scans s ON v.scan_id = s.scan_id WHERE s.user_id = ?`;
                vulnParams = [userId];
            } else {
                vulnQuery = 'SELECT COUNT(*) as count FROM vulnerabilities';
                vulnParams = [];
            }
            const [totalVulns] = await pool.query(vulnQuery, vulnParams);

            // Vulnerabilities by severity
            let severityQuery;
            let severityParams;
            if (userId) {
                severityQuery = `SELECT v.severity, COUNT(*) as count 
                    FROM vulnerabilities v 
                    JOIN scans s ON v.scan_id = s.scan_id 
                    WHERE s.user_id = ?
                    GROUP BY v.severity`;
                severityParams = [userId];
            } else {
                severityQuery = 'SELECT severity, COUNT(*) as count FROM vulnerabilities GROUP BY severity';
                severityParams = [];
            }
            const [severityCounts] = await pool.query(severityQuery, severityParams);

            // Recent scans
            let recentQuery;
            let recentParams;
            if (userId) {
                recentQuery = `SELECT s.*, 
                    COUNT(v.id) as vuln_count
                   FROM scans s
                   LEFT JOIN vulnerabilities v ON s.scan_id = v.scan_id
                   WHERE s.user_id = ?
                   GROUP BY s.id
                   ORDER BY s.created_at DESC
                   LIMIT 5`;
                recentParams = [userId];
            } else {
                recentQuery = `SELECT s.*, 
                    COUNT(v.id) as vuln_count
                   FROM scans s
                   LEFT JOIN vulnerabilities v ON s.scan_id = v.scan_id
                   GROUP BY s.id
                   ORDER BY s.created_at DESC
                   LIMIT 5`;
                recentParams = [];
            }
            const [recentScans] = await pool.query(recentQuery, recentParams);

            // Most common vulnerability types
            let commonQuery;
            let commonParams;
            if (userId) {
                commonQuery = `SELECT v.vulnerability_type, COUNT(*) as count 
                    FROM vulnerabilities v 
                    JOIN scans s ON v.scan_id = s.scan_id 
                    WHERE s.user_id = ?
                    GROUP BY v.vulnerability_type 
                    ORDER BY count DESC 
                    LIMIT 5`;
                commonParams = [userId];
            } else {
                commonQuery = `SELECT vulnerability_type, COUNT(*) as count 
                    FROM vulnerabilities 
                    GROUP BY vulnerability_type 
                    ORDER BY count DESC 
                    LIMIT 5`;
                commonParams = [];
            }
            const [commonVulns] = await pool.query(commonQuery, commonParams);

            res.json({
                totalScans: totalScans[0].count,
                totalVulnerabilities: totalVulns[0].count,
                severityBreakdown: severityCounts,
                recentScans,
                commonVulnerabilities: commonVulns
            });
        } catch (error) {
            console.error('Error getting dashboard stats:', error);
            res.status(500).json({ error: 'Failed to get dashboard stats' });
        }
    },

    // Get user stats (always requires authentication)
    async getUserStats(req, res) {
        try {
            const userId = req.user?.userId;
            console.log('getUserStats called with userId:', userId);

            if (!userId) {
                console.log('No userId found, returning empty stats');
                return res.json({
                    totalScans: 0,
                    totalVulnerabilities: 0,
                    severityBreakdown: [],
                    recentScans: []
                });
            }

            // Total scans for this user
            const [totalScans] = await pool.query(
                'SELECT COUNT(*) as count FROM scans WHERE user_id = ?',
                [userId]
            );

            // Total vulnerabilities from user's scans
            const [totalVulns] = await pool.query(
                `SELECT COUNT(*) as count FROM vulnerabilities v 
                 JOIN scans s ON v.scan_id = s.scan_id 
                 WHERE s.user_id = ?`,
                [userId]
            );

            // Vulnerabilities by severity
            const [severityCounts] = await pool.query(
                `SELECT v.severity, COUNT(*) as count 
                 FROM vulnerabilities v 
                 JOIN scans s ON v.scan_id = s.scan_id 
                 WHERE s.user_id = ?
                 GROUP BY v.severity`,
                [userId]
            );

            // Recent scans
            const [recentScans] = await pool.query(
                `SELECT s.*, COUNT(v.id) as vuln_count
                 FROM scans s
                 LEFT JOIN vulnerabilities v ON s.scan_id = v.scan_id
                 WHERE s.user_id = ?
                 GROUP BY s.id
                 ORDER BY s.created_at DESC
                 LIMIT 5`,
                [userId]
            );

            console.log('Returning stats:', { 
                totalScans: totalScans[0].count,
                totalVulnerabilities: totalVulns[0].count 
            });

            res.json({
                totalScans: totalScans[0].count,
                totalVulnerabilities: totalVulns[0].count,
                severityBreakdown: severityCounts,
                recentScans
            });
        } catch (error) {
            console.error('Error getting user stats:', error);
            res.status(500).json({ error: 'Failed to get user stats' });
        }
    },

    // Debug endpoint - get raw user data
    async getDebugStats(req, res) {
        try {
            const userId = req.user?.userId;

            if (!userId) {
                return res.json({ 
                    error: 'Not authenticated',
                    userId: null 
                });
            }

            // Get all scans for this user
            const [scans] = await pool.query(
                'SELECT scan_id, target_url, status, user_id, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC',
                [userId]
            );

            // Get total count
            const [countResult] = await pool.query(
                'SELECT COUNT(*) as count FROM scans WHERE user_id = ?',
                [userId]
            );

            res.json({
                userId,
                totalScans: countResult[0].count,
                scans: scans
            });
        } catch (error) {
            console.error('Debug error:', error);
            res.status(500).json({ error: error.message });
        }
    },

    // Get vulnerability by ID
    async getVulnerabilityById(req, res) {
        try {
            const { vulnId } = req.params;

            const [vulnerabilities] = await pool.query(
                'SELECT * FROM vulnerabilities WHERE id = ?',
                [vulnId]
            );

            if (vulnerabilities.length === 0) {
                return res.status(404).json({ error: 'Vulnerability not found' });
            }

            // Get related scan info
            const [scanInfo] = await pool.query(
                'SELECT scan_id, target_url FROM scans WHERE scan_id = ?',
                [vulnerabilities[0].scan_id]
            );

            res.json({
                vulnerability: {
                    ...vulnerabilities[0],
                    scan_target_url: scanInfo[0]?.target_url || null
                }
            });
        } catch (error) {
            console.error('Error getting vulnerability:', error);
            res.status(500).json({ error: 'Failed to get vulnerability details' });
        }
    }
};

// Background scan runner
async function runScan(scanId, url) {
    try {
        console.log(`Running scan ${scanId} for ${url}`);

        const vulnerabilities = await scanner.scanTarget(url, scanId);

        // Save vulnerabilities
        for (const vuln of vulnerabilities) {
            vuln.scan_id = scanId;
            await pool.query(
                `INSERT INTO vulnerabilities
         (scan_id, vulnerability_type, owasp_category, severity, title, description, url, evidence, remediation, ghdb_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    vuln.scan_id,
                    vuln.vulnerability_type,
                    vuln.owasp_category || null,
                    vuln.severity,
                    vuln.title,
                    vuln.description,
                    vuln.url,
                    vuln.evidence,
                    vuln.remediation,
                    vuln.ghdb_id
                ]
            );
        }

        // Update scan status
        const severityCounts = {
            critical: vulnerabilities.filter(v => v.severity === 'critical').length,
            high: vulnerabilities.filter(v => v.severity === 'high').length,
            medium: vulnerabilities.filter(v => v.severity === 'medium').length,
            low: vulnerabilities.filter(v => v.severity === 'low').length,
            info: vulnerabilities.filter(v => v.severity === 'info').length
        };

        await pool.query(
            `UPDATE scans SET 
        status = ?, 
        total_vulnerabilities = ?,
        critical_count = ?,
        high_count = ?,
        medium_count = ?,
        low_count = ?,
        info_count = ?,
        completed_at = NOW()
       WHERE scan_id = ?`,
            [
                'completed',
                vulnerabilities.length,
                severityCounts.critical,
                severityCounts.high,
                severityCounts.medium,
                severityCounts.low,
                severityCounts.info,
                scanId
            ]
        );

        // Log completion
        await pool.query(
            'INSERT INTO scan_history (scan_id, action, details) VALUES (?, ?, ?)',
            [scanId, 'scan_completed', `Scan completed. Found ${vulnerabilities.length} vulnerabilities`]
        );

        console.log(`Scan ${scanId} completed. Found ${vulnerabilities.length} vulnerabilities`);
    } catch (error) {
        console.error(`Error in scan ${scanId}:`, error);

        await pool.query(
            'UPDATE scans SET status = ? WHERE scan_id = ?',
            ['failed', scanId]
        );

        await pool.query(
            'INSERT INTO scan_history (scan_id, action, details) VALUES (?, ?, ?)',
            [scanId, 'scan_failed', error.message]
        );
    }
}

module.exports = scanController;