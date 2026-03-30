const { pool } = require('../database/db');
const scanner = require('../services/vulnerabilityScanner');
const { v4: uuidv4 } = require('uuid');

const scanController = {
    // Start a new scan
    async startScan(req, res) {
        try {
            const { url } = req.body;

            if (!url) {
                return res.status(400).json({ error: 'URL is required' });
            }

            const scanId = uuidv4();

            // Create scan record
            await pool.query(
                'INSERT INTO scans (scan_id, target_url, status) VALUES (?, ?, ?)',
                [scanId, url, 'pending']
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

            const [scans] = await pool.query(
                `SELECT s.*, 
          COUNT(v.id) as total_vulnerabilities,
          SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
          SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high_count
         FROM scans s
         LEFT JOIN vulnerabilities v ON s.scan_id = v.scan_id
         GROUP BY s.id
         ORDER BY s.created_at DESC
         LIMIT ? OFFSET ?`,
                [parseInt(limit), parseInt(offset)]
            );

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

    // Delete scan
    async deleteScan(req, res) {
        try {
            const { scanId } = req.params;

            await pool.query('DELETE FROM scans WHERE scan_id = ?', [scanId]);

            res.json({ success: true, message: 'Scan deleted successfully' });
        } catch (error) {
            console.error('Error deleting scan:', error);
            res.status(500).json({ error: 'Failed to delete scan' });
        }
    },

    // Get dashboard stats
    async getDashboardStats(req, res) {
        try {
            // Total scans
            const [totalScans] = await pool.query('SELECT COUNT(*) as count FROM scans');

            // Total vulnerabilities
            const [totalVulns] = await pool.query('SELECT COUNT(*) as count FROM vulnerabilities');

            // Vulnerabilities by severity
            const [severityCounts] = await pool.query(
                'SELECT severity, COUNT(*) as count FROM vulnerabilities GROUP BY severity'
            );

            // Recent scans
            const [recentScans] = await pool.query(
                `SELECT s.*, 
          COUNT(v.id) as vuln_count
         FROM scans s
         LEFT JOIN vulnerabilities v ON s.scan_id = v.scan_id
         GROUP BY s.id
         ORDER BY s.created_at DESC
         LIMIT 5`
            );

            // Most common vulnerability types
            const [commonVulns] = await pool.query(
                `SELECT vulnerability_type, COUNT(*) as count 
         FROM vulnerabilities 
         GROUP BY vulnerability_type 
         ORDER BY count DESC 
         LIMIT 5`
            );

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