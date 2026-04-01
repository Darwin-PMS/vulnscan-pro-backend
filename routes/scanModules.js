/**
 * Scan Modules API Routes
 * OWASP, GHDB, API, Cloud, CI/CD, Mobile, LLM, Container Scanner endpoints
 */

const express = require('express');
const router = express.Router();
const { authenticateToken, optionalAuth } = require('../middleware/auth');
const { requireAdmin } = require('../middleware/admin');
const { getAvailableScanners, scanWithModule, scanMultipleModules, scannerInstances } = require('../modules/scanner');
const { validateScanURL, checkSSRF } = require('../utils/security');

router.get('/modules', authenticateToken, (req, res) => {
    try {
        const scanners = getAvailableScanners();
        res.json({ modules: scanners });
    } catch (error) {
        console.error('Get modules error:', error);
        res.status(500).json({ error: 'Failed to get available modules' });
    }
});

router.get('/modules/owasp/categories', authenticateToken, (req, res) => {
    try {
        res.json(scannerInstances.owasp.getOWASPSummary());
    } catch (error) {
        console.error('Get OWASP categories error:', error);
        res.status(500).json({ error: 'Failed to get OWASP categories' });
    }
});

router.get('/modules/ghdb/categories', authenticateToken, (req, res) => {
    try {
        res.json(scannerInstances.ghdb.getGHDBSummary());
    } catch (error) {
        console.error('Get GHDB categories error:', error);
        res.status(500).json({ error: 'Failed to get GHDB categories' });
    }
});

router.get('/modules/api/categories', authenticateToken, (req, res) => {
    try {
        res.json(scannerInstances.api.getSummary());
    } catch (error) {
        console.error('Get API categories error:', error);
        res.status(500).json({ error: 'Failed to get API categories' });
    }
});

router.get('/modules/cloud/categories', authenticateToken, (req, res) => {
    try {
        res.json(scannerInstances.cloud.getSummary());
    } catch (error) {
        console.error('Get Cloud categories error:', error);
        res.status(500).json({ error: 'Failed to get Cloud categories' });
    }
});

router.get('/modules/cicd/categories', authenticateToken, (req, res) => {
    try {
        res.json(scannerInstances.cicd.getSummary());
    } catch (error) {
        console.error('Get CI/CD categories error:', error);
        res.status(500).json({ error: 'Failed to get CI/CD categories' });
    }
});

router.get('/modules/mobile/categories', authenticateToken, (req, res) => {
    try {
        res.json(scannerInstances.mobile.getSummary());
    } catch (error) {
        console.error('Get Mobile categories error:', error);
        res.status(500).json({ error: 'Failed to get Mobile categories' });
    }
});

router.get('/modules/llm/categories', authenticateToken, (req, res) => {
    try {
        res.json(scannerInstances.llm.getSummary());
    } catch (error) {
        console.error('Get LLM categories error:', error);
        res.status(500).json({ error: 'Failed to get LLM categories' });
    }
});

router.get('/modules/container/categories', authenticateToken, (req, res) => {
    try {
        res.json(scannerInstances.container.getSummary());
    } catch (error) {
        console.error('Get Container categories error:', error);
        res.status(500).json({ error: 'Failed to get Container categories' });
    }
});

router.post('/modules/scan', authenticateToken, async (req, res) => {
    try {
        const { url, module = 'all' } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        if (!validateScanURL(url)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        if (checkSSRF(url)) {
            return res.status(400).json({ error: 'URL blocked by SSRF protection' });
        }

        const { query } = require('../database/db');
        const scanId = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        const [result] = await query(
            `INSERT INTO scans (scan_id, user_id, target_url, status, scan_type) 
             VALUES (?, ?, ?, 'running', ?)`,
            [scanId, req.user.userId, url, module]
        );

        const scanResults = await scanWithModule(module, url, scanId);

        await query(
            `UPDATE scans SET 
             status = 'completed',
             total_vulnerabilities = ?,
             critical_count = ?,
             high_count = ?,
             medium_count = ?,
             low_count = ?,
             info_count = ?,
             completed_at = NOW()
             WHERE scan_id = ?`,
            [
                scanResults.vulnerabilities.length,
                scanResults.summary.critical,
                scanResults.summary.high,
                scanResults.summary.medium,
                scanResults.summary.low,
                scanResults.summary.info,
                scanId
            ]
        );

        for (const vuln of scanResults.vulnerabilities) {
            await query(
                `INSERT INTO vulnerabilities 
                 (scan_id, vulnerability_type, owasp_category, severity, title, description, url, remediation, ghdb_id) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    scanId,
                    vuln.category || vuln.categoryName,
                    vuln.category,
                    vuln.severity,
                    vuln.title,
                    vuln.description,
                    vuln.url,
                    vuln.remediation,
                    vuln.id
                ]
            );
        }

        await query(
            `INSERT INTO scan_history (scan_id, action, details) VALUES (?, 'scan_completed', ?)`,
            [scanId, JSON.stringify({ vulnerabilities: scanResults.vulnerabilities.length })]
        );

        res.json({
            scanId,
            targetUrl: url,
            module,
            status: 'completed',
            totalVulnerabilities: scanResults.vulnerabilities.length,
            summary: scanResults.summary,
            categories: scanResults.categories,
            vulnerabilities: scanResults.vulnerabilities
        });

    } catch (error) {
        console.error('Module scan error:', error);
        res.status(500).json({ error: 'Failed to run module scan' });
    }
});

router.post('/modules/owasp/scan', authenticateToken, async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        if (!validateScanURL(url)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        if (checkSSRF(url)) {
            return res.status(400).json({ error: 'URL blocked by SSRF protection' });
        }

        const { OWASPScanner } = require('../modules/scanner');
        const scanner = new OWASPScanner();
        const scanId = `owasp_${Date.now()}`;

        const results = await scanner.scanTarget(url, scanId);
        res.json(results);

    } catch (error) {
        console.error('OWASP scan error:', error);
        res.status(500).json({ error: 'Failed to run OWASP scan' });
    }
});

router.post('/modules/ghdb/scan', authenticateToken, async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        if (!validateScanURL(url)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        if (checkSSRF(url)) {
            return res.status(400).json({ error: 'URL blocked by SSRF protection' });
        }

        const { GHDBScanner } = require('../modules/scanner');
        const scanner = new GHDBScanner();
        const scanId = `ghdb_${Date.now()}`;

        const results = await scanner.scanTarget(url, scanId);
        res.json(results);

    } catch (error) {
        console.error('GHDB scan error:', error);
        res.status(500).json({ error: 'Failed to run GHDB scan' });
    }
});

router.post('/modules/api/scan', authenticateToken, async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        if (!validateScanURL(url)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        if (checkSSRF(url)) {
            return res.status(400).json({ error: 'URL blocked by SSRF protection' });
        }

        const { APISecurityScanner } = require('../modules/scanner');
        const scanner = new APISecurityScanner();
        const scanId = `api_${Date.now()}`;

        const results = await scanner.scanTarget(url, scanId);
        res.json(results);

    } catch (error) {
        console.error('API scan error:', error);
        res.status(500).json({ error: 'Failed to run API scan' });
    }
});

router.post('/modules/cloud/scan', authenticateToken, async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        if (!validateScanURL(url)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        if (checkSSRF(url)) {
            return res.status(400).json({ error: 'URL blocked by SSRF protection' });
        }

        const { CloudSecurityScanner } = require('../modules/scanner');
        const scanner = new CloudSecurityScanner();
        const scanId = `cloud_${Date.now()}`;

        const results = await scanner.scanTarget(url, scanId);
        res.json(results);

    } catch (error) {
        console.error('Cloud scan error:', error);
        res.status(500).json({ error: 'Failed to run Cloud scan' });
    }
});

router.post('/modules/cicd/scan', authenticateToken, async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        if (!validateScanURL(url)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        if (checkSSRF(url)) {
            return res.status(400).json({ error: 'URL blocked by SSRF protection' });
        }

        const { CICDSecurityScanner } = require('../modules/scanner');
        const scanner = new CICDSecurityScanner();
        const scanId = `cicd_${Date.now()}`;

        const results = await scanner.scanTarget(url, scanId);
        res.json(results);

    } catch (error) {
        console.error('CI/CD scan error:', error);
        res.status(500).json({ error: 'Failed to run CI/CD scan' });
    }
});

router.post('/modules/mobile/scan', authenticateToken, async (req, res) => {
    try {
        const { url, platform = 'android', content } = req.body;

        if (!url && !content) {
            return res.status(400).json({ error: 'URL or content is required' });
        }

        const { MobileSecurityScanner } = require('../modules/scanner');
        const scanner = new MobileSecurityScanner();
        const scanId = `mobile_${Date.now()}`;

        const results = await scanner.scanTarget(url || 'local', scanId, { platform, content });
        res.json(results);

    } catch (error) {
        console.error('Mobile scan error:', error);
        res.status(500).json({ error: 'Failed to run Mobile scan' });
    }
});

router.post('/modules/llm/scan', authenticateToken, async (req, res) => {
    try {
        const { prompt } = req.body;

        if (!prompt) {
            return res.status(400).json({ error: 'Prompt is required' });
        }

        const { LLMSecurityScanner } = require('../modules/scanner');
        const scanner = new LLMSecurityScanner();
        const scanId = `llm_${Date.now()}`;

        const results = await scanner.scanTarget(prompt, scanId);
        res.json(results);

    } catch (error) {
        console.error('LLM scan error:', error);
        res.status(500).json({ error: 'Failed to run LLM scan' });
    }
});

router.post('/modules/llm/validate', authenticateToken, async (req, res) => {
    try {
        const { prompt } = req.body;

        if (!prompt) {
            return res.status(400).json({ error: 'Prompt is required' });
        }

        const { LLMSecurityScanner } = require('../modules/scanner');
        const scanner = new LLMSecurityScanner();

        const validation = scanner.validatePrompt(prompt);
        res.json(validation);

    } catch (error) {
        console.error('LLM validate error:', error);
        res.status(500).json({ error: 'Failed to validate prompt' });
    }
});

router.post('/modules/container/scan', authenticateToken, async (req, res) => {
    try {
        const { url, type = 'docker', content } = req.body;

        if (!url && !content) {
            return res.status(400).json({ error: 'URL or content is required' });
        }

        const { ContainerSecurityScanner } = require('../modules/scanner');
        const scanner = new ContainerSecurityScanner();
        const scanId = `container_${Date.now()}`;

        const results = await scanner.scanTarget(url || 'local', scanId, { type, content });
        res.json(results);

    } catch (error) {
        console.error('Container scan error:', error);
        res.status(500).json({ error: 'Failed to run Container scan' });
    }
});

router.post('/modules/multi-scan', authenticateToken, async (req, res) => {
    try {
        const { url, modules } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        if (!modules || !Array.isArray(modules) || modules.length === 0) {
            return res.status(400).json({ error: 'modules array is required' });
        }

        if (!validateScanURL(url)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        if (checkSSRF(url)) {
            return res.status(400).json({ error: 'URL blocked by SSRF protection' });
        }

        const { query } = require('../database/db');
        const scanId = `multi_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        await query(
            `INSERT INTO scans (scan_id, user_id, target_url, status, scan_type) VALUES (?, ?, ?, 'running', ?)`,
            [scanId, req.user.userId, url, modules.join(',')]
        );

        const scanResults = await scanMultipleModules(modules, url, scanId);

        await query(
            `UPDATE scans SET status = 'completed', total_vulnerabilities = ?, critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, info_count = ?, completed_at = NOW() WHERE scan_id = ?`,
            [scanResults.vulnerabilities.length, scanResults.summary.critical, scanResults.summary.high, scanResults.summary.medium, scanResults.summary.low, scanResults.summary.info, scanId]
        );

        for (const vuln of scanResults.vulnerabilities) {
            await query(
                `INSERT INTO vulnerabilities (scan_id, vulnerability_type, owasp_category, severity, title, description, url, remediation, ghdb_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [scanId, vuln.category || vuln.categoryName || vuln.pipelineType, vuln.category || vuln.provider || 'General', vuln.severity, vuln.title, vuln.description, vuln.url, vuln.remediation, vuln.id]
            );
        }

        res.json({
            scanId,
            targetUrl: url,
            modules,
            status: 'completed',
            totalVulnerabilities: scanResults.vulnerabilities.length,
            summary: scanResults.summary,
            results: scanResults.results,
            vulnerabilities: scanResults.vulnerabilities
        });

    } catch (error) {
        console.error('Multi-scan error:', error);
        res.status(500).json({ error: 'Failed to run multi-module scan' });
    }
});

router.get('/modules/scans', authenticateToken, async (req, res) => {
    try {
        const { query } = require('../database/db');
        const { type, status, page = 1, limit = 20 } = req.query;

        let sql = `SELECT * FROM scans WHERE user_id = ?`;
        const params = [req.user.userId];

        if (type) {
            sql += ` AND scan_type = ?`;
            params.push(type);
        }

        if (status) {
            sql += ` AND status = ?`;
            params.push(status);
        }

        sql += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
        params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

        const [scans] = await query(sql, params);

        const [[{ total }]] = await query(
            `SELECT COUNT(*) as total FROM scans WHERE user_id = ? ${type ? 'AND scan_type = ?' : ''} ${status ? 'AND status = ?' : ''}`,
            type ? [req.user.userId, type, status] : status ? [req.user.userId, status] : [req.user.userId]
        );

        res.json({ scans, total, page: parseInt(page), limit: parseInt(limit) });

    } catch (error) {
        console.error('Get module scans error:', error);
        res.status(500).json({ error: 'Failed to get scans' });
    }
});

router.get('/modules/scan/:scanId', authenticateToken, async (req, res) => {
    try {
        const { scanId } = req.params;
        const { query } = require('../database/db');

        const [scans] = await query(
            `SELECT * FROM scans WHERE scan_id = ? AND user_id = ?`,
            [scanId, req.user.userId]
        );

        if (scans.length === 0) {
            return res.status(404).json({ error: 'Scan not found' });
        }

        const [vulnerabilities] = await query(
            `SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info')`,
            [scanId]
        );

        res.json({
            scan: scans[0],
            vulnerabilities
        });

    } catch (error) {
        console.error('Get scan details error:', error);
        res.status(500).json({ error: 'Failed to get scan details' });
    }
});

module.exports = router;
