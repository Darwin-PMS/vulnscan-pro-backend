const express = require('express');
const router = express.Router();
const aiController = require('../controllers/aiController');

// General chat with AI
router.post('/chat', aiController.chat);

// Analyze vulnerability
router.post('/analyze', aiController.analyzeVulnerability);

// Generate report summary
router.post('/report-summary', aiController.generateReportSummary);

// Get remediation suggestions
router.post('/remediation', aiController.suggestRemediation);

// Explain CVE
router.get('/cve/:cveId', aiController.explainCVE);

// Get security tips
router.get('/tips', aiController.getSecurityTips);

module.exports = router;
