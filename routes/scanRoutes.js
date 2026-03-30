const express = require('express');
const router = express.Router();
const scanController = require('../controllers/scanController');

// Start a new scan
router.post('/start', scanController.startScan);

// Get all scans
router.get('/', scanController.getAllScans);

// Get dashboard stats
router.get('/stats/dashboard', scanController.getDashboardStats);

// Get scan status
router.get('/:scanId/status', scanController.getScanStatus);

// Get scan results
router.get('/:scanId/results', scanController.getScanResults);

// Get scan history
router.get('/:scanId/history', scanController.getScanHistory);

// Get vulnerability by ID
router.get('/vulnerability/:vulnId', scanController.getVulnerabilityById);

// Delete scan
router.delete('/:scanId', scanController.deleteScan);

module.exports = router;