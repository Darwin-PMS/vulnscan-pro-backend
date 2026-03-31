const express = require('express');
const router = express.Router();
const scanController = require('../controllers/scanController');
const { optionalAuth, authenticateToken } = require('../middleware/auth');

// Stats routes - must come before /:scanId routes
router.get('/stats', authenticateToken, scanController.getDashboardStats);
router.get('/stats/dashboard', optionalAuth, scanController.getDashboardStats);

// User-specific stats (requires auth)
router.get('/user/stats', authenticateToken, scanController.getUserStats);

// Start a new scan
router.post('/start', optionalAuth, scanController.startScan);

// Get all scans
router.get('/', optionalAuth, scanController.getAllScans);

// Get vulnerability by ID - must come before /:scanId routes
router.get('/vulnerability/:vulnId', optionalAuth, scanController.getVulnerabilityById);

// Get scan status
router.get('/:scanId/status', optionalAuth, scanController.getScanStatus);

// Get scan results
router.get('/:scanId/results', optionalAuth, scanController.getScanResults);

// Get scan history
router.get('/:scanId/history', optionalAuth, scanController.getScanHistory);

// Delete scan
router.delete('/:scanId', optionalAuth, scanController.deleteScan);

module.exports = router;