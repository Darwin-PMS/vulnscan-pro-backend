const express = require('express');
const router = express.Router();
const mobileController = require('../controllers/mobileController');
const { optionalAuth } = require('../middleware/auth');

router.use(optionalAuth);

router.post('/scan', mobileController.scanAPK);
router.post('/analyze/manifest', mobileController.analyzeManifest);
router.post('/analyze/code', mobileController.analyzeCode);
router.post('/analyze/network', mobileController.analyzeNetwork);
router.get('/patterns/:platform', mobileController.getPatterns);
router.get('/tools/:platform', mobileController.getTools);
router.get('/guide/:platform', mobileController.getSecurityGuide);

module.exports = router;
