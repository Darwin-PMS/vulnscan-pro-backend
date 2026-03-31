const express = require('express');
const router = express.Router();
const subscriptionController = require('../controllers/subscriptionController');
const { authenticateToken } = require('../middleware/auth');

router.get('/tiers', subscriptionController.getAllTiers);

router.get('/tiers/:tierId', subscriptionController.getTier);

router.get('/current', authenticateToken, subscriptionController.getUserSubscription);

router.post('/subscribe', authenticateToken, subscriptionController.subscribe);

router.post('/cancel', authenticateToken, subscriptionController.cancelSubscription);

router.get('/features/:feature', authenticateToken, subscriptionController.checkFeatureAccess);

router.get('/check-limit', authenticateToken, subscriptionController.checkScanLimit);

router.get('/usage', authenticateToken, subscriptionController.getUsageStats);

module.exports = router;
