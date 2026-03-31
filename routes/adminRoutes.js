const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { requireAdmin } = require('../middleware/admin');

router.use(requireAdmin);

router.get('/dashboard', adminController.getDashboardStats);

router.get('/users', adminController.getAllUsers);
router.get('/users/:userId', adminController.getUserById);
router.post('/users', adminController.createUser);
router.put('/users/:userId', adminController.updateUser);
router.delete('/users/:userId', adminController.deleteUser);

router.get('/subscriptions', adminController.getAllSubscriptions);
router.put('/subscriptions/:subId', adminController.updateSubscription);

router.get('/tiers', adminController.getSubscriptionTiers);
router.put('/tiers/:tierId', adminController.updateSubscriptionTier);

router.get('/scans', adminController.getAllScans);
router.delete('/scans/:scanId', adminController.deleteScan);

module.exports = router;
