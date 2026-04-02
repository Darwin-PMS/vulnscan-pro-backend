const { query } = require('../database/db');

const SUBSCRIPTION_FEATURES = {
    free: {
        basic_scans: true,
        owasp_top10: true,
        ghdb_patterns: true,
        pdf_reports: false,
        api_access: false,
        priority_support: false,
        ai_assistant: false,
        custom_dorks: false,
        scheduled_scans: false,
        team_collaboration: false,
        advanced_payloads: false,
        retest_vulnerabilities: false
    },
    starter: {
        basic_scans: true,
        owasp_top10: true,
        ghdb_patterns: true,
        pdf_reports: true,
        api_access: false,
        priority_support: false,
        ai_assistant: false,
        custom_dorks: false,
        scheduled_scans: false,
        team_collaboration: false,
        advanced_payloads: false,
        retest_vulnerabilities: false
    },
    professional: {
        basic_scans: true,
        owasp_top10: true,
        ghdb_patterns: true,
        pdf_reports: true,
        api_access: true,
        priority_support: true,
        ai_assistant: true,
        custom_dorks: false,
        scheduled_scans: true,
        team_collaboration: false,
        advanced_payloads: true,
        retest_vulnerabilities: false
    },
    enterprise: {
        basic_scans: true,
        owasp_top10: true,
        ghdb_patterns: true,
        pdf_reports: true,
        api_access: true,
        priority_support: true,
        ai_assistant: true,
        custom_dorks: true,
        scheduled_scans: true,
        team_collaboration: true,
        advanced_payloads: true,
        retest_vulnerabilities: true
    }
};

const SUBSCRIPTION_LIMITS = {
    free: { scan_limit: 5, concurrent_scans: 1 },
    starter: { scan_limit: 50, concurrent_scans: 2 },
    professional: { scan_limit: 200, concurrent_scans: 5 },
    enterprise: { scan_limit: -1, concurrent_scans: 10 } // -1 = unlimited
};

const subscriptionController = {
    async getAllTiers(req, res) {
        try {
            const tiers = await query(
                'SELECT * FROM subscription_tiers WHERE is_active = TRUE ORDER BY price_monthly ASC'
            );

            const formattedTiers = tiers.map(tier => ({
                ...tier,
                features: typeof tier.features === 'string' ? JSON.parse(tier.features) : tier.features
            }));

            res.json({ tiers: formattedTiers });
        } catch (error) {
            console.error('Error fetching subscription tiers:', error);
            res.status(500).json({ error: 'Failed to fetch subscription tiers' });
        }
    },

    async getTier(req, res) {
        try {
            const { tierId } = req.params;
            const [tier] = await query(
                'SELECT * FROM subscription_tiers WHERE tier_id = ? AND is_active = TRUE',
                [tierId]
            );

            if (!tier) {
                return res.status(404).json({ error: 'Subscription tier not found' });
            }

            res.json({
                tier: {
                    ...tier,
                    features: typeof tier.features === 'string' ? JSON.parse(tier.features) : tier.features
                }
            });
        } catch (error) {
            console.error('Error fetching tier:', error);
            res.status(500).json({ error: 'Failed to fetch subscription tier' });
        }
    },

    async getUserSubscription(req, res) {
        try {
            const userId = req.user?.userId;
            if (!userId) {
                return res.status(401).json({ error: 'Authentication required' });
            }

            const [subscription] = await query(
                `SELECT us.*, st.name as tier_name, st.features, st.scan_limit, st.concurrent_scans
                 FROM user_subscriptions us
                 JOIN subscription_tiers st ON us.tier_id = st.tier
                 WHERE us.user_id = ? AND us.status IN ('active', 'trial')
                 ORDER BY us.created_at DESC LIMIT 1`,
                [userId]
            );

            if (!subscription) {
                return res.json({
                    subscription: null,
                    tier: 'free',
                    features: SUBSCRIPTION_FEATURES.free,
                    limits: SUBSCRIPTION_LIMITS.free
                });
            }

            res.json({
                subscription: {
                    ...subscription,
                    features: typeof subscription.features === 'string' ? JSON.parse(subscription.features) : subscription.features
                },
                tier: subscription.tier_id,
                features: SUBSCRIPTION_FEATURES[subscription.tier_id] || SUBSCRIPTION_FEATURES.free,
                limits: SUBSCRIPTION_LIMITS[subscription.tier_id] || SUBSCRIPTION_LIMITS.free
            });
        } catch (error) {
            console.error('Error fetching user subscription:', error);
            res.status(500).json({ error: 'Failed to fetch subscription' });
        }
    },

    async subscribe(req, res) {
        try {
            const userId = req.user?.userId;
            if (!userId) {
                return res.status(401).json({ error: 'Authentication required' });
            }

            const { tierId, billingCycle = 'monthly' } = req.body;

            if (!tierId) {
                return res.status(400).json({ error: 'Tier ID is required' });
            }

            const [tier] = await query(
                'SELECT * FROM subscription_tiers WHERE tier_id = ? AND is_active = TRUE',
                [tierId]
            );

            if (!tier) {
                return res.status(404).json({ error: 'Subscription tier not found' });
            }

            if (tierId === 'free') {
                return res.status(400).json({ error: 'Cannot subscribe to free tier' });
            }

            const [existing] = await query(
                'SELECT * FROM user_subscriptions WHERE user_id = ? AND status IN (\'active\', \'trial\')',
                [userId]
            );

            if (existing) {
                await query(
                    'UPDATE user_subscriptions SET status = \'cancelled\', cancelled_at = CURRENT_TIMESTAMP WHERE user_id = ?',
                    [userId]
                );
            }

            const startDate = new Date();
            const endDate = new Date();
            if (billingCycle === 'yearly') {
                endDate.setFullYear(endDate.getFullYear() + 1);
            } else {
                endDate.setMonth(endDate.getMonth() + 1);
            }

            const [result] = await query(
                `INSERT INTO user_subscriptions 
                 (user_id, tier_id, status, billing_cycle, start_date, end_date, scans_used_this_month)
                 VALUES (?, ?, 'active', ?, ?, ?, 0)`,
                [userId, tierId, billingCycle, startDate, endDate]
            );

            res.status(201).json({
                success: true,
                message: 'Subscription activated successfully',
                subscription: {
                    id: result.insertId,
                    tierId,
                    tierName: tier.name,
                    billingCycle,
                    startDate,
                    endDate,
                    status: 'active'
                }
            });
        } catch (error) {
            console.error('Error creating subscription:', error);
            res.status(500).json({ error: 'Failed to create subscription' });
        }
    },

    async cancelSubscription(req, res) {
        try {
            const userId = req.user?.userId;
            if (!userId) {
                return res.status(401).json({ error: 'Authentication required' });
            }

            const [subscription] = await query(
                'SELECT * FROM user_subscriptions WHERE user_id = ? AND status = \'active\'',
                [userId]
            );

            if (!subscription) {
                return res.status(404).json({ error: 'No active subscription found' });
            }

            await query(
                'UPDATE user_subscriptions SET status = \'cancelled\', cancelled_at = CURRENT_TIMESTAMP, auto_renew = FALSE WHERE user_id = ?',
                [userId]
            );

            res.json({
                success: true,
                message: 'Subscription cancelled. Access continues until end of billing period.'
            });
        } catch (error) {
            console.error('Error cancelling subscription:', error);
            res.status(500).json({ error: 'Failed to cancel subscription' });
        }
    },

    async checkFeatureAccess(req, res) {
        try {
            const userId = req.user?.userId;
            const { feature } = req.query;

            if (!userId) {
                return res.json({ hasAccess: false, tier: 'free' });
            }

            const [subscription] = await query(
                `SELECT us.*, st.tier, st.features 
                 FROM user_subscriptions us
                 JOIN subscription_tiers st ON us.tier_id = st.tier
                 WHERE us.user_id = ? AND us.status IN ('active', 'trial')
                 ORDER BY us.created_at DESC LIMIT 1`,
                [userId]
            );

            const tierId = subscription?.tier || 'free';
            const features = subscription?.features 
                ? (typeof subscription.features === 'string' ? JSON.parse(subscription.features) : subscription.features)
                : SUBSCRIPTION_FEATURES.free;

            const hasAccess = features[feature] === true;

            res.json({
                hasAccess,
                tier: tierId,
                feature
            });
        } catch (error) {
            console.error('Error checking feature access:', error);
            res.status(500).json({ error: 'Failed to check feature access' });
        }
    },

    async checkScanLimit(req, res) {
        try {
            const userId = req.user?.userId;
            
            if (!userId) {
                return res.json({ 
                    canScan: true, 
                    limit: 0, 
                    used: 0, 
                    remaining: 5,
                    tier: 'anonymous'
                });
            }

            const [subscription] = await query(
                `SELECT us.scans_used_this_month, st.scan_limit, st.concurrent_scans
                 FROM user_subscriptions us
                 JOIN subscription_tiers st ON us.tier_id = st.tier
                 WHERE us.user_id = ? AND us.status IN ('active', 'trial')
                 ORDER BY us.created_at DESC LIMIT 1`,
                [userId]
            );

            const tierId = subscription?.tier_id || 'free';
            const limits = SUBSCRIPTION_LIMITS[tierId] || SUBSCRIPTION_LIMITS.free;
            const used = subscription?.scans_used_this_month || 0;
            const limit = limits.scan_limit;

            let canScan = true;
            let remaining = -1;

            if (limit !== -1) {
                canScan = used < limit;
                remaining = Math.max(0, limit - used);
            } else {
                remaining = -1; // unlimited
            }

            res.json({
                canScan,
                limit,
                used,
                remaining,
                tier: tierId,
                concurrentScans: limits.concurrent_scans
            });
        } catch (error) {
            console.error('Error checking scan limit:', error);
            res.status(500).json({ error: 'Failed to check scan limit' });
        }
    },

    async incrementScanCount(userId) {
        try {
            const [subscription] = await query(
                'SELECT * FROM user_subscriptions WHERE user_id = ? AND status IN (\'active\', \'trial\') ORDER BY created_at DESC LIMIT 1',
                [userId]
            );

            if (subscription) {
                await query(
                    'UPDATE user_subscriptions SET scans_used_this_month = scans_used_this_month + 1 WHERE id = ?',
                    [subscription.id]
                );
            }
            return true;
        } catch (error) {
            console.error('Error incrementing scan count:', error);
            return false;
        }
    },

    async getUsageStats(req, res) {
        try {
            const userId = req.user?.userId;
            
            if (!userId) {
                return res.json({
                    scansUsed: 0,
                    scanLimit: 5,
                    tier: 'Free',
                    isUnlimited: false,
                    billingCycle: null,
                    status: null,
                    nextBillingDate: null
                });
            }

            const [subscription] = await query(
                `SELECT us.scans_used_this_month, us.billing_cycle, us.start_date, us.end_date, us.status, st.scan_limit, st.name as tier_name
                 FROM user_subscriptions us
                 JOIN subscription_tiers st ON us.tier_id = st.tier
                 WHERE us.user_id = ? AND us.status IN ('active', 'trial')
                 ORDER BY us.created_at DESC LIMIT 1`,
                [userId]
            );

            const used = subscription?.scans_used_this_month || 0;
            const limit = subscription?.scan_limit || 5;
            const tier = subscription?.tier_name || 'Free';
            const isUnlimited = limit === -1;
            
            const formatDate = (date) => {
                if (!date) return null;
                return new Date(date).toLocaleDateString('en-US', { 
                    year: 'numeric', 
                    month: 'short', 
                    day: 'numeric' 
                });
            };

            res.json({
                scansUsed: used,
                scanLimit: limit,
                tier,
                isUnlimited,
                percentageUsed: isUnlimited ? 0 : Math.round((used / limit) * 100),
                billingCycle: subscription?.billing_cycle || 'monthly',
                status: subscription?.status || 'inactive',
                nextBillingDate: subscription?.end_date ? formatDate(subscription.end_date) : null
            });
        } catch (error) {
            console.error('Error fetching usage stats:', error);
            res.status(500).json({ error: 'Failed to fetch usage stats' });
        }
    }
};

module.exports = subscriptionController;
module.exports.SUBSCRIPTION_FEATURES = SUBSCRIPTION_FEATURES;
module.exports.SUBSCRIPTION_LIMITS = SUBSCRIPTION_LIMITS;
