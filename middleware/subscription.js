const { SUBSCRIPTION_FEATURES, SUBSCRIPTION_LIMITS } = require('../controllers/subscriptionController');
const { query } = require('../database/db');

const requireFeature = (feature) => {
    return async (req, res, next) => {
        try {
            const userId = req.user?.userId;

            if (!userId) {
                if (feature === 'basic_scans' || SUBSCRIPTION_FEATURES.free[feature]) {
                    return next();
                }
                return res.status(403).json({
                    error: 'Feature not available',
                    message: `This feature requires a premium subscription`,
                    requiredTier: getRequiredTier(feature),
                    upgradeUrl: '/pricing'
                });
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

            if (features[feature] === true) {
                req.user.subscription = {
                    tier: tierId,
                    features,
                    limits: SUBSCRIPTION_LIMITS[tierId]
                };
                return next();
            }

            return res.status(403).json({
                error: 'Feature not available',
                message: `The ${formatFeatureName(feature)} feature requires a premium subscription`,
                requiredTier: getRequiredTier(feature),
                currentTier: tierId,
                upgradeUrl: '/pricing',
                comparisonUrl: `/pricing?compare=${tierId}`
            });
        } catch (error) {
            console.error('Feature check error:', error);
            next();
        }
    };
};

const checkScanLimit = async (req, res, next) => {
    try {
        const userId = req.user?.userId;

        if (!userId) {
            const [anonScans] = await query(
                `SELECT COUNT(*) as count FROM scans WHERE user_id IS NULL AND created_at >= DATE_SUB(NOW(), INTERVAL 1 MONTH)`
            );
            const used = anonScans?.count || 0;
            if (used >= 5) {
                return res.status(403).json({
                    error: 'Scan limit reached',
                    message: 'Anonymous users can perform up to 5 scans per month. Please sign up for a free account.',
                    limit: 5,
                    used,
                    upgradeUrl: '/register'
                });
            }
            return next();
        }

        const [subscription] = await query(
            `SELECT us.scans_used_this_month, us.tier_id, st.scan_limit, st.concurrent_scans
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

        if (limit !== -1 && used >= limit) {
            return res.status(403).json({
                error: 'Scan limit reached',
                message: `You've reached your monthly scan limit of ${limit} scans. Upgrade for more.`,
                limit,
                used,
                tier: tierId,
                upgradeUrl: '/pricing'
            });
        }

        req.user.scanInfo = {
            tier: tierId,
            used,
            limit,
            concurrentScans: limits.concurrent_scans
        };

        next();
    } catch (error) {
        console.error('Scan limit check error:', error);
        next();
    }
};

function getRequiredTier(feature) {
    const tierOrder = ['free', 'starter', 'professional', 'enterprise'];
    for (const tier of tierOrder) {
        if (SUBSCRIPTION_FEATURES[tier][feature]) {
            return tier;
        }
    }
    return 'enterprise';
}

function formatFeatureName(feature) {
    return feature
        .replace(/_/g, ' ')
        .replace(/\b\w/g, c => c.toUpperCase());
}

module.exports = {
    requireFeature,
    checkScanLimit,
    SUBSCRIPTION_FEATURES,
    SUBSCRIPTION_LIMITS
};
