const { query } = require('../database/db');

const subscriptionService = {
    async getAllSubscriptions({ page = 1, limit = 20, tier = '', status = '' }) {
        const offset = (parseInt(page) - 1) * parseInt(limit);
        let whereClause = '1=1';
        const params = [];

        if (tier) {
            whereClause += ' AND us.tier_id = ?';
            params.push(tier);
        }

        if (status) {
            whereClause += ' AND us.status = ?';
            params.push(status);
        }

        const [subscriptions] = await query(`
            SELECT 
                us.*, 
                u.username, 
                u.email, 
                st.name as tier_name, 
                st.price_monthly, 
                st.price_yearly
            FROM user_subscriptions us
            JOIN users u ON us.user_id = u.id
            JOIN subscription_tiers st ON us.tier_id = st.tier
            WHERE ${whereClause}
            ORDER BY us.created_at DESC
            LIMIT ? OFFSET ?
        `, [...params, parseInt(limit), offset]);

        const countResult = await query(
            `SELECT COUNT(*) as total FROM user_subscriptions us WHERE ${whereClause}`,
            params
        );

        return {
            subscriptions,
            total: countResult[0]?.total || 0,
            page: parseInt(page),
            totalPages: Math.ceil((countResult[0]?.total || 0) / parseInt(limit))
        };
    },

    async updateSubscription(subId, updates) {
        const { status, tierId, autoRenew, scansUsedThisMonth } = updates;
        
        const updateFields = [];
        const params = [];

        if (status !== undefined) {
            updateFields.push('status = ?');
            params.push(status);
            if (status === 'cancelled') {
                updateFields.push('cancelled_at = CURRENT_TIMESTAMP');
            }
        }
        if (tierId !== undefined) {
            updateFields.push('tier_id = ?');
            params.push(tierId);
        }
        if (autoRenew !== undefined) {
            updateFields.push('auto_renew = ?');
            params.push(autoRenew);
        }
        if (scansUsedThisMonth !== undefined) {
            updateFields.push('scans_used_this_month = ?');
            params.push(scansUsedThisMonth);
        }

        if (updateFields.length > 0) {
            params.push(subId);
            await query(`UPDATE user_subscriptions SET ${updateFields.join(', ')} WHERE id = ?`, params);
        }

        const [updated] = await query(`
            SELECT us.*, u.username, st.name as tier_name
            FROM user_subscriptions us
            JOIN users u ON us.user_id = u.id
            JOIN subscription_tiers st ON us.tier_id = st.tier
            WHERE us.id = ?
        `, [subId]);

        return updated[0];
    },

    async getSubscriptionTiers() {
        const [tiers] = await query(`
            SELECT * FROM subscription_tiers 
            WHERE is_active = TRUE 
            ORDER BY price_monthly ASC
        `);

        const formattedTiers = tiers.map(tier => ({
            ...tier,
            features: typeof tier.features === 'string' ? JSON.parse(tier.features) : tier.features
        }));

        const [stats] = await query(`
            SELECT st.tier, COUNT(us.id) as subscriber_count
            FROM subscription_tiers st
            LEFT JOIN user_subscriptions us ON st.tier = us.tier_id AND us.status IN ('active', 'trial')
            GROUP BY st.tier
        `);

        return formattedTiers.map(tier => ({
            ...tier,
            subscriberCount: stats.find(s => s.tier === tier.tier)?.subscriber_count || 0
        }));
    },

    async updateSubscriptionTier(tierId, updates) {
        const { name, description, priceMonthly, priceYearly, scanLimit, concurrentScans, features, isActive } = updates;
        
        const updateFields = [];
        const params = [];

        if (name !== undefined) { updateFields.push('name = ?'); params.push(name); }
        if (description !== undefined) { updateFields.push('description = ?'); params.push(description); }
        if (priceMonthly !== undefined) { updateFields.push('price_monthly = ?'); params.push(priceMonthly); }
        if (priceYearly !== undefined) { updateFields.push('price_yearly = ?'); params.push(priceYearly); }
        if (scanLimit !== undefined) { updateFields.push('scan_limit = ?'); params.push(scanLimit); }
        if (concurrentScans !== undefined) { updateFields.push('concurrent_scans = ?'); params.push(concurrentScans); }
        if (features !== undefined) { updateFields.push('features = ?'); params.push(JSON.stringify(features)); }
        if (isActive !== undefined) { updateFields.push('is_active = ?'); params.push(isActive); }

        if (updateFields.length > 0) {
            params.push(tierId);
            await query(`UPDATE subscription_tiers SET ${updateFields.join(', ')} WHERE tier_id = ?`, params);
        }

        const [updated] = await query('SELECT * FROM subscription_tiers WHERE tier_id = ?', [tierId]);
        return updated[0];
    }
};

module.exports = subscriptionService;
