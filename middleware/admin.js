const { query } = require('../database/db');

const requireAdmin = async (req, res, next) => {
    try {
        const userId = req.user?.userId;

        if (!userId) {
            return res.status(401).json({ error: 'Authentication required' });
        }

        const [users] = await query('SELECT role FROM users WHERE id = ?', [userId]);

        if (!users || users.length === 0) {
            return res.status(401).json({ error: 'User not found' });
        }

        if (users[0].role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        next();
    } catch (error) {
        console.error('Admin check error:', error);
        res.status(500).json({ error: 'Authorization check failed' });
    }
};

const getAdminStats = async () => {
    try {
        const [totalUsers] = await query('SELECT COUNT(*) as count FROM users');
        const [activeUsers] = await query('SELECT COUNT(*) as count FROM users WHERE is_active = TRUE');
        const [totalScans] = await query('SELECT COUNT(*) as count FROM scans');
        const [totalVulnerabilities] = await query('SELECT COUNT(*) as count FROM vulnerabilities');

        const [subsByTier] = await query(`
            SELECT st.name, COUNT(us.id) as count 
            FROM subscription_tiers st 
            LEFT JOIN user_subscriptions us ON st.tier = us.tier_id AND us.status = 'active'
            GROUP BY st.tier, st.name
        `);

        const [recentUsers] = await query(`
            SELECT id, username, email, role, is_active, created_at 
            FROM users 
            ORDER BY created_at DESC 
            LIMIT 5
        `);

        const [recentScans] = await query(`
            SELECT s.scan_id, s.target_url, s.status, s.created_at, u.username
            FROM scans s
            LEFT JOIN users u ON s.user_id = u.id
            ORDER BY s.created_at DESC
            LIMIT 5
        `);

        const [monthlyRevenue] = await query(`
            SELECT 
                MONTH(start_date) as month,
                YEAR(start_date) as year,
                COUNT(*) as subscriptions,
                SUM(CASE 
                    WHEN billing_cycle = 'monthly' THEN st.price_monthly 
                    ELSE st.price_yearly / 12 
                END) as revenue
            FROM user_subscriptions us
            JOIN subscription_tiers st ON us.tier_id = st.tier
            WHERE us.status = 'active' AND us.tier_id != 'free'
            AND start_date >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
            GROUP BY YEAR(start_date), MONTH(start_date)
            ORDER BY year DESC, month DESC
        `);

        return {
            totalUsers: totalUsers[0]?.count || 0,
            activeUsers: activeUsers[0]?.count || 0,
            totalScans: totalScans[0]?.count || 0,
            totalVulnerabilities: totalVulnerabilities[0]?.count || 0,
            subscriptionsByTier: subsByTier,
            recentUsers,
            recentScans,
            monthlyRevenue
        };
    } catch (error) {
        console.error('Error getting admin stats:', error);
        throw error;
    }
};

module.exports = { requireAdmin, getAdminStats };
