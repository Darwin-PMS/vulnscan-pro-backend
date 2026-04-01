const { query } = require('../database/db');

const scanService = {
    async getAllScans({ page = 1, limit = 20, status = '', search = '' }) {
        const offset = (parseInt(page) - 1) * parseInt(limit);
        let whereClause = '1=1';
        const params = [];

        if (status) {
            whereClause += ' AND s.status = ?';
            params.push(status);
        }

        if (search) {
            whereClause += ' AND (s.target_url LIKE ? OR u.username LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }

        const [scans] = await query(`
            SELECT s.*, u.username, u.email
            FROM scans s
            LEFT JOIN users u ON s.user_id = u.id
            WHERE ${whereClause}
            ORDER BY s.created_at DESC
            LIMIT ? OFFSET ?
        `, [...params, parseInt(limit), offset]);

        const countResult = await query(
            `SELECT COUNT(*) as total FROM scans s LEFT JOIN users u ON s.user_id = u.id WHERE ${whereClause}`,
            params
        );

        return {
            scans,
            total: countResult[0]?.total || 0,
            page: parseInt(page),
            totalPages: Math.ceil((countResult[0]?.total || 0) / parseInt(limit))
        };
    },

    async deleteScan(scanId) {
        await query('UPDATE scans SET status = ?, deleted_at = NOW() WHERE scan_id = ?', ['deleted', scanId]);
        return { deleted: true, message: 'Scan soft deleted for audit preservation' };
    },

    async getScanById(scanId) {
        const [scans] = await query(`
            SELECT s.*, u.username, u.email
            FROM scans s
            LEFT JOIN users u ON s.user_id = u.id
            WHERE s.scan_id = ?
        `, [scanId]);
        return scans[0] || null;
    }
};

module.exports = scanService;
