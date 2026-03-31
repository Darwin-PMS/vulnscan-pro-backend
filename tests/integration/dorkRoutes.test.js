const request = require('supertest');
const express = require('express');
const dorkRoutes = require('../../routes/dorkRoutes');

jest.mock('../../database/db', () => ({
    pool: {
        query: jest.fn()
    }
}));

const { pool } = require('../../database/db');

const createTestApp = () => {
    const app = express();
    app.use(express.json());
    app.use('/api/dorks', dorkRoutes);
    return app;
};

describe('Dork Routes', () => {
    let app;

    beforeEach(() => {
        app = createTestApp();
        jest.clearAllMocks();
    });

    describe('GET /api/dorks', () => {
        it('should return all active dork patterns', async () => {
            const mockPatterns = [
                {
                    ghdb_id: '8361',
                    title: 'Backup Files',
                    severity: 'high'
                },
                {
                    ghdb_id: 'GHDB-SQL-001',
                    title: 'SQL Injection',
                    severity: 'critical'
                }
            ];

            pool.query.mockResolvedValueOnce([mockPatterns, []]);

            const res = await request(app).get('/api/dorks');

            expect(res.status).toBe(200);
            expect(res.body.patterns).toEqual(mockPatterns);
            expect(pool.query).toHaveBeenCalledWith(
                expect.stringContaining('SELECT * FROM dork_patterns'),
                expect.any(Array)
            );
        });

        it('should order patterns by severity descending', async () => {
            pool.query.mockResolvedValueOnce([[], []]);

            await request(app).get('/api/dorks');

            expect(pool.query).toHaveBeenCalledWith(
                expect.stringContaining('ORDER BY severity DESC'),
                expect.any(Array)
            );
        });

        it('should handle database errors', async () => {
            pool.query.mockRejectedValueOnce(new Error('Database connection failed'));

            const res = await request(app).get('/api/dorks');

            expect(res.status).toBe(500);
            expect(res.body.error).toBe('Failed to fetch dork patterns');
        });
    });

    describe('GET /api/dorks/category/:category', () => {
        it('should return patterns for specific category', async () => {
            const mockPatterns = [
                {
                    ghdb_id: 'GHDB-GIT-001',
                    title: 'Exposed Git Repository',
                    category: 'Sensitive Directories'
                }
            ];

            pool.query.mockResolvedValueOnce([mockPatterns, []]);

            const res = await request(app).get('/api/dorks/category/Sensitive%20Directories');

            expect(res.status).toBe(200);
            expect(res.body.patterns).toEqual(mockPatterns);
            expect(pool.query).toHaveBeenCalledWith(
                expect.stringContaining('WHERE category = ?'),
                ['Sensitive Directories']
            );
        });

        it('should return empty array for non-existent category', async () => {
            pool.query.mockResolvedValueOnce([[], []]);

            const res = await request(app).get('/api/dorks/category/NonExistent');

            expect(res.status).toBe(200);
            expect(res.body.patterns).toEqual([]);
        });

        it('should handle database errors', async () => {
            pool.query.mockRejectedValueOnce(new Error('Database error'));

            const res = await request(app).get('/api/dorks/category/Test');

            expect(res.status).toBe(500);
            expect(res.body.error).toBe('Failed to fetch dork patterns');
        });
    });

    describe('GET /api/dorks/ghdb/:ghdbId', () => {
        it('should return specific pattern by GHDB ID', async () => {
            const mockPattern = {
                ghdb_id: '8361',
                title: 'Backup Files',
                patterns: ['site:{domain} ext:bak']
            };

            pool.query.mockResolvedValueOnce([[mockPattern], []]);

            const res = await request(app).get('/api/dorks/ghdb/8361');

            expect(res.status).toBe(200);
            expect(res.body.pattern).toEqual(mockPattern);
        });

        it('should return 404 for non-existent pattern', async () => {
            pool.query.mockResolvedValueOnce([[], []]);

            const res = await request(app).get('/api/dorks/ghdb/NONEXISTENT');

            expect(res.status).toBe(404);
            expect(res.body.error).toBe('Dork pattern not found');
        });

        it('should handle special characters in GHDB ID', async () => {
            const mockPattern = {
                ghdb_id: 'OWASP-A01-2021',
                title: 'Broken Access Control'
            };

            pool.query.mockResolvedValueOnce([[mockPattern], []]);

            const res = await request(app).get('/api/dorks/ghdb/OWASP-A01-2021');

            expect(res.status).toBe(200);
            expect(res.body.pattern.ghdb_id).toBe('OWASP-A01-2021');
        });

        it('should handle database errors', async () => {
            pool.query.mockRejectedValueOnce(new Error('Query failed'));

            const res = await request(app).get('/api/dorks/ghdb/8361');

            expect(res.status).toBe(500);
            expect(res.body.error).toBe('Failed to fetch dork pattern');
        });
    });
});

describe('Dork Pattern Categories', () => {
    const { pool } = require('../../database/db');
    const createTestApp = () => {
        const app = express();
        app.use(express.json());
        app.use('/api/dorks', dorkRoutes);
        return app;
    };

    it('should include Files Containing Juicy Info category', async () => {
        pool.query.mockResolvedValueOnce([[
            { category: 'Files Containing Juicy Info', ghdb_id: '8361' }
        ], []]);

        const res = await request(createTestApp())
            .get('/api/dorks/category/Files%20Containing%20Juicy%20Info');

        expect(res.status).toBe(200);
    });

    it('should include Sensitive Directories category', async () => {
        pool.query.mockResolvedValueOnce([[
            { category: 'Sensitive Directories', ghdb_id: 'GHDB-GIT-001' }
        ], []]);

        const res = await request(createTestApp())
            .get('/api/dorks/category/Sensitive%20Directories');

        expect(res.status).toBe(200);
    });

    it('should include Vulnerable Files category', async () => {
        pool.query.mockResolvedValueOnce([[
            { category: 'Vulnerable Files', ghdb_id: 'GHDB-SQL-001' }
        ], []]);

        const res = await request(createTestApp())
            .get('/api/dorks/category/Vulnerable%20Files');

        expect(res.status).toBe(200);
    });

    it('should include OWASP Top 10 category', async () => {
        pool.query.mockResolvedValueOnce([[
            { category: 'OWASP Top 10', ghdb_id: 'OWASP-A01-2021' }
        ], []]);

        const res = await request(createTestApp())
            .get('/api/dorks/category/OWASP%20Top%2010');

        expect(res.status).toBe(200);
    });
});
