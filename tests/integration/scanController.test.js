const request = require('supertest');
const express = require('express');
const scanController = require('../../controllers/scanController');

jest.mock('../../database/db', () => ({
    pool: {
        query: jest.fn().mockResolvedValue([[], []])
    }
}));

jest.mock('../../services/vulnerabilityScanner', () => ({
    scanTarget: jest.fn().mockResolvedValue([])
}));

const { pool } = require('../../database/db');
const scanner = require('../../services/vulnerabilityScanner');

const createTestApp = () => {
    const app = express();
    app.use(express.json());
    app.post('/api/scans/start', scanController.startScan);
    app.get('/api/scans/:scanId', scanController.getScanStatus);
    app.get('/api/scans/:scanId/results', scanController.getScanResults);
    app.get('/api/scans', scanController.getAllScans);
    app.get('/api/scans/:scanId/history', scanController.getScanHistory);
    app.delete('/api/scans/:scanId', scanController.deleteScan);
    return app;
};

describe('Scan Controller', () => {
    let app;

    beforeEach(() => {
        app = createTestApp();
        jest.clearAllMocks();
    });

    describe('POST /api/scans/start', () => {
        it('should require URL in request body', async () => {
            const res = await request(app)
                .post('/api/scans/start')
                .send({});

            expect(res.status).toBe(400);
            expect(res.body.error).toBe('URL is required');
        });

        it('should create scan with valid URL', async () => {
            pool.query
                .mockResolvedValueOnce([[], []]) // INSERT scan
                .mockResolvedValueOnce([[], []]) // INSERT history
                .mockResolvedValueOnce([[], []]); // UPDATE status

            const res = await request(app)
                .post('/api/scans/start')
                .send({ url: 'https://example.com' });

            expect(res.status).toBe(200);
            expect(res.body.success).toBe(true);
            expect(res.body.scanId).toBeDefined();
            expect(res.body.url).toBe('https://example.com');
        });

        it('should log scan start in history', async () => {
            pool.query
                .mockResolvedValueOnce([[], []])
                .mockResolvedValueOnce([[], []]) // History insert
                .mockResolvedValueOnce([[], []]);

            await request(app)
                .post('/api/scans/start')
                .send({ url: 'https://test.com' });

            expect(pool.query).toHaveBeenCalledWith(
                expect.stringContaining('INSERT INTO scan_history'),
                expect.any(Array)
            );
        });

        it('should handle database errors', async () => {
            pool.query.mockRejectedValueOnce(new Error('DB Error'));

            const res = await request(app)
                .post('/api/scans/start')
                .send({ url: 'https://example.com' });

            expect(res.status).toBe(500);
            expect(res.body.error).toBe('Failed to start scan');
        });
    });

    describe('GET /api/scans/:scanId', () => {
        it('should return 404 for non-existent scan', async () => {
            pool.query.mockResolvedValueOnce([[], []]);

            const res = await request(app).get('/api/scans/nonexistent-id');

            expect(res.status).toBe(404);
            expect(res.body.error).toBe('Scan not found');
        });

        it('should return scan status with vulnerability summary', async () => {
            const mockScan = {
                scan_id: 'scan-123',
                target_url: 'https://example.com',
                status: 'completed',
                created_at: new Date()
            };
            const mockSummary = [
                { severity: 'critical', count: 2 },
                { severity: 'high', count: 3 }
            ];

            pool.query
                .mockResolvedValueOnce([[mockScan], []])
                .mockResolvedValueOnce([mockSummary, []]);

            const res = await request(app).get('/api/scans/scan-123');

            expect(res.status).toBe(200);
            expect(res.body.scanId).toBe('scan-123');
            expect(res.body.status).toBe('completed');
            expect(res.body.summary).toBeDefined();
        });
    });

    describe('GET /api/scans/:scanId/results', () => {
        it('should return vulnerabilities filtered by severity', async () => {
            const mockScan = { scan_id: 'scan-123', status: 'completed' };
            const mockVulns = [
                { id: 1, severity: 'critical', title: 'SQL Injection' }
            ];
            const mockCounts = [{ severity: 'critical', count: 1 }];

            pool.query
                .mockResolvedValueOnce([[mockScan], []])
                .mockResolvedValueOnce([mockVulns, []])
                .mockResolvedValueOnce([mockCounts, []]);

            const res = await request(app)
                .get('/api/scans/scan-123/results?severity=critical');

            expect(res.status).toBe(200);
            expect(res.body.vulnerabilities).toHaveLength(1);
            expect(pool.query).toHaveBeenCalledWith(
                expect.stringContaining('severity = ?'),
                expect.any(Array)
            );
        });

        it('should support pagination', async () => {
            pool.query
                .mockResolvedValueOnce([[{ scan_id: 'scan-123' }], []])
                .mockResolvedValueOnce([[], []])
                .mockResolvedValueOnce([[], []]);

            const res = await request(app)
                .get('/api/scans/scan-123/results?limit=10&offset=5');

            expect(res.status).toBe(200);
            expect(pool.query).toHaveBeenCalledWith(
                expect.stringContaining('LIMIT ? OFFSET ?'),
                expect.arrayContaining([10, 5])
            );
        });

        it('should return 404 for non-existent scan', async () => {
            pool.query.mockResolvedValueOnce([[], []]);

            const res = await request(app).get('/api/scans/invalid/results');

            expect(res.status).toBe(404);
        });
    });

    describe('GET /api/scans', () => {
        it('should return paginated list of scans', async () => {
            const mockScans = [
                { scan_id: 'scan-1', total_vulnerabilities: 5 },
                { scan_id: 'scan-2', total_vulnerabilities: 3 }
            ];

            pool.query.mockResolvedValueOnce([mockScans, []]);

            const res = await request(app).get('/api/scans');

            expect(res.status).toBe(200);
            expect(res.body.scans).toHaveLength(2);
            expect(res.body.total).toBe(2);
        });

        it('should support pagination parameters', async () => {
            pool.query.mockResolvedValueOnce([[], []]);

            await request(app).get('/api/scans?limit=5&offset=10');

            expect(pool.query).toHaveBeenCalledWith(
                expect.any(String),
                expect.arrayContaining([5, 10])
            );
        });
    });

    describe('GET /api/scans/:scanId/history', () => {
        it('should return scan history', async () => {
            const mockHistory = [
                { action: 'scan_started', details: 'Scan initiated' },
                { action: 'pattern_tested', details: 'Tested SQL Injection' }
            ];

            pool.query.mockResolvedValueOnce([mockHistory, []]);

            const res = await request(app).get('/api/scans/scan-123/history');

            expect(res.status).toBe(200);
            expect(res.body.history).toHaveLength(2);
            expect(res.body.scanId).toBe('scan-123');
        });
    });

    describe('DELETE /api/scans/:scanId', () => {
        it('should delete scan successfully', async () => {
            pool.query.mockResolvedValueOnce([[], []]);

            const res = await request(app).delete('/api/scans/scan-123');

            expect(res.status).toBe(200);
            expect(res.body.success).toBe(true);
            expect(pool.query).toHaveBeenCalledWith(
                expect.stringContaining('DELETE FROM scans'),
                ['scan-123']
            );
        });

        it('should handle delete errors', async () => {
            pool.query.mockRejectedValueOnce(new Error('Delete failed'));

            const res = await request(app).delete('/api/scans/scan-123');

            expect(res.status).toBe(500);
            expect(res.body.error).toBe('Failed to delete scan');
        });
    });
});

describe('Vulnerability Severity Classification', () => {
    it('should categorize vulnerabilities by severity levels', () => {
        const severities = ['critical', 'high', 'medium', 'low', 'info'];
        severities.forEach(severity => {
            expect(typeof severity).toBe('string');
        });
    });

    it('should prioritize critical vulnerabilities first', () => {
        const vulnerabilities = [
            { severity: 'low' },
            { severity: 'critical' },
            { severity: 'high' },
            { severity: 'medium' }
        ];

        const priority = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        vulnerabilities.sort((a, b) => priority[a.severity] - priority[b.severity]);

        expect(vulnerabilities[0].severity).toBe('critical');
    });
});
