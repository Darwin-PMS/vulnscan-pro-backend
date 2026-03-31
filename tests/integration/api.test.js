const request = require('supertest');
const app = require('../server');

describe('Health Check Endpoint', () => {
    it('GET /api/health should return 200', async () => {
        const res = await request(app).get('/api/health');
        expect(res.status).toBe(200);
    });
});

describe('Auth Routes', () => {
    describe('POST /api/auth/register', () => {
        it('should validate required fields', async () => {
            const res = await request(app)
                .post('/api/auth/register')
                .send({});
            expect(res.status).toBe(400);
        });
    });

    describe('POST /api/auth/login', () => {
        it('should require email and password', async () => {
            const res = await request(app)
                .post('/api/auth/login')
                .send({});
            expect(res.status).toBe(400);
        });
    });
});

describe('Scan Routes', () => {
    describe('POST /api/scans/start', () => {
        it('should require authentication', async () => {
            const res = await request(app)
                .post('/api/scans/start')
                .send({ url: 'http://example.com' });
            expect(res.status).toBe(401);
        });
    });

    describe('GET /api/scans', () => {
        it('should require authentication', async () => {
            const res = await request(app).get('/api/scans');
            expect(res.status).toBe(401);
        });
    });
});
