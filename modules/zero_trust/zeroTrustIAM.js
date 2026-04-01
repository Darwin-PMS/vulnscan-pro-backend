/**
 * Zero Trust IAM Module
 * Based on NIST SP 800-207 Zero Trust Architecture
 * Reference: https://csrc.nist.gov/projects/zero-trust-architecture
 */

const { v4: uuidv4 } = require('uuid');
const { query } = require('../../database/db');

const TRUST_LEVELS = {
    ZERO: 0,
    LOW: 0.3,
    MEDIUM: 0.6,
    HIGH: 0.8,
    FULL: 1.0
};

const SESSION_STATES = {
    ACTIVE: 'active',
    SUSPENDED: 'suspended',
    REVOKED: 'revoked',
    EXPIRED: 'expired'
};

class ZeroTrustIAM {
    constructor() {
        this.riskFactors = {
            newDevice: 0.2,
            newLocation: 0.15,
            newTimeWindow: 0.1,
            velocityChange: 0.25,
            failedAttempts: 0.3,
            vpnDetected: 0.05,
            torDetected: 0.4,
            proxyDetected: 0.2,
            datacenterIP: 0.15
        };
    }

    // ==================== SESSION TRUST SCORING ====================
    
    async calculateSessionTrust(userId, sessionData = {}) {
        const {
            deviceFingerprint,
            ipAddress,
            geoLocation,
            userAgent,
            authMethod,
            mfaUsed = false,
            riskHistory = []
        } = sessionData;
        
        let trustScore = TRUST_LEVELS.MEDIUM;
        const riskFactors = [];
        
        if (!mfaUsed) {
            trustScore -= 0.2;
            riskFactors.push({ factor: 'no_mfa', impact: -0.2 });
        }
        
        const deviceCheck = await this.validateDevice(userId, deviceFingerprint);
        if (!deviceCheck.known) {
            trustScore -= this.riskFactors.newDevice;
            riskFactors.push({ factor: 'new_device', impact: -this.riskFactors.newDevice });
        }
        
        const geoCheck = await this.checkGeoAnomaly(userId, geoLocation);
        if (geoCheck.anomalous) {
            trustScore -= this.riskFactors.newLocation;
            riskFactors.push({ factor: 'geo_anomaly', impact: -this.riskFactors.newLocation, details: geoCheck });
        }
        
        const timeCheck = await this.checkTimeAnomaly(userId);
        if (timeCheck.anomalous) {
            trustScore -= this.riskFactors.newTimeWindow;
            riskFactors.push({ factor: 'time_anomaly', impact: -this.riskFactors.newTimeWindow });
        }
        
        const velocityCheck = await this.checkVelocityAnomaly(userId);
        if (velocityCheck.anomalous) {
            trustScore -= this.riskFactors.velocityChange;
            riskFactors.push({ factor: 'velocity_change', impact: -this.riskFactors.velocityChange });
        }
        
        const networkCheck = await this.analyzeNetworkContext(ipAddress);
        if (networkCheck.tor) {
            trustScore -= this.riskFactors.torDetected;
            riskFactors.push({ factor: 'tor_detected', impact: -this.riskFactors.torDetected });
        }
        if (networkCheck.proxy) {
            trustScore -= this.riskFactors.proxyDetected;
            riskFactors.push({ factor: 'proxy_detected', impact: -this.riskFactors.proxyDetected });
        }
        
        trustScore = Math.max(0, Math.min(1, trustScore));
        
        const result = {
            score: trustScore,
            level: this.getTrustLevel(trustScore),
            riskFactors,
            requiresMFA: trustScore < 0.6,
            adaptivePolicy: this.determineAdaptivePolicy(trustScore, riskFactors),
            evaluatedAt: new Date().toISOString()
        };
        
        await this.recordTrustEvaluation(userId, result);
        
        return result;
    }
    
    getTrustLevel(score) {
        if (score >= 0.9) return { name: 'FULL', color: 'green' };
        if (score >= 0.7) return { name: 'HIGH', color: 'blue' };
        if (score >= 0.4) return { name: 'MEDIUM', color: 'yellow' };
        if (score >= 0.2) return { name: 'LOW', color: 'orange' };
        return { name: 'ZERO', color: 'red' };
    }
    
    determineAdaptivePolicy(trustScore, riskFactors) {
        const policies = {
            highRisk: {
                requireReauth: true,
                requireMFA: true,
                restrictActions: ['delete', 'admin', 'export'],
                sessionTimeout: 300,
                alertLevel: 'critical'
            },
            mediumRisk: {
                requireReauth: false,
                requireMFA: false,
                restrictActions: ['admin'],
                sessionTimeout: 1800,
                alertLevel: 'warning'
            },
            lowRisk: {
                requireReauth: false,
                requireMFA: false,
                restrictActions: [],
                sessionTimeout: 7200,
                alertLevel: 'info'
            }
        };
        
        if (trustScore < 0.4) return policies.highRisk;
        if (trustScore < 0.7) return policies.mediumRisk;
        return policies.lowRisk;
    }
    
    // ==================== DEVICE FINGERPRINTING ====================
    
    async validateDevice(userId, fingerprint) {
        const [knownDevices] = await query(`
            SELECT * FROM trusted_devices 
            WHERE user_id = ? AND fingerprint = ?
            AND is_active = TRUE
        `, [userId, fingerprint]);
        
        if (knownDevices.length > 0) {
            return {
                known: true,
                deviceId: knownDevices[0].id,
                firstSeen: knownDevices[0].created_at,
                lastUsed: knownDevices[0].last_used,
                trustLevel: knownDevices[0].trust_level
            };
        }
        
        return { known: false };
    }
    
    async registerTrustedDevice(userId, deviceInfo) {
        const {
            fingerprint,
            deviceType,
            browser,
            os,
            ipAddress
        } = deviceInfo;
        
        const deviceId = uuidv4();
        
        await query(`
            INSERT INTO trusted_devices 
            (id, user_id, fingerprint, device_type, browser, os, ip_address, trust_level, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
        `, [deviceId, userId, fingerprint, deviceType, browser, os, ipAddress, TRUST_LEVELS.LOW]);
        
        return {
            deviceId,
            status: 'registered',
            requiresVerification: true
        };
    }
    
    // ==================== GEO ANOMALY DETECTION ====================
    
    async checkGeoAnomaly(userId, currentLocation) {
        if (!currentLocation) {
            return { anomalous: false, reason: 'no_location_data' };
        }
        
        const [knownLocations] = await query(`
            SELECT country, city, latitude, longitude
            FROM user_locations
            WHERE user_id = ?
            ORDER BY last_seen DESC
            LIMIT 5
        `, [userId]);
        
        if (knownLocations.length === 0) {
            await this.recordLocation(userId, currentLocation);
            return { anomalous: false, reason: 'first_location' };
        }
        
        const currentCountry = currentLocation.country;
        const knownCountries = knownLocations.map(l => l.country);
        
        if (!knownCountries.includes(currentCountry)) {
            await this.recordLocation(userId, currentLocation);
            await this.logSecurityEvent('GEO_ANOMALY', {
                userId,
                expected: knownCountries,
                actual: currentCountry,
                location: currentLocation
            });
            
            return {
                anomalous: true,
                reason: 'new_country',
                expected: knownCountries,
                actual: currentCountry,
                requiresVerification: true
            };
        }
        
        const distance = this.calculateDistance(
            { lat: knownLocations[0].latitude, lon: knownLocations[0].longitude },
            { lat: currentLocation.latitude, lon: currentLocation.longitude }
        );
        
        if (distance > 500) {
            return {
                anomalous: true,
                reason: 'impossible_travel',
                distanceKm: Math.round(distance),
                requiresVerification: true
            };
        }
        
        return { anomalous: false };
    }
    
    calculateDistance(loc1, loc2) {
        const R = 6371;
        const dLat = this.toRad(loc2.lat - loc1.lat);
        const dLon = this.toRad(loc2.lon - loc1.lon);
        const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                  Math.cos(this.toRad(loc1.lat)) * Math.cos(this.toRad(loc2.lat)) *
                  Math.sin(dLon/2) * Math.sin(dLon/2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        return R * c;
    }
    
    toRad(deg) {
        return deg * (Math.PI / 180);
    }
    
    async recordLocation(userId, location) {
        await query(`
            INSERT INTO user_locations 
            (id, user_id, country, city, latitude, longitude, ip_address, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
        `, [uuidv4(), userId, location.country, location.city, location.latitude, location.longitude, location.ipAddress]);
    }
    
    // ==================== TIME ANOMALY DETECTION ====================
    
    async checkTimeAnomaly(userId) {
        const [loginHistory] = await query(`
            SELECT HOUR(created_at) as hour, COUNT(*) as count
            FROM login_history
            WHERE user_id = ?
            AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY HOUR(created_at)
            ORDER BY count DESC
            LIMIT 5
        `, [userId]);
        
        if (loginHistory.length === 0) {
            return { anomalous: false };
        }
        
        const currentHour = new Date().getHours();
        const commonHours = loginHistory.map(h => h.hour);
        const avgHour = commonHours.reduce((a, b) => a + b, 0) / commonHours.length;
        
        if (!commonHours.includes(currentHour)) {
            const hourDiff = Math.abs(currentHour - avgHour);
            if (hourDiff > 8) {
                return {
                    anomalous: true,
                    reason: 'unusual_time',
                    typicalHours: commonHours,
                    currentHour
                };
            }
        }
        
        return { anomalous: false };
    }
    
    // ==================== VELOCITY ANOMALY DETECTION ====================
    
    async checkVelocityAnomaly(userId) {
        const [recentLogins] = await query(`
            SELECT created_at, ip_address
            FROM login_history
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 5
        `, [userId]);
        
        if (recentLogins.length < 2) {
            return { anomalous: false };
        }
        
        for (let i = 0; i < recentLogins.length - 1; i++) {
            const curr = new Date(recentLogins[i].created_at);
            const prev = new Date(recentLogins[i + 1].created_at);
            const timeDiff = (curr - prev) / 1000 / 60;
            
            if (timeDiff < 5 && recentLogins[i].ip_address !== recentLogins[i + 1].ip_address) {
                return {
                    anomalous: true,
                    reason: 'impossible_velocity',
                    timeDiffMinutes: timeDiff
                };
            }
        }
        
        return { anomalous: false };
    }
    
    // ==================== NETWORK CONTEXT ANALYSIS ====================
    
    async analyzeNetworkContext(ipAddress) {
        const [knownIPs] = await query(`
            SELECT ip_address, type, is_trusted
            FROM known_ip_addresses
            WHERE ip_address = ?
        `, [ipAddress]);
        
        const analysis = {
            tor: await this.checkTorExitNode(ipAddress),
            proxy: await this.checkProxy(ipAddress),
            vpn: await this.checkVPN(ipAddress),
            datacenter: await this.checkDatacenter(ipAddress),
            vpnDetected: false,
            torDetected: false,
            proxyDetected: false,
            riskScore: 0
        };
        
        if (analysis.tor) {
            analysis.torDetected = true;
            analysis.riskScore += this.riskFactors.torDetected;
        }
        if (analysis.proxy) {
            analysis.proxyDetected = true;
            analysis.riskScore += this.riskFactors.proxyDetected;
        }
        if (analysis.vpn) {
            analysis.vpnDetected = true;
        }
        if (analysis.datacenter) {
            analysis.riskScore += this.riskFactors.datacenterIP;
        }
        
        return analysis;
    }
    
    async checkTorExitNode(ip) {
        const torExitNodes = [
            '185.220.101.', '185.220.102.', '185.220.103.',
            '199.249.230.', '204.85.191.'
        ];
        return torExitNodes.some(node => ip.startsWith(node));
    }
    
    async checkProxy(ip) {
        const proxyHeaders = ['x-forwarded-for', 'x-real-ip', 'via'];
        return ip.startsWith('10.') || ip.startsWith('192.168.');
    }
    
    async checkVPN(ip) {
        return false;
    }
    
    async checkDatacenter(ip) {
        return ip.startsWith('35.') || ip.startsWith('104.') || ip.startsWith('45.');
    }
    
    // ==================== ADAPTIVE MFA ====================
    
    async determineMFARequirements(trustScore, actionType) {
        const mfaRequirements = {
            CRITICAL: {
                actions: ['admin_delete', 'role_change', 'data_export', 'settings_change'],
                baseRequirement: TRUST_LEVELS.HIGH
            },
            HIGH: {
                actions: ['password_change', 'email_change', 'payment'],
                baseRequirement: TRUST_LEVELS.MEDIUM
            },
            STANDARD: {
                actions: ['login', 'view_data'],
                baseRequirement: TRUST_LEVELS.LOW
            }
        };
        
        let requiredLevel = TRUST_LEVELS.LOW;
        
        for (const [tier, config] of Object.entries(mfaRequirements)) {
            if (config.actions.includes(actionType)) {
                requiredLevel = config.baseRequirement;
                break;
            }
        }
        
        return {
            mfaRequired: trustScore < requiredLevel,
            trustScore,
            requiredLevel,
            mfaMethods: this.getAvailableMFAMethods(trustScore)
        };
    }
    
    getAvailableMFAMethods(trustScore) {
        const methods = [];
        
        if (trustScore < 0.3) {
            methods.push('totp', 'email', 'sms', 'hardware_key');
        } else if (trustScore < 0.6) {
            methods.push('totp', 'email');
        } else {
            methods.push('totp');
        }
        
        return methods;
    }
    
    // ==================== PRIVILEGED ACCESS MANAGEMENT ====================
    
    async validatePrivilegedAccess(userId, resource, action) {
        const [user] = await query(`
            SELECT role FROM users WHERE id = ? AND is_active = TRUE
        `, [userId]);
        
        if (!user || user.length === 0) {
            return { allowed: false, reason: 'user_not_found' };
        }
        
        if (user[0].role !== 'admin') {
            const [permissions] = await query(`
                SELECT * FROM resource_permissions
                WHERE user_id = ? AND resource = ? AND action = ?
                AND is_active = TRUE
            `, [userId, resource, action]);
            
            if (permissions.length === 0) {
                await this.logSecurityEvent('UNAUTHORIZED_PRIVILEGED_ACCESS', {
                    userId, resource, action
                });
                return { allowed: false, reason: 'no_permission' };
            }
        }
        
        await this.logPrivilegedAccess(userId, resource, action);
        
        return {
            allowed: true,
            userRole: user[0].role,
            timestamp: new Date().toISOString()
        };
    }
    
    async logPrivilegedAccess(userId, resource, action) {
        await query(`
            INSERT INTO privileged_access_logs
            (id, user_id, resource, action, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, NOW())
        `, [uuidv4(), userId, resource, action, null]);
    }
    
    // ==================== SESSION MANAGEMENT ====================
    
    async createSecureSession(userId, sessionData) {
        const session = {
            id: uuidv4(),
            userId,
            state: SESSION_STATES.ACTIVE,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
            lastActivity: new Date().toISOString(),
            trustScore: sessionData.trustScore || 0.5,
            deviceFingerprint: sessionData.deviceFingerprint,
            ipAddress: sessionData.ipAddress,
            userAgent: sessionData.userAgent,
            mfaVerified: sessionData.mfaUsed || false
        };
        
        await query(`
            INSERT INTO user_sessions
            (session_id, user_id, state, trust_score, device_fingerprint, 
             ip_address, user_agent, mfa_verified, created_at, expires_at, last_activity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            session.id, session.userId, session.state, session.trustScore,
            session.deviceFingerprint, session.ipAddress, session.userAgent,
            session.mfaVerified, session.createdAt, session.expiresAt, session.lastActivity
        ]);
        
        return session;
    }
    
    async validateSession(sessionId) {
        const [session] = await query(`
            SELECT * FROM user_sessions WHERE session_id = ?
        `, [sessionId]);
        
        if (!session || session.length === 0) {
            return { valid: false, reason: 'session_not_found' };
        }
        
        if (session[0].state !== SESSION_STATES.ACTIVE) {
            return { valid: false, reason: 'session_' + session[0].state };
        }
        
        if (new Date(session[0].expires_at) < new Date()) {
            await this.updateSessionState(sessionId, SESSION_STATES.EXPIRED);
            return { valid: false, reason: 'session_expired' };
        }
        
        return {
            valid: true,
            session: session[0],
            trustScore: session[0].trust_score,
            requiresReauth: session[0].trust_score < 0.6
        };
    }
    
    async updateSessionState(sessionId, state) {
        await query(`
            UPDATE user_sessions SET state = ? WHERE session_id = ?
        `, [state, sessionId]);
    }
    
    async revokeAllSessions(userId, reason = 'manual') {
        await query(`
            UPDATE user_sessions 
            SET state = ?, revoked_at = NOW()
            WHERE user_id = ? AND state = 'active'
        `, [SESSION_STATES.REVOKED, userId]);
        
        await this.logSecurityEvent('ALL_SESSIONS_REVOKED', { userId, reason });
    }
    
    // ==================== TOKEN LIFECYCLE ====================
    
    async rotateToken(userId, tokenType) {
        const oldTokenId = uuidv4();
        const newTokenId = uuidv4();
        const rotatedAt = new Date().toISOString();
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        
        await query(`
            INSERT INTO token_lifecycle 
            (id, user_id, token_type, action, rotated_at, expires_at)
            VALUES (?, ?, ?, 'rotate', ?, ?)
        `, [oldTokenId, userId, tokenType, rotatedAt, expiresAt]);
        
        return {
            newTokenId,
            expiresAt,
            rotatedFrom: oldTokenId
        };
    }
    
    async revokeToken(tokenId, reason) {
        await query(`
            INSERT INTO token_lifecycle 
            (id, user_id, action, reason, created_at)
            VALUES (?, NULL, 'revoke', ?, NOW())
        `, [tokenId, reason]);
    }
    
    // ==================== IDENTITY PROOFING ====================
    
    async initiateIdentityProofing(userId) {
        const proofingSession = {
            id: uuidv4(),
            userId,
            status: 'initiated',
            steps: [
                { step: 'email_verification', status: 'pending' },
                { step: 'phone_verification', status: 'pending' },
                { step: 'document_upload', status: 'pending' },
                { step: 'biometric_check', status: 'pending' }
            ],
            initiatedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        };
        
        await query(`
            INSERT INTO identity_proofing
            (id, user_id, status, steps, initiated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [
            proofingSession.id,
            proofingSession.userId,
            proofingSession.status,
            JSON.stringify(proofingSession.steps),
            proofingSession.initiatedAt,
            proofingSession.expiresAt
        ]);
        
        return proofingSession;
    }
    
    // ==================== AUDIT LOGGING ====================
    
    async recordTrustEvaluation(userId, result) {
        await query(`
            INSERT INTO trust_evaluations
            (id, user_id, trust_score, level, risk_factors, created_at)
            VALUES (?, ?, ?, ?, ?, NOW())
        `, [uuidv4(), userId, result.score, result.level.name, JSON.stringify(result.riskFactors)]);
    }
    
    async logSecurityEvent(eventType, data) {
        await query(`
            INSERT INTO security_events
            (id, event_type, severity, data, created_at)
            VALUES (?, ?, ?, ?, NOW())
        `, [uuidv4(), eventType, 'MEDIUM', JSON.stringify(data)]);
    }
}

module.exports = {
    ZeroTrustIAM,
    TRUST_LEVELS,
    SESSION_STATES
};
