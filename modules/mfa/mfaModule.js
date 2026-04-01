/**
 * MFA Module - Multi-Factor Authentication
 * Supports TOTP, Email OTP, and Backup Codes
 */

const { v4: uuidv4 } = require('uuid');
const { query } = require('../../database/db');
const crypto = require('crypto');

class MFAModule {
    constructor() {
        this.otpExpiry = 5 * 60 * 1000;
        this.otpLength = 6;
        this.backupCodesCount = 10;
    }

    async generateTOTPSecret(userId) {
        const secret = crypto.randomBytes(20).toString('base32').slice(0, 24);
        const backupCodes = this.generateBackupCodes();
        
        await query(`
            INSERT INTO mfa_configurations 
            (id, user_id, type, secret, backup_codes, created_at, is_active)
            VALUES (?, ?, 'totp', ?, ?, NOW(), TRUE)
        `, [uuidv4(), userId, secret, JSON.stringify(backupCodes)]);

        const qrCodeUrl = this.getTOTPQRCodeUrl(secret, 'VulnScan Pro', userId);
        
        return {
            secret,
            backupCodes,
            qrCodeUrl,
            manualEntryKey: secret
        };
    }

    generateBackupCodes() {
        const codes = [];
        for (let i = 0; i < this.backupCodesCount; i++) {
            codes.push({
                code: crypto.randomBytes(4).toString('hex').toUpperCase(),
                used: false,
                usedAt: null
            });
        }
        return codes;
    }

    getTOTPQRCodeUrl(secret, issuer, user) {
        const otpauth = `otpauth://totp/${issuer}:${user}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
        return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauth)}`;
    }

    verifyTOTP(secret, token) {
        const time = Math.floor(Date.now() / 30000);
        const delta = 1;

        for (let i = -delta; i <= delta; i++) {
            const expectedToken = this.generateTOTPToken(secret, time + i);
            if (expectedToken === token) {
                return { valid: true };
            }
        }

        return { valid: false, reason: 'Invalid or expired code' };
    }

    generateTOTPToken(secret, counter) {
        const counterBuffer = Buffer.alloc(8);
        counterBuffer.writeBigInt64BE(BigInt(counter), 0);

        const hmac = crypto.createHmac('sha1', Buffer.from(secret, 'base32'));
        hmac.update(counterBuffer);
        const hash = hmac.digest();

        const offset = hash[hash.length - 1] & 0xf;
        const code = (
            ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff)
        ) % Math.pow(10, this.otpLength);

        return code.toString().padStart(this.otpLength, '0');
    }

    async generateEmailOTP(userId) {
        const otp = crypto.randomInt(100000, 999999).toString();
        const expiresAt = new Date(Date.now() + this.otpExpiry);

        await query(`
            INSERT INTO mfa_configurations 
            (id, user_id, type, secret, backup_codes, expires_at, created_at, is_active)
            VALUES (?, ?, 'email', ?, NULL, ?, NOW(), FALSE)
        `, [uuidv4(), userId, otp, expiresAt]);

        await this.sendEmailOTP(userId, otp);

        return {
            expiresAt,
            message: 'OTP sent to your email'
        };
    }

    async sendEmailOTP(userId, otp) {
        const [user] = await query('SELECT email, username FROM users WHERE id = ?', [userId]);
        if (!user) return;

        console.log(`[MFA] Email OTP for ${user.username}: ${otp}`);
        
        return true;
    }

    async verifyEmailOTP(userId, otp) {
        const [config] = await query(`
            SELECT * FROM mfa_configurations 
            WHERE user_id = ? AND type = 'email' AND is_active = FALSE
            ORDER BY created_at DESC LIMIT 1
        `, [userId]);

        if (!config) {
            return { valid: false, reason: 'No OTP found' };
        }

        if (new Date(config.expires_at) < new Date()) {
            return { valid: false, reason: 'OTP has expired' };
        }

        if (config.secret !== otp) {
            return { valid: false, reason: 'Invalid OTP' };
        }

        await query('UPDATE mfa_configurations SET is_active = TRUE WHERE id = ?', [config.id]);

        return { valid: true };
    }

    async verifyBackupCode(userId, code) {
        const [config] = await query(`
            SELECT * FROM mfa_configurations 
            WHERE user_id = ? AND type = 'totp' AND is_active = TRUE
        `, [userId]);

        if (!config) {
            return { valid: false, reason: 'MFA not enabled' };
        }

        const backupCodes = JSON.parse(config.backup_codes);
        const codeIndex = backupCodes.findIndex(
            c => c.code === code.toUpperCase() && !c.used
        );

        if (codeIndex === -1) {
            return { valid: false, reason: 'Invalid backup code' };
        }

        backupCodes[codeIndex].used = true;
        backupCodes[codeIndex].usedAt = new Date().toISOString();

        await query(
            'UPDATE mfa_configurations SET backup_codes = ? WHERE id = ?',
            [JSON.stringify(backupCodes), config.id]
        );

        return { valid: true, remainingCodes: backupCodes.filter(c => !c.used).length };
    }

    async getMFAStatus(userId) {
        const [config] = await query(`
            SELECT type, is_active FROM mfa_configurations 
            WHERE user_id = ? ORDER BY created_at DESC LIMIT 1
        `, [userId]);

        return {
            enabled: config?.is_active || false,
            type: config?.type || null,
            methods: ['totp', 'email', 'backup']
        };
    }

    async disableMFA(userId, code) {
        const [config] = await query(`
            SELECT * FROM mfa_configurations WHERE user_id = ? AND is_active = TRUE
        `, [userId]);

        if (!config) {
            return { success: false, reason: 'MFA not enabled' };
        }

        if (config.type === 'totp') {
            const verified = this.verifyTOTP(config.secret, code);
            if (!verified.valid) {
                return { success: false, reason: 'Invalid verification code' };
            }
        } else if (config.type === 'email') {
            const verified = await this.verifyEmailOTP(userId, code);
            if (!verified.valid) {
                return { success: false, reason: 'Invalid verification code' };
            }
        }

        await query('DELETE FROM mfa_configurations WHERE user_id = ?', [userId]);

        return { success: true };
    }

    async setupMFA(userId, method = 'totp') {
        switch (method) {
            case 'totp':
                return await this.generateTOTPSecret(userId);
            case 'email':
                return await this.generateEmailOTP(userId);
            default:
                throw new Error('Invalid MFA method');
        }
    }

    async completeMFAEnable(userId, verifyCode) {
        const [config] = await query(`
            SELECT * FROM mfa_configurations WHERE user_id = ? AND type = 'totp' AND is_active = FALSE
        `, [userId]);

        if (!config) {
            return { success: false, reason: 'No pending MFA setup' };
        }

        const verified = this.verifyTOTP(config.secret, verifyCode);
        if (!verified.valid) {
            return { success: false, reason: 'Invalid code' };
        }

        await query('UPDATE mfa_configurations SET is_active = TRUE WHERE id = ?', [config.id]);

        return { success: true };
    }
}

module.exports = new MFAModule();
