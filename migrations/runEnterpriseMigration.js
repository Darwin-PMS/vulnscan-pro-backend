/**
 * Enterprise Database Migration
 * Run: node migrations/runEnterpriseMigration.js
 */

const { pool } = require('../database/db');

const MIGRATION_SQL = `
-- =====================================================
-- ENTERPRISE TABLES MIGRATION
-- =====================================================

-- MFA Configurations
CREATE TABLE IF NOT EXISTS mfa_configurations (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    type ENUM('totp', 'email', 'sms') NOT NULL,
    secret VARCHAR(255),
    backup_codes JSON,
    is_active BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_type (user_id, type)
);

-- Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    ip_address VARCHAR(100),
    user_agent TEXT,
    status ENUM('success', 'failure') DEFAULT 'success',
    risk_level ENUM('low', 'medium', 'high', 'critical') DEFAULT 'low',
    metadata JSON,
    session_id VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_action (user_id, action),
    INDEX idx_created_at (created_at),
    INDEX idx_risk_level (risk_level)
);

-- Security Events
CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(36) PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    source VARCHAR(50),
    user_id INT,
    ip_address VARCHAR(45),
    data JSON,
    status ENUM('new', 'investigating', 'resolved', 'false_positive') DEFAULT 'new',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_severity (severity),
    INDEX idx_status (status)
);

-- Incident Tickets
CREATE TABLE IF NOT EXISTS incident_tickets (
    ticket_id VARCHAR(36) PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    status ENUM('open', 'investigating', 'escalated', 'resolved', 'closed') DEFAULT 'open',
    user_id INT,
    description TEXT,
    source VARCHAR(50),
    assigned_to INT,
    escalation_level INT DEFAULT 0,
    timeline JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    INDEX idx_status (status),
    INDEX idx_severity (severity)
);

-- Login History
CREATE TABLE IF NOT EXISTS login_history (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    failure_reason VARCHAR(100),
    mfa_used BOOLEAN DEFAULT FALSE,
    mfa_method VARCHAR(50),
    device_fingerprint VARCHAR(255),
    geo_location JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_created (user_id, created_at)
);

-- Login Attempts
CREATE TABLE IF NOT EXISTS login_attempts (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT,
    ip_address VARCHAR(45),
    success BOOLEAN DEFAULT FALSE,
    failure_reason VARCHAR(100),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_timestamp (user_id, timestamp),
    INDEX idx_ip_timestamp (ip_address, timestamp)
);

-- Trusted Devices
CREATE TABLE IF NOT EXISTS trusted_devices (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    fingerprint VARCHAR(255) NOT NULL,
    device_type VARCHAR(50),
    browser VARCHAR(100),
    os VARCHAR(100),
    ip_address VARCHAR(45),
    trust_level DECIMAL(3,2) DEFAULT 0.30,
    first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_user_fingerprint (user_id, fingerprint)
);

-- User Locations
CREATE TABLE IF NOT EXISTS user_locations (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    country VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    ip_address VARCHAR(45),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_location (user_id, country)
);

-- User Sessions
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    state ENUM('active', 'suspended', 'revoked', 'expired') DEFAULT 'active',
    trust_score DECIMAL(3,2) DEFAULT 0.50,
    device_fingerprint VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    mfa_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_state (user_id, state)
);

-- Trust Evaluations
CREATE TABLE IF NOT EXISTS trust_evaluations (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    trust_score DECIMAL(3,2) NOT NULL,
    level VARCHAR(20),
    risk_factors JSON,
    device_fingerprint VARCHAR(255),
    ip_address VARCHAR(45),
    evaluated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_score (user_id, trust_score)
);

-- Privilege Access Logs
CREATE TABLE IF NOT EXISTS privileged_access_logs (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    outcome ENUM('success', 'denied', 'error') DEFAULT 'success',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_resource (user_id, resource)
);

-- Token Lifecycle
CREATE TABLE IF NOT EXISTS token_lifecycle (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT,
    token_type VARCHAR(50),
    action ENUM('created', 'used', 'refreshed', 'rotated', 'revoked', 'expired') NOT NULL,
    reason VARCHAR(100),
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_token (user_id, token_type)
);

-- Custom Roles
CREATE TABLE IF NOT EXISTS custom_roles (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    permissions JSON,
    created_by INT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Permission Changes
CREATE TABLE IF NOT EXISTS permission_changes (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    old_role VARCHAR(50),
    new_role VARCHAR(50),
    changed_by INT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id)
);

-- Consent Records
CREATE TABLE IF NOT EXISTS consent_records (
    consent_id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    type ENUM('marketing', 'analytics', 'functional', 'essential') NOT NULL,
    purpose TEXT,
    status ENUM('granted', 'denied', 'withdrawn', 'pending') DEFAULT 'pending',
    method VARCHAR(50),
    granted_at TIMESTAMP NULL,
    withdrawn_at TIMESTAMP NULL,
    ip_address VARCHAR(100),
    user_agent TEXT,
    version VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_type (user_id, type)
);

-- Privacy Audit Logs
CREATE TABLE IF NOT EXISTS privacy_audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    data_category VARCHAR(50),
    user_id INT,
    details JSON,
    consent_id VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id)
);

-- Data Export Requests
CREATE TABLE IF NOT EXISTS data_export_requests (
    request_id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    status ENUM('pending', 'processing', 'completed', 'failed', 'expired') DEFAULT 'pending',
    format VARCHAR(20) DEFAULT 'json',
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    INDEX idx_user_status (user_id, status)
);

-- Data Deletion Requests
CREATE TABLE IF NOT EXISTS data_deletion_requests (
    request_id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',
    type ENUM('soft', 'hard') DEFAULT 'soft',
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    INDEX idx_user_status (user_id, status)
);

-- AI Audit Logs
CREATE TABLE IF NOT EXISTS ai_audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT,
    prompt TEXT,
    sanitized_prompt TEXT,
    response TEXT,
    trust_score DECIMAL(3,2),
    hallucination_detected JSON,
    safety_violations JSON,
    tokens_used INT,
    model_version VARCHAR(50),
    latency_ms INT,
    action VARCHAR(100),
    details JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_created (user_id, created_at)
);

-- AI Approval Requests
CREATE TABLE IF NOT EXISTS ai_approval_requests (
    request_id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    request_type VARCHAR(50),
    prompt TEXT,
    response_preview TEXT,
    trust_score DECIMAL(3,2),
    status ENUM('pending', 'approved', 'rejected', 'expired') DEFAULT 'pending',
    context JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP NULL,
    reviewed_by INT,
    decision VARCHAR(50),
    notes TEXT,
    INDEX idx_status (status)
);

-- Notifications
CREATE TABLE IF NOT EXISTS notifications (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT,
    data JSON,
    priority ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    channel ENUM('in_app', 'email', 'sms', 'webhook') DEFAULT 'in_app',
    status ENUM('unread', 'read', 'archived') DEFAULT 'unread',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    read_at TIMESTAMP NULL,
    INDEX idx_user_status (user_id, status)
);

-- System Backups
CREATE TABLE IF NOT EXISTS system_backups (
    backup_id VARCHAR(36) PRIMARY KEY,
    type ENUM('full', 'incremental', 'differential') NOT NULL,
    status ENUM('in_progress', 'completed', 'failed', 'verified') DEFAULT 'in_progress',
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP NULL,
    location VARCHAR(500),
    size VARCHAR(50),
    checksum VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add columns to existing users table
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS last_password_change TIMESTAMP NULL,
ADD COLUMN IF NOT EXISTS failed_login_attempts INT DEFAULT 0,
ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP NULL;

-- Add columns to existing scans table  
ALTER TABLE scans
ADD COLUMN IF NOT EXISTS scan_type ENUM('web', 'api', 'mobile', 'network', 'full') DEFAULT 'web',
ADD COLUMN IF NOT EXISTS risk_score INT;

-- Add columns to vulnerabilities table
ALTER TABLE vulnerabilities
ADD COLUMN IF NOT EXISTS cve_ids JSON,
ADD COLUMN IF NOT EXISTS cvss_score DECIMAL(3,1),
ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS false_positive BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS mitigated BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS mitigated_at TIMESTAMP NULL;
`;

async function runMigration() {
    console.log('Starting enterprise migration...');
    
    try {
        const connection = await pool.getConnection();
        
        const statements = MIGRATION_SQL
            .split(';')
            .map(s => s.trim())
            .filter(s => s.length > 0 && !s.startsWith('--'));
        
        for (const statement of statements) {
            try {
                await connection.query(statement);
                console.log('Executed:', statement.substring(0, 50) + '...');
            } catch (err) {
                if (err.code !== 'ER_TABLE_EXISTS_ERROR' && err.code !== 'ER_DUP_FIELDNAME') {
                    console.error('Statement failed:', err.message);
                }
            }
        }
        
        connection.release();
        console.log('\nEnterprise migration completed successfully!');
    } catch (error) {
        console.error('Migration failed:', error);
        process.exit(1);
    }
}

runMigration();
