/**
 * Enterprise Database Schema
 * NIST CSF, Privacy, Zero Trust, Compliance Ready
 */

const ENTERPRISE_SCHEMA = `
-- =====================================================
-- VULNSCAN PRO - ENTERPRISE DATABASE SCHEMA
-- NIST CSF, Privacy, Zero Trust, Compliance Ready
-- =====================================================

-- =====================================================
-- CORE TABLES
-- =====================================================

-- Existing users table (enhanced)
ALTER TABLE users ADD COLUMN IF NOT EXISTS 
    last_password_change TIMESTAMP NULL,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    identity_verified BOOLEAN DEFAULT FALSE,
    trusted_devices_limit INT DEFAULT 5;

-- Existing scans table (enhanced)
ALTER TABLE scans ADD COLUMN IF NOT EXISTS 
    scan_type ENUM('web', 'api', 'mobile', 'network', 'full') DEFAULT 'web',
    scan_profile VARCHAR(50),
    is_scheduled BOOLEAN DEFAULT FALSE,
    schedule_cron VARCHAR(100),
    risk_score INT,
    compliance_frameworks JSON;

-- Existing vulnerabilities table (enhanced)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS 
    cve_ids JSON,
    cvss_score DECIMAL(3,1),
    owasp_category VARCHAR(50),
    remediation_priority ENUM('critical', 'high', 'medium', 'low'),
    remediation_effort ENUM('low', 'medium', 'high'),
    false_positive BOOLEAN DEFAULT FALSE,
    verified BOOLEAN DEFAULT FALSE,
    mitigated BOOLEAN DEFAULT FALSE,
    mitigated_at TIMESTAMP NULL,
    mitigated_by INT;

-- =====================================================
-- AUDIT & COMPLIANCE TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    details JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    status ENUM('success', 'failure', 'partial') DEFAULT 'success',
    risk_level ENUM('low', 'medium', 'high', 'critical') DEFAULT 'low',
    session_id VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_action (user_id, action),
    INDEX idx_created_at (created_at),
    INDEX idx_action (action),
    INDEX idx_risk_level (risk_level)
);

CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(36) PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    source VARCHAR(50),
    user_id INT,
    ip_address VARCHAR(45),
    data JSON,
    status ENUM('new', 'investigating', 'resolved', 'false_positive') DEFAULT 'new',
    assigned_to INT,
    resolution_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    INDEX idx_event_type (event_type),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
);

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
    INDEX idx_severity (severity),
    INDEX idx_created_at (created_at)
);

-- =====================================================
-- BACKUP & DISASTER RECOVERY
-- =====================================================

CREATE TABLE IF NOT EXISTS system_backups (
    backup_id VARCHAR(36) PRIMARY KEY,
    type ENUM('full', 'incremental', 'differential') NOT NULL,
    status ENUM('in_progress', 'completed', 'failed', 'verified') DEFAULT 'in_progress',
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP NULL,
    location VARCHAR(500),
    size VARCHAR(50),
    checksum VARCHAR(64),
    verified_at TIMESTAMP NULL,
    verified_by INT,
    retention_days INT DEFAULT 30,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS disaster_recovery_plans (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    rto_minutes INT DEFAULT 240,
    rpo_minutes INT DEFAULT 60,
    steps JSON,
    test_history JSON,
    last_tested_at TIMESTAMP NULL,
    next_test_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP
);

-- =====================================================
-- CONSENT & PRIVACY TABLES
-- =====================================================

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
    INDEX idx_user_type (user_id, type),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS privacy_audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    data_category ENUM('pii', 'sensitive', 'health', 'financial', 'biometric', 'location', 'behavioral', 'technical'),
    user_id INT,
    details JSON,
    consent_id VARCHAR(36),
    data_subject_request_id VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS data_export_requests (
    request_id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    status ENUM('pending', 'processing', 'completed', 'failed', 'expired') DEFAULT 'pending',
    format VARCHAR(20) DEFAULT 'json',
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    download_url VARCHAR(500),
    INDEX idx_user_status (user_id, status),
    INDEX idx_requested_at (requested_at)
);

CREATE TABLE IF NOT EXISTS data_deletion_requests (
    request_id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',
    type ENUM('soft', 'hard') DEFAULT 'soft',
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    scheduled_at TIMESTAMP NULL,
    INDEX idx_user_status (user_id, status),
    INDEX idx_requested_at (requested_at)
);

-- =====================================================
-- ZERO TRUST & IAM TABLES
-- =====================================================

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
    verified BOOLEAN DEFAULT FALSE,
    INDEX idx_user_fingerprint (user_id, fingerprint),
    INDEX idx_is_active (is_active)
);

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
    risk_level ENUM('low', 'medium', 'high') DEFAULT 'low',
    INDEX idx_user_location (user_id, country),
    INDEX idx_last_seen (last_seen)
);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    state ENUM('active', 'suspended', 'revoked', 'expired') DEFAULT 'active',
    trust_score DECIMAL(3,2) DEFAULT 0.50,
    device_fingerprint VARCHAR(255),
    ip_address VARCHAR(45),
    geo_location JSON,
    user_agent TEXT,
    mfa_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP NULL,
    INDEX idx_user_state (user_id, state),
    INDEX idx_expires_at (expires_at)
);

CREATE TABLE IF NOT EXISTS trust_evaluations (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    trust_score DECIMAL(3,2) NOT NULL,
    level VARCHAR(20),
    risk_factors JSON,
    device_fingerprint VARCHAR(255),
    ip_address VARCHAR(45),
    geo_location JSON,
    evaluated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_score (user_id, trust_score),
    INDEX idx_evaluated_at (evaluated_at)
);

CREATE TABLE IF NOT EXISTS privileged_access_logs (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    outcome ENUM('success', 'denied', 'error') DEFAULT 'success',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_resource (user_id, resource),
    INDEX idx_timestamp (timestamp)
);

CREATE TABLE IF NOT EXISTS token_lifecycle (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT,
    token_type VARCHAR(50),
    action ENUM('created', 'used', 'refreshed', 'rotated', 'revoked', 'expired') NOT NULL,
    reason VARCHAR(100),
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_token (user_id, token_type),
    INDEX idx_action (action)
);

CREATE TABLE IF NOT EXISTS known_ip_addresses (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT,
    ip_address VARCHAR(45) NOT NULL,
    type ENUM('home', 'work', 'vpn', 'datacenter', 'other') DEFAULT 'other',
    is_trusted BOOLEAN DEFAULT FALSE,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_user_ip (user_id, ip_address),
    INDEX idx_ip_address (ip_address)
);

CREATE TABLE IF NOT EXISTS identity_proofing (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    status ENUM('initiated', 'pending_verification', 'verified', 'failed', 'expired') DEFAULT 'initiated',
    steps JSON,
    initiated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    verification_method VARCHAR(50),
    INDEX idx_user_status (user_id, status)
);

-- =====================================================
-- AI GOVERNANCE TABLES
-- =====================================================

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
    INDEX idx_user_created (user_id, created_at),
    INDEX idx_trust_score (trust_score),
    INDEX idx_created_at (created_at)
);

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
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS ai_bias_logs (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT,
    input_type VARCHAR(50),
    output_sample TEXT,
    bias_indicators JSON,
    bias_score DECIMAL(3,2),
    reviewed BOOLEAN DEFAULT FALSE,
    reviewed_by INT,
    reviewed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- VULNERABILITY & THREAT TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS cve_tracking (
    id VARCHAR(36) PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL UNIQUE,
    severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
    cvss_score DECIMAL(3,1),
    affected_components JSON,
    patch_status ENUM('unpatched', 'patched', 'mitigated', 'not_applicable') DEFAULT 'unpatched',
    risk_score INT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    patched_at TIMESTAMP NULL,
    notes TEXT,
    INDEX idx_cve_severity (cve_id, severity),
    INDEX idx_patch_status (patch_status)
);

CREATE TABLE IF NOT EXISTS threat_intel_feeds (
    id VARCHAR(36) PRIMARY KEY,
    source VARCHAR(100) NOT NULL,
    indicator_type VARCHAR(50),
    indicator_value TEXT,
    threat_type VARCHAR(100),
    confidence_score DECIMAL(3,2),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    expires_at TIMESTAMP,
    raw_data JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_indicator (indicator_type, indicator_value),
    INDEX idx_threat_type (threat_type),
    INDEX idx_expires (expires_at)
);

CREATE TABLE IF NOT EXISTS abuse_patterns (
    id VARCHAR(36) PRIMARY KEY,
    pattern_type VARCHAR(50) NOT NULL,
    pattern_description TEXT,
    detection_rule TEXT,
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    auto_action ENUM('log', 'alert', 'block', 'ban') DEFAULT 'alert',
    is_active BOOLEAN DEFAULT TRUE,
    hit_count INT DEFAULT 0,
    last_triggered TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS forensic_evidence (
    id VARCHAR(36) PRIMARY KEY,
    incident_id VARCHAR(36),
    evidence_type ENUM('log', 'screenshot', 'network_capture', 'memory_dump', 'file_sample', 'other') NOT NULL,
    description TEXT,
    file_path VARCHAR(500),
    hash_sha256 VARCHAR(64),
    chain_of_custody JSON,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    collected_by INT,
    preserved_until TIMESTAMP NULL,
    integrity_verified BOOLEAN DEFAULT FALSE,
    INDEX idx_incident (incident_id),
    INDEX idx_collected_at (collected_at)
);

-- =====================================================
-- API USAGE & RATE LIMITING
-- =====================================================

CREATE TABLE IF NOT EXISTS api_usage_logs (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10),
    status_code INT,
    response_time_ms INT,
    request_size INT,
    response_size INT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_endpoint (user_id, endpoint),
    INDEX idx_created_at (created_at),
    INDEX idx_response_time (response_time_ms)
);

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    id VARCHAR(36) PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    bucket_type ENUM('ip', 'user', 'api_key') NOT NULL,
    tokens INT DEFAULT 100,
    max_tokens INT DEFAULT 100,
    refill_rate INT DEFAULT 10,
    last_refill TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_identifier_type (identifier, bucket_type),
    INDEX idx_tokens (tokens)
);

-- =====================================================
-- COMPLIANCE & REPORTING TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS compliance_reports (
    id VARCHAR(36) PRIMARY KEY,
    framework ENUM('nist_csf', 'iso_27001', 'soc2', 'gdpr', 'pdp', 'hipaa') NOT NULL,
    report_type ENUM('assessment', 'audit', 'gap_analysis', 'risk_assessment') NOT NULL,
    period_start DATE,
    period_end DATE,
    overall_score DECIMAL(5,2),
    status ENUM('draft', 'review', 'approved', 'published') DEFAULT 'draft',
    findings JSON,
    recommendations JSON,
    evidence_files JSON,
    generated_by INT,
    approved_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP NULL,
    published_at TIMESTAMP NULL,
    INDEX idx_framework_status (framework, status),
    INDEX idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS control_mappings (
    id VARCHAR(36) PRIMARY KEY,
    framework VARCHAR(50) NOT NULL,
    control_id VARCHAR(50) NOT NULL,
    control_name VARCHAR(255),
    implementation_status ENUM('implemented', 'partial', 'planned', 'not_applicable') DEFAULT 'planned',
    control_owner INT,
    last_reviewed TIMESTAMP NULL,
    next_review TIMESTAMP NULL,
    evidence_references JSON,
    notes TEXT,
    UNIQUE KEY uk_framework_control (framework, control_id),
    INDEX idx_implementation (implementation_status)
);

CREATE TABLE IF NOT EXISTS vendor_assessments (
    id VARCHAR(36) PRIMARY KEY,
    vendor_name VARCHAR(255) NOT NULL,
    vendor_type VARCHAR(100),
    risk_score INT,
    assessment_status ENUM('pending', 'in_progress', 'completed', 'expired') DEFAULT 'pending',
    assessment_type ENUM('questionnaire', 'audit', 'pentest', 'full') DEFAULT 'questionnaire',
    last_assessed TIMESTAMP NULL,
    next_assessment TIMESTAMP NULL,
    documents JSON,
    findings JSON,
    approved_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- NOTIFICATIONS & ALERTS
-- =====================================================

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
    INDEX idx_user_status (user_id, status),
    INDEX idx_type (type),
    INDEX idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    alert_type VARCHAR(50),
    conditions JSON NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    actions JSON,
    is_active BOOLEAN DEFAULT TRUE,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    triggered_count INT DEFAULT 0,
    last_triggered TIMESTAMP NULL
);

CREATE TABLE IF NOT EXISTS alert_subscriptions (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    alert_rule_id VARCHAR(36),
    channel ENUM('in_app', 'email', 'sms', 'webhook') DEFAULT 'in_app',
    webhook_url VARCHAR(500),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_alert (user_id, alert_rule_id)
);

-- =====================================================
-- LOGIN HISTORY
-- =====================================================

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
    INDEX idx_user_created (user_id, created_at),
    INDEX idx_ip (ip_address)
);

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

-- =====================================================
-- ASSET MANAGEMENT
-- =====================================================

CREATE TABLE IF NOT EXISTS asset_inventory (
    id VARCHAR(36) PRIMARY KEY,
    asset_type ENUM('api_endpoint', 'database', 'service', 'component', 'dependency') NOT NULL,
    asset_identifier VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    description TEXT,
    owner INT,
    classification ENUM('public', 'internal', 'confidential', 'restricted') DEFAULT 'internal',
    risk_level ENUM('low', 'medium', 'high', 'critical'),
    dependencies JSON,
    last_scanned TIMESTAMP NULL,
    vulnerability_count INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_type_active (asset_type, is_active),
    INDEX idx_risk (risk_level)
);

-- =====================================================
-- INDEXES FOR PERFORMANCE
-- =====================================================

CREATE INDEX IF NOT EXISTS idx_audit_user_action ON audit_logs(user_id, action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_security_severity ON security_events(severity, status);
CREATE INDEX IF NOT EXISTS idx_incident_status ON incident_tickets(status, severity);
CREATE INDEX IF NOT EXISTS idx_consent_user ON consent_records(user_id, type);
CREATE INDEX IF NOT EXISTS idx_session_user ON user_sessions(user_id, state);
CREATE INDEX IF NOT EXISTS idx_trust_user ON trust_evaluations(user_id, trust_score);
CREATE INDEX IF NOT EXISTS idx_ai_audit_user ON ai_audit_logs(user_id, created_at);
`;

module.exports = { ENTERPRISE_SCHEMA };
