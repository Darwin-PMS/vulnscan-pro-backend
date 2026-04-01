/**
 * Enterprise Database Schema Additions
 * Tables for multi-tenancy, RBAC, workflows, integrations
 * Run this to extend your existing database
 */

const ENTERPRISE_TABLES = `
-- =====================================================
-- MULTI-TENANT TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    namespace VARCHAR(100) UNIQUE NOT NULL,
    plan ENUM('free', 'basic', 'pro', 'enterprise') DEFAULT 'basic',
    settings JSON,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_namespace (namespace),
    INDEX idx_plan (plan)
);

CREATE TABLE IF NOT EXISTS user_tenants (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    tenant_id VARCHAR(36) NOT NULL,
    role ENUM('owner', 'admin', 'user', 'guest') DEFAULT 'user',
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_user_tenant (user_id, tenant_id),
    INDEX idx_tenant (tenant_id),
    INDEX idx_user (user_id)
);

CREATE TABLE IF NOT EXISTS tenant_resources (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    limit INT NOT NULL,
    current_usage INT DEFAULT 0,
    UNIQUE KEY uk_tenant_resource (tenant_id, resource_type),
    INDEX idx_tenant (tenant_id)
);

-- =====================================================
-- PROJECT MANAGEMENT TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS projects (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    tenant_id VARCHAR(36),
    owner_id INT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    risk_score INT DEFAULT 0,
    business_criticality ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_tenant (tenant_id),
    INDEX idx_owner (owner_id)
);

CREATE TABLE IF NOT EXISTS project_members (
    id VARCHAR(36) PRIMARY KEY,
    project_id VARCHAR(36) NOT NULL,
    user_id INT NOT NULL,
    role ENUM('owner', 'admin', 'member', 'viewer') DEFAULT 'member',
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_project_user (project_id, user_id),
    INDEX idx_project (project_id),
    INDEX idx_user (user_id)
);

CREATE TABLE IF NOT EXISTS assets (
    id VARCHAR(36) PRIMARY KEY,
    project_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    type ENUM('domain', 'api', 'webapp', 'mobile', 'container', 'cloud', 'source_code') NOT NULL,
    url VARCHAR(500),
    description TEXT,
    is_public BOOLEAN DEFAULT FALSE,
    environment ENUM('production', 'staging', 'development', 'test') DEFAULT 'production',
    data_classification ENUM('public', 'internal', 'confidential', 'restricted') DEFAULT 'internal',
    criticality ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    risk_score INT DEFAULT 0,
    last_scanned TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_project (project_id),
    INDEX idx_type (type),
    INDEX idx_public (is_public)
);

-- =====================================================
-- VULNERABILITY WORKFLOW TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS vulnerability_workflows (
    id VARCHAR(36) PRIMARY KEY,
    vulnerability_id VARCHAR(36) NOT NULL,
    current_state ENUM('open', 'triaged', 'assigned', 'in_progress', 'fixed', 'rescan_pending', 'verified', 'closed') DEFAULT 'open',
    sla_due_date TIMESTAMP NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_vulnerability (vulnerability_id),
    INDEX idx_state (current_state),
    INDEX idx_sla (sla_due_date)
);

CREATE TABLE IF NOT EXISTS workflow_transitions (
    id VARCHAR(36) PRIMARY KEY,
    vulnerability_id VARCHAR(36) NOT NULL,
    from_state VARCHAR(50),
    to_state VARCHAR(50) NOT NULL,
    transitioned_by INT,
    notes TEXT,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_vulnerability (vulnerability_id),
    INDEX idx_created (created_at)
);

CREATE TABLE IF NOT EXISTS vulnerability_comments (
    id VARCHAR(36) PRIMARY KEY,
    vulnerability_id VARCHAR(36) NOT NULL,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_vulnerability (vulnerability_id),
    INDEX idx_user (user_id)
);

-- =====================================================
-- INTEGRATION TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS integrations (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36),
    user_id INT NOT NULL,
    type ENUM('scm', 'ticketing', 'messaging', 'siem', 'sca', 'scanner', 'compliance') NOT NULL,
    provider VARCHAR(50) NOT NULL,
    name VARCHAR(255),
    config TEXT NOT NULL,
    status ENUM('active', 'inactive', 'error') DEFAULT 'active',
    last_sync TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_tenant (tenant_id),
    INDEX idx_provider (provider),
    INDEX idx_status (status)
);

CREATE TABLE IF NOT EXISTS integration_logs (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36),
    integration_id VARCHAR(36),
    integration_type VARCHAR(50),
    action VARCHAR(100),
    external_id VARCHAR(100),
    status ENUM('success', 'failed') DEFAULT 'success',
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_integration (integration_id),
    INDEX idx_created (created_at)
);

CREATE TABLE IF NOT EXISTS integration_webhooks (
    id VARCHAR(36) PRIMARY KEY,
    integration_id VARCHAR(36) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    webhook_url VARCHAR(500) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_integration (integration_id)
);

-- =====================================================
-- SCHEDULED SCANS
-- =====================================================

CREATE TABLE IF NOT EXISTS scheduled_scans (
    id VARCHAR(36) PRIMARY KEY,
    project_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    modules JSON NOT NULL,
    schedule_cron VARCHAR(100),
    schedule_type ENUM('once', 'daily', 'weekly', 'monthly', 'custom') DEFAULT 'weekly',
    next_run_at TIMESTAMP NULL,
    last_run_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_by INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_project (project_id),
    INDEX idx_next_run (next_run_at),
    INDEX idx_active (is_active)
);

-- =====================================================
-- SCAN QUEUE & WORKER TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS scan_queue (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(100) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    status ENUM('queued', 'processing', 'completed', 'failed', 'cancelled') DEFAULT 'queued',
    priority ENUM('low', 'normal', 'high', 'critical') DEFAULT 'normal',
    progress INT DEFAULT 0,
    worker_id VARCHAR(100),
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_scan_id (scan_id),
    INDEX idx_status (status),
    INDEX idx_priority (priority)
);

-- =====================================================
-- COMPLIANCE REPORTING
-- =====================================================

CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    framework ENUM('nist_csf', 'iso_27001', 'soc2', 'pci_dss', 'hipaa', 'gdpr') NOT NULL,
    version VARCHAR(20),
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS compliance_controls (
    id VARCHAR(36) PRIMARY KEY,
    framework_id VARCHAR(36) NOT NULL,
    control_id VARCHAR(50) NOT NULL,
    control_name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    implementation_status ENUM('implemented', 'partial', 'planned', 'not_applicable') DEFAULT 'planned',
    last_reviewed TIMESTAMP NULL,
    next_review TIMESTAMP NULL,
    evidence JSON,
    notes TEXT,
    UNIQUE KEY uk_framework_control (framework_id, control_id),
    INDEX idx_framework (framework_id),
    INDEX idx_status (implementation_status)
);

CREATE TABLE IF NOT EXISTS compliance_assessments (
    id VARCHAR(36) PRIMARY KEY,
    framework_id VARCHAR(36) NOT NULL,
    project_id VARCHAR(36),
    assessment_type ENUM('self', 'internal', 'external') DEFAULT 'self',
    status ENUM('in_progress', 'completed', 'failed') DEFAULT 'in_progress',
    score DECIMAL(5,2),
    findings JSON,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    assessed_by INT,
    INDEX idx_framework (framework_id),
    INDEX idx_project (project_id)
);

-- =====================================================
-- PERMISSION CHANGES AUDIT
-- =====================================================

CREATE TABLE IF NOT EXISTS permission_changes (
    id VARCHAR(36) PRIMARY KEY,
    user_id INT NOT NULL,
    old_role VARCHAR(50),
    new_role VARCHAR(50) NOT NULL,
    changed_by INT NOT NULL,
    tenant_id VARCHAR(36),
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_id),
    INDEX idx_changed_by (changed_by)
);

-- =====================================================
-- CUSTOM ROLES
-- =====================================================

CREATE TABLE IF NOT EXISTS custom_roles (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSON NOT NULL,
    tenant_id VARCHAR(36),
    is_active BOOLEAN DEFAULT TRUE,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_tenant (tenant_id)
);

-- =====================================================
-- CVE & THREAT INTELLIGENCE
-- =====================================================

CREATE TABLE IF NOT EXISTS cve_tracking (
    id VARCHAR(36) PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL UNIQUE,
    description TEXT,
    severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
    cvss_score DECIMAL(3,1),
    affected_products JSON,
    patch_available BOOLEAN DEFAULT FALSE,
    patch_version VARCHAR(50),
    in_kev BOOLEAN DEFAULT FALSE,
    epss_score DECIMAL(5,2),
    first_published TIMESTAMP NULL,
    last_modified TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_cve (cve_id),
    INDEX idx_severity (severity),
    INDEX idx_kev (in_kev)
);

CREATE TABLE IF NOT EXISTS threat_intel (
    id VARCHAR(36) PRIMARY KEY,
    indicator_type VARCHAR(50) NOT NULL,
    indicator_value TEXT NOT NULL,
    threat_type VARCHAR(100),
    source VARCHAR(100),
    confidence_score DECIMAL(3,2),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_indicator (indicator_type, indicator_value(100)),
    INDEX idx_threat (threat_type)
);

-- =====================================================
-- ADD TO EXISTING TABLES (if not exists)
-- =====================================================

-- Add to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_super_admin BOOLEAN DEFAULT FALSE;

-- Add to scans table
ALTER TABLE scans ADD COLUMN IF NOT EXISTS project_id VARCHAR(36);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS asset_id VARCHAR(36);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS modules JSON;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS schedule_id VARCHAR(36);

-- Add to vulnerabilities table
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS project_id VARCHAR(36);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS asset_id VARCHAR(36);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS assigned_to INT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS status VARCHAR(50);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS risk_score INT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS false_positive BOOLEAN DEFAULT FALSE;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT FALSE;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS duplicate_of VARCHAR(36);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS risk_accepted BOOLEAN DEFAULT FALSE;
`;

module.exports = { ENTERPRISE_TABLES };