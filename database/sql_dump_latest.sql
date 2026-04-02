-- =====================================================
-- VulnScan Pro Database Schema & Master Data
-- Version: 2.1.0
-- Date: 2026-04-02
-- Description: Complete database schema with all modules and master data
-- =====================================================

-- =====================================================
-- CORE TABLES
-- =====================================================

-- Users Table
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `email` VARCHAR(100) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `role` ENUM('user', 'admin', 'enterprise') DEFAULT 'user',
    `is_active` BOOLEAN DEFAULT TRUE,
    `is_email_verified` BOOLEAN DEFAULT FALSE,
    `email_verification_token` VARCHAR(255),
    `password_reset_token` VARCHAR(255),
    `password_reset_expires` DATETIME,
    `failed_login_attempts` INT DEFAULT 0,
    `locked_until` DATETIME,
    `last_login` DATETIME,
    `subscription_id` INT,
    `subscription_tier` ENUM('free', 'basic', 'pro', 'enterprise') DEFAULT 'free',
    `scan_quota` INT DEFAULT 10,
    `scans_used` INT DEFAULT 0,
    `mfa_enabled` BOOLEAN DEFAULT FALSE,
    `mfa_method` ENUM('totp', 'email', 'sms', 'backup_code') DEFAULT NULL,
    `mfa_secret` VARCHAR(255),
    `mfa_backup_codes` TEXT,
    `profile_picture` VARCHAR(255),
    `first_name` VARCHAR(50),
    `last_name` VARCHAR(50),
    `company` VARCHAR(100),
    `job_title` VARCHAR(100),
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_email` (`email`),
    INDEX `idx_role` (`role`),
    INDEX `idx_subscription` (`subscription_tier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Scans Table
CREATE TABLE IF NOT EXISTS `scans` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` VARCHAR(255) NOT NULL UNIQUE,
    `user_id` INT NOT NULL,
    `target_url` VARCHAR(500) NOT NULL,
    `scan_type` ENUM('full', 'owasp', 'ghdb', 'api', 'cloud', 'cicd', 'mobile', 'llm', 'container', 'custom') DEFAULT 'full',
    `status` ENUM('pending', 'running', 'completed', 'failed', 'cancelled') DEFAULT 'pending',
    `progress` INT DEFAULT 0,
    `total_vulnerabilities` INT DEFAULT 0,
    `critical_count` INT DEFAULT 0,
    `high_count` INT DEFAULT 0,
    `medium_count` INT DEFAULT 0,
    `low_count` INT DEFAULT 0,
    `info_count` INT DEFAULT 0,
    `scan_modules` TEXT,
    `scan_options` JSON,
    `scheduled` BOOLEAN DEFAULT FALSE,
    `scheduled_at` DATETIME,
    `parent_scan_id` VARCHAR(255),
    `is_recurring` BOOLEAN DEFAULT FALSE,
    `recurring_pattern` VARCHAR(50),
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `started_at` DATETIME,
    `completed_at` DATETIME,
    `deleted_at` DATETIME,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_scan_id` (`scan_id`),
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_status` (`status`),
    INDEX `idx_scan_type` (`scan_type`),
    INDEX `idx_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Vulnerabilities Table
CREATE TABLE IF NOT EXISTS `vulnerabilities` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` VARCHAR(255) NOT NULL,
    `vulnerability_type` VARCHAR(255) NOT NULL,
    `owasp_category` VARCHAR(255),
    `cwe_id` VARCHAR(20),
    `cve_id` VARCHAR(20),
    `severity` ENUM('critical', 'high', 'medium', 'low', 'info') NOT NULL,
    `cvss_score` DECIMAL(3,1),
    `title` VARCHAR(500) NOT NULL,
    `description` TEXT,
    `url` VARCHAR(1000),
    `parameter` VARCHAR(255),
    `method` VARCHAR(10),
    `evidence` TEXT,
    `remediation` TEXT,
    `false_positive` BOOLEAN DEFAULT FALSE,
    `verified` BOOLEAN DEFAULT FALSE,
    `status` ENUM('open', 'in_progress', 'resolved', 'accepted', 'false_positive') DEFAULT 'open',
    `assigned_to` INT,
    `notes` TEXT,
    `ghdb_id` VARCHAR(50),
    `nist_category` VARCHAR(100),
    `discovered_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `resolved_at` DATETIME,
    FOREIGN KEY (`scan_id`) REFERENCES `scans`(`scan_id`) ON DELETE CASCADE,
    FOREIGN KEY (`assigned_to`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    INDEX `idx_scan_id` (`scan_id`),
    INDEX `idx_severity` (`severity`),
    INDEX `idx_status` (`status`),
    INDEX `idx_owasp` (`owasp_category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Scan History Table
CREATE TABLE IF NOT EXISTS `scan_history` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` VARCHAR(255) NOT NULL,
    `action` VARCHAR(255) NOT NULL,
    `details` TEXT,
    `metadata` JSON,
    `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`scan_id`) REFERENCES `scans`(`scan_id`) ON DELETE CASCADE,
    INDEX `idx_scan_id` (`scan_id`),
    INDEX `idx_timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Dork Patterns Table (GHDB)
CREATE TABLE IF NOT EXISTS `dork_patterns` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `ghdb_id` VARCHAR(50) UNIQUE NOT NULL,
    `title` VARCHAR(500) NOT NULL,
    `description` TEXT,
    `category` VARCHAR(255),
    `search_pattern` VARCHAR(1000) NOT NULL,
    `severity` ENUM('critical', 'high', 'medium', 'low', 'info') DEFAULT 'medium',
    `is_active` BOOLEAN DEFAULT TRUE,
    `risk_level` ENUM('low', 'medium', 'high', 'critical'),
    `impact` TEXT,
    `example` TEXT,
    `references` TEXT,
    `owasp_category` VARCHAR(255),
    `nist_category` VARCHAR(100),
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_ghdb_id` (`ghdb_id`),
    INDEX `idx_category` (`category`),
    INDEX `idx_severity` (`severity`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Subscriptions Table
CREATE TABLE IF NOT EXISTS `subscriptions` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `tier` ENUM('free', 'basic', 'pro', 'enterprise') NOT NULL,
    `status` ENUM('active', 'cancelled', 'expired', 'pending') DEFAULT 'pending',
    `start_date` DATE NOT NULL,
    `end_date` DATE,
    `billing_cycle` ENUM('monthly', 'yearly', 'lifetime') DEFAULT 'monthly',
    `price` DECIMAL(10,2),
    `currency` VARCHAR(3) DEFAULT 'USD',
    `payment_method` VARCHAR(50),
    `payment_id` VARCHAR(255),
    `auto_renew` BOOLEAN DEFAULT TRUE,
    `features` JSON,
    `scan_limit` INT,
    `api_access` BOOLEAN DEFAULT FALSE,
    `team_members` INT DEFAULT 1,
    `custom_scans` BOOLEAN DEFAULT FALSE,
    `priority_support` BOOLEAN DEFAULT FALSE,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_status` (`status`),
    INDEX `idx_tier` (`tier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Subscription Tiers Table
CREATE TABLE IF NOT EXISTS `subscription_tiers` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `tier` VARCHAR(50) NOT NULL UNIQUE,
    `name` VARCHAR(100) NOT NULL,
    `description` TEXT,
    `price_monthly` DECIMAL(10,2),
    `price_yearly` DECIMAL(10,2),
    `features` JSON,
    `scan_limit` INT,
    `api_access` BOOLEAN DEFAULT FALSE,
    `team_members` INT DEFAULT 1,
    `custom_scans` BOOLEAN DEFAULT FALSE,
    `priority_support` BOOLEAN DEFAULT FALSE,
    `is_active` BOOLEAN DEFAULT TRUE,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_tier` (`tier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- ENTERPRISE & SECURITY TABLES
-- =====================================================

-- MFA Configurations Table
CREATE TABLE IF NOT EXISTS `mfa_configurations` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `method` ENUM('totp', 'email', 'sms', 'backup_code') NOT NULL,
    `secret` VARCHAR(255),
    `backup_codes` TEXT,
    `phone_number` VARCHAR(20),
    `is_active` BOOLEAN DEFAULT FALSE,
    `is_verified` BOOLEAN DEFAULT FALSE,
    `verification_attempts` INT DEFAULT 0,
    `last_used` DATETIME,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit Logs Table
CREATE TABLE IF NOT EXISTS `audit_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT,
    `action` VARCHAR(255) NOT NULL,
    `resource_type` VARCHAR(100),
    `resource_id` VARCHAR(255),
    `ip_address` VARCHAR(45),
    `user_agent` TEXT,
    `request_method` VARCHAR(10),
    `request_path` VARCHAR(500),
    `request_body` TEXT,
    `response_status` INT,
    `risk_level` ENUM('low', 'medium', 'high', 'critical') DEFAULT 'low',
    `metadata` JSON,
    `session_id` VARCHAR(255),
    `location` VARCHAR(255),
    `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_action` (`action`),
    INDEX `idx_resource` (`resource_type`, `resource_id`),
    INDEX `idx_risk_level` (`risk_level`),
    INDEX `idx_timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Security Events Table
CREATE TABLE IF NOT EXISTS `security_events` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `event_type` VARCHAR(100) NOT NULL,
    `severity` ENUM('info', 'low', 'medium', 'high', 'critical') DEFAULT 'medium',
    `title` VARCHAR(255) NOT NULL,
    `description` TEXT,
    `user_id` INT,
    `ip_address` VARCHAR(45),
    `user_agent` TEXT,
    `status` ENUM('new', 'investigating', 'resolved', 'false_positive') DEFAULT 'new',
    `resolution` TEXT,
    `resolved_by` INT,
    `resolved_at` DATETIME,
    `metadata` JSON,
    `source` VARCHAR(100),
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    FOREIGN KEY (`resolved_by`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    INDEX `idx_event_type` (`event_type`),
    INDEX `idx_severity` (`severity`),
    INDEX `idx_status` (`status`),
    INDEX `idx_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Incident Tickets Table
CREATE TABLE IF NOT EXISTS `incident_tickets` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `ticket_id` VARCHAR(50) NOT NULL UNIQUE,
    `type` ENUM('security', 'technical', 'compliance', 'operational') DEFAULT 'security',
    `severity` ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    `status` ENUM('open', 'investigating', 'escalated', 'resolved', 'closed') DEFAULT 'open',
    `title` VARCHAR(500) NOT NULL,
    `description` TEXT,
    `user_id` INT,
    `assigned_to` INT,
    `priority` INT DEFAULT 5,
    `escalation_level` INT DEFAULT 0,
    `source` VARCHAR(100),
    `related_scan_id` VARCHAR(255),
    `related_vulnerability_id` INT,
    `tags` JSON,
    `attachments` JSON,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `resolved_at` DATETIME,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    FOREIGN KEY (`assigned_to`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    INDEX `idx_ticket_id` (`ticket_id`),
    INDEX `idx_status` (`status`),
    INDEX `idx_severity` (`severity`),
    INDEX `idx_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Incident History Table
CREATE TABLE IF NOT EXISTS `incident_history` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `ticket_id` VARCHAR(50) NOT NULL,
    `action` VARCHAR(255) NOT NULL,
    `changes` JSON,
    `performed_by` INT,
    `notes` TEXT,
    `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`ticket_id`) REFERENCES `incident_tickets`(`ticket_id`) ON DELETE CASCADE,
    FOREIGN KEY (`performed_by`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    INDEX `idx_ticket_id` (`ticket_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- RBAC TABLES
-- =====================================================

-- Roles Table
CREATE TABLE IF NOT EXISTS `roles` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(50) NOT NULL UNIQUE,
    `display_name` VARCHAR(100) NOT NULL,
    `description` TEXT,
    `permissions` JSON,
    `is_system` BOOLEAN DEFAULT FALSE,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Permissions Table
CREATE TABLE IF NOT EXISTS `permissions` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(100) NOT NULL UNIQUE,
    `resource` VARCHAR(50) NOT NULL,
    `action` VARCHAR(50) NOT NULL,
    `description` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_name` (`name`),
    INDEX `idx_resource` (`resource`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User Roles Table
CREATE TABLE IF NOT EXISTS `user_roles` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `role_id` INT NOT NULL,
    `assigned_by` INT,
    `assigned_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`role_id`) REFERENCES `roles`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`assigned_by`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    UNIQUE KEY `unique_user_role` (`user_id`, `role_id`),
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_role_id` (`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- ENTERPRISE TABLES
-- =====================================================

-- Tenants Table
CREATE TABLE IF NOT EXISTS `tenants` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `tenant_id` VARCHAR(50) NOT NULL UNIQUE,
    `name` VARCHAR(100) NOT NULL,
    `domain` VARCHAR(100),
    `status` ENUM('active', 'suspended', 'pending') DEFAULT 'pending',
    `plan` ENUM('free', 'basic', 'pro', 'enterprise') DEFAULT 'free',
    `max_users` INT DEFAULT 5,
    `max_scans` INT DEFAULT 100,
    `storage_quota` BIGINT DEFAULT 10737418240,
    `storage_used` BIGINT DEFAULT 0,
    `settings` JSON,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_tenant_id` (`tenant_id`),
    INDEX `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tenant Users Table
CREATE TABLE IF NOT EXISTS `tenant_users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `tenant_id` VARCHAR(50) NOT NULL,
    `user_id` INT NOT NULL,
    `role` VARCHAR(50) DEFAULT 'member',
    `invited_by` INT,
    `joined_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`tenant_id`) ON DELETE CASCADE,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`invited_by`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    UNIQUE KEY `unique_tenant_user` (`tenant_id`, `user_id`),
    INDEX `idx_tenant_id` (`tenant_id`),
    INDEX `idx_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- API Keys Table
CREATE TABLE IF NOT EXISTS `api_keys` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `key_name` VARCHAR(100) NOT NULL,
    `key_hash` VARCHAR(255) NOT NULL,
    `prefix` VARCHAR(20) NOT NULL,
    `permissions` JSON,
    `rate_limit` INT DEFAULT 1000,
    `last_used` DATETIME,
    `expires_at` DATETIME,
    `is_active` BOOLEAN DEFAULT TRUE,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_key_hash` (`key_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- SCANNER MODULE TABLES
-- =====================================================

-- Scan Modules Table
CREATE TABLE IF NOT EXISTS `scan_modules` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `module_name` VARCHAR(100) NOT NULL UNIQUE,
    `display_name` VARCHAR(255) NOT NULL,
    `description` TEXT,
    `category` VARCHAR(50),
    `is_active` BOOLEAN DEFAULT TRUE,
    `requires_subscription` VARCHAR(50) DEFAULT 'free',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_module_name` (`module_name`),
    INDEX `idx_category` (`category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Scan Results Cache Table
CREATE TABLE IF NOT EXISTS `scan_results_cache` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `target_url` VARCHAR(500) NOT NULL,
    `module` VARCHAR(100) NOT NULL,
    `result_hash` VARCHAR(255) NOT NULL,
    `result_data` JSON,
    `expires_at` DATETIME NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_target` (`target_url`, `module`),
    INDEX `idx_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- MASTER DATA INSERTION
-- =====================================================

-- Insert Default Admin User (Password: Password@123)
INSERT INTO `users` (`username`, `email`, `password`, `role`, `is_active`, `is_email_verified`, `subscription_tier`, `scan_quota`, `first_name`, `last_name`, `company`) VALUES
('admin', 'admin@vulnscan.pro', '$2b$10$Yoh8BNjXokYZ9qmbI6JYRuImDZ5chZ3b.6otGqBmt80r5OCQ87I22', 'admin', TRUE, TRUE, 'enterprise', -1, 'System', 'Administrator', 'VulnScan Pro Inc.');

-- Insert Test Users
INSERT INTO `users` (`username`, `email`, `password_hash`, `role`, `is_active`, `is_email_verified`, `subscription_tier`, `scan_quota`, `first_name`, `last_name`, `company`) VALUES
('admin', 'admin@vulnscan.pro', '$2b$10$Yoh8BNjXokYZ9qmbI6JYRuImDZ5chZ3b.6otGqBmt80r5OCQ87I22', 'admin', TRUE, TRUE, 'enterprise', -1, 'System', 'Administrator', 'VulnScan Pro Inc.'),
('john_doe', 'john@example.com', '$2b$10$Yoh8BNjXokYZ9qmbI6JYRuImDZ5chZ3b.6otGqBmt80r5OCQ87I22', 'user', TRUE, TRUE, 'free', 5, 'John', 'Doe', 'Tech Corp'),
('jane_smith', 'jane@example.com', '$2b$10$Yoh8BNjXokYZ9qmbI6JYRuImDZ5chZ3b.6otGqBmt80r5OCQ87I22', 'user', TRUE, TRUE, 'pro', 200, 'Jane', 'Smith', 'SecureTech Inc'),
('enterprise_user', 'enterprise@example.com', '$2b$10$Yoh8BNjXokYZ9qmbI6JYRuImDZ5chZ3b.6otGqBmt80r5OCQ87I22', 'enterprise', TRUE, TRUE, 'enterprise', -1, 'Enterprise', 'User', 'BigCorp Industries');

-- Insert Subscription Tiers
INSERT INTO `subscription_tiers` (`tier`, `name`, `description`, `price_monthly`, `price_yearly`, `features`, `scan_limit`, `api_access`, `team_members`, `custom_scans`, `priority_support`, `is_active`) VALUES
('free', 'Free', 'Basic vulnerability scanning for hobbyists', 0.00, 0.00, '{"basic_scans": true, "owasp_top10": true, "ghdb_patterns": true, "pdf_reports": false, "api_access": false, "priority_support": false, "ai_assistant": false, "custom_dorks": false, "scheduled_scans": false, "team_collaboration": false}', 5, FALSE, 1, FALSE, FALSE, TRUE),
('basic', 'Basic', 'For small teams and freelancers', 19.99, 199.99, '{"basic_scans": true, "owasp_top10": true, "ghdb_patterns": true, "pdf_reports": true, "api_access": false, "priority_support": false, "ai_assistant": false, "custom_dorks": false, "scheduled_scans": false, "team_collaboration": false, "advanced_payloads": false}', 50, FALSE, 3, FALSE, FALSE, TRUE),
('pro', 'Professional', 'For growing businesses', 49.99, 499.99, '{"basic_scans": true, "owasp_top10": true, "ghdb_patterns": true, "pdf_reports": true, "api_access": true, "priority_support": true, "ai_assistant": true, "custom_dorks": false, "scheduled_scans": true, "team_collaboration": false, "advanced_payloads": true}', 200, TRUE, 5, FALSE, TRUE, TRUE),
('enterprise', 'Enterprise', 'For large organizations', 149.99, 1499.99, '{"basic_scans": true, "owasp_top10": true, "ghdb_patterns": true, "pdf_reports": true, "api_access": true, "priority_support": true, "ai_assistant": true, "custom_dorks": true, "scheduled_scans": true, "team_collaboration": true, "advanced_payloads": true}', -1, TRUE, -1, TRUE, TRUE, TRUE);

-- Insert Roles
INSERT INTO `roles` (`name`, `display_name`, `description`, `permissions`, `is_system`) VALUES
('admin', 'Administrator', 'Full system access with all permissions', '{"all": true}', TRUE),
('user', 'Standard User', 'Regular user with basic scan access', '{"scan": ["read", "write"], "vulnerability": ["read"], "report": ["read", "write"]}', TRUE),
('enterprise', 'Enterprise User', 'Enterprise user with advanced features', '{"scan": ["read", "write", "execute"], "vulnerability": ["read", "write"], "report": ["read", "write", "export"], "api": ["read", "write"], "team": ["read", "write"]}', TRUE),
('analyst', 'Security Analyst', 'Can view and analyze vulnerabilities', '{"scan": ["read"], "vulnerability": ["read", "write"], "report": ["read"]}', TRUE),
('viewer', 'Viewer', 'Read-only access to scans and reports', '{"scan": ["read"], "vulnerability": ["read"], "report": ["read"]}', TRUE);

-- Insert Permissions
INSERT INTO `permissions` (`name`, `resource`, `action`, `description`) VALUES
('scan_read', 'scan', 'read', 'View scan results'),
('scan_write', 'scan', 'write', 'Create new scans'),
('scan_execute', 'scan', 'execute', 'Run scans'),
('scan_delete', 'scan', 'delete', 'Delete scan results'),
('vulnerability_read', 'vulnerability', 'read', 'View vulnerabilities'),
('vulnerability_write', 'vulnerability', 'write', 'Update vulnerability status'),
('vulnerability_delete', 'vulnerability', 'delete', 'Delete vulnerabilities'),
('report_read', 'report', 'read', 'View reports'),
('report_write', 'report', 'write', 'Create reports'),
('report_export', 'report', 'export', 'Export reports'),
('api_read', 'api', 'read', 'View API keys'),
('api_write', 'api', 'write', 'Create API keys'),
('user_read', 'user', 'read', 'View users'),
('user_write', 'user', 'write', 'Manage users'),
('admin_access', 'admin', 'access', 'Admin panel access');

-- Insert User Roles
INSERT INTO `user_roles` (`user_id`, `role_id`, `assigned_by`) VALUES
(1, 1, NULL),
(2, 2, 1),
(3, 3, 1),
(4, 4, 1);

-- Insert Sample Dork Patterns
INSERT INTO `dork_patterns` (`ghdb_id`, `title`, `description`, `category`, `search_pattern`, `severity`, `risk_level`, `impact`, `owasp_category`, `nist_category`) VALUES
('DORK-001', 'Exposed MySQL Databases', 'Google dork to find exposed MySQL database files', 'Sensitive Files', 'ext:sql +("MySQL" +"dump")', 'critical', 'critical', 'Database exposure may lead to data breach', 'A01:2021-Broken Access Control', 'PR.DS-1'),
('DORK-002', 'Exposed Config Files', 'Find exposed configuration files containing credentials', 'Sensitive Files', 'ext:env | ext:ini | ext:conf +("password" OR "secret")', 'critical', 'critical', 'Exposed credentials can be exploited', 'A02:2021-Cryptographic Failures', 'PR.DS-2'),
('DORK-003', 'Publicly Exposed Notebooks', 'Find exposed Jupyter notebooks with potential code', 'Sensitive Files', 'ext:ipynb +("password" OR "api_key" OR "secret")', 'high', 'high', 'Code and credentials exposure', 'A01:2021-Broken Access Control', 'PR.DS-1'),
('DORK-004', 'AWS Access Keys', 'Find publicly exposed AWS access keys', 'Sensitive Files', 'AKIA | ASIA | ABIA | ACCA +("key" OR "secret")', 'critical', 'critical', 'Full AWS account compromise', 'A02:2021-Cryptographic Failures', 'PR.DS-2'),
('DORK-005', 'SQL Injection Parameters', 'Find URLs with potential SQL injection points', 'Injection', 'inurl:php?id= | inurl:asp?id= | inurl:query?id=', 'high', 'high', 'SQL injection can lead to data theft', 'A03:2021-Injection', 'PR.DS-1'),
('DORK-006', 'Exposed .git Directory', 'Find exposed .git repositories', 'Sensitive Files', 'inurl:.git/ | intitle:"Index of" ".git"', 'high', 'high', 'Source code exposure', 'A01:2021-Broken Access Control', 'PR.DS-1'),
('DORK-007', 'WordPress Config Exposure', 'Find exposed WordPress configuration files', 'Web Servers', 'filetype:php "wp-config.php" -download', 'critical', 'critical', 'Database credentials exposure', 'A02:2021-Cryptographic Failures', 'PR.DS-2'),
('DORK-008', 'Exposed PHPMyAdmin', 'Find publicly accessible PHPMyAdmin installations', 'Web Servers', 'intitle:"phpMyAdmin" "Welcome to phpMyAdmin"', 'high', 'high', 'Database administration interface exposed', 'A01:2021-Broken Access Control', 'PR.AC-1'),
('DORK-009', 'Open Elasticsearch', 'Find exposed Elasticsearch instances', 'Databases', '"cluster_name" "elasticsearch" "version"', 'high', 'high', 'Unprotected database access', 'A01:2021-Broken Access Control', 'PR.AC-1'),
('DORK-010', 'JWT Tokens in URL', 'Find JWT tokens exposed in URLs', 'Sensitive Files', 'inurl:jwt | inurl:token | inurl:access_token', 'medium', 'medium', 'Token exposure may lead to unauthorized access', 'A02:2021-Cryptographic Failures', 'PR.DS-2'),
('DORK-011', 'Private Keys', 'Find exposed private keys', 'Sensitive Files', 'ext:key | ext:pem | ext:ppk +("PRIVATE KEY")', 'critical', 'critical', 'Identity and encryption compromise', 'A02:2021-Cryptographic Failures', 'PR.DS-2'),
('DORK-012', 'Backup Files', 'Find exposed backup files', 'Sensitive Files', 'ext:bak | ext:backup | ext:old +("sql" OR "database")', 'high', 'high', 'Database backup exposure', 'A04:2021-Insecure Design', 'PR.DS-1'),
('DORK-013', 'Exposed MongoDB', 'Find unprotected MongoDB databases', 'Databases', 'MongoDB "_connectionUri" | "mongodb://"', 'high', 'high', 'Unprotected database access', 'A01:2021-Broken Access Control', 'PR.AC-1'),
('DORK-014', 'Log Files', 'Find exposed log files', 'Sensitive Files', 'ext:log +("password" OR "error" OR "exception")', 'medium', 'medium', 'Sensitive information in logs', 'A01:2021-Broken Access Control', 'PR.DS-1'),
('DORK-015', 'Excel Files with SSN', 'Find spreadsheets containing sensitive data', 'Sensitive Files', 'filetype:xlsx +("SSN" OR "social security" OR "credit card")', 'critical', 'critical', 'PII data breach', 'A04:2021-Insecure Design', 'PR.DS-1'),
('DORK-016', 'Docker Config', 'Find exposed Docker configuration files', 'Sensitive Files', 'Dockerfile +("password" OR "secret" OR "api_key")', 'high', 'high', 'Container configuration exposure', 'A04:2021-Insecure Design', 'PR.DS-2'),
('DORK-017', 'PDF with Credentials', 'Find PDFs containing credentials', 'Sensitive Files', 'filetype:pdf +("username" OR "password" OR "credentials")', 'high', 'high', 'Credential exposure', 'A02:2021-Cryptographic Failures', 'PR.DS-2'),
('DORK-018', 'Exposed Redis', 'Find unprotected Redis instances', 'Databases', 'Redis "PONG" | "redis_version"', 'high', 'high', 'Unprotected in-memory database', 'A01:2021-Broken Access Control', 'PR.AC-1'),
('DORK-019', 'S3 Bucket Listing', 'Find publicly accessible S3 buckets', 'Cloud Storage', 'site:s3.amazonaws.com +("Bucket" OR "Object")', 'high', 'high', 'Cloud storage data exposure', 'A01:2021-Broken Access Control', 'PR.DS-1'),
('DORK-020', 'Exposed Admin Panels', 'Find exposed administrative interfaces', 'Web Servers', 'inurl:admin | inurl:administrator | inurl:backend', 'medium', 'medium', 'Administrative interface exposed', 'A01:2021-Broken Access Control', 'PR.AC-1');

-- Insert Scan Modules
INSERT INTO `scan_modules` (`module_name`, `display_name`, `description`, `category`, `is_active`, `requires_subscription`) VALUES
('owasp_scanner', 'OWASP Top 10 Scanner', 'Comprehensive scanning for OWASP Top 10 vulnerabilities', 'Web Security', TRUE, 'free'),
('dork_scanner', 'Dork Pattern Scanner', 'Google Hacking Database pattern scanning', 'Information Gathering', TRUE, 'free'),
('api_scanner', 'API Security Scanner', 'REST and GraphQL API security testing', 'API Security', TRUE, 'pro'),
('mobile_scanner', 'Mobile App Scanner', 'Android and iOS application security', 'Mobile Security', TRUE, 'pro'),
('cloud_scanner', 'Cloud Security Scanner', 'AWS, Azure, GCP security assessment', 'Cloud Security', TRUE, 'enterprise'),
('container_scanner', 'Container Security', 'Docker and Kubernetes security scanning', 'Container Security', TRUE, 'enterprise'),
('llm_scanner', 'LLM Security Scanner', 'AI/LLM application vulnerability detection', 'AI Security', TRUE, 'enterprise'),
('cicd_scanner', 'CI/CD Security', 'Pipeline and deployment security scanning', 'DevSecOps', TRUE, 'enterprise'),
('secret_scanner', 'Secret Scanner', 'Detect hardcoded credentials and API keys', 'Secrets Detection', TRUE, 'free'),
('sca_scanner', 'SCA Scanner', 'Software Composition Analysis for dependencies', 'Dependency Security', TRUE, 'free');

-- Insert Sample Subscriptions
INSERT INTO `subscriptions` (`user_id`, `tier`, `status`, `start_date`, `end_date`, `billing_cycle`, `price`, `features`, `scan_limit`, `api_access`, `team_members`, `auto_renew`) VALUES
(1, 'enterprise', 'active', '2026-01-01', '2027-01-01', 'yearly', 1499.99, '{"all_features": true}', -1, TRUE, 10, TRUE),
(2, 'free', 'active', '2026-01-15', NULL, 'monthly', 0, '{"basic_scans": true}', 5, FALSE, 1, FALSE),
(3, 'pro', 'active', '2026-02-01', '2027-02-01', 'yearly', 499.99, '{"all_features": true, "priority_support": true}', 200, TRUE, 5, TRUE),
(4, 'enterprise', 'active', '2026-03-01', '2027-03-01', 'yearly', 1499.99, '{"all_features": true}', -1, TRUE, 10, TRUE);

-- Create Enterprise Tenant
INSERT INTO `tenants` (`tenant_id`, `name`, `domain`, `status`, `plan`, `max_users`, `max_scans`) VALUES
('VULNSCAN-PRO', 'VulnScan Pro Inc.', 'vulnscan.pro', 'active', 'enterprise', 100, -1);

-- Insert Tenant User
INSERT INTO `tenant_users` (`tenant_id`, `user_id`, `role`, `invited_by`) VALUES
('VULNSCAN-PRO', 1, 'owner', NULL);

-- =====================================================
-- COMPLETE
-- =====================================================

SELECT 'Database initialized successfully with master data!' AS status;
SELECT COUNT(*) AS users_created FROM users;
SELECT COUNT(*) AS dorks_created FROM dork_patterns;
SELECT COUNT(*) AS tiers_created FROM subscription_tiers;
SELECT COUNT(*) AS modules_created FROM scan_modules;
