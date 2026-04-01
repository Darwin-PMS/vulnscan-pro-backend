-- =====================================================
-- VulnScan Pro Database Schema
-- Version: 2.0.0
-- Date: 2026-03-31
-- Description: Complete database schema with all modules
-- =====================================================

-- =====================================================
-- CORE TABLES
-- =====================================================

-- Users Table
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `email` VARCHAR(100) NOT NULL UNIQUE,
    `password` VARCHAR(255) NOT NULL,
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
    `expires_at` DATETIME,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`role_id`) REFERENCES `roles`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`assigned_by`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    UNIQUE KEY `uk_user_role` (`user_id`, `role_id`),
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_role_id` (`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Role Permissions Table
CREATE TABLE IF NOT EXISTS `role_permissions` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `role_id` INT NOT NULL,
    `permission_id` INT NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`role_id`) REFERENCES `roles`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`permission_id`) REFERENCES `permissions`(`id`) ON DELETE CASCADE,
    UNIQUE KEY `uk_role_permission` (`role_id`, `permission_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Permission Changes Audit Table
CREATE TABLE IF NOT EXISTS `permission_changes` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `target_user_id` INT,
    `action` ENUM('grant', 'revoke', 'modify') NOT NULL,
    `permission_name` VARCHAR(100),
    `old_value` TEXT,
    `new_value` TEXT,
    `performed_by` INT,
    `reason` TEXT,
    `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`target_user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    FOREIGN KEY (`performed_by`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- ZERO TRUST TABLES
-- =====================================================

-- Trusted Devices Table
CREATE TABLE IF NOT EXISTS `trusted_devices` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `device_fingerprint` VARCHAR(255) NOT NULL,
    `device_name` VARCHAR(100),
    `device_type` VARCHAR(50),
    `browser` VARCHAR(100),
    `os` VARCHAR(100),
    `ip_address` VARCHAR(45),
    `last_ip` VARCHAR(45),
    `geo_location` VARCHAR(255),
    `last_access` DATETIME,
    `is_trusted` BOOLEAN DEFAULT FALSE,
    `trust_score` INT DEFAULT 50,
    `risk_factors` JSON,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    UNIQUE KEY `uk_device` (`user_id`, `device_fingerprint`),
    INDEX `idx_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Session Trust Scores Table
CREATE TABLE IF NOT EXISTS `session_trust_scores` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `session_id` VARCHAR(255) NOT NULL,
    `user_id` INT NOT NULL,
    `device_fingerprint` VARCHAR(255),
    `ip_address` VARCHAR(45),
    `geo_location` VARCHAR(255),
    `trust_score` INT DEFAULT 50,
    `risk_factors` JSON,
    `anomalies_detected` JSON,
    `is_verified` BOOLEAN DEFAULT FALSE,
    `mfa_used` BOOLEAN DEFAULT FALSE,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_session_id` (`session_id`),
    INDEX `idx_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Token Blacklist Table
CREATE TABLE IF NOT EXISTS `token_blacklist` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `token_hash` VARCHAR(255) NOT NULL UNIQUE,
    `user_id` INT NOT NULL,
    `reason` VARCHAR(255),
    `blacklisted_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `expires_at` DATETIME NOT NULL,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_token_hash` (`token_hash`),
    INDEX `idx_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- PRIVACY & GDPR TABLES
-- =====================================================

-- User Consents Table
CREATE TABLE IF NOT EXISTS `user_consents` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `consent_type` VARCHAR(100) NOT NULL,
    `purpose` TEXT,
    `granted` BOOLEAN DEFAULT FALSE,
    `ip_address` VARCHAR(45),
    `user_agent` TEXT,
    `granted_at` DATETIME,
    `withdrawn_at` DATETIME,
    `version` VARCHAR(20),
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    UNIQUE KEY `uk_user_consent` (`user_id`, `consent_type`),
    INDEX `idx_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Consent Templates Table
CREATE TABLE IF NOT EXISTS `consent_templates` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `consent_type` VARCHAR(100) NOT NULL UNIQUE,
    `name` VARCHAR(255) NOT NULL,
    `description` TEXT,
    `purpose` TEXT,
    `is_mandatory` BOOLEAN DEFAULT FALSE,
    `version` VARCHAR(20),
    `is_active` BOOLEAN DEFAULT TRUE,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_consent_type` (`consent_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data Processing Records Table (GDPR)
CREATE TABLE IF NOT EXISTS `data_processing_records` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `processing_type` VARCHAR(100) NOT NULL,
    `data_categories` JSON,
    `purpose` TEXT,
    `legal_basis` VARCHAR(100),
    `recipients` JSON,
    `retention_period` VARCHAR(100),
    `security_measures` TEXT,
    `is_international_transfer` BOOLEAN DEFAULT FALSE,
    `transfer_safeguards` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data Export Requests Table
CREATE TABLE IF NOT EXISTS `data_export_requests` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `request_id` VARCHAR(50) NOT NULL UNIQUE,
    `user_id` INT NOT NULL,
    `status` ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',
    `data_categories` JSON,
    `format` ENUM('json', 'csv', 'pdf') DEFAULT 'json',
    `download_url` VARCHAR(500),
    `expires_at` DATETIME,
    `requested_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `completed_at` DATETIME,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data Deletion Requests Table
CREATE TABLE IF NOT EXISTS `data_deletion_requests` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `request_id` VARCHAR(50) NOT NULL UNIQUE,
    `user_id` INT NOT NULL,
    `status` ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',
    `soft_delete` BOOLEAN DEFAULT TRUE,
    `anonymize` BOOLEAN DEFAULT TRUE,
    `reason` TEXT,
    `requested_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `scheduled_at` DATETIME,
    `completed_at` DATETIME,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- NIST CSF & COMPLIANCE TABLES
-- =====================================================

-- NIST CSF Controls Table
CREATE TABLE IF NOT EXISTS `nist_controls` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `function` ENUM('IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER', 'GOVERN') NOT NULL,
    `category` VARCHAR(100) NOT NULL,
    `control_id` VARCHAR(20) NOT NULL UNIQUE,
    `name` VARCHAR(255) NOT NULL,
    `description` TEXT,
    `implementation_tiers` JSON,
    `assurance_level` INT DEFAULT 1,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_function` (`function`),
    INDEX `idx_control_id` (`control_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- NIST Compliance Status Table
CREATE TABLE IF NOT EXISTS `nist_compliance` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `control_id` VARCHAR(20) NOT NULL,
    `status` ENUM('implemented', 'partial', 'not_implemented', 'not_applicable') DEFAULT 'not_implemented',
    `implementation_percentage` INT DEFAULT 0,
    `evidence` TEXT,
    `last_assessed` DATETIME,
    `next_review` DATETIME,
    `notes` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    UNIQUE KEY `uk_user_control` (`user_id`, `control_id`),
    INDEX `idx_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Risk Register Table
CREATE TABLE IF NOT EXISTS `risk_register` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `risk_id` VARCHAR(50) NOT NULL UNIQUE,
    `title` VARCHAR(255) NOT NULL,
    `description` TEXT,
    `category` VARCHAR(100),
    `likelihood` ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    `impact` ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    `risk_score` INT,
    `status` ENUM('identified', 'analyzing', 'mitigating', 'monitoring', 'accepted', 'resolved') DEFAULT 'identified',
    `mitigation_strategy` TEXT,
    `mitigation_actions` JSON,
    `residual_risk` INT,
    `owner` INT,
    `identified_by` INT,
    `identified_at` DATETIME,
    `resolved_at` DATETIME,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`owner`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    FOREIGN KEY (`identified_by`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    INDEX `idx_status` (`status`),
    INDEX `idx_risk_score` (`risk_score`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Anomalies Table
CREATE TABLE IF NOT EXISTS `anomalies` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `type` VARCHAR(100) NOT NULL,
    `severity` ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    `risk_level` ENUM('low', 'medium', 'high') DEFAULT 'medium',
    `description` TEXT,
    `user_id` INT,
    `session_id` VARCHAR(255),
    `ip_address` VARCHAR(45),
    `trigger_data` JSON,
    `status` ENUM('detected', 'investigating', 'confirmed', 'false_positive') DEFAULT 'detected',
    `detected_at` DATETIME,
    `resolved_at` DATETIME,
    `notes` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL,
    INDEX `idx_type` (`type`),
    INDEX `idx_status` (`status`),
    INDEX `idx_severity` (`severity`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- AI GOVERNANCE TABLES
-- =====================================================

-- AI Usage Logs Table
CREATE TABLE IF NOT EXISTS `ai_usage_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `action_type` VARCHAR(100) NOT NULL,
    `input` TEXT,
    `output` TEXT,
    `model` VARCHAR(100),
    `tokens_used` INT,
    `cost` DECIMAL(10,4),
    `trust_score` DECIMAL(5,2),
    `validation_result` JSON,
    `processing_time` INT,
    `metadata` JSON,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_action_type` (`action_type`),
    INDEX `idx_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Prompt Validation Logs Table
CREATE TABLE IF NOT EXISTS `prompt_validation_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `prompt` TEXT NOT NULL,
    `is_safe` BOOLEAN DEFAULT TRUE,
    `issues_found` JSON,
    `risk_score` INT,
    `action_taken` VARCHAR(100),
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_is_safe` (`is_safe`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- SCAN MODULES TABLES
-- =====================================================

-- OWASP Scan Results Table
CREATE TABLE IF NOT EXISTS `owasp_scan_results` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` VARCHAR(255) NOT NULL,
    `owasp_category` VARCHAR(50) NOT NULL,
    `category_name` VARCHAR(255),
    `vulnerability_id` VARCHAR(50),
    `title` VARCHAR(500),
    `description` TEXT,
    `severity` ENUM('critical', 'high', 'medium', 'low', 'info'),
    `url` VARCHAR(1000),
    `remediation` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`scan_id`) REFERENCES `scans`(`scan_id`) ON DELETE CASCADE,
    INDEX `idx_scan_id` (`scan_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- GHDB Scan Results Table
CREATE TABLE IF NOT EXISTS `ghdb_scan_results` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` VARCHAR(255) NOT NULL,
    `ghdb_id` VARCHAR(50),
    `category` VARCHAR(100),
    `title` VARCHAR(500),
    `dork_pattern` VARCHAR(1000),
    `severity` ENUM('critical', 'high', 'medium', 'low', 'info'),
    `url` VARCHAR(1000),
    `remediation` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`scan_id`) REFERENCES `scans`(`scan_id`) ON DELETE CASCADE,
    INDEX `idx_scan_id` (`scan_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- API Security Scan Results Table
CREATE TABLE IF NOT EXISTS `api_scan_results` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` VARCHAR(255) NOT NULL,
    `api_category` VARCHAR(50),
    `vulnerability_id` VARCHAR(50),
    `title` VARCHAR(500),
    `description` TEXT,
    `severity` ENUM('critical', 'high', 'medium', 'low', 'info'),
    `endpoint` VARCHAR(500),
    `method` VARCHAR(10),
    `remediation` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`scan_id`) REFERENCES `scans`(`scan_id`) ON DELETE CASCADE,
    INDEX `idx_scan_id` (`scan_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Cloud Security Scan Results Table
CREATE TABLE IF NOT EXISTS `cloud_scan_results` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` VARCHAR(255) NOT NULL,
    `provider` VARCHAR(20),
    `vulnerability_id` VARCHAR(50),
    `title` VARCHAR(500),
    `description` TEXT,
    `severity` ENUM('critical', 'high', 'medium', 'low', 'info'),
    `resource_arn` VARCHAR(500),
    `remediation` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`scan_id`) REFERENCES `scans`(`scan_id`) ON DELETE CASCADE,
    INDEX `idx_scan_id` (`scan_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- CI/CD Security Scan Results Table
CREATE TABLE IF NOT EXISTS `cicd_scan_results` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` VARCHAR(255) NOT NULL,
    `pipeline_type` VARCHAR(50),
    `vulnerability_id` VARCHAR(50),
    `title` VARCHAR(500),
    `description` TEXT,
    `severity` ENUM('critical', 'high', 'medium', 'low', 'info'),
    `file_path` VARCHAR(500),
    `remediation` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`scan_id`) REFERENCES `scans`(`scan_id`) ON DELETE CASCADE,
    INDEX `idx_scan_id` (`scan_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Mobile Security Scan Results Table
CREATE TABLE IF NOT EXISTS `mobile_scan_results` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` VARCHAR(255) NOT NULL,
    `platform` ENUM('android', 'ios'),
    `vulnerability_id` VARCHAR(50),
    `title` VARCHAR(500),
    `description` TEXT,
    `severity` ENUM('critical', 'high', 'medium', 'low', 'info'),
    `file_path` VARCHAR(500),
    `component` VARCHAR(255),
    `remediation` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`scan_id`) REFERENCES `scans`(`scan_id`) ON DELETE CASCADE,
    INDEX `idx_scan_id` (`scan_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Container Security Scan Results Table
CREATE TABLE IF NOT EXISTS `container_scan_results` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` VARCHAR(255) NOT NULL,
    `container_type` VARCHAR(50),
    `vulnerability_id` VARCHAR(50),
    `title` VARCHAR(500),
    `description` TEXT,
    `severity` ENUM('critical', 'high', 'medium', 'low', 'info'),
    `image` VARCHAR(255),
    `yaml_path` VARCHAR(500),
    `remediation` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`scan_id`) REFERENCES `scans`(`scan_id`) ON DELETE CASCADE,
    INDEX `idx_scan_id` (`scan_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- LLM Security Scan Results Table
CREATE TABLE IF NOT EXISTS `llm_scan_results` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `scan_id` VARCHAR(255) NOT NULL,
    `attack_category` VARCHAR(100),
    `vulnerability_id` VARCHAR(50),
    `title` VARCHAR(500),
    `description` TEXT,
    `severity` ENUM('critical', 'high', 'medium', 'low', 'info'),
    `prompt_sample` TEXT,
    `risk_score` INT,
    `remediation` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`scan_id`) REFERENCES `scans`(`scan_id`) ON DELETE CASCADE,
    INDEX `idx_scan_id` (`scan_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- INSERT DEFAULT DATA
-- =====================================================

-- Insert default subscription tiers
INSERT INTO `subscription_tiers` (`tier`, `name`, `price_monthly`, `price_yearly`, `features`, `scan_limit`, `api_access`, `team_members`) VALUES
('free', 'Free', 0.00, 0.00, '{"basic_scans": true, "reports": false}', 10, FALSE, 1),
('basic', 'Basic', 9.99, 99.99, '{"basic_scans": true, "reports": true, "email_support": true}', 50, FALSE, 1),
('pro', 'Professional', 29.99, 299.99, '{"all_scans": true, "reports": true, "priority_support": true, "api_access": true}', 500, TRUE, 5),
('enterprise', 'Enterprise', 99.99, 999.99, '{"all_scans": true, "unlimited_reports": true, "dedicated_support": true, "api_access": true, "sso": true, "audit_logs": true}', -1, TRUE, -1)
ON DUPLICATE KEY UPDATE name = VALUES(name);

-- Insert subscription tiers (schema.sql format)
INSERT INTO `subscription_tiers` (`tier`, `name`, `description`, `price_monthly`, `price_yearly`, `features`, `scan_limit`, `api_access`, `team_members`, `custom_scans`, `priority_support`) VALUES
('free', 'Free', 'Basic vulnerability scanning for hobbyists', 0.00, 0.00, '{"basic_scans": true, "owasp_top10": true, "ghdb_patterns": true, "pdf_reports": false, "api_access": false, "priority_support": false, "ai_assistant": false, "custom_dorks": false, "scheduled_scans": false, "team_collaboration": false, "advanced_payloads": false, "retest_vulnerabilities": false}', 5, FALSE, 1, FALSE, FALSE),
('starter', 'Starter', 'For small teams and freelancers', 19.99, 199.99, '{"basic_scans": true, "owasp_top10": true, "ghdb_patterns": true, "pdf_reports": true, "api_access": false, "priority_support": false, "ai_assistant": false, "custom_dorks": false, "scheduled_scans": false, "team_collaboration": false, "advanced_payloads": false, "retest_vulnerabilities": false}', 50, FALSE, 2, FALSE, FALSE),
('professional', 'Professional', 'For growing businesses', 49.99, 499.99, '{"basic_scans": true, "owasp_top10": true, "ghdb_patterns": true, "pdf_reports": true, "api_access": true, "priority_support": true, "ai_assistant": true, "custom_dorks": false, "scheduled_scans": true, "team_collaboration": false, "advanced_payloads": true, "retest_vulnerabilities": false}', 200, TRUE, 5, FALSE, TRUE),
('enterprise', 'Enterprise', 'For large organizations', 149.99, 1499.99, '{"basic_scans": true, "owasp_top10": true, "ghdb_patterns": true, "pdf_reports": true, "api_access": true, "priority_support": true, "ai_assistant": true, "custom_dorks": true, "scheduled_scans": true, "team_collaboration": true, "advanced_payloads": true, "retest_vulnerabilities": true}', -1, TRUE, 10, TRUE, TRUE)
ON DUPLICATE KEY UPDATE name = VALUES(name);

-- Insert default roles
INSERT INTO `roles` (`name`, `display_name`, `description`, `is_system`) VALUES
('super_admin', 'Super Administrator', 'Full system access with all permissions', TRUE),
('admin', 'Administrator', 'Administrative access to manage users and settings', TRUE),
('security_analyst', 'Security Analyst', 'Can view scans, vulnerabilities, and reports', FALSE),
('viewer', 'Viewer', 'Read-only access to scans and reports', FALSE)
ON DUPLICATE KEY UPDATE display_name = VALUES(display_name);

-- Insert default permissions
INSERT INTO `permissions` (`name`, `resource`, `action`, `description`) VALUES
('users.read', 'users', 'read', 'View user information'),
('users.write', 'users', 'write', 'Create and update users'),
('users.delete', 'users', 'delete', 'Delete users'),
('scans.read', 'scans', 'read', 'View scan results'),
('scans.write', 'scans', 'write', 'Create and modify scans'),
('scans.delete', 'scans', 'delete', 'Delete scans'),
('vulnerabilities.read', 'vulnerabilities', 'read', 'View vulnerabilities'),
('vulnerabilities.write', 'vulnerabilities', 'write', 'Modify vulnerability status'),
('reports.read', 'reports', 'read', 'View reports'),
('reports.write', 'reports', 'write', 'Create and modify reports'),
('settings.read', 'settings', 'read', 'View system settings'),
('settings.write', 'settings', 'write', 'Modify system settings'),
('audit.read', 'audit', 'read', 'View audit logs'),
('audit.write', 'audit', 'write', 'Modify audit settings'),
('enterprise.read', 'enterprise', 'read', 'View enterprise features'),
('enterprise.write', 'enterprise', 'write', 'Modify enterprise settings')
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- Insert default consent templates
INSERT INTO `consent_templates` (`consent_type`, `name`, `description`, `purpose`, `is_mandatory`, `version`) VALUES
('essential', 'Essential Cookies', 'Required for basic site functionality', 'Authentication, security', TRUE, '1.0'),
('analytics', 'Analytics', 'Help us understand how visitors use our site', 'Improve user experience', FALSE, '1.0'),
('marketing', 'Marketing', 'Used to deliver relevant ads', 'Advertising', FALSE, '1.0'),
('personalization', 'Personalization', 'Remember your preferences', 'User preferences', FALSE, '1.0')
ON DUPLICATE KEY UPDATE name = VALUES(name);

-- Insert OWASP Top 10 categories
INSERT INTO `nist_controls` (`function`, `category`, `control_id`, `name`, `description`) VALUES
('IDENTIFY', 'Asset Management', 'ID.AM-1', 'Physical Devices Inventory', 'Physical devices in the organization are inventoried'),
('IDENTIFY', 'Asset Management', 'ID.AM-2', 'Software Inventory', 'Software platforms and applications are inventoried'),
('PROTECT', 'Identity Management', 'PR.AC-1', 'Identity Credentials', 'Identities and credentials are issued, managed, verified'),
('PROTECT', 'Access Control', 'PR.AC-4', 'Access Control', 'Access permissions are managed incorporating principles of least privilege'),
('DETECT', 'Anomalies and Events', 'DE.AE-1', 'Event Detection', 'A baseline of network operations is established'),
('DETECT', 'Security Continuous', 'DE.CM-1', 'Network Monitoring', 'The network is monitored to detect potential security events'),
('RESPOND', 'Response Planning', 'RS.RP-1', 'Response Plan', 'Response plan is executed during or after an incident'),
('RECOVER', 'Recovery Planning', 'RC.RP-1', 'Recovery Plan', 'Recovery plan is executed during or after a cyber incident'),
('GOVERN', 'Governance', 'GV.OV-1', 'Security Policy', 'Organizational cybersecurity policy is established'),
('GOVERN', 'Risk Assessment', 'GV.RR-1', 'Risk Assessment', 'Risk to organizational operations is assessed')
ON DUPLICATE KEY UPDATE name = VALUES(name);

-- Insert dork patterns (GHDB data from schema.sql)
INSERT INTO `dork_patterns` (`ghdb_id`, `title`, `description`, `category`, `owasp_category`, `search_pattern`, `severity`) VALUES
('REACT-001', 'React Developer Tools Exposure', 'React DevTools is enabled in production - exposing component tree and state', 'React Vulnerabilities', NULL, 'site:{domain} __REACT_DEVTOOLS_GLOBAL_HOOK__ | site:{domain} __reactFiber', 'medium'),
('REACT-002', 'React Source Maps in Production', 'Source map are exposed in production, revealing full source code', 'React Vulnerabilities', NULL, 'site:{domain} *.js.map | site:{domain} main.*.js.map', 'high'),
('REACT-003', 'Exposed React State/Data in Client', 'Sensitive data exposed in React state or props visible in browser', 'React Vulnerabilities', NULL, 'site:{domain} dangerouslySetInnerHTML', 'high'),
('REACT-004', 'React Bundle Size Anomaly', 'Unusually large bundle size may indicate embedded secrets or sensitive data', 'React Vulnerabilities', NULL, 'site:{domain} bundle.js', 'info'),
('REACT-005', 'CORS Misconfiguration - React App', 'CORS policy allows unrestricted access from any origin', 'React Vulnerabilities', NULL, 'Access-Control-Allow-Origin: *', 'high'),
('REACT-006', 'JWT Token in LocalStorage (React)', 'JWT tokens stored in localStorage are vulnerable to XSS attacks', 'React Vulnerabilities', NULL, 'localStorage.getItem | localStorage.setItem | sessionStorage.getItem', 'high'),
('REACT-007', 'Exposed API Base URL in React', 'API endpoints exposed in React source code', 'React Vulnerabilities', NULL, 'baseURL | API_URL | REACT_APP_API', 'medium'),
('REACT-008', 'React Router Information Disclosure', 'React Router reveals application structure and hidden routes', 'React Vulnerabilities', NULL, 'react-router | BrowserRouter | Switch | Route path', 'low'),
('REACT-009', 'Exposed Environment Variables (React)', 'REACT_APP_ prefixed environment variables exposed in client bundle', 'React Vulnerabilities', NULL, 'REACT_APP_ | .env', 'critical'),
('REACT-010', 'React Select/Search Component SQLi', 'Search/select components in React apps vulnerable to SQL injection', 'React Vulnerabilities', NULL, 'site:{domain} inurl:search | site:{domain} inurl:query', 'critical'),
('NODE-001', 'Exposed package.json', 'Package.json exposed revealing dependencies and versions', 'Node.js Vulnerabilities', NULL, 'site:{domain} package.json', 'medium'),
('NODE-002', 'Exposed node_modules Directory', 'Node modules directory exposed - potential for dependency vulnerability scanning', 'Node.js Vulnerabilities', NULL, 'site:{domain} inurl:node_modules', 'high'),
('NODE-003', 'Express.js Debug Mode Enabled', 'Express running in debug mode exposing stack traces', 'Node.js Vulnerabilities', NULL, 'Express | x-powered-by', 'medium'),
('NODE-004', 'Express Session Misconfiguration', 'Express sessions improperly configured', 'Node.js Vulnerabilities', NULL, 'connect.sid | express-session', 'medium'),
('NODE-005', 'Node.js Version Disclosure', 'Node.js version exposed in headers or error pages', 'Node.js Vulnerabilities', NULL, 'Node.js | node.js', 'low'),
('NODE-006', 'Exposed .npmrc File', '.npmrc configuration file exposed with potential credentials', 'Node.js Vulnerabilities', NULL, 'site:{domain} .npmrc', 'critical'),
('NODE-007', 'Express CORS Misconfiguration', 'CORS configured to allow all origins in Express', 'Node.js Vulnerabilities', NULL, 'Access-Control-Allow-Origin: *', 'high'),
('NODE-008', 'MongoDB Injection in Node.js', 'NoSQL injection vulnerability in MongoDB queries', 'Node.js Vulnerabilities', NULL, 'site:{domain} mongodb | site:{domain} mongoose', 'critical'),
('NODE-009', 'Template Injection (EJS/Pug) in Node.js', 'Server-side template injection vulnerability', 'Node.js Vulnerabilities', NULL, 'site:{domain} ejs | site:{domain} pug | site:{domain} handlebars', 'critical'),
('NODE-010', 'Mass Assignment in Node.js API', 'API vulnerable to mass assignment allowing unauthorized field updates', 'Node.js Vulnerabilities', NULL, 'site:{domain} api | site:{domain} rest', 'high'),
('EXPRESS-001', 'Express File Upload Vulnerability', 'Unrestricted file upload endpoint in Express app', 'Express Vulnerabilities', NULL, 'site:{domain} multer | site:{domain} upload | site:{domain} file', 'critical'),
('EXPRESS-002', 'Express GraphQL Introspection', 'GraphQL introspection enabled exposing schema', 'Express Vulnerabilities', NULL, 'site:{domain} graphql | site:{domain} gql', 'high'),
('EXPRESS-003', 'JWT Algorithm Confusion', 'JWT verification susceptible to algorithm confusion attack', 'Express Vulnerabilities', NULL, 'site:{domain} jwt | site:{domain} token', 'critical'),
('EXPRESS-004', 'Exposed Redis/Memcached Console', 'Cache server management interface exposed', 'Express Vulnerabilities', NULL, 'Redis | Memcached', 'high'),
('EXPRESS-005', 'Rate Limiting Not Implemented', 'No rate limiting protection against brute force/DOS', 'Express Vulnerabilities', NULL, 'site:{domain} api', 'medium'),
('EXPRESS-006', 'Helmet.js Security Headers Missing', 'Security headers not properly configured', 'Express Vulnerabilities', NULL, 'site:{domain} express', 'medium'),
('EXPRESS-007', 'GraphQL Directives Injection', 'GraphQL directives vulnerable to injection', 'Express Vulnerabilities', NULL, 'site:{domain} graphql', 'high'),
('EXPRESS-008', 'WebSocket Security Issues', 'WebSocket endpoints lack proper authentication/authorization', 'Express Vulnerabilities', NULL, 'site:{domain} websocket | site:{domain} socket.io | site:{domain} ws', 'medium'),
('EXPRESS-009', 'Exposed Swagger/OpenAPI Docs', 'API documentation exposed in production', 'Express Vulnerabilities', NULL, 'site:{domain} swagger | site:{domain} openapi | site:{domain} api-docs', 'medium'),
('EXPRESS-010', 'Request Body Parser Vulnerabilities', 'Body parser misconfiguration leading to DoS or data exposure', 'Express Vulnerabilities', NULL, 'site:{domain} body-parser | site:{domain} express.json', 'medium'),
('API-001', 'Exposed API Endpoints', 'REST API endpoints without proper protection', 'API Vulnerabilities', NULL, 'site:{domain} /api/ | site:{domain} /v1/ | site:{domain} /v2/', 'high'),
('API-002', 'GraphQL Batch Query Attack', 'GraphQL vulnerable to batched query attacks', 'API Vulnerabilities', NULL, 'site:{domain} graphql', 'medium'),
('API-003', 'Broken Authentication - API', 'API authentication can be bypassed', 'API Vulnerabilities', NULL, 'site:{domain} api', 'critical'),
('API-004', 'Excessive Data Exposure - API', 'API returns more data than necessary', 'API Vulnerabilities', NULL, 'site:{domain} api', 'medium'),
('API-005', 'Mass Assignment - API', 'API allows updating internal fields', 'API Vulnerabilities', NULL, 'site:{domain} api', 'high'),
('API-006', 'Function Level Authorization Bypass', 'API allows accessing higher privilege functions', 'API Vulnerabilities', NULL, 'site:{domain} api', 'high'),
('API-007', 'GraphQL Field Duplication Attack', 'GraphQL vulnerable to field duplication DoS', 'API Vulnerabilities', NULL, 'site:{domain} graphql', 'medium'),
('API-008', 'REST API Version Not Specified', 'API versioning issues causing data exposure', 'API Vulnerabilities', NULL, 'site:{domain} /api', 'low'),
('API-009', 'Improper Inventory Management - API', 'Old API versions with known vulnerabilities still active', 'API Vulnerabilities', NULL, 'site:{domain} api', 'medium'),
('API-010', 'Unprotected Cloud Metadata API', 'Cloud instance metadata API accessible from application', 'API Vulnerabilities', NULL, '169.254.169.254 | metadata.google.internal', 'critical'),
('INJ-001', 'Command Injection - Node.js', 'OS command injection via child_process functions', 'Injection Vulnerabilities', NULL, 'site:{domain} child_process | site:{domain} exec | site:{domain} spawn', 'critical'),
('INJ-002', 'LDAP Injection - Node.js', 'LDAP injection via user input', 'Injection Vulnerabilities', NULL, 'site:{domain} ldap | site:{domain} active directory', 'high'),
('INJ-003', 'Server-Side XSS in Express', 'Server-side XSS via unsanitized template rendering', 'Injection Vulnerabilities', NULL, 'site:{domain} render', 'high'),
('INJ-004', 'Prototype Pollution in Node.js', 'JavaScript prototype pollution vulnerability', 'Injection Vulnerabilities', NULL, 'site:{domain} merge | site:{domain} clone', 'critical'),
('INJ-005', 'Path Traversal - Node.js', 'Path traversal via unsanitized file paths', 'Injection Vulnerabilities', NULL, 'site:{domain} static | site:{domain} file | site:{domain} download', 'critical'),
('INJ-006', 'ReDoS - Regular Expression DoS', 'Vulnerable regex causing denial of service', 'Injection Vulnerabilities', NULL, 'site:{domain} regex | site:{domain} validate', 'medium'),
('INJ-007', 'Eval Injection in Node.js', 'eval() used with user-controlled input', 'Injection Vulnerabilities', NULL, 'eval | Function( | setTimeout | setInterval', 'critical'),
('AUTH-001', 'Weak JWT Secret', 'JWT signed with weak or known secret', 'Authentication Vulnerabilities', NULL, 'site:{domain} jwt | site:{domain} jsonwebtoken', 'critical'),
('AUTH-002', 'Missing Authorization Header', 'API endpoints missing Bearer token validation', 'Authentication Vulnerabilities', NULL, 'site:{domain} Authorization', 'high'),
('AUTH-003', 'Session Fixation', 'Session ID not regenerated after login', 'Authentication Vulnerabilities', NULL, 'site:{domain} session', 'high'),
('AUTH-004', 'Credential in URL', 'Credentials passed in URL query string', 'Authentication Vulnerabilities', NULL, 'site:{domain} password= | site:{domain} token= | site:{domain} secret=', 'medium'),
('AUTH-005', 'Improper Password Storage', 'Passwords not properly hashed', 'Authentication Vulnerabilities', NULL, 'site:{domain} bcrypt | site:{domain} password', 'critical')
ON DUPLICATE KEY UPDATE title = VALUES(title);

-- Insert additional GHDB patterns from schema.sql
INSERT INTO `dork_patterns` (`ghdb_id`, `title`, `description`, `category`, `owasp_category`, `search_pattern`, `severity`) VALUES
('8361', 'Sensitive File Disclosure - Backup Files', 'Finds backup files that may contain sensitive information', 'Files Containing Juicy Info', NULL, 'site:{domain} ext:bkf ext:bkp ext:bak ext:old ext:backup | site:{domain} inurl:backup ext:sql|ext:zip|ext:tar|ext:gz | site:{domain} ext:sql|ext:sql.gz|ext:sql.zip', 'high'),
('GHDB-SQL-001', 'SQL Injection Vulnerability Detection', 'Detects potential SQL injection points', 'Vulnerable Files', NULL, 'site:{domain} inurl:id=|inurl:page=|inurl:cat=|inurl:product=', 'critical'),
('GHDB-XSS-001', 'Cross-Site Scripting (XSS) Detection', 'Detects potential XSS vulnerabilities in URL parameters', 'Vulnerable Files', NULL, 'site:{domain} inurl:search=|inurl:q=|inurl:query=|inurl:s=', 'high'),
('GHDB-LOGIN-001', 'Exposed Admin Panels', 'Finds exposed administrative login pages', 'Pages Containing Login Portals', NULL, 'site:{domain} inurl:admin|inurl:administrator|inurl:login|inurl:wp-login | site:{domain} intitle:"Admin Login"|intitle:"Administrator Login"', 'medium'),
('GHDB-CONFIG-001', 'Configuration File Exposure', 'Finds exposed configuration files', 'Files Containing Juicy Info', NULL, 'site:{domain} ext:xml ext:conf ext:cnf ext:reg ext:inf ext:rdp ext:cfg ext:txt ext:ora ext:ini | site:{domain} inurl:wp-config.php|inurl:configuration.php|inurl:config.php', 'critical'),
('GHDB-GIT-001', 'Exposed Git Repository', 'Finds exposed .git directories', 'Sensitive Directories', NULL, 'site:{domain} inurl:"/.git" | site:{domain} "Index of /.git"', 'critical'),
('GHDB-LOG-001', 'Exposed Log Files', 'Finds exposed log files', 'Files Containing Juicy Info', NULL, 'site:{domain} ext:log | site:{domain} filetype:log', 'medium'),
('GHDB-DIR-001', 'Directory Listing Enabled', 'Finds directories with indexing enabled', 'Sensitive Directories', NULL, 'site:{domain} intitle:"Index of" | site:{domain} "Index of /"', 'medium'),
('GHDB-ROBOTS-001', 'Robots.txt Sensitive Information', 'Analyzes robots.txt for sensitive paths', 'Sensitive Directories', NULL, 'site:{domain} inurl:robots.txt', 'info'),
('GHDB-API-001', 'Exposed API Endpoints', 'Finds exposed API endpoints and documentation', 'Vulnerable Files', NULL, 'site:{domain} inurl:/api/|inurl:/v1/|inurl:/v2/ | site:{domain} inurl:swagger|inurl:api-docs|inurl:openapi', 'medium'),
('GHDB-S3-001', 'AWS S3 Bucket Exposure', 'Finds potentially exposed AWS S3 buckets', 'Sensitive Directories', NULL, 'site:s3.amazonaws.com {domain} | site:{domain} s3.amazonaws.com', 'high'),
('GHDB-SVN-001', 'Exposed SVN Repository', 'Finds exposed .svn directories', 'Sensitive Directories', NULL, 'site:{domain} inurl:"/.svn"', 'critical'),
('GHDB-DS-001', 'DS_Store File Exposure', 'Finds exposed macOS .DS_Store files', 'Files Containing Juicy Info', NULL, 'site:{domain} inurl:.DS_Store', 'low'),
('GHDB-PHP-001', 'PHP Information Disclosure', 'Finds exposed PHP info pages', 'Vulnerable Files', NULL, 'site:{domain} inurl:phpinfo|inurl:php-info', 'high'),
('OWASP-A01-2021', 'Broken Access Control - IDOR', 'Detects potential IDOR vulnerabilities where object references expose internal implementation', 'OWASP Top 10', 'A01:2021-Broken Access Control', 'site:{domain} inurl:id=|inurl:user_id=|inurl:account_id=|inurl:order_id=', 'high'),
('OWASP-A01-2021-PATH', 'Broken Access Control - Path Traversal', 'Detects potential path traversal vulnerabilities', 'OWASP Top 10', 'A01:2021-Broken Access Control', 'site:{domain} inurl:file=|inurl:path=|inurl:folder=|inurl:dir=', 'critical'),
('OWASP-A02-2021', 'Cryptographic Failures - Sensitive Data', 'Detects forms transmitting sensitive data without encryption', 'OWASP Top 10', 'A02:2021-Cryptographic Failures', 'site:{domain} inurl:password|inurl:credit|inurl:card|inurl:ssn|inurl:secret', 'critical'),
('OWASP-A03-2021-SQL', 'Injection - SQL Injection', 'Advanced SQL injection vulnerability detection', 'OWASP Top 10', 'A03:2021-Injection', 'site:{domain} ext:php inurl:?|ext:asp inurl:?|ext:jsp inurl:?|ext:aspx inurl:?', 'critical'),
('OWASP-A03-2021-CMD', 'Injection - Command Injection', 'Detects potential command injection vulnerabilities', 'OWASP Top 10', 'A03:2021-Injection', 'site:{domain} inurl:host=|inurl:ip=|inurl:domain=|inurl:cmd=|inurl:exec=', 'critical'),
('OWASP-A03-2021-LDAP', 'Injection - LDAP Injection', 'Detects potential LDAP injection points', 'OWASP Top 10', 'A03:2021-Injection', 'site:{domain} inurl:ldap|inurl:directory|inurl:adsearch', 'high'),
('OWASP-A03-2021-XXE', 'Injection - XXE', 'Detects potential XXE vulnerabilities in XML endpoints', 'OWASP Top 10', 'A03:2021-Injection', 'site:{domain} inurl:xml|inurl:soap|inurl:wsdl|inurl:api ext:xml', 'critical'),
('OWASP-A04-2021', 'Insecure Design - Business Logic', 'Detects potential insecure design patterns', 'OWASP Top 10', 'A04:2021-Insecure Design', 'site:{domain} inurl:price=|inurl:amount=|inurl:quantity=|inurl:discount=', 'high'),
('OWASP-A05-2021', 'Security Misconfiguration - Default Credentials', 'Detects default login pages that may have default credentials', 'OWASP Top 10', 'A05:2021-Security Misconfiguration', 'site:{domain} intitle:"Apache Tomcat" "Manager"|intitle:"IIS" "Welcome"|intitle:"WordPress Setup"', 'critical'),
('OWASP-A06-2021', 'Vulnerable/Outdated Components', 'Detects outdated software versions and vulnerable components', 'OWASP Top 10', 'A06:2021-Vulnerable and Outdated Components', 'site:{domain} "Powered by" "WordPress"|"Powered by" "Joomla"|"Powered by" "Drupal" | site:{domain} "Apache/2.2"|"Apache/2.0"|"nginx/1.0"|"PHP/5."', 'high'),
('OWASP-A07-2021', 'Identification/Auth Failures - Weak Session', 'Detects weak session management and authentication issues', 'OWASP Top 10', 'A07:2021-Identification and Authentication Failures', 'site:{domain} inurl:password reset|inurl:forgot password|inurl:recover', 'high'),
('OWASP-A08-2021', 'Software Integrity Failures - Insecure Deserialization', 'Detects potential insecure deserialization endpoints', 'OWASP Top 10', 'A08:2021-Software and Data Integrity Failures', 'site:{domain} inurl:object=|inurl:serialize|inurl:deserialize|inurl:base64', 'critical'),
('OWASP-A09-2021', 'Security Logging Failures - Debug Endpoints', 'Detects debug endpoints that may leak information', 'OWASP Top 10', 'A09:2021-Security Logging and Monitoring Failures', 'site:{domain} inurl:debug|inurl:trace|inurl:actuator|inurl:/.env', 'high'),
('OWASP-A10-2021', 'Server-Side Request Forgery (SSRF)', 'Detects potential SSRF vulnerabilities', 'OWASP Top 10', 'A10:2021-Server-Side Request Forgery (SSRF)', 'site:{domain} inurl:url=|inurl:path=|inurl:dest=|inurl:callback=|inurl:redirect=', 'high'),
('GHDB-PWD-001', 'Exposed Password Files - htpasswd', 'Finds htpasswd files containing encrypted passwords', 'Files Containing Passwords', NULL, 'intitle:"Index of" htpasswd', 'critical'),
('GHDB-PWD-002', 'Exposed Password Database - pwd.db', 'Finds pwd.db password database files', 'Files Containing Passwords', NULL, 'intitle:"Index of" pwd.db', 'critical'),
('GHDB-PWD-003', 'Password in Database Connection', 'Finds database connection strings with passwords', 'Files Containing Passwords', NULL, 'jdbc:mysql://localhost:3306/ |username| |password ext:yml|ext:java', 'critical'),
('GHDB-PWD-004', 'WordPress Config with DB Password', 'Exposed WordPress configuration with database credentials', 'Files Containing Passwords', NULL, 'inurl:wp-config.php intext:DB_PASSWORD', 'critical'),
('GHDB-PWD-005', 'Config Files with Passwords', 'Configuration files containing password definitions', 'Files Containing Passwords', NULL, 'filetype:config "password" | "passwd"', 'high'),
('GHDB-PWD-006', 'Excel Files with Passwords', 'Spreadsheets potentially containing login credentials', 'Files Containing Passwords', NULL, 'ext:xls | ext:xlsx intext:password', 'high'),
('GHDB-PWD-007', 'PHPMyAdmin Config', 'PHPMyAdmin configuration files with credentials', 'Files Containing Passwords', NULL, 'intitle:"phpMyAdmin" "Welcome to phpMyAdmin"', 'critical'),
('GHDB-PWD-008', 'SQL Dump with Passwords', 'SQL database dumps containing password hashes', 'Files Containing Passwords', NULL, 'ext:sql intext:"INSERT INTO users" | intext:"password"', 'critical'),
('GHDB-PWD-009', 'AWS Credentials Exposed', 'AWS access keys and secrets in config files', 'Files Containing Passwords', NULL, 'filetype:ini AWS_ACCESS_KEY | AWS_SECRET_KEY', 'critical'),
('GHDB-PWD-010', 'Private Key Exposed', 'Exposed private SSH or SSL keys', 'Files Containing Passwords', NULL, '"-----BEGIN RSA PRIVATE KEY-----" ext:key', 'critical'),
('GHDB-USR-001', 'Exposed Usernames File', 'Finds files containing username lists', 'Files Containing Usernames', NULL, 'intitle:"index of" "/usernames"', 'high'),
('GHDB-USR-002', 'Contact Lists Exposed', 'Exposed contact or user lists', 'Files Containing Usernames', NULL, 'intitle:"index of" "contacts.txt"', 'high'),
('GHDB-USR-003', 'Database Properties with Username', 'Database properties files with credentials', 'Files Containing Usernames', NULL, 'intitle:"index of" "db.properties"', 'high'),
('GHDB-USR-004', 'FTP Credentials Exposed', 'FTP client configuration with saved credentials', 'Files Containing Usernames', NULL, 'intitle:"index of" "filezilla.xml"', 'high'),
('GHDB-USR-005', 'SQL Users Dump', 'Exposed SQL user data', 'Files Containing Usernames', NULL, 'intitle:"index of" "users.sql"', 'high'),
('GHDB-USR-006', 'PuTTY Credentials', 'PuTTY saved sessions with credentials', 'Files Containing Usernames', NULL, 'filetype:log username putty', 'high'),
('GHDB-USR-007', 'Windows Registry Username', 'Windows registry with stored usernames', 'Files Containing Usernames', NULL, 'filetype:reg reg intext:"internet account manager"', 'medium'),
('GHDB-USR-008', 'Webalizer Usernames', 'Webalizer stats exposing usernames', 'Files Containing Usernames', NULL, 'intext:"webalizer" intext:"Total Usernames"', 'medium'),
('GHDB-DIR-002', 'Sensitive /etc/passwd Exposure', 'Exposed Unix password files', 'Sensitive Directories', NULL, 'intext:"root:x:0:0:root:/root:/bin/bash" inurl:*=/etc/passwd', 'critical'),
('GHDB-DIR-003', 'Shadow Password Exposure', 'Exposed Unix shadow password files', 'Sensitive Directories', NULL, 'intitle:"index of" "/master.passwd"', 'critical'),
('GHDB-DIR-004', 'FTP Users Directory', 'FTP users configuration directory', 'Sensitive Directories', NULL, 'intitle:"index of" "/ftpusers"', 'high'),
('GHDB-DIR-005', 'Git Credentials Store', 'Git credential store files', 'Sensitive Directories', NULL, 'intitle:"index of" ".git-credentials"', 'critical'),
('GHDB-DIR-006', 'AWS Config Directory', 'AWS configuration directory exposure', 'Sensitive Directories', NULL, 'intitle:"index of" ".aws"', 'high'),
('GHDB-DIR-007', 'Database Backup Directory', 'Exposed database backup directories', 'Sensitive Directories', NULL, 'inurl:/backup intitle:index of backup intext:*sql', 'high'),
('GHDB-DIR-008', 'Tomcat Users XML', 'Tomcat users configuration file', 'Sensitive Directories', NULL, 'intitle:"index of" "tomcat-users.xml"', 'critical'),
('GHDB-DIR-009', 'WP-Content Uploads', 'WordPress uploads directory listing', 'Sensitive Directories', NULL, 'inurl:/wp-content/uploads/ ext:txt', 'medium'),
('GHDB-DIR-010', 'Backup Files Directory', 'Backup directory with sensitive files', 'Sensitive Directories', NULL, 'site:{domain} inurl:backup ext:sql|ext:zip|ext:tar|ext:gz', 'high'),
('GHDB-DIR-011', 'S3 Bucket Public Access', 'Publicly accessible S3 buckets', 'Sensitive Directories', NULL, 'site:s3.amazonaws.com inurl:/ | site:amazonaws.com filetype:xls password', 'critical'),
('GHDB-JUICE-001', 'PDF with Sensitive Info', 'PDF documents containing sensitive information', 'Files Containing Juicy Info', NULL, 'filetype:pdf intext:"confidential" | intext:"secret"', 'high'),
('GHDB-JUICE-002', 'Excel Spreadsheets', 'Excel files with business data', 'Files Containing Juicy Info', NULL, 'ext:xls | ext:xlsx intext:@gmail.com | intext:@yahoo.com', 'high'),
('GHDB-JUICE-003', 'Confidential Documents', 'General confidential documents', 'Files Containing Juicy Info', NULL, 'intitle:"index of" "confidential" | "private"', 'high'),
('GHDB-JUICE-004', 'Wallet Backups', 'Cryptocurrency wallet backups', 'Files Containing Juicy Info', NULL, 'intitle:"index of" "wallet.dat"', 'critical'),
('GHDB-JUICE-005', 'Business Documents', 'Business planning documents', 'Files Containing Juicy Info', NULL, 'filetype:doc inurl:"gov" intext:"business plan"', 'medium'),
('GHDB-JUICE-006', 'Server Logs', 'Exposed server log files', 'Files Containing Juicy Info', NULL, 'site:{domain} ext:log | site:{domain} filetype:log', 'medium'),
('GHDB-JUICE-007', 'Connection Strings', 'Database connection strings', 'Files Containing Juicy Info', NULL, 'connectionString & inurl:web & ext:config', 'high'),
('GHDB-JUICE-008', 'Environment Variables', 'Exposed .env files with secrets', 'Files Containing Juicy Info', NULL, '"index of" ".env" | intitle:"index of" ".env"', 'critical'),
('GHDB-JUICE-009', 'JSON API Responses', 'Exposed API response data', 'Files Containing Juicy Info', NULL, 'intitle:"index of" "users.json" | "api.json"', 'high'),
('GHDB-JUICE-010', 'YAML Configurations', 'YAML configuration files', 'Files Containing Juicy Info', NULL, 'intitle:"index of" "credentials.yml" | "config.yml"', 'high'),
('GHDB-ERR-001', 'SQL Error Disclosure', 'SQL error messages revealing database info', 'Error Messages', NULL, 'site:{domain} intext:"SQL syntax" | intext:"MySQLSyntaxError"', 'high'),
('GHDB-ERR-002', 'PHP Error Disclosure', 'PHP errors exposing code paths', 'Error Messages', NULL, 'site:{domain} "Parse error" | "Fatal error" intext:php', 'high'),
('GHDB-ERR-003', 'ASP.NET Error Pages', 'ASP.NET error pages with stack traces', 'Error Messages', NULL, 'site:{domain} "Server Error in" "/Application"', 'medium'),
('GHDB-ERR-004', 'Java Stack Traces', 'Java exception stack traces', 'Error Messages', NULL, 'site:{domain} "java.lang.NullPointerException" | "at java."', 'high'),
('GHDB-ERR-005', 'WordPress Debug Log', 'WordPress debug.log exposure', 'Error Messages', NULL, 'inurl:wp-content/debug.log', 'high'),
('GHDB-ERR-006', 'Apache Tomcat Default Pages', 'Apache Tomcat default or error pages', 'Error Messages', NULL, 'site:{domain} intitle:"Apache Tomcat" "Manager"', 'medium'),
('GHDB-ERR-007', 'IIS Error Pages', 'IIS server error pages', 'Error Messages', NULL, 'site:{domain} intitle:"IIS" "Welcome"', 'medium'),
('GHDB-ERR-008', 'Django Debug Mode', 'Django debug error pages', 'Error Messages', NULL, 'site:{domain} "Traceback (most recent call last)"', 'high'),
('GHDB-WEB-001', 'Nginx Server Detection', 'Nginx server version disclosure', 'Web Server Detection', NULL, 'site:{domain} "Server: nginx" | "nginx/"', 'low'),
('GHDB-WEB-002', 'Apache Server Detection', 'Apache server version disclosure', 'Web Server Detection', NULL, 'site:{domain} "Server: Apache" | "Apache/2."', 'low'),
('GHDB-WEB-003', 'Microsoft IIS Detection', 'IIS server version detection', 'Web Server Detection', NULL, 'site:{domain} "Server: Microsoft-IIS"', 'low'),
('GHDB-WEB-004', 'Express.js Detection', 'Express.js framework detection', 'Web Server Detection', NULL, 'site:{domain} "X-Powered-By: Express"', 'low'),
('GHDB-WEB-005', 'AWS S3 Bucket Detection', 'AWS S3 bucket detection', 'Web Server Detection', NULL, 'site:s3.amazonaws.com | site:amazonaws.com', 'medium'),
('GHDB-WEB-006', 'Cloudflare Detection', 'Cloudflare CDN detection', 'Web Server Detection', NULL, 'site:{domain} "cf-ray" | "cloudflare"', 'info'),
('GHDB-WEB-007', 'PHP Version Disclosure', 'PHP version disclosure', 'Web Server Detection', NULL, 'site:{domain} "X-Powered-By: PHP"', 'low'),
('GHDB-WEB-008', 'ASP.NET Version', 'ASP.NET version disclosure', 'Web Server Detection', NULL, 'site:{domain} "X-AspNet-Version"', 'low'),
('GHDB-VULN-001', 'CVE Disclosures', 'CVE vulnerability announcements', 'Advisories and Vulnerabilities', NULL, 'site:{domain} "CVE-2023" | "CVE-2024"', 'medium'),
('GHDB-VULN-002', 'Exploit-DB References', 'Exploit-DB referenced vulnerabilities', 'Advisories and Vulnerabilities', NULL, 'site:{domain} "exploit-db.com" | "EDB-ID"', 'medium'),
('GHDB-VULN-003', 'NVD References', 'National Vulnerability Database references', 'Advisories and Vulnerabilities', NULL, 'site:{domain} "nvd.nist.gov" | "CVE"', 'medium'),
('GHDB-VULN-004', 'GitHub Security Advisories', 'GitHub security advisories', 'Advisories and Vulnerabilities', NULL, 'site:{domain} "github.com/advisories"', 'medium'),
('GHDB-VULN-005', 'ZeroDay Initiative', 'ZeroDay Initiative vulnerability reports', 'Advisories and Vulnerabilities', NULL, 'site:{domain} "zerodayinitiative.com"', 'medium'),
('GHDB-LOGIN-002', 'Joomla Admin Login', 'Joomla administrative login page', 'Pages Containing Login Portals', NULL, 'site:{domain} inurl:/administrator | inurl:joomla', 'medium'),
('GHDB-LOGIN-003', 'Drupal Admin Login', 'Drupal administrative login page', 'Pages Containing Login Portals', NULL, 'site:{domain} inurl:user/login | inurl:admin', 'medium'),
('GHDB-LOGIN-004', 'cPanel Login', 'cPanel webmail login', 'Pages Containing Login Portals', NULL, 'site:{domain} inurl:cpanel | inurl:webmail', 'medium'),
('GHDB-LOGIN-005', 'Plesk Login', 'Plesk control panel login', 'Pages Containing Login Portals', NULL, 'site:{domain} inurl:plesk | inurl:login.php', 'medium'),
('GHDB-LOGIN-006', 'phpMyAdmin Login', 'phpMyAdmin database interface', 'Pages Containing Login Portals', NULL, 'site:{domain} inurl:phpmyadmin | inurl:myadmin', 'high'),
('GHDB-LOGIN-007', 'Jenkins Login', 'Jenkins CI/CD login', 'Pages Containing Login Portals', NULL, 'site:{domain} inurl:jenkins | inurl:login', 'medium'),
('GHDB-LOGIN-008', 'Grafana Login', 'Grafana monitoring dashboard', 'Pages Containing Login Portals', NULL, 'site:{domain} inurl:grafana | inurl:3000/login', 'medium'),
('GHDB-LOGIN-009', 'Kubernetes Dashboard', 'Kubernetes dashboard exposure', 'Pages Containing Login Portals', NULL, 'site:{domain} inurl:kubernetes | inurl:6443', 'high'),
('GHDB-LOGIN-010', 'Elasticsearch Login', 'Elasticsearch login', 'Pages Containing Login Portals', NULL, 'site:{domain} inurl:elasticsearch | inurl:9200', 'high'),
('GHDB-SHOP-001', 'E-commerce Config Exposure', 'E-commerce configuration files', 'Sensitive Online Shopping Info', NULL, 'site:{domain} "config.php" "stripe"', 'high'),
('GHDB-SHOP-002', 'Payment Gateway Config', 'Payment gateway configuration', 'Sensitive Online Shopping Info', NULL, 'filetype:env "STRIPE_SECRET_KEY" | "PAYPAL"', 'critical'),
('GHDB-SHOP-003', 'Order Database Exposure', 'Exposed order or transaction databases', 'Sensitive Online Shopping Info', NULL, 'ext:sql intext:"orders" | intext:"transactions"', 'high'),
('GHDB-NET-001', 'Network Config Files', 'Network configuration files', 'Network or Vulnerability Data', NULL, 'site:{domain} ext:conf | ext:cfg intext:"ip" | "network"', 'medium'),
('GHDB-NET-002', 'VPN Configs', 'VPN configuration files', 'Network or Vulnerability Data', NULL, 'site:{domain} ext:ovpn | ext:vpnexport', 'high'),
('GHDB-NET-003', 'Cisco Configs', 'Cisco router/switch configurations', 'Network or Vulnerability Data', NULL, 'filetype:conf "cisco" "enable password"', 'critical'),
('GHDB-NET-004', 'AWS Security Group Exposed', 'AWS security group configurations', 'Network or Vulnerability Data', NULL, 'site:{domain} "security group" ext:json', 'medium'),
('GHDB-FOOT-001', 'Reverse Shell Scripts', 'Potentially malicious reverse shell scripts', 'Footholds', NULL, 'filetype:sh "bash -i" | "/bin/sh -i"', 'critical'),
('GHDB-FOOT-002', 'Web Shell Detection', 'Web shell backdoors', 'Footholds', NULL, 'site:{domain} inurl:shell | inurl:backdoor', 'critical'),
('GHDB-FOOT-003', 'Meterpreter Scripts', 'Meterpreter payload scripts', 'Footholds', NULL, 'site:{domain} "meterpreter" "payload"', 'critical'),
('GHDB-FOOT-004', 'nc Reverse Shell', 'Netcat reverse shell commands', 'Footholds', NULL, 'site:{domain} "nc -e" | "nc -lvnp"', 'critical'),
('GHDB-FOOT-005', 'PHP Shell', 'PHP web shell backdoors', 'Footholds', NULL, 'site:{domain} "<?php system(" | "eval(base64_decode"', 'critical'),
('OWASP-2023-A01', 'OWASP 2023 - Broken Access Control', 'Insecure IDOR and broken access control patterns', 'OWASP Top 10 2023', 'A01:2023-Broken Access Control', 'site:{domain} inurl:id=|inurl:user_id=|inurl:account_id=', 'high'),
('OWASP-2023-A02', 'OWASP 2023 - Cryptographic Failures', 'Weak encryption and cryptographic failures', 'OWASP Top 10 2023', 'A02:2023-Cryptographic Failures', 'site:{domain} inurl:encrypt=|inurl:decrypt=|inurl:key=', 'critical'),
('OWASP-2023-A03', 'OWASP 2023 - Injection', 'SQL, NoSQL, and command injection', 'OWASP Top 10 2023', 'A03:2023-Injection', 'site:{domain} inurl:q=|inurl:query=|inurl:search=', 'critical'),
('OWASP-2023-A04', 'OWASP 2023 - Insecure Design', 'Security misconfiguration and insecure design', 'OWASP Top 10 2023', 'A04:2023-Insecure Design', 'site:{domain} inurl:config|intitle:"500 Internal Server Error"', 'high'),
('OWASP-2023-A05', 'OWASP 2023 - Security Misconfiguration', 'Security misconfiguration vulnerabilities', 'OWASP Top 10 2023', 'A05:2023-Security Misconfiguration', 'site:{domain} "X-Powered-By:" | "Server:"', 'medium'),
('OWASP-2023-A06', 'OWASP 2023 - Vulnerable Components', 'Outdated and vulnerable components', 'OWASP Top 10 2023', 'A06:2023-Vulnerable and Outdated Components', 'site:{domain} "jquery-" | "bootstrap-" | "vue."', 'high'),
('OWASP-2023-A07', 'OWASP 2023 - Auth Failures', 'Authentication and authorization failures', 'OWASP Top 10 2023', 'A07:2023-Identification and Authentication Failures', 'site:{domain} inurl:login|inurl:signup|inurl:register', 'high'),
('OWASP-2023-A08', 'OWASP 2023 - Data Integrity Failures', 'Software and data integrity failures', 'OWASP Top 10 2023', 'A08:2023-Software and Data Integrity Failures', 'site:{domain} inurl:deserialize|inurl:unserialize', 'critical'),
('OWASP-2023-A09', 'OWASP 2023 - Logging Failures', 'Security logging and monitoring failures', 'OWASP Top 10 2023', 'A09:2023-Security Logging and Monitoring Failures', 'site:{domain} inurl:debug|inurl:trace', 'medium'),
('OWASP-2023-A10', 'OWASP 2023 - SSRF', 'Server-side request forgery', 'OWASP Top 10 2023', 'A10:2023-Server-Side Request Forgery', 'site:{domain} inurl:url=|inurl:fetch=|inurl:proxy=', 'high'),
('OWASP-API-001', 'API Security - Broken Object Level Authorization', 'API endpoints without proper object-level authorization', 'OWASP API Security', NULL, 'site:{domain}/api/ | site:{domain}/v1/ | site:{domain}/v2/', 'high'),
('OWASP-API-002', 'API Security - Broken Authentication', 'API authentication vulnerabilities', 'OWASP API Security', NULL, 'site:{domain}/api/auth | site:{domain}/api/login', 'high'),
('OWASP-API-003', 'API Security - Excessive Data Exposure', 'API exposing sensitive data', 'OWASP API Security', NULL, 'site:{domain}/api/users | site:{domain}/api/data', 'high'),
('OWASP-API-004', 'API Security - Lack of Rate Limiting', 'API without rate limiting', 'OWASP API Security', NULL, 'site:{domain}/api/ | "429 Too Many Requests"', 'medium'),
('OWASP-API-005', 'API Security - Mass Assignment', 'API mass assignment vulnerability', 'OWASP API Security', NULL, 'site:{domain}/api/ PUT | site:{domain}/api/ PATCH', 'high'),
('OWASP-MOB-001', 'Mobile - Improper Credential Usage', 'Mobile app improper credential handling', 'OWASP Mobile Top 10', NULL, 'site:{domain} "SharedPreferences" | "NSUserDefaults"', 'high'),
('OWASP-MOB-002', 'Mobile - Insecure Authentication', 'Mobile app insecure authentication', 'OWASP Mobile Top 10', NULL, 'site:{domain} "biometric" | "fingerprint" | "faceid"', 'medium'),
('OWASP-MOB-003', 'Mobile - Insecure Data Storage', 'Mobile app insecure data storage', 'OWASP Mobile Top 10', NULL, 'site:{domain} "cache" | "shared" ext:xml', 'high'),
('OWASP-MOB-004', 'Mobile - Insufficient Reverse Engineering Protections', 'Mobile app easily reverse engineered', 'OWASP Mobile Top 10', NULL, 'site:{domain} "classes.dex" | "android:debuggable"', 'critical'),
('OWASP-CLOUD-001', 'Cloud - Improper IAM Configuration', 'Improper identity and access management', 'OWASP Cloud Top 10', NULL, 'site:{domain} "IAM" | "access key" | "secret key"', 'critical'),
('OWASP-CLOUD-002', 'Cloud - Insecure Data Storage', 'Cloud storage misconfigurations', 'OWASP Cloud Top 10', NULL, 'site:amazonaws.com "s3" | "bucket"', 'high'),
('OWASP-CLOUD-003', 'Cloud - Lambda Injection', 'AWS Lambda function injection', 'OWASP Cloud Top 10', NULL, 'site:{domain} "lambda" | "serverless"', 'high'),
('OWASP-CLOUD-004', 'Cloud - Container Security', 'Exposed container orchestration', 'OWASP Cloud Top 10', NULL, 'site:{domain} "kubernetes" | "k8s" | "docker"', 'high'),
('OWASP-CLOUD-005', 'Cloud - Azure Blob Misconfiguration', 'Azure blob storage exposure', 'OWASP Cloud Top 10', NULL, 'site:blob.core.windows.net | site:azuresite.com', 'critical'),
('OWASP-CICD-001', 'CI/CD - Poisoned Pipeline Execution', 'Compromised CI/CD pipeline', 'OWASP CI/CD Top 10', NULL, 'site:{domain} ".github/workflows" | site:{domain} ".gitlab-ci.yml"', 'critical'),
('OWASP-CICD-002', 'CI/CD - Insufficient Flow Control', 'CI/CD flow control issues', 'OWASP CI/CD Top 10', NULL, 'site:{domain} "Jenkins" "Credentials"', 'high'),
('OWASP-CICD-003', 'CI/CD - Dependency Chain Abuse', 'Supply chain attacks via dependencies', 'OWASP CI/CD Top 10', NULL, 'site:{domain} "package.json" | "requirements.txt" | "Gemfile"', 'high'),
('OWASP-CICD-004', 'CI/CD - Poisoned Job Execution', 'Compromised CI job', 'OWASP CI/CD Top 10', NULL, 'site:{domain} "circleci" | "travis-ci" | "azure-pipelines"', 'high'),
('OWASP-LLM-001', 'LLM - Prompt Injection', 'Prompt injection vulnerabilities', 'OWASP LLM Top 10', NULL, 'site:{domain} "chatgpt" | "openai" | "llm" | "bard"', 'high'),
('OWASP-LLM-002', 'LLM - Insecure Output Handling', 'Insecure handling of LLM output', 'OWASP LLM Top 10', NULL, 'site:{domain} "ai" "response" | site:{domain} "model" "output"', 'medium'),
('OWASP-LLM-003', 'LLM - Training Data Poisoning', 'Training data manipulation', 'OWASP LLM Top 10', NULL, 'site:{domain} "training" "data" "ml" | "dataset"', 'medium'),
('OWASP-LLM-004', 'LLM - Model Denial of Service', 'LLM DoS through resource exhaustion', 'OWASP LLM Top 10', NULL, 'site:{domain} "llm" "timeout" | "rate limit"', 'high'),
('OWASP-SRV-001', 'Serverless - Overprivileged Function', 'Serverless function with excessive permissions', 'OWASP Serverless Top 10', NULL, 'site:{domain} "lambda" "role" | "function" "arn"', 'high'),
('OWASP-SRV-002', 'Serverless - Injection', 'Server-side template injection', 'OWASP Serverless Top 10', NULL, 'site:{domain} "serverless" "template" | "dynamodb"', 'high'),
('OWASP-IOT-001', 'IoT - Weak Credentials', 'IoT device weak default credentials', 'OWASP IoT Top 10', NULL, 'site:{domain} "default password" | "admin:admin"', 'critical'),
('OWASP-IOT-002', 'IoT - Insecure Network Services', 'Exposed IoT network services', 'OWASP IoT Top 10', NULL, 'site:{domain} "iot" | "mqtt" | "coap" | "zigbee"', 'high'),
('OWASP-IOT-003', 'IoT - Lack of Secure Update Mechanism', 'IoT devices without secure updates', 'OWASP IoT Top 10', NULL, 'site:{domain} "firmware" "update" | "ota"', 'high'),
('OWASP-DOCKER-001', 'Docker - Insecure Image', 'Docker image from untrusted registry', 'OWASP Docker Top 10', NULL, 'site:{domain} "Dockerfile" | "docker-compose"', 'high'),
('OWASP-DOCKER-002', 'Docker - Privilege Escalation', 'Docker container privilege escalation', 'OWASP Docker Top 10', NULL, 'site:{domain} "docker.sock" | "--privileged"', 'critical'),
('OWASP-DOCKER-003', 'Docker - Secrets in Image', 'Hardcoded secrets in Docker image', 'OWASP Docker Top 10', NULL, 'site:{domain} "ENV " | "docker" "secret"', 'high'),
('OWASP-K8S-001', 'Kubernetes - Exposed Dashboard', 'Kubernetes dashboard publicly accessible', 'OWASP Kubernetes Top 10', NULL, 'site:{domain} "kubernetes" "dashboard" | "port:8001"', 'critical'),
('OWASP-K8S-002', 'Kubernetes - Kubelet API', 'Kubelet API exposed', 'OWASP Kubernetes Top 10', NULL, 'site:{domain} "10250" | "10255" | "kubelet"', 'critical'),
('OWASP-K8S-003', 'Kubernetes - RBAC Misconfiguration', 'Kubernetes RBAC misconfiguration', 'OWASP Kubernetes Top 10', NULL, 'site:{domain} "clusterrole" "clusteradmin"', 'high'),
('OWASP-DEV-001', 'DevSecOps - Hardcoded Secrets', 'Hardcoded secrets in code', 'OWASP DevSecOps Top 10', NULL, 'site:{domain} "api_key" | "secret" | "password"', 'critical'),
('OWASP-DEV-002', 'DevSecOps - Unprotected Secrets', 'Unprotected secret management', 'OWASP DevSecOps Top 10', NULL, 'site:{domain} "secrets" "manager" | "vault"', 'high'),
('OWASP-DEV-003', 'DevSecOps - Insufficient Monitoring', 'Lack of security monitoring', 'OWASP DevSecOps Top 10', NULL, 'site:{domain} "monitoring" "alert" | "security"', 'medium'),
('OWASP-WS-001', 'WebSocket - Lack of Origin Validation', 'WebSocket origin check missing', 'OWASP WebSocket Top 10', NULL, 'site:{domain} "websocket" | "socket.io" | "ws://"', 'high'),
('OWASP-WS-002', 'WebSocket - Sensitive Data Exposure', 'WebSocket sensitive data exposure', 'OWASP WebSocket Top 10', NULL, 'site:{domain} "wss://" "login" | "auth"', 'medium'),
('OWASP-ASVS-001', 'ASVS - Authentication Verification', 'Authentication mechanism verification', 'OWASP ASVS', NULL, 'site:{domain} "mfa" | "2fa" | "totp"', 'high'),
('OWASP-ASVS-002', 'ASVS - Session Management', 'Session management verification', 'OWASP ASVS', NULL, 'site:{domain} "session" "token" | "sessionid"', 'medium'),
('OWASP-ASVS-003', 'ASVS - Access Control', 'Access control verification', 'OWASP ASVS', NULL, 'site:{domain} "permission" | "authorize" | "role"', 'high'),
('VULN-001', 'Heartbleed Vulnerability', 'OpenSSL Heartbleed detection', 'Vulnerability Detection', NULL, 'site:{domain} "heartbleed" | "openssl" "vulnerable"', 'critical'),
('VULN-002', 'Shellshock Vulnerability', 'Bash Shellshock CVE-2014-6271', 'Vulnerability Detection', NULL, 'site:{domain} "() { :; }" | "cgi" "shellshock"', 'critical'),
('VULN-003', 'Log4j Vulnerability', 'Log4j RCE CVE-2021-44228', 'Vulnerability Detection', NULL, 'site:{domain} "log4j" | "jndi" | "lookup"', 'critical'),
('VULN-004', 'Spring4Shell Vulnerability', 'Spring Framework RCE CVE-2022-22965', 'Vulnerability Detection', NULL, 'site:{domain} "spring" "rce" | "class.module"', 'critical'),
('VULN-005', 'Apache Struts Vulnerability', 'Apache Struts RCE', 'Vulnerability Detection', NULL, 'site:{domain} "struts" | "apache" "ognl"', 'critical'),
('VULN-006', 'Oracle WebLogic Vulnerability', 'Oracle WebLogic RCE', 'Vulnerability Detection', NULL, 'site:{domain} "weblogic" | "coherence"', 'critical'),
('VULN-007', 'F5 BIG-IP Vulnerability', 'F5 BIG-IP RCE', 'Vulnerability Detection', NULL, 'site:f5.com | site:big-ip | "tmui"', 'critical'),
('VULN-008', 'Atlassian Confluence Vulnerability', 'Atlassian Confluence OGNL injection', 'Vulnerability Detection', NULL, 'site:{domain} "confluence" | "atlassian"', 'critical'),
('VULN-009', 'VMware vCenter Vulnerability', 'VMware vCenter RCE', 'Vulnerability Detection', NULL, 'site:{domain} "vcenter" | "vmware"', 'critical'),
('VULN-010', 'Fortinet VPN Vulnerability', 'Fortinet VPN authentication bypass', 'Vulnerability Detection', NULL, 'site:{domain} "fortinet" | "fortigate" | "ssl vpn"', 'critical')
ON DUPLICATE KEY UPDATE title = VALUES(title);

-- =====================================================
-- CREATE INDEXES FOR PERFORMANCE
-- =====================================================

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS `idx_scans_user_status` ON `scans`(`user_id`, `status`);
CREATE INDEX IF NOT EXISTS `idx_vulns_scan_severity` ON `vulnerabilities`(`scan_id`, `severity`);
CREATE INDEX IF NOT EXISTS `idx_audit_user_timestamp` ON `audit_logs`(`user_id`, `timestamp`);
CREATE INDEX IF NOT EXISTS `idx_incidents_status_severity` ON `incident_tickets`(`status`, `severity`);

-- User Subscriptions Table (from schema.sql)
CREATE TABLE IF NOT EXISTS `user_subscriptions` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `tier_id` VARCHAR(50) NOT NULL,
    `status` ENUM('active', 'cancelled', 'expired', 'trial') DEFAULT 'active',
    `billing_cycle` ENUM('monthly', 'yearly') DEFAULT 'monthly',
    `scans_used_this_month` INT DEFAULT 0,
    `start_date` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `end_date` TIMESTAMP NULL,
    `cancelled_at` TIMESTAMP NULL,
    `auto_renew` BOOLEAN DEFAULT TRUE,
    `stripe_subscription_id` VARCHAR(255),
    `stripe_customer_id` VARCHAR(255),
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_status` (`status`),
    INDEX `idx_end_date` (`end_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
