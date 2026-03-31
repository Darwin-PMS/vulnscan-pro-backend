const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'vulnerability_scanner',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const initializeDatabase = async () => {
  try {
    const connection = await pool.getConnection();

    // Create scans table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS scans (
        id INT AUTO_INCREMENT PRIMARY KEY,
        scan_id VARCHAR(255) UNIQUE NOT NULL,
        user_id INT,
        target_url VARCHAR(500) NOT NULL,
        status ENUM('pending', 'running', 'completed', 'failed') DEFAULT 'pending',
        total_vulnerabilities INT DEFAULT 0,
        critical_count INT DEFAULT 0,
        high_count INT DEFAULT 0,
        medium_count INT DEFAULT 0,
        low_count INT DEFAULT 0,
        info_count INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP NULL,
        INDEX idx_scan_id (scan_id),
        INDEX idx_user_id (user_id),
        INDEX idx_status (status),
        INDEX idx_created_at (created_at)
      )
    `);

    // Add user_id column if it doesn't exist (for existing databases)
    try {
      await connection.query(`ALTER TABLE scans ADD COLUMN user_id INT AFTER scan_id`);
    } catch (err) {
      // Column already exists, ignore
    }

    // Add index on user_id if it doesn't exist
    try {
      await connection.query(`ALTER TABLE scans ADD INDEX idx_user_id (user_id)`);
    } catch (err) {
      // Index already exists, ignore
    }

    // Create vulnerabilities table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INT AUTO_INCREMENT PRIMARY KEY,
        scan_id VARCHAR(255) NOT NULL,
        vulnerability_type VARCHAR(255) NOT NULL,
        owasp_category VARCHAR(255),
        severity ENUM('critical', 'high', 'medium', 'low', 'info') NOT NULL,
        title VARCHAR(500) NOT NULL,
        description TEXT,
        url VARCHAR(1000),
        evidence TEXT,
        remediation TEXT,
        ghdb_id VARCHAR(50),
        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
        INDEX idx_vuln_scan_id (scan_id),
        INDEX idx_severity (severity),
        INDEX idx_vuln_type (vulnerability_type),
        INDEX idx_owasp_category (owasp_category)
      )
    `);

    // Create scan_history table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS scan_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        scan_id VARCHAR(255) NOT NULL,
        action VARCHAR(255) NOT NULL,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
        INDEX idx_history_scan_id (scan_id)
      )
    `);

    // Create dork_patterns table for storing GHDB patterns
    await connection.query(`
  CREATE TABLE IF NOT EXISTS dork_patterns (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ghdb_id VARCHAR(50) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    category VARCHAR(255),
    search_pattern VARCHAR(1000) NOT NULL,
    severity ENUM('critical', 'high', 'medium', 'low', 'info') DEFAULT 'medium',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ghdb_id (ghdb_id),
    INDEX idx_category (category)
  )
`);

    // Add owasp_category column if it doesn't exist (migration)
    try {
      await connection.query(`
            ALTER TABLE dork_patterns
            ADD COLUMN owasp_category VARCHAR(255),
            ADD INDEX idx_owasp_category (owasp_category)
        `);
    } catch (err) {
      // Column already exists, ignore error
      if (err.code !== 'ER_DUP_FIELDNAME') {
        console.error('Migration error:', err.message);
      }
    }

    // Create users table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(100),
        role ENUM('user', 'admin') DEFAULT 'user',
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        last_login TIMESTAMP NULL,
        INDEX idx_username (username),
        INDEX idx_email (email),
        INDEX idx_role (role)
      )
    `);

    // Add role column if it doesn't exist (migration)
    try {
      await connection.query(`ALTER TABLE users ADD COLUMN role ENUM('user', 'admin') DEFAULT 'user'`);
    } catch (err) {
      if (err.code !== 'ER_DUP_FIELDNAME') {
        // Column may already exist, ignore
      }
    }

    // Create subscription_tiers table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS subscription_tiers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tier_id VARCHAR(50) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        price_monthly DECIMAL(10,2) DEFAULT 0.00,
        price_yearly DECIMAL(10,2) DEFAULT 0.00,
        scan_limit_monthly INT DEFAULT 0,
        concurrent_scans INT DEFAULT 1,
        features JSON,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_tier_id (tier_id),
        INDEX idx_active (is_active)
      )
    `);

    // Create user_subscriptions table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS user_subscriptions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        tier_id VARCHAR(50) NOT NULL,
        status ENUM('active', 'cancelled', 'expired', 'trial') DEFAULT 'active',
        billing_cycle ENUM('monthly', 'yearly') DEFAULT 'monthly',
        scans_used_this_month INT DEFAULT 0,
        start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        end_date TIMESTAMP NULL,
        cancelled_at TIMESTAMP NULL,
        auto_renew BOOLEAN DEFAULT TRUE,
        stripe_subscription_id VARCHAR(255),
        stripe_customer_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_user_id (user_id),
        INDEX idx_status (status),
        INDEX idx_end_date (end_date)
      )
    `);

    // Initialize default subscription tiers
    await connection.query(`
      INSERT IGNORE INTO subscription_tiers (tier_id, name, description, price_monthly, price_yearly, scan_limit_monthly, concurrent_scans, features) VALUES
      ('free', 'Free', 'Basic vulnerability scanning for hobbyists', 0.00, 0.00, 5, 1, '{"basic_scans": true, "owasp_top10": true, "ghdb_patterns": true, "pdf_reports": false, "api_access": false, "priority_support": false, "ai_assistant": false, "custom_dorks": false, "scheduled_scans": false, "team_collaboration": false, "advanced_payloads": false, "retest_vulnerabilities": false}'),
      ('starter', 'Starter', 'For small teams and freelancers', 19.99, 199.99, 50, 2, '{"basic_scans": true, "owasp_top10": true, "ghdb_patterns": true, "pdf_reports": true, "api_access": false, "priority_support": false, "ai_assistant": false, "custom_dorks": false, "scheduled_scans": false, "team_collaboration": false, "advanced_payloads": false, "retest_vulnerabilities": false}'),
      ('professional', 'Professional', 'For growing businesses', 49.99, 499.99, 200, 5, '{"basic_scans": true, "owasp_top10": true, "ghdb_patterns": true, "pdf_reports": true, "api_access": true, "priority_support": true, "ai_assistant": true, "custom_dorks": false, "scheduled_scans": true, "team_collaboration": false, "advanced_payloads": true, "retest_vulnerabilities": false}'),
      ('enterprise', 'Enterprise', 'For large organizations', 149.99, 1499.99, -1, 10, '{"basic_scans": true, "owasp_top10": true, "ghdb_patterns": true, "pdf_reports": true, "api_access": true, "priority_support": true, "ai_assistant": true, "custom_dorks": true, "scheduled_scans": true, "team_collaboration": true, "advanced_payloads": true, "retest_vulnerabilities": true}')
    `);

    connection.release();
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
};

const query = async (sql, params) => {
  const [results] = await pool.execute(sql, params);
  return results;
};

module.exports = { pool, initializeDatabase, query };