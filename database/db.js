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
        INDEX idx_status (status),
        INDEX idx_created_at (created_at)
      )
    `);

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

    connection.release();
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
};

module.exports = { pool, initializeDatabase };