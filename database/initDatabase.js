/**
 * Database Initialization Script
 * Creates all tables for VulnScan Pro
 */

const fs = require('fs');
const path = require('path');
const { Pool } = require('mysql2/promise');

require('dotenv').config();

const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'vulnscan_pro',
    multipleStatements: true
});

async function initializeDatabase() {
    console.log('Starting database initialization...');
    
    try {
        const sqlPath = path.join(__dirname, 'sql_dump_2026_03_31.sql');
        const sql = fs.readFileSync(sqlPath, 'utf8');
        
        const statements = sql
            .split(';')
            .map(s => s.trim())
            .filter(s => s.length > 0 && !s.startsWith('--'));
        
        let createdTables = 0;
        let errors = [];
        
        for (const statement of statements) {
            try {
                await pool.query(statement);
                const match = statement.match(/CREATE TABLE IF NOT EXISTS `?(\w+)`?/i);
                if (match) {
                    createdTables++;
                    console.log(`  ✓ Created/verified: ${match[1]}`);
                }
            } catch (err) {
                if (!err.message.includes('already exists')) {
                    errors.push({ statement: statement.substring(0, 100), error: err.message });
                }
            }
        }
        
        console.log(`\n✓ Database initialization complete!`);
        console.log(`  Tables processed: ${createdTables}`);
        console.log(`  Errors: ${errors.length}`);
        
        if (errors.length > 0) {
            console.log('\nErrors encountered:');
            errors.forEach((e, i) => {
                console.log(`  ${i + 1}. ${e.error}`);
            });
        }
        
    } catch (error) {
        console.error('Failed to initialize database:', error.message);
        throw error;
    } finally {
        await pool.end();
    }
}

if (require.main === module) {
    initializeDatabase()
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
}

module.exports = { initializeDatabase };
