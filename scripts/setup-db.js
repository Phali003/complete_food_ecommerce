const mysql = require('mysql2/promise');
require('dotenv').config();

async function setupDatabase() {
    let rootConnection;
    let dbConnection;
    
    try {
        console.log('Initializing database setup...');
        console.log(`Host: ${process.env.DB_HOST}`);
        console.log(`User: ${process.env.DB_USER}`);
        console.log(`Database: ${process.env.DB_NAME}`);
        
        // First connect without database to create it if needed
        rootConnection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD
        });

        console.log('✅ Connected to MySQL server');

        // Create database if it doesn't exist
        await rootConnection.query(`CREATE DATABASE IF NOT EXISTS ${process.env.DB_NAME} 
                                   CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
        console.log(`✅ Database '${process.env.DB_NAME}' created or already exists`);

        // Close root connection
        await rootConnection.end();
        
        // Connect to the specific database
        dbConnection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            multipleStatements: true
        });
        
        console.log(`✅ Connected to '${process.env.DB_NAME}' database`);

        // Create users table with case-insensitive collation
        console.log('Creating/updating users table...');
        await dbConnection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) COLLATE utf8mb4_unicode_ci UNIQUE NOT NULL,
                email VARCHAR(255) COLLATE utf8mb4_unicode_ci UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('user', 'admin') DEFAULT 'user',
                is_active BOOLEAN DEFAULT TRUE,
                is_super_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_username (username),
                INDEX idx_email (email),
                INDEX idx_role (role)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `);
        
        // Add indexes for case-insensitive searches if they don't exist
        try {
            await dbConnection.query(`
                ALTER TABLE users 
                ADD INDEX idx_username_lower (LOWER(username)),
                ADD INDEX idx_email_lower (LOWER(email))
            `);
        } catch (error) {
            // Ignore if indexes already exist
            if (!error.message.includes('Duplicate key name')) {
                throw error;
            }
        }
        
        console.log('✅ Users table created/updated successfully');

        // Create password_history table for security
        console.log('Creating password_history table...');
        await dbConnection.query(`
            CREATE TABLE IF NOT EXISTS password_history (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);
        console.log('✅ Password history table created/updated successfully');

        // Create audit_log table for tracking authentication events
        console.log('Creating audit_log table...');
        await dbConnection.query(`
            CREATE TABLE IF NOT EXISTS audit_log (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT,
                event_type VARCHAR(50) NOT NULL,
                event_description TEXT,
                ip_address VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
                INDEX idx_user_id (user_id),
                INDEX idx_event_type (event_type),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        `);
        console.log('✅ Audit log table created/updated successfully');

        // Create table for tracking password reset attempts
        console.log('Creating password_reset_attempts table...');
        await dbConnection.query(`
            CREATE TABLE IF NOT EXISTS password_reset_attempts (
                id INT PRIMARY KEY AUTO_INCREMENT,
                target_username VARCHAR(50) NOT NULL,
                initiated_by INT,
                attempt_count INT DEFAULT 1,
                attempt_window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_attempt_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(45),
                FOREIGN KEY (initiated_by) REFERENCES users(id) ON DELETE SET NULL,
                INDEX idx_target_username (target_username),
                INDEX idx_window_start (attempt_window_start)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `);
        console.log('✅ Password reset attempts table created/updated successfully');
        
        // Create a test user if no users exist
        const [userCount] = await dbConnection.query('SELECT COUNT(*) as count FROM users');
        if (userCount[0].count === 0) {
            console.log('Creating a test user...');
            const bcrypt = require('bcryptjs');
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash('Test123!', salt);
            
            await dbConnection.query(`
                INSERT INTO users (username, email, password_hash, role)
                VALUES ('testuser', 'test@example.com', ?, 'user')
            `, [hashedPassword]);
            
            console.log('✅ Test user created:');
            console.log('   Username: testuser');
            console.log('   Email: test@example.com');
            console.log('   Password: Test123!');
        } else {
            console.log(`ℹ️ Database already has ${userCount[0].count} user(s), skipping test user creation`);
        }

        console.log('\n✅ Database setup completed successfully!');
        
        // Run a test query to verify case-insensitive search
        console.log('\nTesting case-insensitive user lookup...');
        const [testResult] = await dbConnection.query(`
            SELECT id, username, email FROM users 
            WHERE LOWER(username) = LOWER('TESTUSER') 
            OR LOWER(email) = LOWER('TEST@EXAMPLE.COM')
        `);
        
        if (testResult.length > 0) {
            console.log('✅ Case-insensitive lookup working properly');
            console.log(`Found user: ${testResult[0].username} (${testResult[0].email})`);
        } else {
            console.log('⚠️ Case-insensitive lookup test failed - no users found');
        }
        
    } catch (error) {
        console.error('❌ Error setting up database:', error);
        throw error;
    } finally {
        if (rootConnection) {
            await rootConnection.end();
        }
        if (dbConnection) {
            await dbConnection.end();
            console.log('Database connections closed');
        }
    }
}

// Run the setup
setupDatabase()
    .then(() => {
        console.log('\n🎉 All done! Your database is ready for authentication.');
        console.log('You should now be able to register and login with the application.');
        process.exit(0);
    })
    .catch(error => {
        console.error('\n❌ Setup failed:', error.message);
        console.error('Please check your MySQL configuration and try again.');
        process.exit(1);
    });

