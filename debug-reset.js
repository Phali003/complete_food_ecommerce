// debug-reset.js
require('dotenv').config();
const mysql = require('mysql2/promise');

async function debugPasswordReset() {
    // Create connection pool
    const pool = await mysql.createPool({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        debug: true // Enable debug mode
    });

    try {
        console.log('Database Configuration:', {
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            database: process.env.DB_NAME,
            port: process.env.DB_PORT
        });

        // Test direct connection
        console.log('\nTesting direct connection...');
        const connection = await pool.getConnection();
        console.log('Connection established successfully');

        // Test basic query
        console.log('\nTesting basic query...');
        const [testRow] = await connection.execute('SELECT 1 as test');
        console.log('Basic query result:', testRow);

        // Test user lookup
        console.log('\nLooking up test user...');
        const [users] = await connection.execute(
            'SELECT id, username, email FROM users WHERE email = ?',
            ['priscphalis@gmail.com']
        );
        console.log('User lookup result:', users[0]);

        if (users.length > 0) {
            const user = users[0];
            
            // Test token generation and storage
            console.log('\nTesting token storage...');
            const crypto = require('crypto');
            const resetToken = crypto.randomBytes(20).toString('hex');
            const resetTokenExpiry = new Date(Date.now() + 3600000);

            console.log('Generated token:', resetToken);
            console.log('Token expiry:', resetTokenExpiry);

            // Test update query
            console.log('\nAttempting to update user with token...');
            await connection.execute(
                'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?',
                [resetToken, resetTokenExpiry, user.id]
            );
            console.log('Update query executed');

            // Verify update
            console.log('\nVerifying token storage...');
            const [verification] = await connection.execute(
                'SELECT reset_token, reset_token_expiry FROM users WHERE id = ?',
                [user.id]
            );
            console.log('Verification result:', verification[0]);
        }

        // Release connection
        connection.release();
        console.log('\nConnection released');

    } catch (error) {
        console.error('Debug Error:', error);
    } finally {
        await pool.end();
        console.log('\nPool ended');
    }
}

// Run debug test
console.log('Starting debug test...');
debugPasswordReset().catch(console.error);

