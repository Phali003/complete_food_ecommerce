// test-reset-debug.js
require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

async function testResetPasswordEndpoint() {
    // Create pool exactly as in the route
    const pool = await mysql.createPool({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    });

    try {
        const token = '700b98b8d5ef09129cb458e94ff64bfbc88ed0d2';
        const password = 'NewPassword123!';
        
        console.log('Starting reset password debug...');
        console.log('Token:', token);

        // Step 1: Find user with valid reset token
        console.log('\nFinding user with token...');
        console.log('Executing query:', 'SELECT id, email, username FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()');
        const [rows] = await pool.execute(
            'SELECT id, email, username FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()',
            [token]
        );
        
        console.log('Query result:', rows);

        if (!rows || rows.length === 0) {
            console.log('No user found with valid token');
            return;
        }

        const user = rows[0];
        console.log('\nUser found:', {
            id: user.id,
            email: user.email,
            username: user.username
        });

        // Step 2: Hash new password
        console.log('\nHashing password...');
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Step 3: Update password and clear reset token
        console.log('\nUpdating password...');
        await pool.execute(
            'UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
            [hashedPassword, user.id]
        );

        // Step 4: Store in password history
        console.log('\nStoring in password history...');
        await pool.execute(
            'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
            [user.id, hashedPassword]
        );

        // Step 5: Verify final state
        console.log('\nVerifying final state...');
        const [verifyResult] = await pool.execute(
            'SELECT reset_token, reset_token_expiry FROM users WHERE id = ?',
            [user.id]
        );
        console.log('Final verification:', verifyResult[0]);

        console.log('\nReset password debug completed successfully');

    } catch (error) {
        console.error('Error during reset password debug:', error);
    } finally {
        await pool.end();
    }
}

// Run debug test
console.log('Starting reset password debug test...');
testResetPasswordEndpoint().catch(console.error);

