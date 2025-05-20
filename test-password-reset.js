// test-password-reset.js
require('dotenv').config();
const mysql = require('mysql2/promise');

async function testResetPassword() {
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
        // Test data
        const token = '06f60071530ea913959559c65071b04ce2b417c7';
        const newPassword = 'NewTestPassword123!';

        console.log('Testing reset password with token:', token);

        // Find user with valid reset token
        const [rows] = await pool.execute(
            'SELECT id, email, username FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()',
            [token]
        );

        if (!rows || rows.length === 0) {
            console.error('No user found with valid token');
            return;
        }

        const user = rows[0];
        console.log('Found user:', { id: user.id, email: user.email, username: user.username });

        // Hash new password
        const bcrypt = require('bcryptjs');
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update password and clear reset token
        await pool.execute(
            'UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
            [hashedPassword, user.id]
        );

        // Store in password history
        await pool.execute(
            'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
            [user.id, hashedPassword]
        );

        console.log('Password reset successful');

        // Verify the changes
        const [verifyUser] = await pool.execute(
            'SELECT reset_token, reset_token_expiry FROM users WHERE id = ?',
            [user.id]
        );

        console.log('Verification result:', verifyUser[0]);

    } catch (error) {
        console.error('Error during password reset:', error);
    } finally {
        await pool.end();
    }
}

testResetPassword().catch(console.error);

