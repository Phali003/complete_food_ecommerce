// test-reset.js
require('dotenv').config();
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');

async function testPasswordReset() {
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
        console.log('Starting test with exact route logic...');
        
        // 1. Find user
        console.log('\nFinding user...');
        const [rows] = await pool.execute(
            'SELECT id, username, email FROM users WHERE email = ?',
            ['priscphalis@gmail.com']
        );
        console.log('User found:', rows[0]);

        if (rows && rows.length > 0) {
            const user = rows[0];
            
            // 2. Generate token
            console.log('\nGenerating reset token...');
            const resetToken = crypto.randomBytes(20).toString('hex');
            const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour
            console.log('Token generated:', {
                token: resetToken,
                expiry: resetTokenExpiry
            });

            // 3. Update user with token
            console.log('\nUpdating user with reset token...');
            await pool.execute(
                'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?',
                [resetToken, resetTokenExpiry, user.id]
            );

            // 4. Verify token storage
            console.log('\nVerifying token storage...');
            const [verifyResult] = await pool.execute(
                'SELECT reset_token, reset_token_expiry FROM users WHERE id = ?',
                [user.id]
            );
            console.log('Verification result:', verifyResult[0]);

            // 5. Test email configuration
            console.log('\nTesting email configuration...');
            const transporter = nodemailer.createTransport({
                host: process.env.EMAIL_HOST,
                port: parseInt(process.env.EMAIL_PORT),
                secure: process.env.EMAIL_SECURE === 'true',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASSWORD
                }
            });

            const resetUrl = `http://localhost:3000/reset-password.html?token=${resetToken}`;

            // 6. Send test email
            console.log('\nSending test email...');
            const mailResult = await transporter.sendMail({
                from: `"Fresh Eats Market" <${process.env.EMAIL_USER}>`,
                to: user.email,
                subject: 'Password Reset Request',
                html: `
                    <h1>Password Reset Request</h1>
                    <p>Hello ${user.username},</p>
                    <p>You requested to reset your password. Please click the link below to reset it:</p>
                    <a href="${resetUrl}">Reset Password</a>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                `
            });
            console.log('Email sent:', mailResult.messageId);
        }
        
    } catch (error) {
        console.error('Error details:', {
            message: error.message,
            stack: error.stack
        });
    } finally {
        await pool.end();
    }
}

// Set development environment
process.env.NODE_ENV = 'development';

// Run the test
testPasswordReset();

