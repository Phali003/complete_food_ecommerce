// test-full-reset.js
require('dotenv').config();
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

async function testFullReset() {
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
        console.log('Starting full reset test...');
        const email = 'priscphalis@gmail.com';

        // Clear any existing tokens
        console.log('\nClearing existing tokens...');
        await pool.execute(
            'UPDATE users SET reset_token = NULL, reset_token_expiry = NULL WHERE email = ?',
            [email]
        );

        // Step 1: Find user
        console.log('\nFinding user...');
        const [users] = await pool.execute(
            'SELECT id, username, email FROM users WHERE email = ?',
            [email]
        );

        if (!users || users.length === 0) {
            console.log('No user found with email:', email);
            return;
        }

        const user = users[0];
        console.log('Found user:', user);

        // Step 2: Generate token
        console.log('\nGenerating reset token...');
        const resetToken = crypto.randomBytes(20).toString('hex');
        const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour
        console.log('Token:', resetToken);
        console.log('Expiry:', resetTokenExpiry);

        // Step 3: Store token
        console.log('\nStoring token in database...');
        await pool.execute(
            'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?',
            [resetToken, resetTokenExpiry, user.id]
        );

        // Step 4: Verify token storage
        console.log('\nVerifying token storage...');
        const [verification] = await pool.execute(
            'SELECT reset_token, reset_token_expiry FROM users WHERE id = ?',
            [user.id]
        );
        console.log('Token verification:', verification[0]);

        // Step 5: Configure email
        console.log('\nConfiguring email transport...');
        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: parseInt(process.env.EMAIL_PORT),
            secure: process.env.EMAIL_SECURE === 'true',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD
            }
        });

        // Step 6: Send test email
        console.log('\nSending test email...');
        const resetUrl = `http://localhost:3000/reset-password.html?token=${resetToken}`;
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

        console.log('\nTest completed successfully');

    } catch (error) {
        console.error('Error during test:', error);
    } finally {
        await pool.end();
    }
}

// Run test
testFullReset().catch(console.error);

