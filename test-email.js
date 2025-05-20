const nodemailer = require('nodemailer');
require('dotenv').config();

async function testEmailConfig() {
    console.log('Testing email configuration...');
    console.log('Email settings:', {
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        secure: process.env.EMAIL_SECURE === 'true',
        auth: {
            user: process.env.EMAIL_USER,
            // Password length only for security
            passLength: process.env.EMAIL_PASSWORD ? process.env.EMAIL_PASSWORD.length : 0
        }
    });

    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        secure: process.env.EMAIL_SECURE === 'true',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD
        },
        debug: true,
        logger: true
    });

    try {
        console.log('Verifying email configuration...');
        const verification = await transporter.verify();
        console.log('Verification result:', verification);
        
        console.log('Attempting to send test email...');
        const info = await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER,
            subject: 'Test Email',
            text: 'This is a test email to verify the email configuration.'
        });
        console.log('Email sent successfully:', info);
    } catch (error) {
        console.error('Error:', error);
        if (error.code === 'EAUTH') {
            console.error('Authentication failed. Please check your email credentials.');
        }
    }
}

testEmailConfig().catch(console.error);

