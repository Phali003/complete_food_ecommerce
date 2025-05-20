// email-test.js
require('dotenv').config();
const nodemailer = require('nodemailer');

async function testEmail() {
    // Log all environment variables related to email (without the password)
    console.log('Email Configuration:', {
        EMAIL_HOST: process.env.EMAIL_HOST,
        EMAIL_PORT: process.env.EMAIL_PORT,
        EMAIL_SECURE: process.env.EMAIL_SECURE,
        EMAIL_USER: process.env.EMAIL_USER,
        EMAIL_PASSWORD_LENGTH: process.env.EMAIL_PASSWORD ? process.env.EMAIL_PASSWORD.length : 0
    });

    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT),
        secure: process.env.EMAIL_SECURE === 'true',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD
        },
        tls: {
            // Do not fail on invalid certs
            rejectUnauthorized: false
        },
        debug: true,
        logger: true
    });

    try {
        console.log('\nTesting SMTP connection...');
        const verified = await transporter.verify();
        console.log('SMTP connection test result:', verified);

        console.log('\nAttempting to send test email...');
        const info = await transporter.sendMail({
            from: `"Test" <${process.env.EMAIL_USER}>`,
            to: process.env.EMAIL_USER,
            subject: 'SMTP Test',
            text: 'This is a test email.',
            html: '<b>This is a test email.</b>'
        });

        console.log('Email sent successfully:', {
            messageId: info.messageId,
            response: info.response,
            accepted: info.accepted,
            rejected: info.rejected
        });
    } catch (error) {
        console.error('Error details:', {
            name: error.name,
            message: error.message,
            code: error.code,
            command: error.command,
            response: error.response
        });
        
        if (error.code === 'EAUTH') {
            console.error('\nAuthentication failed. Please check:');
            console.error('1. 2-Step Verification is enabled on your Gmail account');
            console.error('2. You are using an App Password, not your regular Gmail password');
            console.error('3. The App Password is correctly copied without spaces');
        }
    }
}

testEmail().catch(console.error);

