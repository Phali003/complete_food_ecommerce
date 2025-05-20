/**
 * Email Configuration Tester
 * Utility to verify email configuration and send test emails
 */

const nodemailer = require('nodemailer');
require('dotenv').config();

/**
 * Test email configuration
 * @returns {Promise<Object>} Result of the email configuration test
 */
async function testEmailConfig() {
  console.log('Testing email configuration...');
  
  // Check if configuration exists
  if (!process.env.EMAIL_HOST || !process.env.EMAIL_PORT || 
      !process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
    console.error('❌ Email configuration is missing. Please check your .env file');
    return {
      success: false,
      message: 'Email configuration is incomplete',
      missingFields: [
        !process.env.EMAIL_HOST ? 'EMAIL_HOST' : null,
        !process.env.EMAIL_PORT ? 'EMAIL_PORT' : null,
        !process.env.EMAIL_USER ? 'EMAIL_USER' : null,
        !process.env.EMAIL_PASSWORD ? 'EMAIL_PASSWORD' : null
      ].filter(field => field !== null)
    };
  }
  
  // Create transporter with current configuration
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: parseInt(process.env.EMAIL_PORT),
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      }
    });
    
    // Verify the transporter configuration
    await transporter.verify();
    console.log('✅ Email configuration verified successfully');
    
    return {
      success: true,
      message: 'Email configuration is valid',
      config: {
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        secure: process.env.EMAIL_SECURE === 'true',
        user: process.env.EMAIL_USER,
        // Don't log the password for security reasons
      }
    };
  } catch (error) {
    console.error('❌ Email configuration verification failed:', error);
    
    return {
      success: false,
      message: 'Email configuration verification failed',
      error: {
        code: error.code,
        message: error.message
      },
      troubleshooting: getEmailTroubleshooting(error)
    };
  }
}

/**
 * Send a test email to verify the entire email system
 * @param {string} testEmail - Email address to send the test to
 * @returns {Promise<Object>} Result of the test email sending
 */
async function sendTestEmail(testEmail) {
  if (!testEmail) {
    return {
      success: false,
      message: 'No test email address provided'
    };
  }
  
  // First verify configuration
  const configTest = await testEmailConfig();
  if (!configTest.success) {
    return configTest;
  }
  
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: parseInt(process.env.EMAIL_PORT),
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      }
    });
    
    // Send the test email
    const info = await transporter.sendMail({
      from: `"${process.env.SITE_NAME || 'System Test'}" <${process.env.EMAIL_USER}>`,
      to: testEmail,
      subject: 'Email System Test',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
          <h1 style="color: #333; border-bottom: 1px solid #eee; padding-bottom: 10px;">Email System Test</h1>
          <p>This is a test email to verify that your email configuration is working correctly.</p>
          <p>If you received this email, your email system is properly configured.</p>
          <p>Timestamp: ${new Date().toISOString()}</p>
          <p style="margin-top: 30px; font-size: 12px; color: #777; border-top: 1px solid #eee; padding-top: 10px;">
            This is an automated test message.
          </p>
        </div>
      `,
      text: `
        Email System Test
        
        This is a test email to verify that your email configuration is working correctly.
        
        If you received this email, your email system is properly configured.
        
        Timestamp: ${new Date().toISOString()}
        
        This is an automated test message.
      `
    });
    
    console.log('✅ Test email sent:', info.messageId);
    return {
      success: true,
      message: 'Test email sent successfully',
      messageId: info.messageId,
      previewUrl: nodemailer.getTestMessageUrl(info)
    };
  } catch (error) {
    console.error('❌ Test email sending failed:', error);
    
    return {
      success: false,
      message: 'Test email sending failed',
      error: {
        code: error.code,
        message: error.message
      },
      troubleshooting: getEmailTroubleshooting(error)
    };
  }
}

/**
 * Get troubleshooting guidance for email errors
 * @param {Error} error - The error that occurred
 * @returns {Object} Troubleshooting guidance
 */
function getEmailTroubleshooting(error) {
  // Default troubleshooting object
  const troubleshooting = {
    possibleCauses: [],
    suggestedActions: []
  };
  
  // Analyze error code and provide specific guidance
  switch (error.code) {
    case 'EAUTH':
      troubleshooting.possibleCauses.push(
        'Authentication failed',
        'Invalid username or password',
        'Two-factor authentication may be required'
      );
      troubleshooting.suggestedActions.push(
        'Verify your email credentials',
        'If using Gmail, create an app password',
        'Check if your email provider requires special setup'
      );
      break;
    
    case 'ESOCKET':
    case 'ECONNECTION':
    case 'ETIMEDOUT':
      troubleshooting.possibleCauses.push(
        'Connection to email server failed',
        'Incorrect port or host',
        'Firewall or network issue'
      );
      troubleshooting.suggestedActions.push(
        'Verify your host and port settings',
        'Check if SSL/TLS settings are correct',
        'Check your network connection',
        'Verify your firewall is not blocking the connection'
      );
      break;
      
    case 'EENVELOPE':
      troubleshooting.possibleCauses.push(
        'Invalid email address format',
        'Sender email address not accepted'
      );
      troubleshooting.suggestedActions.push(
        'Verify your from and to email addresses',
        'Ensure your email domain is properly configured'
      );
      break;
    
    default:
      troubleshooting.possibleCauses.push(
        'Unknown email configuration issue',
        'Server configuration issue'
      );
      troubleshooting.suggestedActions.push(
        'Check your email server logs',
        'Verify all email configuration parameters',
        'Check if your email provider has service interruptions'
      );
  }
  
  // Add general advice
  troubleshooting.generalAdvice = 'If problems persist, contact your email service provider or system administrator.';
  
  return troubleshooting;
}

module.exports = {
  testEmailConfig,
  sendTestEmail,
  getEmailTroubleshooting
};
