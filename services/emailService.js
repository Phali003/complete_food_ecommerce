/**
 * Email Service
 * Handles email sending using Resend.com
 */

const { Resend } = require('resend');
require('dotenv').config();

// Initialize Resend with API key
let resend = null;

/**
 * Initialize the Resend client
 * @returns {Object} The Resend client instance
 */
function getResendClient() {
  if (!resend && process.env.RESEND_API_KEY) {
    resend = new Resend(process.env.RESEND_API_KEY);
  }
  return resend;
}

/**
 * Test the email configuration
 * @returns {Promise<Object>} Result of the email configuration test
 */
async function testEmailConfig() {
  console.log('Testing Resend email configuration...');
  
  // Check if API key exists
  if (!process.env.RESEND_API_KEY) {
    console.error('❌ Resend API key is missing. Please check your .env file');
    return {
      success: false,
      message: 'Resend API key is missing',
      missingFields: ['RESEND_API_KEY']
    };
  }
  
  try {
    // Initialize the client
    const client = getResendClient();
    
    // We'll perform a simple API ping to verify the API key works
    // This doesn't actually send an email
    const domains = await client.domains.list();
    
    console.log('✅ Resend configuration verified successfully');
    return {
      success: true,
      message: 'Resend configuration is valid',
      config: {
        apiKeyExists: !!process.env.RESEND_API_KEY,
        fromEmail: process.env.FROM_EMAIL || 'Not configured'
      }
    };
  } catch (error) {
    console.error('❌ Resend configuration verification failed:', error);
    
    return {
      success: false,
      message: 'Resend configuration verification failed',
      error: {
        code: error.statusCode,
        message: error.message
      },
      troubleshooting: getEmailTroubleshooting(error)
    };
  }
}

/**
 * Send an email using Resend
 * @param {Object} options - Email options
 * @param {string} options.to - Recipient email address
 * @param {string} options.subject - Email subject
 * @param {string} options.html - HTML content of the email
 * @param {string} [options.text] - Plain text content of the email (optional)
 * @param {string} [options.from] - Sender email address (defaults to FROM_EMAIL env var)
 * @returns {Promise<Object>} Result of the email sending
 */
async function sendEmail({ to, subject, html, text, from }) {
  // Validate parameters
  if (!to || !subject || !html) {
    return {
      success: false,
      message: 'Missing required parameters (to, subject, or html)',
      missingFields: [
        !to ? 'to' : null,
        !subject ? 'subject' : null,
        !html ? 'html' : null
      ].filter(field => field !== null)
    };
  }

  // Get the sender email
  const fromEmail = from || process.env.FROM_EMAIL || process.env.EMAIL_USER;
  if (!fromEmail) {
    return {
      success: false,
      message: 'No sender email address configured',
      missingFields: ['FROM_EMAIL or EMAIL_USER']
    };
  }
  
  try {
    // First verify configuration
    const configTest = await testEmailConfig();
    if (!configTest.success) {
      return configTest;
    }
    
    const client = getResendClient();
    
    // Prepare email data
    const emailData = {
      from: fromEmail,
      to: to,
      subject: subject,
      html: html
    };
    
    // Add text version if provided
    if (text) {
      emailData.text = text;
    }
    
    // Send the email
    const { data, error } = await client.emails.send(emailData);
    
    if (error) {
      throw error;
    }
    
    console.log('✅ Email sent with ID:', data.id);
    return {
      success: true,
      message: 'Email sent successfully',
      emailId: data.id
    };
  } catch (error) {
    console.error('❌ Email sending failed:', error);
    
    return {
      success: false,
      message: 'Email sending failed',
      error: {
        code: error.statusCode,
        message: error.message
      },
      troubleshooting: getEmailTroubleshooting(error)
    };
  }
}

/**
 * Send a test email to verify the email system
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
  
  const siteName = process.env.SITE_NAME || 'Fresh Eats Market';
  
  return sendEmail({
    to: testEmail,
    subject: 'Email System Test',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
        <h1 style="color: #333; border-bottom: 1px solid #eee; padding-bottom: 10px;">Email System Test</h1>
        <p>This is a test email to verify that your email configuration is working correctly.</p>
        <p>If you received this email, your Resend email system is properly configured.</p>
        <p>Timestamp: ${new Date().toISOString()}</p>
        <p style="margin-top: 30px; font-size: 12px; color: #777; border-top: 1px solid #eee; padding-top: 10px;">
          This is an automated test message from ${siteName}.
        </p>
      </div>
    `,
    text: `
      Email System Test
      
      This is a test email to verify that your email configuration is working correctly.
      
      If you received this email, your Resend email system is properly configured.
      
      Timestamp: ${new Date().toISOString()}
      
      This is an automated test message from ${siteName}.
    `
  });
}

/**
 * Send a password reset email
 * @param {Object} options - Password reset options
 * @param {string} options.to - Recipient email address
 * @param {string} options.resetToken - Password reset token
 * @param {string} options.resetUrl - Base URL for password reset
 * @returns {Promise<Object>} Result of the password reset email sending
 */
async function sendPasswordResetEmail({ to, resetToken, resetUrl }) {
  const siteName = process.env.SITE_NAME || 'Fresh Eats Market';
  const tokenExpiry = parseInt(process.env.RESET_TOKEN_EXPIRY || '15');
  
  // Build the full reset URL - avoid double paths if resetUrl already contains the full path
  const fullResetUrl = resetUrl.includes('reset-password.html') 
    ? resetUrl 
    : `${resetUrl}/reset-password.html?token=${resetToken}`;

  return sendEmail({
    to: to,
    subject: `Password Reset Request - ${siteName}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h1 style="color: #4CAF50;">Password Reset</h1>
        </div>
        
        <p>Hello,</p>
        
        <p>We received a request to reset your password for your ${siteName} account. If you didn't make this request, you can safely ignore this email.</p>
        
        <p>To reset your password, click the button below:</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${fullResetUrl}" style="background-color: #4CAF50; color: white; padding: 12px 20px; text-decoration: none; border-radius: 4px; font-weight: bold;">Reset My Password</a>
        </div>
        
        <p>Or copy and paste this URL into your browser:</p>
        <p style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; word-break: break-all;">
          ${fullResetUrl}
        </p>
        
        <p>This password reset link is only valid for the next ${tokenExpiry} minutes.</p>
        
        <p>If you're having trouble, please contact our support team.</p>
        
        <p>Thanks,<br>The ${siteName} Team</p>
        
        <div style="margin-top: 30px; font-size: 12px; color: #777; border-top: 1px solid #eee; padding-top: 20px;">
          <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns about your account security.</p>
        </div>
      </div>
    `,
    text: `
      Password Reset - ${siteName}
      
      Hello,
      
      We received a request to reset your password for your ${siteName} account.
      
      To reset your password, click the link below:
      
      ${fullResetUrl}
      
      This password reset link is only valid for the next ${tokenExpiry} minutes.
      
      If you didn't request a password reset, please ignore this email or contact support if you have concerns about your account security.
      
      Thanks,
      The ${siteName} Team
    `
  });
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
  
  // Analyze error and provide specific guidance
  if (error.statusCode === 401 || error.statusCode === 403) {
    troubleshooting.possibleCauses.push(
      'Invalid API key',
      'API key has been revoked or expired',
      'API key does not have permission to send emails'
    );
    troubleshooting.suggestedActions.push(
      'Check if your RESEND_API_KEY is correct',
      'Generate a new API key in your Resend dashboard',
      'Make sure your Resend account is active'
    );
  } else if (error.statusCode === 429) {
    troubleshooting.possibleCauses.push(
      'Rate limit exceeded',
      'Too many requests in a short period'
    );
    troubleshooting.suggestedActions.push(
      'Implement rate limiting in your application',
      'Wait a few minutes before trying again',
      'Contact Resend to increase your limits if needed'
    );
  } else if (error.statusCode === 400) {
    troubleshooting.possibleCauses.push(
      'Invalid request parameters',
      'Recipient email address may be invalid',
      'Sender domain not verified'
    );
    troubleshooting.suggestedActions.push(
      'Check that the recipient email address is valid',
      'Verify your sender domain in the Resend dashboard',
      'Ensure FROM_EMAIL is set to a verified domain or address'
    );
  } else {
    troubleshooting.possibleCauses.push(
      'Network connectivity issue',
      'Resend service disruption',
      'Unknown configuration issue'
    );
    troubleshooting.suggestedActions.push(
      'Check your internet connection',
      'Verify Resend service status',
      'Retry the operation after a few minutes'
    );
  }
  
  // Add general advice
  troubleshooting.generalAdvice = 'For detailed help, check the Resend documentation at https://resend.com/docs or contact their support.';
  
  return troubleshooting;
}

module.exports = {
  testEmailConfig,
  sendEmail,
  sendTestEmail,
  sendPasswordResetEmail,
  getEmailTroubleshooting
};

