// test-reset-email.js
import dotenv from 'dotenv';
import { testEmailConfig, sendPasswordResetEmail } from './services/emailService.js';
import crypto from 'crypto';

// Initialize environment variables
dotenv.config();

// Get email from command line arguments or use default
const targetEmail = process.argv[2] || 'priscphalis@gmail.com';

// Generate a test reset token
const generateTestToken = () => crypto.randomBytes(32).toString('hex');

// Test configuration
const TEST_CONFIG = {
  email: targetEmail,
  username: 'Test User',
  frontendUrl: process.env.FRONTEND_URL || 'https://fresh-eats-market.onrender.com'
};

async function testResetEmail() {
  console.log('\n=== Testing Password Reset Email Service ===\n');
  
  // Log environment configuration
  console.log('Environment Configuration:');
  console.log('- RESEND_API_KEY:', process.env.RESEND_API_KEY ? '✓ Present' : '✗ Missing');
  console.log('- FROM_EMAIL:', process.env.FROM_EMAIL || '✗ Missing');
  console.log('- FRONTEND_URL:', TEST_CONFIG.frontendUrl);
  console.log('- NODE_ENV:', process.env.NODE_ENV || 'development');
  
  try {
    // Step 1: Test email configuration
    console.log('\n1. Testing email configuration...');
    const configResult = await testEmailConfig();
    
    if (!configResult.success) {
      throw new Error(`Configuration test failed: ${configResult.message}`);
    }
    console.log('✓ Email configuration verified');
    
    // Step 2: Send test reset email
    console.log('\n2. Sending test password reset email...');
    
    // Generate test reset URL
    const testToken = generateTestToken();
    const resetUrl = `${TEST_CONFIG.frontendUrl}/reset-password?token=${testToken}`;
    
    console.log('Test email details:');
    console.log('- Recipient:', TEST_CONFIG.email);
    console.log('- Reset URL:', resetUrl);
    
    const emailResult = await sendPasswordResetEmail({
      email: TEST_CONFIG.email,
      username: TEST_CONFIG.username,
      resetUrl: resetUrl
    });
    
    if (!emailResult.success) {
      throw new Error(`Failed to send reset email: ${emailResult.message}`);
    }
    
    console.log('\n✓ Password reset email sent successfully!');
    console.log('Email ID:', emailResult.emailId);
    console.log('\nPlease check your email inbox at:', TEST_CONFIG.email);
    console.log('(Note: The email might take a few minutes to arrive)');
    
  } catch (error) {
    console.error('\n✗ Test failed:', error.message);
    
    if (error.stack) {
      console.error('\nStack trace:', error.stack);
    }
    
    process.exit(1);
  }
}

// Run the test
console.log('Starting password reset email test...');
testResetEmail().catch(console.error);
