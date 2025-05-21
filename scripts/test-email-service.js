/**
 * Email Service Test Script
 * 
 * This script tests the email service by validating configuration
 * and sending a test email to verify functionality.
 * 
 * Usage:
 * node scripts/test-email-service.js your-email@example.com
 */

// Import required modules
const { 
  testEmailConfig, 
  sendTestEmail 
} = require('../services/emailService');
require('dotenv').config();

/**
 * Run the email service tests
 * @param {string} testEmailAddress - Email address to send test email to
 */
async function runEmailTests(testEmailAddress) {
  console.log('\n🔍 STARTING EMAIL SERVICE TEST\n');
  console.log('='.repeat(50));

  try {
    // Step 1: Verify that the Resend API key is configured
    console.log('\n📋 TESTING EMAIL CONFIGURATION:');
    console.log('-'.repeat(50));
    
    const configResult = await testEmailConfig();
    
    console.log('Config Test Result:', JSON.stringify(configResult, null, 2));
    
    if (!configResult.success) {
      console.error('\n❌ EMAIL CONFIGURATION TEST FAILED');
      console.error('Please check your API key and Resend.com setup before proceeding.');
      console.error('Troubleshooting:');
      
      if (configResult.troubleshooting) {
        console.error('- Possible Causes:');
        configResult.troubleshooting.possibleCauses.forEach(cause => {
          console.error(`  * ${cause}`);
        });
        
        console.error('- Suggested Actions:');
        configResult.troubleshooting.suggestedActions.forEach(action => {
          console.error(`  * ${action}`);
        });
      }
      
      console.error('\nExiting test due to configuration issues.');
      return;
    }
    
    console.log('\n✅ EMAIL CONFIGURATION TEST PASSED');
    
    // Step 2: Send a test email if configuration passed
    if (testEmailAddress) {
      console.log('\n📧 SENDING TEST EMAIL:');
      console.log('-'.repeat(50));
      console.log(`Sending test email to: ${testEmailAddress}`);
      
      const emailResult = await sendTestEmail(testEmailAddress);
      
      console.log('Email Test Result:', JSON.stringify(emailResult, null, 2));
      
      if (emailResult.success) {
        console.log(`\n✅ TEST EMAIL SENT SUCCESSFULLY to ${testEmailAddress}`);
        console.log(`Email ID: ${emailResult.emailId}`);
        console.log('\nPlease check your inbox (and spam folder) to confirm receipt.');
      } else {
        console.error('\n❌ TEST EMAIL SENDING FAILED');
        
        if (emailResult.troubleshooting) {
          console.error('- Possible Causes:');
          emailResult.troubleshooting.possibleCauses.forEach(cause => {
            console.error(`  * ${cause}`);
          });
          
          console.error('- Suggested Actions:');
          emailResult.troubleshooting.suggestedActions.forEach(action => {
            console.error(`  * ${action}`);
          });
        }
      }
    } else {
      console.log('\n⚠️ NO TEST EMAIL ADDRESS PROVIDED');
      console.log('To send a test email, run the script with an email address:');
      console.log('node scripts/test-email-service.js your-email@example.com');
    }
    
  } catch (error) {
    console.error('\n❌ UNEXPECTED ERROR DURING EMAIL TESTING:');
    console.error(error);
  }
  
  console.log('\n='.repeat(50));
  console.log('🏁 EMAIL SERVICE TEST COMPLETED\n');
}

// Get test email address from command line argument
const testEmailAddress = process.argv[2];

// Run the tests
runEmailTests(testEmailAddress)
  .catch(error => {
    console.error('Fatal error in test execution:', error);
    process.exit(1);
  });

