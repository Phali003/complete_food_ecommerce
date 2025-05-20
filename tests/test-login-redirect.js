/**
 * Login Redirection Test Script
 * 
 * This script tests the server's login response to verify it includes the proper redirectUrl
 * and that the redirection behavior should work correctly.
 */

const axios = require('axios');

// Configuration
const API_URL = 'http://localhost:3000/api/auth/login'; // Updated to use port 3000
const TEST_CREDENTIALS = {
  identifier: 'priscphalis@gmail.com', // Updated with real user email
  password: 'B1N0M1@l'                 // Updated with real user password
};

// Helper function to log results with color
function logResult(message, success = true) {
  const color = success ? '\x1b[32m' : '\x1b[31m'; // Green for success, red for error
  const reset = '\x1b[0m';
  console.log(`${color}${message}${reset}`);
}

// Test the login redirect functionality
async function testLoginRedirect() {
  console.log('=== Testing Login Redirection Functionality ===');
  console.log(`Testing login endpoint: ${API_URL}`);
  console.log(`Using credentials: ${TEST_CREDENTIALS.identifier}`);
  console.log('Make sure the server is running on port 3000\n');
  
  try {
    // Send login request
    const response = await axios.post(API_URL, TEST_CREDENTIALS);
    
    // Check if response is successful
    if (response.status === 200 && response.data.success) {
      logResult('✓ Login request successful');
      
      // Extract the data object for easier access
      const { data } = response.data;
      
      // Output complete response structure for debugging
      console.log('Response structure:', JSON.stringify(response.data, null, 2));
      
      // Check if response contains the user data
      if (data && data.user) {
        logResult('✓ Response contains user data');
        
        // Check if response contains the token
        if (data.token) {
          logResult('✓ Response contains authentication token');
          
          // Check if redirectUrl exists in the data object
          if ('redirectUrl' in data) {
            logResult(`✓ Response contains redirectUrl: ${data.redirectUrl}`);
            
            // Verify redirectUrl is 'index.html'
            if (data.redirectUrl === 'index.html') {
              logResult('✓ RedirectUrl is correctly set to "index.html"');
              console.log('\nLogin redirect functionality is working correctly on the server side!');
              console.log('The client-side JavaScript should now properly handle the redirect.');
            } else {
              logResult(`✗ RedirectUrl is not set to "index.html" as expected: ${data.redirectUrl}`, false);
            }
          } else {
            logResult('✗ Response does not contain redirectUrl', false);
            // Show the data structure to help debug
            console.log('\nData object structure:', JSON.stringify(data, null, 2));
          }
        } else {
          logResult('✗ Response does not contain authentication token', false);
        }
      } else {
        logResult('✗ Response does not contain user data', false);
      }
    } else {
      logResult(`✗ Login request failed: ${response.data.message || 'Unknown error'}`, false);
    }
  } catch (error) {
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      logResult(`✗ Server error: ${error.response.status} - ${error.response.data.message || 'Unknown error'}`, false);
    } else if (error.request) {
      // The request was made but no response was received
      logResult('✗ No response received from server. Make sure the server is running.', false);
    } else {
      // Something happened in setting up the request that triggered an Error
      logResult(`✗ Error: ${error.message}`, false);
    }
  }
}

// Run the test
testLoginRedirect();

