// test-prod-auth.js - Production environment test for database and forgot password functionality
import mysql from 'mysql2/promise';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Production-specific configuration
const CONFIG = {
  baseUrl: 'https://fresh-eats-market.onrender.com',  // Render production URL
  apiPath: '/api/auth',
  testEmail: 'priscphalis@gmail.com',  // Test email for reset password flow
  dbConfig: {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: {
      rejectUnauthorized: true,
      ca: null
    }
  }
};

// Test database connection specifically
async function testDatabase() {
  console.log('\n🔍 Testing production database connection...');
  
  try {
    // Load SSL certificate
    const certPath = path.join(__dirname, 'certs', 'ca.pem');
    console.log(`Loading SSL certificate from: ${certPath}`);
    
    if (!fs.existsSync(certPath)) {
      console.error(`❌ Certificate file not found at ${certPath}`);
      return false;
    }
    
    const caCert = fs.readFileSync(certPath, 'utf8');
    CONFIG.dbConfig.ssl.ca = caCert;

    console.log('Connecting to database with configuration:');
    console.log(`  Host: ${CONFIG.dbConfig.host}`);
    console.log(`  User: ${CONFIG.dbConfig.user}`);
    console.log(`  Database: ${CONFIG.dbConfig.database}`);
    console.log(`  Port: ${CONFIG.dbConfig.port}`);
    console.log(`  SSL: Enabled with CA certificate`);

    // Create connection
    const connection = await mysql.createConnection(CONFIG.dbConfig);
    
    // Test basic connectivity
    await connection.ping();
    console.log('✅ Database ping successful');

    // Test users table
    const [userRows] = await connection.query('SELECT COUNT(*) as count FROM users');
    console.log('✅ Users table accessible, count:', userRows[0].count);

    // Test password_reset_tokens table
    const [tokenRows] = await connection.query('SELECT COUNT(*) as count FROM password_reset_tokens');
    console.log('✅ Password reset tokens table accessible, count:', tokenRows[0].count);

    // Check SSL status
    const [sslStatus] = await connection.query("SHOW STATUS LIKE 'Ssl_cipher'");
    console.log('SSL Status:', {
      cipher: sslStatus[0].Value,
      secure: !!sslStatus[0].Value
    });

    await connection.end();
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    
    // Provide more detailed error diagnostics
    if (error.code === 'ER_NO_SUCH_TABLE') {
      console.error('Table does not exist - check database schema');
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.error('Access denied - check database credentials');
    } else if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
      console.error('Cannot reach database host - check network or host address');
    } else if (error.code === 'CERT_HAS_EXPIRED') {
      console.error('SSL certificate has expired - update CA certificate');
    }
    
    console.error('Full error:', error);
    return false;
  }
}

// Test forgot password endpoint specifically
async function testForgotPassword() {
  console.log('\n🔍 Testing forgot password endpoint in production...');
  
  try {
    const url = `${CONFIG.baseUrl}${CONFIG.apiPath}/forgot-password`;
    console.log(`Making request to: ${url}`);
    console.log(`Using test email: ${CONFIG.testEmail}`);
    
    const startTime = Date.now();
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: CONFIG.testEmail
      })
    });
    const requestTime = Date.now() - startTime;
    
    console.log(`Request completed in ${requestTime}ms`);
    console.log('Response status:', response.status);
    
    let responseData;
    try {
      responseData = await response.json();
    } catch (e) {
      console.error('Response is not valid JSON:', e.message);
      console.log('Raw response text:', await response.text().catch(() => 'Unable to read response text'));
      responseData = null;
    }
    
    console.log('Response data:', responseData);

    if (response.status === 500) {
      console.error('❌ Internal Server Error detected');
      console.error('This confirms the 500 error issue in production');
      return false;
    }

    if (response.ok) {
      console.log('✅ Forgot password endpoint returned success response');
    } else {
      console.error(`❌ Forgot password endpoint returned error status: ${response.status}`);
    }

    return response.ok;
  } catch (error) {
    console.error('❌ Forgot password request failed:', error.message);
    console.error('Full error:', error);
    return false;
  }
}

// Run all tests in sequence
async function runProductionTests() {
  console.log('====================================');
  console.log('🔍 TESTING PRODUCTION ENVIRONMENT');
  console.log('====================================');
  console.log('Test started at:', new Date().toISOString());
  console.log('Database Host:', CONFIG.dbConfig.host);
  console.log('API URL:', CONFIG.baseUrl);

  // Test database first - this is likely the source of the issues
  const dbSuccess = await testDatabase();
  
  if (!dbSuccess) {
    console.error('❌ Database connection failed - this may be causing the 500 errors');
  }

  // Test forgot password even if DB test fails
  const forgotPasswordSuccess = await testForgotPassword();
  
  console.log('\n====================================');
  console.log('TEST RESULTS SUMMARY');
  console.log('====================================');
  console.log(`Database Connection: ${dbSuccess ? '✅ PASSED' : '❌ FAILED'}`);
  console.log(`Forgot Password Endpoint: ${forgotPasswordSuccess ? '✅ PASSED' : '❌ FAILED'}`);
  
  if (!dbSuccess || !forgotPasswordSuccess) {
    console.log('\nNext Steps:');
    
    if (!dbSuccess) {
      console.log('- Verify DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, and DB_PORT in .env file');
      console.log('- Ensure ca.pem certificate is up-to-date and valid');
      console.log('- Check if IP whitelist on Aiven MySQL includes your Render IP');
    }
    
    if (!forgotPasswordSuccess) {
      console.log('- Check Render logs for detailed error messages');
      console.log('- Verify RESEND_API_KEY is valid in the Render environment variables');
      console.log('- Check email service configuration in emailService.js');
    }
  }
}

// Run all tests with appropriate error handling
runProductionTests()
  .then(() => {
    console.log('\nTests completed.');
    process.exit(0);
  })
  .catch(error => {
    console.error('\nFatal error during testing:', error);
    console.error('This is likely an issue with the test script itself, not the application.');
    process.exit(1);
  });

