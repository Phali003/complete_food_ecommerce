/**
 * Production Environment Test Script
 * Tests database connection and forgot password functionality to identify internal server errors
 * 
 * Usage:
 *   node scripts/test-prod-environment.js
 */

import dotenv from 'dotenv';
import axios from 'axios';
import mysql from 'mysql2/promise';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Load environment variables
dotenv.config();

// Get current file's directory
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Define colors for console output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m'
};

/**
 * Log a header message
 * @param {string} message - Message to log
 */
function logHeader(message) {
  console.log('\n' + colors.bright + colors.blue + '='.repeat(80) + colors.reset);
  console.log(colors.bright + colors.blue + ' ' + message + colors.reset);
  console.log(colors.bright + colors.blue + '='.repeat(80) + colors.reset + '\n');
}

/**
 * Log a success message
 * @param {string} message - Message to log
 */
function logSuccess(message) {
  console.log(colors.green + '✓ ' + message + colors.reset);
}

/**
 * Log an error message
 * @param {string} message - Message to log
 * @param {Error} [error] - Optional error object
 */
function logError(message, error = null) {
  console.error(colors.red + '✗ ' + message + colors.reset);
  if (error) {
    console.error(colors.dim + '  Error details: ' + error.message + colors.reset);
  }
}

/**
 * Log an info message
 * @param {string} message - Message to log
 */
function logInfo(message) {
  console.log(colors.cyan + 'ℹ ' + message + colors.reset);
}

/**
 * Log a warning message
 * @param {string} message - Message to log
 */
function logWarning(message) {
  console.log(colors.yellow + '⚠ ' + message + colors.reset);
}

/**
 * Log a step message
 * @param {string} message - Message to log
 */
function logStep(message) {
  console.log(colors.magenta + '→ ' + message + colors.reset);
}

/**
 * Log an object with pretty formatting
 * @param {string} label - Label for the object
 * @param {Object} obj - Object to log
 */
function logObject(label, obj) {
  console.log(colors.cyan + label + ':' + colors.reset);
  console.log(colors.dim + JSON.stringify(obj, null, 2) + colors.reset);
}

/**
 * Check if required environment variables are present
 * @returns {boolean} True if all required variables are present
 */
function checkEnvironmentVariables() {
  logHeader('Checking Environment Variables');
  
  const requiredVars = [
    'DB_HOST',
    'DB_USER',
    'DB_PASSWORD',
    'DB_NAME',
    'DB_PORT',
    'DB_SSL',
    'RESEND_API_KEY',
    'FROM_EMAIL',
    'NODE_ENV'
  ];
  
  const missingVars = requiredVars.filter(varName => !process.env[varName]);
  
  if (missingVars.length > 0) {
    logError(`Missing required environment variables: ${missingVars.join(', ')}`);
    return false;
  }
  
  logSuccess('All required environment variables are present');
  
  // Warn if not in production mode
  if (process.env.NODE_ENV !== 'production') {
    logWarning(`Running in ${process.env.NODE_ENV} mode instead of production`);
  }
  
  return true;
}

/**
 * Load SSL certificate for database connection
 * @returns {string|null} Certificate content or null if not available
 */
function loadSSLCertificate() {
  logStep('Loading SSL certificate');
  
  try {
    // Look for certificate in the certs directory
    const certPath = path.join(process.cwd(), 'certs', 'ca.pem');
    
    if (!fs.existsSync(certPath)) {
      logWarning(`Certificate file not found at ${certPath}`);
      return null;
    }
    
    const caCert = fs.readFileSync(certPath, 'utf8');
    
    // Simple validation
    if (!caCert.includes('-----BEGIN CERTIFICATE-----') || 
        !caCert.includes('-----END CERTIFICATE-----')) {
      logWarning('Invalid certificate format: Missing BEGIN/END markers');
      return null;
    }
    
    logSuccess('SSL certificate loaded successfully');
    return caCert;
  } catch (error) {
    logError('Failed to load SSL certificate', error);
    return null;
  }
}

/**
 * Test database connection
 * @returns {Promise<boolean>} True if connection successful
 */
async function testDatabaseConnection() {
  logHeader('Testing Database Connection');
  
  logObject('Database Configuration', {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    ssl: process.env.DB_SSL || 'true'
  });
  
  const caCert = loadSSLCertificate();
  
  // Configure pool options
  const poolConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    
    // Connection pool settings
    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0,
    
    // Increase timeouts for cloud database
    connectTimeout: 60000, // 60 seconds
    
    // SSL configuration
    ssl: process.env.DB_SSL === 'true' ? {
      rejectUnauthorized: true,
      ca: caCert,
      minVersion: 'TLSv1.2'
    } : undefined
  };
  
  let pool = null;
  let connection = null;
  
  try {
    logStep('Creating connection pool');
    pool = mysql.createPool(poolConfig);
    
    logStep('Acquiring connection from pool');
    connection = await pool.getConnection();
    logSuccess('Connection acquired successfully');
    
    // Test basic connectivity with a ping
    logStep('Testing connection with ping');
    await connection.ping();
    logSuccess('Ping successful');
    
    // Verify SSL connection
    logStep('Verifying SSL connection');
    const [sslResults] = await connection.query("SHOW STATUS LIKE 'Ssl_cipher'");
    const sslCipher = sslResults[0]?.Value;
    
    if (!sslCipher && process.env.DB_SSL === 'true') {
      logWarning('SSL CONNECTION FAILED: No SSL cipher reported by database');
    } else if (sslCipher) {
      logSuccess(`SSL connection verified with cipher: ${sslCipher}`);
      
      // Get more SSL details
      const [sslDetails] = await connection.query("SHOW STATUS WHERE Variable_name LIKE 'ssl%'");
      const sslInfo = {};
      sslDetails.forEach(row => {
        sslInfo[row.Variable_name] = row.Value;
      });
      
      logObject('SSL Connection Details', sslInfo);
    }
    
    // Test actual queries to database tables
    logStep('Testing query on users table');
    const [users] = await connection.query('SELECT COUNT(*) as count FROM users');
    logSuccess(`Users table query successful - ${users[0].count} users found`);
    
    logStep('Testing password reset tables');
    let passwordResetTablesExist = true;
    
    try {
      const [tokens] = await connection.query('SELECT COUNT(*) as count FROM password_reset_tokens');
      logSuccess(`Password reset tokens table exists - ${tokens[0].count} tokens found`);
    } catch (error) {
      passwordResetTablesExist = false;
      logError('Password reset tokens table does not exist or cannot be accessed', error);
    }
    
    try {
      const [attempts] = await connection.query('SELECT COUNT(*) as count FROM password_reset_attempts');
      logSuccess(`Password reset attempts table exists - ${attempts[0].count} attempts found`);
    } catch (error) {
      passwordResetTablesExist = false;
      logError('Password reset attempts table does not exist or cannot be accessed', error);
    }
    
    if (!passwordResetTablesExist) {
      logWarning('Password reset functionality may not work due to missing tables');
    }
    
    return true;
  } catch (error) {
    logError('Database connection test failed', error);
    
    // More detailed error information
    logObject('Error Details', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage
    });
    
    // Specific error handling
    if (error.code === 'CERT_HAS_EXPIRED') {
      logError('CA Certificate has expired - please update it');
    } else if (error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
      logError('Unable to verify certificate - check your CA certificate');
    } else if (error.code === 'ECONNREFUSED') {
      logError('Connection refused - check your database host and port');
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      logError('Access denied - check your database username and password');
    } else if (error.code === 'HANDSHAKE_SSL_ERROR' || error.message.includes('ssl')) {
      logError('SSL configuration error - check your SSL settings');
    }
    
    return false;
  } finally {
    // Release resources
    if (connection) {
      try {
        logStep('Releasing connection');
        connection.release();
        logSuccess('Connection released successfully');
      } catch (releaseError) {
        logError('Error releasing connection', releaseError);
      }
    }
    
    if (pool) {
      try {
        logStep('Ending pool');
        await pool.end();
        logSuccess('Pool ended successfully');
      } catch (endError) {
        logError('Error ending pool', endError);
      }
    }
  }
}

/**
 * Test forgot password API endpoint
 * @returns {Promise<boolean>} True if test passed
 */
async function testForgotPasswordAPI() {
  logHeader('Testing Forgot Password API');
  
  // Determine API base URL
  const apiBaseUrl = process.env.API_BASE_URL || 'https://fresh-eats-market.onrender.com';
  const forgotPasswordEndpoint = '/api/auth/forgot-password';
  const fullUrl = `${apiBaseUrl}${forgotPasswordEndpoint}`;
  
  logInfo(`Using API URL: ${fullUrl}`);
  
  // Define test cases with expected results
  const testCases = [
    {
      name: 'Valid email format (may or may not exist in database)',
      data: { email: 'test@example.com' },
      expectedStatus: 200,
      shouldSucceed: true
    },
    {
      name: 'Empty email',
      data: { email: '' },
      expectedStatus: 400,
      shouldSucceed: false
    },
    {
      name: 'Missing email field',
      data: {},
      expectedStatus: 400,
      shouldSucceed: false
    },
    {
      name: 'Invalid email format',
      data: { email: 'invalid-email' },
      expectedStatus: 400,
      shouldSucceed: false
    }
  ];
  
  let allTestsPassed = true;
  
  // Test request headers
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-Test-Mode': 'true',
    'User-Agent': 'ProdTest/1.0'
  };
  
  // Run each test case
  for (const testCase of testCases) {
    logStep(`Testing case: ${testCase.name}`);
    
    try {
      const startTime = Date.now();
      const response = await axios({
        method: 'post',
        url: fullUrl,
        data: testCase.data,
        headers,
        validateStatus: () => true, // Don't throw on any status code
        timeout: 30000 // 30 second timeout
      });
      const duration = Date.now() - startTime;
      
      const result = {
        status: response.status,
        data: response.data,
        duration: `${duration}ms`,
        headers: response.headers
      };
      
      // Determine if test passed
      let testPassed = false;
      if (testCase.shouldSucceed) {
        testPassed = response.status === testCase.expectedStatus && response.data.success === true;
      } else {
        testPassed = response.status === testCase.expectedStatus;
      }
      
      if (testPassed) {
        logSuccess(`Test passed: ${testCase.name} (${duration}ms)`);
      } else {
        logError(`Test failed: ${testCase.name} - Expected status ${testCase.expectedStatus}, got ${response.status}`);
        allTestsPassed = false;
      }
      
      // Log response details
      logObject('Response', result);
    } catch (error) {
      logError(`Test error: ${testCase.name}`, error);
      
      // Check for specific error types
      if (error.code === 'ECONNREFUSED') {
        logError('Connection refused - API server may be down');
      } else if (error.code === 'ECONNABORTED') {
        logError('Connection timed out - API server may be overloaded');
      } else if (error.response) {
        logObject('Error Response', {
          status: error.response.status,
          data: error.response.data,
          headers: error.response.headers
        });
      }

