/**
 * Production Environment Test Script
 * Tests database connection and forgot password functionality to identify internal server errors
 * 
 * Usage:
 *   node scripts/test-prod-environment.mjs
 */

// IMMEDIATE OUTPUT TO VERIFY SCRIPT EXECUTION
process.stdout.write('====== SCRIPT EXECUTION STARTED ======\n');
process.stdout.write(`Time: ${new Date().toISOString()}\n`);
process.stdout.write(`Node version: ${process.version}\n`);
process.stdout.write(`Arguments: ${process.argv.join(' ')}\n`);

import dotenv from 'dotenv';
import axios from 'axios';
import mysql from 'mysql2/promise';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Debug flag to enable detailed logging
const DEBUG = true;

// Test configuration
const CONFIG = {
  // API request timeout in milliseconds (60 seconds)
  apiTimeout: 60000,
  // Number of retries for API requests
  apiRetries: 2,
  // Delay between retries in milliseconds
  retryDelay: 3000,
  // Tests to skip (can be overridden via command line args)
  skipTests: {
    database: false,
    api: false,
    email: false
  }
};

// Parse command line arguments
function parseCommandLineArgs() {
  const args = process.argv.slice(2);
  args.forEach(arg => {
    if (arg === '--skip-database') {
      CONFIG.skipTests.database = true;
    } else if (arg === '--skip-api') {
      CONFIG.skipTests.api = true;
    } else if (arg === '--skip-email') {
      CONFIG.skipTests.email = true;
    } else if (arg === '--api-timeout' && args[args.indexOf(arg) + 1]) {
      CONFIG.apiTimeout = parseInt(args[args.indexOf(arg) + 1], 10) * 1000; // Convert to ms
    }
  });
  
  debug('Command line args parsed', CONFIG);
}

// Parse command line args early
parseCommandLineArgs();

// Debug logging function
function debug(message, obj = null) {
  if (DEBUG) {
    console.log(`[DEBUG] ${message}`);
    if (obj) {
      console.log(JSON.stringify(obj, null, 2));
    }
  }
}

// Retry a function with exponential backoff
async function retryWithBackoff(fn, retries = CONFIG.apiRetries, delay = CONFIG.retryDelay, label = 'operation') {
  try {
    return await fn();
  } catch (error) {
    if (retries <= 0) {
      logError(`${label} failed after all retry attempts`, error);
      throw error;
    }
    
    logWarning(`${label} failed, retrying in ${delay/1000}s... (${retries} attempts left)`);
    await new Promise(resolve => setTimeout(resolve, delay));
    return retryWithBackoff(fn, retries - 1, delay * 1.5, label);
  }
}

// Force immediate console flush
process.stdout.write('Initializing test script...\n');

// Define exported functions at the module level
export {
  checkEnvironmentVariables,
  testDatabaseConnection,
  testForgotPasswordAPI,
  testEmailService,
  runAllTests
};

// Load environment variables
console.log('Loading environment variables...');
dotenv.config();
debug('Environment variables loaded', { 
  nodeEnv: process.env.NODE_ENV,
  dbHost: process.env.DB_HOST ? 'Set' : 'Not set',
  hasApiKey: process.env.RESEND_API_KEY ? 'Set' : 'Not set'
});

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

// Force synchronous logger to debug issues with console buffering
function syncLog(message) {
  process.stdout.write(`${message}\n`);
}

// Track test execution flow
syncLog("✅ Module loaded successfully");

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
 * @param {boolean} [skip=false] - Set to true to skip this test
 * @returns {Promise<boolean>} True if connection successful or skipped
 */
async function testDatabaseConnection(skip = CONFIG.skipTests.database) {
  if (skip) {
    logWarning('Database connection test SKIPPED');
    return true; // Return true to not fail the overall test
  }
  
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
 * @param {boolean} [skip=false] - Set to true to skip this test
 * @returns {Promise<boolean>} True if test passed or skipped
 */
async function testForgotPasswordAPI(skip = CONFIG.skipTests.api) {
  if (skip) {
    logWarning('Forgot password API test SKIPPED');
    return true; // Return true to not fail the overall test
  }
  
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
      
      // Use retry with backoff for API requests
      const response = await retryWithBackoff(async () => {
        syncLog(`Attempting API request for test case: ${testCase.name}...`);
        return await axios({
          method: 'post',
          url: fullUrl,
          data: testCase.data,
          headers,
          validateStatus: () => true, // Don't throw on any status code
          timeout: CONFIG.apiTimeout, // Use configurable timeout
          proxy: false, // Disable any proxy settings
          maxRedirects: 5, // Allow reasonable redirects
          decompress: true, // Handle compression automatically
          // Additional options for better error reporting
          maxBodyLength: 1000000,
          maxContentLength: 1000000,
          transitional: {
            clarifyTimeoutError: true
          }
        });
      }, CONFIG.apiRetries, CONFIG.retryDelay, `API test: ${testCase.name}`);
      
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
      
      // Enhanced error reporting for different error types
      if (error.code === 'ECONNREFUSED') {
        logError('Connection refused - API server may be down');
        logObject('Connection Details', {
          url: fullUrl,
          host: new URL(fullUrl).hostname,
          port: new URL(fullUrl).port || (new URL(fullUrl).protocol === 'https:' ? '443' : '80')
        });
      } else if (error.code === 'ECONNABORTED') {
        logError(`Connection timed out after ${CONFIG.apiTimeout/1000}s - API server may be overloaded`);
        logObject('Timeout Details', {
          url: fullUrl,
          timeout: CONFIG.apiTimeout,
          timeoutSeconds: CONFIG.apiTimeout/1000,
          retries: CONFIG.apiRetries
        });
      } else if (error.code === 'ETIMEDOUT') {
        logError('TCP timeout - API server may be experiencing network issues');
      } else if (error.code === 'ENOTFOUND') {
        logError('DNS lookup failed - check hostname');
      } else if (error.response) {
        // Server responded with an error status code
        logObject('Error Response', {
          status: error.response.status,
          statusText: error.response.statusText,
          data: error.response.data,
          headers: error.response.headers
        });
      } else {
        // Generic error with more details
        logObject('Error Details', {
          name: error.name,
          message: error.message,
          code: error.code,
          stack: DEBUG ? error.stack : 'Stack trace hidden (enable DEBUG for details)'
        });
      }
      
      allTestsPassed = false;
    }
  }
  
  return allTestsPassed;
}

/**
 * Test email service configuration and connectivity
 * @param {boolean} [skip=false] - Set to true to skip this test
 * @returns {Promise<boolean>} True if email service is configured correctly or skipped
 */
async function testEmailService(skip = CONFIG.skipTests.email) {
  if (skip) {
    logWarning('Email service test SKIPPED');
    return true; // Return true to not fail the overall test
  }
  
  logHeader('Testing Email Service Configuration');
  
  // Check for required email configuration
  if (!process.env.RESEND_API_KEY) {
    logError('RESEND_API_KEY environment variable is missing');
    return false;
  }
  
  if (!process.env.FROM_EMAIL) {
    logError('FROM_EMAIL environment variable is missing');
    return false;
  }
  
  logSuccess('Email environment variables are present');
  
  try {
    // Import the Resend client dynamically to avoid issues if it's not installed
    logStep('Initializing Resend client');
    let Resend;
    try {
      const resendModule = await import('resend');
      Resend = resendModule.Resend;
    } catch (importError) {
      logError('Failed to import Resend module', importError);
      logWarning('Make sure "resend" package is installed (npm install resend)');
      return false;
    }
    
    // Initialize Resend client
    const resend = new Resend(process.env.RESEND_API_KEY);
    
    // Attempt to list domains to verify API key without sending an email
    logStep('Verifying API key by listing domains');
    try {
      const domains = await resend.domains.list();
      logSuccess('API key is valid - successfully listed domains');
      logObject('Domains', domains);
      return true;
    } catch (apiError) {
      logError('API key validation failed', apiError);
      
      if (apiError.statusCode === 401 || apiError.statusCode === 403) {
        logError('Invalid API key or permissions issue');
      } else if (apiError.statusCode === 429) {
        logError('Rate limit exceeded');
      }
      
      logObject('API Error Details', {
        statusCode: apiError.statusCode,
        message: apiError.message,
        name: apiError.name
      });
      
      return false;
    }
  } catch (error) {
    logError('Email service test failed', error);
    return false;
  }
}

/**
 * Run all tests and report results
 * @param {Object} options - Test options
 * @param {boolean} options.skipDatabase - Whether to skip database tests
 * @param {boolean} options.skipApi - Whether to skip API tests
 * @param {boolean} options.skipEmail - Whether to skip email tests
 * @returns {Promise<number>} Exit code (0 for success, 1 for failures)
 */
async function runAllTests(options = {}) {
  // Apply any options passed directly to this function (overrides config)
  if (options.skipDatabase !== undefined) CONFIG.skipTests.database = options.skipDatabase;
  if (options.skipApi !== undefined) CONFIG.skipTests.api = options.skipApi;
  if (options.skipEmail !== undefined) CONFIG.skipTests.email = options.skipEmail;
  
  logHeader('PRODUCTION ENVIRONMENT TEST SUITE');
  logInfo(`Test started at: ${new Date().toISOString()}`);
  logInfo(`Node.js version: ${process.version}`);
  logInfo(`Environment: ${process.env.NODE_ENV || 'Not set'}`);
  
  // Log configuration
  logObject('Test Configuration', {
    apiTimeout: `${CONFIG.apiTimeout/1000} seconds`,
    apiRetries: CONFIG.apiRetries,
    retryDelay: `${CONFIG.retryDelay/1000} seconds`,
    skipDatabase: CONFIG.skipTests.database,
    skipApi: CONFIG.skipTests.api, 
    skipEmail: CONFIG.skipTests.email
  });
  
  // Object to track test results
  const results = {
    environmentCheck: false,
    databaseConnection: false,
    forgotPasswordAPI: false,
    emailService: false
  };
  
  // Track start time
  const startTime = Date.now();
  
  try {
    // Check environment variables
    results.environmentCheck = checkEnvironmentVariables();
    if (!results.environmentCheck) {
      logWarning('Environment variable check failed - some tests may not work correctly');
    }
    
    // Test database connection
    logInfo('Starting database connection test...');
    results.databaseConnection = await testDatabaseConnection(CONFIG.skipTests.database);
    
    // Test forgot password API
    logInfo('Starting forgot password API test...');
    results.forgotPasswordAPI = await testForgotPasswordAPI(CONFIG.skipTests.api);
    
    // Test email service
    logInfo('Starting email service test...');
    results.emailService = await testEmailService(CONFIG.skipTests.email);
  } catch (error) {
    logError('Unexpected error during test execution', error);
  }
  
  // Calculate duration
  const duration = (Date.now() - startTime) / 1000;
  
  // Print summary
  logHeader('TEST RESULTS SUMMARY');
  console.log(colors.bright + colors.white + 'Test Results:' + colors.reset);
  Object.entries(results).forEach(([test, passed]) => {
    const status = passed 
      ? colors.green + 'PASSED' + colors.reset 
      : colors.red + 'FAILED' + colors.reset;
    console.log(`${colors.cyan}${test}:${colors.reset} ${status}`);
  });
  
  const totalPassed = Object.values(results).filter(r => r).length;
  const totalTests = Object.keys(results).length;
  
  console.log(colors.bright + colors.white + `\nSummary: ${totalPassed}/${totalTests} tests passed` + colors.reset);
  console.log(colors.bright + colors.white + `Total duration: ${duration.toFixed(2)} seconds` + colors.reset);
  
  // Determine overall status
  const allPassed = Object.values(results).every(r => r);
  
  if (allPassed) {
    logSuccess('All tests passed successfully!');
    return 0; // Success exit code
  } else {
    logError('One or more tests failed');
    
    // Specific error messages for failed tests
    if (!results.databaseConnection) {
      logError('Database connection test failed - check database configuration');
    }
    if (!results.forgotPasswordAPI) {
      logError('Forgot password API test failed - check API implementation');
    }
    if (!results.emailService) {
      logError('Email service test failed - check email configuration');
    }
    
    return 1; // Error exit code
  }
}

// Handle process termination gracefully
process.on('SIGINT', () => {
  syncLog('\nTest interrupted by user');
  logWarning('Test interrupted by user');
  process.exit(2);
});

process.on('unhandledRejection', (reason, promise) => {
  syncLog('UNHANDLED REJECTION DETECTED:');
  console.error(reason);
  logError('Unhandled Promise Rejection', reason);
});

process.on('uncaughtException', (error) => {
  syncLog('UNCAUGHT EXCEPTION DETECTED:');
  console.error(error);
  logError('Uncaught Exception', error);
  process.exit(3);
});

// Force immediate test execution
syncLog('🚀 Starting test execution NOW...');

// Print help message if requested
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`
Usage: node test-prod-environment.mjs [options]

Options:
  --skip-database       Skip database connection tests
  --skip-api            Skip API tests
  --skip-email          Skip email service tests
  --api-timeout <sec>   Set API timeout in seconds (default: ${CONFIG.apiTimeout/1000})
  --help, -h            Show this help message

Examples:
  node test-prod-environment.mjs --skip-api
  node test-prod-environment.mjs --api-timeout 120
  node test-prod-environment.mjs --skip-database --skip-email
  `);
  process.exit(0);
}

// IIFE to allow top-level await
(async () => {
  try {
    syncLog('➡️ Calling runAllTests()...');
    const exitCode = await runAllTests();
    syncLog(`✅ Tests completed with exit code: ${exitCode}`);
    process.exit(exitCode);
  } catch (error) {
    syncLog('❌ ERROR DURING TEST EXECUTION:');
    console.error(error);
    logError('Error in test execution', error);
    process.exit(1);
  }
})();

syncLog('➡️ Test execution initiated - this line should appear before test results');

