/**
 * Database Configuration Module
 * Handles MySQL database connection pool management with proper error handling
 */

// Required modules for database connectivity and SSL
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

console.log('Initializing database connection module...');

// -----------------------------------------------
// Helper Functions - Defined BEFORE being used
// -----------------------------------------------

// Connection pool monitoring function definition - moved to the top to avoid initialization issues
const startPoolMonitoring = () => {
  console.log('Initializing pool monitoring...');
  
  try {
    // Safety check - make sure pool exists and has proper methods
    if (!pool || typeof pool.on !== 'function') {
      console.error('Cannot start pool monitoring: pool is not properly initialized');
      return false;
    }
    
    // Monitor pool events with safe binding
    safeBindEvent('acquire', (connection) => {
      console.log('Connection %d acquired', connection.threadId);
    });

    safeBindEvent('release', (connection) => {
      console.log('Connection %d released', connection.threadId);
    });

    safeBindEvent('enqueue', () => {
      console.warn('Waiting for available connection slot');
    });

    // Monitor pool status periodically
    const statusInterval = setInterval(async () => {
      try {
        // Use async/await to check pool status
        const status = await (async () => {
          if (!pool || !pool.pool) return 'Pool not initialized';
          
          return {
            threadId: pool.pool.threadId,
            connectionLimit: pool.config?.connectionLimit,
            queueLimit: pool.config?.queueLimit,
            waitForConnections: pool.config?.waitForConnections
          };
        })();
        
        console.log('Pool Status:', status);
      } catch (error) {
        console.error('Error checking pool status:', error);
      }
    }, 300000); // Check every 5 minutes
    
    if (process.env.NODE_ENV !== 'production') {
      // Clean up interval on process exit in development
      process.on('SIGINT', () => {
        clearInterval(statusInterval);
        console.log('Pool monitoring stopped due to process termination');
      });
    }
    
    console.log('Pool monitoring initialized successfully');
    return true;
  } catch (error) {
    console.error('Failed to initialize pool monitoring:', error);
    return false;
  }
};

// Define SSL monitoring function before it's used
const startSSLMonitoring = () => {
  console.log('Initializing SSL monitoring...');
  
  // Function to check SSL health
  const checkSSLHealth = async () => {
    console.log('Running SSL health check...');
    console.log('==========================================');
    
    try {
      if (!pool) {
        console.error('Cannot check SSL health: pool is not initialized');
        return;
      }
      
      const connection = await pool.getConnection();
      
      try {
        // Check SSL status
        const [sslInfo] = await connection.query(`
          SHOW STATUS WHERE Variable_name IN (
            'Ssl_version', 'Ssl_cipher', 'Ssl_verify_mode'
          )
        `);
        
        // Transform results into a more usable format
        const sslStatus = {};
        sslInfo.forEach(row => {
          sslStatus[row.Variable_name] = row.Value;
        });
        
        // Verify SSL configuration
        const healthStatus = {
          sslVersion: sslStatus.Ssl_version,
          cipher: sslStatus.Ssl_cipher,
          verifyMode: sslStatus.Ssl_verify_mode,
          isEncrypted: sslStatus.Ssl_cipher !== '',
          caFileExists: process.env.DB_CA_CERT ? fs.existsSync(process.env.DB_CA_CERT) : false,
          caCertLoaded: !!caCert,
          sslEnabled: process.env.DB_SSL === 'true',
          environment: process.env.NODE_ENV
        };

        console.log('SSL Health Status:', healthStatus);

        // Check for potential issues
        if (!healthStatus.isEncrypted && process.env.DB_SSL === 'true') {
          console.error('WARNING: Connection not encrypted despite SSL being enabled');
        }
        if (process.env.NODE_ENV === 'production' && !healthStatus.caCertLoaded) {
          console.error('WARNING: No CA certificate loaded for production environment');
        }
        if (healthStatus.sslVersion && !healthStatus.sslVersion.match(/TLSv1\.[23]/)) {
          console.error('WARNING: Using older TLS version:', healthStatus.sslVersion);
        }

      } catch (error) {
        console.error('SSL health check query failed:', error);
      } finally {
        if (connection) {
          try {
            connection.release();
          } catch (releaseError) {
            console.error('Error releasing connection during SSL health check:', releaseError);
          }
        }
      }

    } catch (error) {
      console.error('SSL health check failed - could not acquire connection:', error);
    }

    console.log('==========================================');
  };

  // Run health check every 15 minutes
  const healthCheckInterval = setInterval(checkSSLHealth, 900000);
  
  // Run initial check asynchronously to avoid blocking
  setTimeout(checkSSLHealth, 5000);
  
  // Make sure we don't orphan interval
  if (process.env.NODE_ENV !== 'production') {
    process.on('SIGINT', () => {
      clearInterval(healthCheckInterval);
      console.log('SSL monitoring stopped due to process termination');
    });
  }
  
  console.log('SSL monitoring initialized successfully');
  return true;
};

// Helper for safely binding events to pool
const safeBindEvent = (eventName, handler) => {
  if (pool && typeof pool.on === 'function') {
    try {
      pool.on(eventName, handler);
      console.log(`Bound event handler for ${eventName}`);
    } catch (error) {
      console.error(`Failed to bind event handler for ${eventName}:`, error);
    }
  } else {
    console.error(`Cannot bind ${eventName} event: pool is not properly initialized`);
  }
};

/**
 * Load SSL certificate for database connection
 * @returns {string|null} Certificate content or null if not available
 */
function loadSSLCertificate() {
  try {
    // Look for certificate in the certs directory
    const certPath = path.join(process.cwd(), 'certs', 'ca.pem');
    console.log('Reading certificate from', certPath + '...');
    
    if (!fs.existsSync(certPath)) {
      console.warn('Certificate file not found at', certPath);
      return null;
    }
    
    const caCert = fs.readFileSync(certPath, 'utf8');
    
    // Simple validation
    const isValid = caCert.includes('-----BEGIN CERTIFICATE-----') && 
                    caCert.includes('-----END CERTIFICATE-----');
    
    console.log('SSL certificate loaded successfully:', {
      size: caCert.length,
      valid: isValid
    });
    return isValid ? caCert : null;
  } catch (error) {
    console.error('Failed to load SSL certificate:', error);
    return null;
  }
}

// Proceed with database initialization

// -----------------------------------------------
// Load CA Certificate for SSL
// -----------------------------------------------
const caCert = loadSSLCertificate();

// -----------------------------------------------
// Database Pool Configuration
// -----------------------------------------------
console.log('Database Configuration:', {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: process.env.DB_SSL
});

// Configure pool options with only valid mysql2 options
const poolConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  
  // Connection pool settings
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  
  // Increase timeouts for cloud database (use only supported options)
  connectTimeout: 60000, // 60 seconds
  
  // SSL configuration optimized for cloud hosting
  ssl: process.env.DB_SSL === 'true' ? {
    rejectUnauthorized: true,
    ca: caCert,
    minVersion: 'TLSv1.2'
  } : undefined,
  
  // Additional settings for stability
  multipleStatements: false,
  dateStrings: true
};

// -----------------------------------------------
// Pool Initialization
// -----------------------------------------------
let pool = null;

/**
 * Initialize the database connection pool
 * @returns {Promise<Object>} The connection pool
 */
async function initializePool() {
  try {
    // If pool is already initialized, return it
    if (pool) {
      console.log('Pool already initialized, reusing existing pool');
      return pool;
    }
    
    console.log('Initializing MySQL connection pool with config:', {
      host: poolConfig.host,
      user: poolConfig.user,
      database: poolConfig.database,
      port: poolConfig.port,
      ssl: poolConfig.ssl ? 'enabled' : 'disabled',
      environment: process.env.NODE_ENV
    });
    
    // Create the pool
    try {
      pool = mysql.createPool(poolConfig);
      console.log('MySQL connection pool created successfully');
    } catch (poolCreationError) {
      console.error('Failed to create connection pool:', poolCreationError);
      throw poolCreationError;
    }
    
    // Test connection immediately
    console.log('⏳ Testing initial database connection...');
    let connection;
    try {
      // Get connection from pool
      connection = await pool.getConnection();
      
      // Test connection with ping
      await connection.ping();
      console.log('✅ Database connection test successful');
        
      // Check SSL status if enabled
      if (process.env.DB_SSL === 'true') {
        const [rows] = await connection.query("SHOW STATUS LIKE 'Ssl_cipher'");
        const cipher = rows[0] ? rows[0].Value : null;
          
        if (!cipher) {
          console.warn('⚠️ WARNING: SSL may not be enabled despite configuration');
        } else {
          console.log('✅ SSL connection verified with cipher:', cipher);
        }
      }
    } catch (error) {
      // Handle both connection acquisition and ping/query errors
      if (error.code === 'ECONNREFUSED' || error.message.includes('getConnection')) {
        console.error('❌ Failed to acquire connection for initial test:', error);
      } else {
        console.error('❌ Database connection test failed:', error);
      }
      throw error;
    } finally {
      // Ensure connection is always released if it exists
      if (connection) {
        connection.release();
        connection = null; // Ensure connection is nullified after release
      }
    }

    // Start monitoring AFTER pool is successfully initialized
    startPoolMonitoring();
    startSSLMonitoring();
    
    return pool;
  } catch (error) {
    console.error('Failed to initialize connection pool:', error);
    // Reset pool to null if initialization failed
    pool = null;
    throw error;
  }
}

// -----------------------------------------------
// Database query helpers
// -----------------------------------------------

/**
 * Execute a database query with proper error handling
 * @param {string} sql - SQL query to execute
 * @param {Array} params - Query parameters
 * @returns {Promise<Array>} Query results
 */
async function query(sql, params = []) {
  if (!pool) {
    try {
      await initializePool();
    } catch (error) {
      throw new Error(`Failed to initialize pool for query: ${error.message}`);
    }
  }
  
  try {
    const [results] = await pool.query(sql, params);
    return results;
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  }
}

/**
 * Execute a prepared statement with proper error handling
 * @param {string} sql - SQL query to execute
 * @param {Array} params - Query parameters
 * @returns {Promise<Array>} Query results
 */
async function execute(sql, params = []) {
  if (!pool) {
    try {
      await initializePool();
    } catch (error) {
      throw new Error(`Failed to initialize pool for execute: ${error.message}`);
    }
  }
  
  try {
    const [results] = await pool.execute(sql, params);
    return results;
  } catch (error) {
    console.error('Database execute error:', error);
    throw error;
  }
}

/**
 * Get a connection from the pool
 * @returns {Promise<Object>} Database connection
 */
async function getConnection() {
  if (!pool) {
    try {
      await initializePool();
    } catch (error) {
      throw new Error(`Failed to initialize pool for connection: ${error.message}`);
    }
  }
  
  try {
    return await pool.getConnection();
  } catch (error) {
    console.error('Error getting connection from pool:', error);
    throw error;
  }
}

// Define health check function before exporting
const checkConnectionHealth = async () => {
  if (!pool || typeof pool.getConnection !== 'function') {
    console.error('Cannot check connection health - pool not properly initialized');
    return false;
  }
  
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.ping();
    return true;
  } catch (error) {
    console.error('Connection health check failed:', error);
    return false;
  } finally {
    if (connection) {
      try {
        connection.release();
      } catch (releaseError) {
        console.error('Error releasing connection during health check:', releaseError);
      }
    }
  }
};

// Define connection verification function before exporting
const verifyConnection = async (connection, operation = 'operation') => {
  console.log(`Verifying connection before ${operation}...`);
  try {
    await connection.ping();  // This will throw if connection is invalid
    return true;
  } catch (error) {
    console.error(`Connection verification failed for ${operation}:`, error);
    throw error;
  }
};

// Helper for SSL error handling (needed for some other functions)
const handleSSLError = (error) => {
  if (error.message && (
    error.message.includes('SSL') || 
    error.message.includes('certificate') || 
    error.message.includes('TLS')
  )) {
    console.error('SSL/TLS Connection Error: This may be due to misconfigured SSL settings.');
    console.error('For Aiven MySQL databases, ensure you have:');
    console.error('1. Set DB_SSL=true in your .env file');
    console.error('2. Configured the proper SSL mode in your Aiven console');
    console.error('3. Place your CA certificate in the "certs" directory as ca.pem or similar');
    console.error('   (or set DB_CA_CERT environment variable to your certificate file path/content)');
    return true;
  }
  return false;
};

// Helper function to verify SSL/TLS connection security
const verifyConnectionSecurity = async (connection) => {
  try {
    // Check SSL status with proper SQL syntax (using single quotes for SQL)
    const [sslStatus] = await connection.query("SHOW STATUS LIKE 'Ssl%'");
    
    // Create SSL info object with proper Promise handling
    const sslInfo = await Promise.resolve().then(() => {
      const info = {};
      if (sslStatus && Array.isArray(sslStatus)) {
        sslStatus.forEach(row => {
          if (row && row.Variable_name) {
            info[row.Variable_name] = row.Value;
          }
        });
      }
      return info;
    });

    // Enhanced cipher strength verification
    const isStrongCipher = (() => {
      if (!sslInfo.Ssl_cipher) return false;
      
      // Check for strong encryption algorithms
      const hasStrongEncryption = 
        sslInfo.Ssl_cipher.includes('AES-256') ||
        sslInfo.Ssl_cipher.includes('CHACHA20');
      
      // Check for strong hash algorithms
      const hasStrongHash =
        sslInfo.Ssl_cipher.includes('SHA384') ||
        sslInfo.Ssl_cipher.includes('SHA256');
      
      // Check for modern cipher modes
      const hasStrongMode =
        sslInfo.Ssl_cipher.includes('GCM') ||
        sslInfo.Ssl_cipher.includes('CCM') ||
        sslInfo.Ssl_cipher.includes('POLY1305');
      
      return hasStrongEncryption && hasStrongHash && hasStrongMode;
    })();
    
    // Log SSL connection details for monitoring
    console.log('SSL Connection Details:', {
      version: sslInfo.Ssl_version || 'Not set',
      cipher: sslInfo.Ssl_cipher || 'Not set',
      isEncrypted: !!sslInfo.Ssl_cipher,
      isStrongCipher: isStrongCipher,
      cipherStrength: isStrongCipher ? 'Strong' : (sslInfo.Ssl_cipher ? 'Moderate/Weak' : 'None')
    });
    
    // Return true if using SSL/TLS with a cipher, false otherwise
    return !!sslInfo.Ssl_cipher;
  } catch (error) {
    console.error('Error verifying connection security:', error);
    return false;
  }
};

// Factory for creating database method wrappers

// Test function for pool connection
const testPoolConnection = async (pool) => {
  let connection;
  try {
    console.log('⏳ Testing initial database connection...');
    connection = await pool.getConnection();
    
    // Basic connection test with ping
    await connection.ping();
    console.log('✅ Database ping successful');
    
    // Verify SSL connection (critical for Aiven)
    const [sslResults] = await connection.query("SHOW STATUS LIKE 'Ssl_cipher'");
    const sslCipher = sslResults[0]?.Value;
    
    if (!sslCipher) {
      console.error('❌ SSL CONNECTION FAILED: No SSL cipher reported by database');
      console.error('This indicates the SSL connection was not established');
      console.error('Please verify your CA certificate and SSL configuration');
      throw new Error('SSL connection verification failed - insecure connection');
    }
    
    console.log('✅ SSL connection verified with cipher:', sslCipher);
    
    // Test a simple query
    const [testResults] = await connection.query('SELECT 1 AS connection_test');
    if (testResults[0].connection_test === 1) {
      console.log('✅ Test query executed successfully');
    }
    
    console.log('✅ Initial pool connection test successful');
    return true;
  } catch (error) {
    console.error('❌ Initial pool connection test failed:', error.message);
    console.error('Error code:', error.code);
    console.error('Error stack:', error.stack);
    
    // More detailed error information
    if (error.code === 'CERT_HAS_EXPIRED') {
      console.error('CA Certificate has expired - please update it');
    } else if (error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
      console.error('Unable to verify certificate - check your CA certificate');
    } else if (error.code === 'ECONNREFUSED') {
      console.error('Connection refused - check your database host and port');
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.error('Access denied - check your database username and password');
    }
    
    throw error;
  } finally {
    if (connection) {
      try {
        connection.release();
        console.log('Connection released after initial test');
      } catch (releaseError) {
        console.error('Error releasing connection during initial test:', releaseError);
      }
    }
  }
};

// Other helper functions for database operations

// Factory to create database methods with proper connection handling
const createPoolMethods = (pool) => {
  if (!pool || typeof pool.getConnection !== 'function') {
    throw new Error('Invalid pool passed to createPoolMethods - missing getConnection function');
  }

  // Define the query method with direct connection acquisition
  const query = async (sql, params) => {
    let connection;
    try {
      connection = await pool.getConnection().catch(connError => {
        console.error('Failed to acquire connection:', connError);
        throw new Error(`Database connection error: ${connError.message}`);
      });
      
      console.log('Pool connection acquired for query');
      const [results] = await connection.query(sql, params);
      console.log('Query executed successfully, result count:', 
        Array.isArray(results) ? results.length : 'non-array result');
      return results;
    } catch (error) {
      console.error('Query Error:', {
        message: error.message,
        code: error.code,
        sql: sql,
        params: JSON.stringify(params)
      });
      throw error;
    } finally {
      if (connection) {
        try {
          connection.release();
          console.log('Connection released after query');
        } catch (releaseError) {
          console.error('Error releasing connection:', releaseError);
        }
      }
    }
  };

  // Define the execute method with direct connection acquisition
  const execute = async (sql, params) => {
    let connection;
    try {
      connection = await pool.getConnection().catch(connError => {
        console.error('Failed to acquire connection for execute:', connError);
        throw new Error(`Database connection error in execute: ${connError.message}`);
      });
      
      console.log('Using execute method with dedicated connection');
      const [results] = await connection.execute(sql, params);
      return results;
    } catch (error) {
      console.error('Execute Error:', {
        message: error.message,
        code: error.code,
        sql: sql,
        params: JSON.stringify(params)
      });
      throw error;
    } finally {
      if (connection) {
        try {
          connection.release();
          console.log('Connection released after execute');
        } catch (releaseError) {
          console.error('Error releasing connection after execute:', releaseError);
        }
      }
    }
  };

  return { query, execute };
};

// Add enhanced connection error handler with Aiven-specific diagnostics
// Only add the event handler if pool is initialized
if (pool) {
  pool.on('error', (err) => {
  console.error('==========================================');
  console.error('POOL CONNECTION ERROR');
  console.error('==========================================');
  console.error('Database Pool Error:', {
    message: err.message,
    code: err.code,
    errno: err.errno,
    sqlState: err.sqlState,
    sqlMessage: err.sqlMessage,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    ssl: process.env.DB_SSL,
    environment: process.env.NODE_ENV,
    timestamp: new Date().toISOString()
  });
  
// Add special handling for Aiven SSL errors
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    console.error('Aiven connection was lost - this could be due to network issues or server timeout');
    console.error('Recommend: Check your network connection and Aiven service status');
  } 

  // Specific error type handling
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    console.error('Error: Database connection was closed unexpectedly');
  }
  if (err.code === 'ER_CON_COUNT_ERROR') {
    console.error('Error: Database has too many connections');
  }
  else if (err.code === 'ECONNREFUSED') {
    console.error('Error: Database connection was refused');
  } else {
    console.error('Stack Trace:', err.stack);
  }

  // Enhanced error handling with categorization
  if (handleSSLError(err)) {
    // SSL errors already handled by handleSSLError
  } else if (err.code === 'ER_ACCESS_DENIED_ERROR') {
    console.error('Error: Access denied. Check your database credentials.');
  } else if (err.code === 'ER_BAD_DB_ERROR') {
    console.error('Error: Database does not exist.');
  } else if (err.code === 'PROTOCOL_SEQUENCE_ERROR') {
    console.error('Error: Bad protocol sequence. Possible connection state issue.');
  } else if (err.code === 'ETIMEDOUT') {
    console.error('Error: Connection timed out. Check network connectivity.');
  } else {
    console.error('Unhandled database error. Please check:', {
      errorCode: err.code,
      errorType: err.constructor.name
    });
  }

  console.error('==========================================');
  });
}

// Connection management functions

// Note: Connection handler is now defined only once in the pool initialization section

// Test the connection using pool
const testConnection = async () => {
  // Check if we're in development mode and should use a mock connection
  if (process.env.NODE_ENV === 'development' && process.env.MOCK_DB === 'true') {
    console.warn('=================================================================');
    console.warn('WARNING: Using mock database connection for development purposes.');
    console.warn('This is intended for testing the server only, not for data operations.');
    console.warn('Set MOCK_DB=false in .env to use a real database connection.');
    console.warn('=================================================================');
    return true;
  }
  
  // Real database connection
  let connection;
  try {
    console.log('Testing database connection...');
    
    // Initialize pool if it doesn't exist yet
    if (!pool) {
      try {
        console.log('Pool not initialized yet, initializing...');
        await initializePool();
        if (!pool) {
          throw new Error('Pool initialization failed');
        }
      } catch (initError) {
        console.error('Failed to initialize database pool:', initError);
        return false;
      }
    }
    
    // Get a connection from the pool
    connection = await pool.getConnection();
    console.log('Test connection acquired from pool');
    
    // Skip SSL verification in development
    if (process.env.NODE_ENV !== 'production') {
      console.log('Skipping detailed SSL verification in development mode');
    } else {
      // Only verify SSL in production
      try {
        await verifyConnectionSecurity(connection);
      } catch (sslError) {
        console.warn('SSL verification error, but continuing:', sslError.message);
      }
    }
    
    // Simple query test - just use query instead of execute for consistency
    try {
      const [result] = await connection.query('SELECT 1 as test');
      console.log('Test query successful', result);
    } catch (queryError) {
      console.error('Test query failed:', queryError);
      if (connection) connection.release();
      return false;
    }
    
    connection.release();
    console.log('Database connected successfully via pool');
    return true;
  } catch (error) {
    console.error('Database Connection Error:', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      ssl: process.env.DB_SSL,
      environment: process.env.NODE_ENV
    });
    
    // Special handling for connection errors
    if (error.code === 'PROTOCOL_CONNECTION_LOST') {
      console.error('Database connection was closed unexpectedly');
    } else if (error.code === 'ER_CON_COUNT_ERROR') {
      console.error('Database has too many connections');
    } else if (error.code === 'ECONNREFUSED') {
      console.error('Database connection was refused - check host and port');
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.error('Access denied - check username and password');
    } else if (error.code === 'HANDSHAKE_SSL_ERROR') {
      console.error('SSL handshake error - check SSL configuration');
    }
    
    // Suggest using mock database if in development
    if (process.env.NODE_ENV === 'development') {
      console.warn('');
      console.warn('To bypass database connection for testing, add MOCK_DB=true to your .env file');
    }
    
    return false;
  } finally {
    // Always release connection in the finally block
    if (connection) {
      try {
        connection.release();
      } catch (releaseError) {
        console.error('Error releasing connection:', releaseError);
      }
    }
  }
};

// Test with direct connection (not using pool)
const testDirectConnection = async () => {
  console.log('Testing direct connection to database...');
  console.log('Connection params:', {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
  });
  
  try {
    // Create a direct connection
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      port: process.env.DB_PORT || 3306,
      connectTimeout: 10000,
      // Add SSL configuration for direct connections using same settings as pool
      ssl: process.env.DB_SSL === 'true' ? {
        rejectUnauthorized: process.env.NODE_ENV === 'production',
        minVersion: 'TLSv1.2',
        // Only add CA cert if available, otherwise use default trusted certificates
        ...(caCert ? { ca: caCert } : {})
      } : undefined
    });

    // Verify SSL/TLS security for direct connection
    const isSecure = await verifyConnectionSecurity(connection);
    if (!isSecure && process.env.DB_SSL === 'true') {
      console.warn('Warning: Direct connection may not be properly encrypted despite SSL being enabled');
    }
    
    console.log('Direct connection established successfully');
    
    // Test a simple query
    try {
      const [result] = await connection.execute('SELECT 1 as test');
      console.log('Direct connection test query succeeded:', result);
    } catch (queryError) {
      console.error('Direct connection test query failed:', queryError);
      await connection.end();
      return false;
    }
    
    // Test actual user table
    try {
      const [users] = await connection.execute('SELECT COUNT(*) as count FROM users');
      console.log('Users table test query succeeded:', users);
    } catch (tableError) {
      console.error('Users table test query failed:', tableError);
      await connection.end();
      return false;
    }
    
    await connection.end();
    console.log('Direct connection closed');
    return true;
  } catch (error) {
    console.error('Direct Connection Error:', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      ssl: process.env.DB_SSL,
      environment: process.env.NODE_ENV
    });
    console.error('Stack trace:', error.stack);
    
    // Provide specific guidance for SSL-related errors
    handleSSLError(error);
    
    return false;
  }
};

// Begin transaction
const beginTransaction = async () => {
  // Check if we're using mock database
  if (process.env.NODE_ENV === 'development' && process.env.MOCK_DB === 'true') {
    console.warn('MOCK DB: Transaction started');
    return Promise.resolve({ mockTransaction: true }); // Return promise for consistency
  }
  
  try {
    const connection = await pool.getConnection();
    console.log('Pool connection acquired for transaction');
    
    // Verify SSL/TLS security for transaction connection
    const isSecure = await verifyConnectionSecurity(connection);
    if (!isSecure && process.env.DB_SSL === 'true') {
      console.warn('Warning: Transaction connection may not be properly encrypted despite SSL being enabled');
      // Continue with transaction but log the warning
    }
    
    // Begin transaction with proper promise handling
    await connection.beginTransaction();
    console.log('Transaction started successfully');
    return connection;
  } catch (error) {
    console.error('Failed to begin transaction:', error);
    throw error; // Re-throw to allow handling by caller
  }
};

// Commit transaction
const commitTransaction = async (connection) => {
  // Check if we're using mock database
  if (process.env.NODE_ENV === 'development' && process.env.MOCK_DB === 'true' && connection.mockTransaction) {
    console.warn('MOCK DB: Transaction committed');
    return;
  }
  
  let isSecure = false;
  try {
    // Verify connection is still valid
    try {
      await verifyConnection(connection, 'commit');
    } catch (verifyError) {
      console.error('Connection verification failed before commit:', verifyError);
      throw verifyError;
    }

    // Verify SSL security before commit
    isSecure = await verifyConnectionSecurity(connection);
    if (!isSecure && process.env.DB_SSL === 'true') {
      console.warn('Warning: Commit operation connection may not be properly encrypted despite SSL being enabled');
    }

    await connection.commit();
    console.log('Transaction committed successfully');
  } catch (error) {
    console.error('Transaction Commit Error:', {
      message: error.message,
      code: error.code,
      stack: error.stack
    });
    throw error;
  } finally {
    if (connection) connection.release();
    console.log('Transaction connection released');
  }
};

// Rollback transaction
const rollbackTransaction = async (connection) => {
  // Check if we're using mock database
  if (process.env.NODE_ENV === 'development' && process.env.MOCK_DB === 'true' && connection.mockTransaction) {
    console.warn('MOCK DB: Transaction rolled back');
    return;
  }
  
  let isSecure = false;
  try {
    // Verify connection is still valid
    try {
      await verifyConnection(connection, 'rollback');
    } catch (verifyError) {
      console.error('Connection verification failed before rollback:', verifyError);
      throw verifyError;
    }

    // Verify SSL security before rollback
    isSecure = await verifyConnectionSecurity(connection);
    if (!isSecure && process.env.DB_SSL === 'true') {
      console.warn('Warning: Rollback operation connection may not be properly encrypted despite SSL being enabled');
    }

    await connection.rollback();
    console.log('Transaction rolled back successfully');
  } catch (error) {
    console.error('Transaction Rollback Error:', {
      message: error.message,
      code: error.code,
      stack: error.stack
    });
    throw error;
  } finally {
    if (connection) connection.release();
    console.log('Transaction connection released');
  }
};

// Direct query function (uses a new connection each time instead of pool)
const directQuery = async (sql, params) => {
  console.log('==========================================');
  console.log('DIRECT QUERY EXECUTION START');
  console.log('==========================================');
  console.log('Executing direct query (no pool)');
  console.log('SQL:', sql);
  console.log('Params:', JSON.stringify(params, null, 2));
  
  let connection = null;
  
  try {
    // Create a direct connection
    console.log('Creating direct MySQL connection...');
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      port: process.env.DB_PORT || 3306,
      connectTimeout: 10000,
      supportBigNumbers: true,
      bigNumberStrings: true,
      // Use consistent SSL configuration across all connection types
      ssl: process.env.DB_SSL === 'true' ? {
        rejectUnauthorized: process.env.NODE_ENV === 'production',
        minVersion: 'TLSv1.2',
        // Only add CA cert if available, otherwise use default trusted certificates
        ...(caCert ? { ca: caCert } : {})
      } : undefined
    });
    
    console.log('Direct query connection established');
    console.log('Connection ID:', connection.threadId);

    // Verify SSL/TLS security for direct query connection
    const isSecure = await verifyConnectionSecurity(connection);
    if (!isSecure && process.env.DB_SSL === 'true') {
      console.warn('Warning: Direct query connection may not be properly encrypted despite SSL being enabled');
    }
    
    // Test connection with ping
    console.log('Testing connection with ping...');
    await connection.ping();
    console.log('Ping successful, connection is good');
    
    // Execute the query
    console.log('Executing query...');
    const [results] = await connection.execute(sql, params);
    
    console.log('Query executed successfully');
    console.log('Result type:', typeof results);
    console.log('Is array:', Array.isArray(results));
    console.log('Result count:', Array.isArray(results) ? results.length : 'non-array');
    
    if (Array.isArray(results) && results.length > 0) {
      console.log('First result keys:', Object.keys(results[0]).join(', '));
    }
    
    // Close connection
    console.log('Closing connection...');
    await connection.end();
    console.log('Connection closed successfully');
    
    console.log('==========================================');
    console.log('DIRECT QUERY EXECUTION COMPLETED');
    console.log('==========================================');
    
    return results;
  } catch (error) {
    console.error('==========================================');
    console.error('DIRECT QUERY EXECUTION FAILED');
    console.error('==========================================');
    console.error('Direct Query Error:', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
      sql: sql,
      params: JSON.stringify(params)
    });
    console.error('Connection Details:', {
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      ssl: process.env.DB_SSL,
      environment: process.env.NODE_ENV
    });
    console.error('Stack Trace:', error.stack);
    
    // Handle SSL-related errors
    handleSSLError(error);
    
    // Ensure connection is closed even on error
    if (connection) {
      try {
        console.log('Attempting to close connection after error...');
        await connection.end();
        console.log('Connection closed after error');
      } catch (closeError) {
        console.error('Failed to close connection after error:', closeError.message);
      }
    }
    
    // Re-throw the error
    throw error;
  }
};

// Additional utility functions for database operations

// The initializePool function handles all pool configuration and monitoring

// Add helpful utility function for checking database connectivity
const checkDatabaseConnectivity = async () => {
  try {
    // Initialize pool if it doesn't exist yet
    if (!pool) {
      try {
        console.log('Pool not initialized yet, initializing for connectivity check...');
        await initializePool();
        if (!pool) {
          throw new Error('Pool initialization failed during connectivity check');
        }
      } catch (initError) {
        console.error('Failed to initialize database pool during connectivity check:', initError);
        return false;
      }
    }
    
    const connection = await pool.getConnection();
    try {
      await connection.ping();
      console.log('Database connectivity check: Success');
      return true;
    } finally {
      if (connection) {
        connection.release();
      }
    }
  } catch (error) {
    console.error('Database connectivity check: Failed', error);
    return false;
  }
};

// -----------------------------------------------
// Module Exports
// -----------------------------------------------
module.exports = {
  initializePool,
  query,
  execute,
  getConnection,
  pool: () => pool,
  
  // Utility functions for database operations
  checkHealth: checkConnectionHealth,
  directQuery,
  testConnection,
  testDirectConnection,
  beginTransaction,
  commitTransaction,
  rollbackTransaction,
  checkDatabaseConnectivity,
  verifyConnection
};
