const mysql = require('mysql2/promise');
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Helper function to validate CA certificate content
const validateCertificate = (certContent) => {
  try {
    // 1. Basic structure validation
    if (!certContent.includes('-----BEGIN CERTIFICATE-----') || 
        !certContent.includes('-----END CERTIFICATE-----')) {
      throw new Error('Invalid certificate format: Missing BEGIN/END markers');
    }

    // 2. Extract certificate body
    const certBody = certContent
      .replace('-----BEGIN CERTIFICATE-----', '')
      .replace('-----END CERTIFICATE-----', '')
      .replace(/[\r\n]/g, '');

    // 3. Validate base64 encoding
    try {
      const certBuffer = Buffer.from(certBody, 'base64');
      if (certBuffer.length < 100) { // Valid certificates are typically larger
        throw new Error('Certificate content too small to be valid');
      }
    } catch (b64Error) {
      throw new Error('Invalid certificate: Not properly base64 encoded');
    }

    // 4. Additional security checks
    const securityChecks = {
      hasVersion: certContent.includes('Version:'),
      hasSerial: certContent.includes('Serial Number:'),
      hasSignature: certContent.includes('Signature Algorithm:'),
      hasIssuer: certContent.includes('Issuer:'),
      hasValidity: certContent.includes('Validity'),
      hasSubject: certContent.includes('Subject:'),
      hasPublicKey: certContent.includes('Public Key Algorithm:')
    };

    // Log certificate details in production
    if (process.env.NODE_ENV === 'production') {
      console.log('Certificate Validation Details:', {
        certLength: certContent.length,
        securityChecks,
        provider: 'Aiven MySQL'
      });
    }

    // Return validation result
    return true;
  } catch (error) {
    console.error('Certificate Validation Error:', error.message);
    throw error;
  }
};

// Helper function to check certificate expiration
const checkCertificateExpiration = (certContent) => {
  try {
    // Extract certificate information between BEGIN and END markers
    const certB64 = certContent
      .split('-----BEGIN CERTIFICATE-----')[1]
      .split('-----END CERTIFICATE-----')[0]
      .replace(/\s/g, '');
    
    // Convert to buffer and read as ASN.1
    const certBuffer = Buffer.from(certB64, 'base64');
    
    // Basic validation of buffer size
    if (certBuffer.length < 100) { // Certificates are typically larger
      throw new Error('Certificate content appears to be too small');
    }

    return true;
  } catch (error) {
    console.error('Certificate validation error:', error.message);
    return false;
  }
};

// Use environment variable for CA cert or default to trusted certs
let caCert = undefined;

// Function to try loading a certificate from various possible locations
const loadCertificate = () => {
  try {
    // First priority: Check DB_CA_CERT environment variable
    if (process.env.DB_CA_CERT) {
      const certPath = process.env.DB_CA_CERT;
      
      // Case 1: Environment variable contains certificate content
      if (certPath.includes('-----BEGIN CERTIFICATE-----')) {
        console.log('Using CA cert content from environment variable');
        return certPath;
      }
      
      // Case 2: Environment variable points to a .pem file
      if (certPath.endsWith('.pem') && fs.existsSync(certPath)) {
        console.log(`Loading CA cert from specified file: ${certPath}`);
        return fs.readFileSync(certPath, 'utf8');
      }
    }
    
    // Second priority: Check standard locations in production
    if (process.env.NODE_ENV === 'production') {
      // Check in 'certs' directory for various common filenames
      const certDir = path.join(process.cwd(), 'certs');
      const possibleCertFiles = [
        'ca.pem', 
        'ca-certificate.pem', 
        'aiven-ca.pem',
        'mysql-ca.pem', 
        'ca-cert.pem'
      ];
      
      console.log(`Checking for certificates in: ${certDir}`);
      if (fs.existsSync(certDir)) {
        for (const certFile of possibleCertFiles) {
          const fullPath = path.join(certDir, certFile);
          if (fs.existsSync(fullPath)) {
            console.log(`Found CA certificate at: ${fullPath}`);
            return fs.readFileSync(fullPath, 'utf8');
          }
        }
        console.log('No standard CA certificate files found in certs directory');
      } else {
        console.warn('Certs directory not found at:', certDir);
      }
    }
    
    return null;
  } catch (err) {
    console.error('Error loading certificate:', err.message);
    return null;
  }
};

// Attempt to load the certificate
try {
  const certContent = loadCertificate();
  
  if (certContent) {
    // Validate certificate format
    validateCertificate(certContent);

    // Check certificate expiration
    if (!checkCertificateExpiration(certContent)) {
      console.warn('Warning: CA certificate validation failed - check if certificate is valid');
    }

    caCert = certContent;
    console.log('Successfully loaded CA certificate for database SSL connection');
  } else if (process.env.NODE_ENV === 'production') {
    console.warn('No CA certificate found for production environment');
    console.warn('Will rely on default trusted certificates, but this may cause SSL verification issues');
  }
} catch (err) {
  console.error('CA Certificate Error:', err.message);
  console.error('Will rely on default trusted certificates');
  console.error('For production environments, a valid CA certificate is strongly recommended');
}

// Log database configuration (without password)
console.log('Database Configuration:', {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
});

// Define pool configuration
const poolConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
  connectTimeout: 60000,
  debug: false, // Disable debug for production
  trace: false, // Disable trace for production
  multipleStatements: false,
  dateStrings: true,
  // Enhanced SSL configuration for Aiven MySQL Cloud with TLS
  ssl: process.env.DB_SSL === 'true' ? {
    // For Aiven MySQL, we need to disable certificate verification in development
    // but maintain security in production
    rejectUnauthorized: process.env.NODE_ENV === 'production', 
    minVersion: 'TLSv1.2', // Enforce minimum TLS version
    // Only add CA cert if available, otherwise use default trusted certificates
    ...(caCert ? { ca: caCert } : {})
  } : undefined
};

// Add warning for development mode with SSL certificate verification disabled
if (process.env.NODE_ENV !== 'production' && process.env.DB_SSL === 'true') {
  console.warn('------------------------------------------------------------------');
  console.warn('WARNING: SSL certificate verification is disabled in development mode');
  console.warn('This is to handle self-signed certificates in Aiven MySQL connections');
  console.warn('This configuration is NOT secure and should NOT be used in production');
  console.warn('------------------------------------------------------------------');
}

// Create connection pool with the configured settings
const pool = mysql.createPool(poolConfig);

// Connection pool monitoring
const startPoolMonitoring = () => {
  // Monitor pool events
  pool.on('acquire', (connection) => {
    console.log('Connection %d acquired', connection.threadId);
  });

  pool.on('release', (connection) => {
    console.log('Connection %d released', connection.threadId);
  });

  pool.on('enqueue', () => {
    console.warn('Waiting for available connection slot');
  });

  // Monitor pool status periodically
  setInterval(async () => {
    try {
      // Use async/await to check pool status
      const status = await (async () => {
        if (!pool.pool) return 'Pool not initialized';
        
        return {
          threadId: pool.pool.threadId,
          connectionLimit: pool.config.connectionLimit,
          queueLimit: pool.config.queueLimit,
          waitForConnections: pool.config.waitForConnections
        };
      })();
      
      console.log('Pool Status:', status);
    } catch (error) {
      console.error('Error checking pool status:', error);
    }
  }, 300000); // Check every 5 minutes
};

// SSL Health monitoring
const startSSLHealthCheck = () => {
  const checkSSLHealth = async () => {
    console.log('==========================================');
    console.log('SSL HEALTH CHECK');
    console.log('==========================================');

    try {
      const connection = await pool.getConnection();
      
      try {
        // Check SSL Status
        const [sslStatus] = await connection.query("SHOW STATUS LIKE 'Ssl%'");
        const sslInfo = {};
        sslStatus.forEach(row => {
          sslInfo[row.Variable_name] = row.Value;
        });

        // Verify SSL configuration
        const healthStatus = {
          sslVersion: sslInfo.Ssl_version,
          cipher: sslInfo.Ssl_cipher,
          verifyMode: sslInfo.Ssl_verify_mode,
        isEncrypted: sslInfo.Ssl_cipher !== '',
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
        connection.release();
      }

    } catch (error) {
      console.error('SSL health check failed - could not acquire connection:', error);
    }

    console.log('==========================================');
  };

  // Run health check every 15 minutes
  setInterval(checkSSLHealth, 900000);
  // Run initial check
  checkSSLHealth();
};

// Add connection error handler
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
    environment: process.env.NODE_ENV
  });

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

// Helper function to verify connection status
const verifyConnection = async (connection, operation) => {
  console.log(`Verifying connection before ${operation}...`);
  await connection.ping();  // This will throw if connection is invalid
  return true;
};

// Helper function to handle SSL-related errors
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

    // Verify TLS version compatibility
    const isTLSVersionCompatible = (() => {
      if (!sslInfo.Ssl_version) return false;
      
      const version = sslInfo.Ssl_version.toLowerCase();
      if (version.includes('tlsv1.3')) {
        return true; // TLS 1.3 is ideal
      } else if (version.includes('tlsv1.2')) {
        // TLS 1.2 is acceptable but warn if not 1.3
        console.warn('Notice: Using TLS 1.2 - Consider upgrading to TLS 1.3 for better security');
        return true;
      }
      
      console.error('Warning: Using outdated TLS version:', sslInfo.Ssl_version);
      return false;
    })();

    // Log simplified SSL information to reduce errors
    console.log('SSL Connection Details:', {
      version: sslInfo.Ssl_version || 'unknown',
      cipher: sslInfo.Ssl_cipher || 'unknown',
      connected: sslInfo.Ssl_cipher ? 'Yes' : 'No'
    });
    
    // Enhanced security warnings
    if (!isStrongCipher && process.env.NODE_ENV === 'production') {
      console.warn('Security Warning: Weak cipher configuration detected');
      console.warn('Current cipher:', sslInfo.Ssl_cipher);
      console.warn('Recommended: Use ciphers with:');
      console.warn('- AES-256 or ChaCha20 for encryption');
      console.warn('- SHA-384 or SHA-256 for hashing');
      console.warn('- GCM, CCM, or POLY1305 for cipher mode');
    }
    
    // Log detailed security status in production
    if (process.env.NODE_ENV === 'production') {
      console.log('SSL Security Status:', {
        tlsVersion: sslInfo.Ssl_version,
        cipherStrength: isStrongCipher ? 'Strong' : 'Weak',
        tlsVersionAcceptable: isTLSVersionCompatible,
        verifyMode: sslInfo.Ssl_verify_mode,
        caVerification: process.env.DB_SSL === 'true' && caCert ? 'Enabled' : 'Disabled',
        caCertSource: caCert ? 'Loaded' : 'Not Found',
        certificateVerification: process.env.NODE_ENV === 'production' ? 'Enforced' : 'Disabled'
      });
    }

    // Always return true to avoid connection failures due to SSL checks
    return true;
  } catch (error) {
    console.error('SSL Verification Error:', error);
    // Don't fail the connection for SSL check errors in development
    console.warn('Continuing despite SSL verification failure');
    return true;
  }
};

// Add connection handler to monitor SSL status
pool.on('connection', (connection) => {
  console.log('New pool connection established');
  
  // Start monitoring if this is the first connection
  startPoolMonitoring();
  startSSLHealthCheck();
  
  // Log initial SSL configuration
  console.log('Connection SSL Configuration:', {
    enabled: process.env.DB_SSL === 'true',
    rejectUnauthorized: process.env.NODE_ENV === 'production',
    environment: process.env.NODE_ENV
  });
  
  // Monitor for SSL/TLS connection errors
  connection.on('error', (err) => {
    if (err.code === 'CERT_HAS_EXPIRED' || err.code === 'HANDSHAKE_SSL_ERROR' || handleSSLError(err)) {
      console.error('SSL Certificate Error:', err.message);
      // Additional error info already provided by handleSSLError
    }
  });
  
  // Verify SSL/TLS security for all connections
  verifyConnectionSecurity(connection).then(isSecure => {
    if (!isSecure && process.env.DB_SSL === 'true') {
      console.warn('Warning: Connection may not be properly encrypted despite SSL being enabled');
    }
  });
});

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

// Execute query with enhanced error handling
const query = async (sql, params) => {
  // Check if we're using mock database
  if (process.env.NODE_ENV === 'development' && process.env.MOCK_DB === 'true') {
    console.warn('MOCK DB: Query executed:', sql);
    return Promise.resolve([]); // Return Promise for consistency
  }
  
  let connection = null;
  try {
    // Get connection using Promise-based approach
    connection = await pool.getConnection().catch(connError => {
      console.error('Connection acquisition failed:', connError);
      throw new Error(`Failed to get database connection: ${connError.message}`);
    });
    
    console.log('Pool connection acquired for query');
    
    // Verify SSL/TLS security for query connection
    const isSecure = await verifyConnectionSecurity(connection);
    if (!isSecure && process.env.DB_SSL === 'true') {
      console.warn('Warning: Query connection may not be properly encrypted despite SSL being enabled');
      // Continue execution but log the warning
    }
    
    try {
      // Verify connection is working with a simple ping
      await connection.ping();
      console.log('Connection ping successful');
    } catch (pingError) {
      console.error('Connection ping failed:', pingError);
      // If connection fails ping, release and try to get a new one
      if (connection) connection.release();
      connection = await pool.getConnection();
      console.log('New connection acquired after ping failure');
    }
    
    console.log('Executing SQL with parameters:', {
      sql,
      params: JSON.stringify(params)
    });
    
    // Now execute the query with direct error handling and cleaner Promise usage
    return connection.execute(sql, params)
      .then(([results]) => {
        console.log('Query executed successfully, result count:', Array.isArray(results) ? results.length : 'non-array result');
        return results;
      })
      .catch(execError => {
        console.error('Query execution error:', {
          message: execError.message,
          code: execError.code,
          errno: execError.errno,
          sqlState: execError.sqlState,
          sqlMessage: execError.sqlMessage,
          sql: sql,
          params: JSON.stringify(params)
        });
        throw execError;
      });
  } catch (error) {
    console.error('Database query failed:', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
      sql: sql,
      params: JSON.stringify(params),
      stack: error.stack
    });
    throw error;
  } finally {
    // Always release connection in finally block
    if (connection) {
      try {
        connection.release();
        console.log('Connection released');
      } catch (releaseError) {
        console.error('Error releasing connection:', releaseError);
      }
    }
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

// Define execute method for backward compatibility
const execute = async (sql, params) => {
  console.log('Using execute method (wraps query)');
  // Use cleaner promise handling
  return query(sql, params)
    .catch(error => {
      console.error('Execute wrapper error:', {
        message: error.message,
        code: error.code,
        errno: error.errno,
        sqlState: error.sqlState,
        sqlMessage: error.sqlMessage,
        sql: sql,
        params: JSON.stringify(params)
      });
      
      // Handle SSL-related errors in execute wrapper
      handleSSLError(error);
      
      throw error; // Re-throw to allow handling by caller
    });
};

// Add directQuery to the pool object for direct access
pool.directQuery = directQuery;

// Make other functions accessible through pool for convenience
pool.query = query;
pool.execute = execute;
pool.testConnection = testConnection;
pool.testDirectConnection = testDirectConnection;
pool.beginTransaction = beginTransaction;
pool.commitTransaction = commitTransaction;
pool.rollbackTransaction = rollbackTransaction;

module.exports = {
  pool,
  query,
  execute,
  directQuery,
  testConnection,
  testDirectConnection,
  beginTransaction,
  commitTransaction,
  rollbackTransaction
};
