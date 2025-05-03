const mysql = require('mysql2/promise');
require('dotenv').config();

// Log database configuration (without password)
console.log('Database Configuration:', {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
});

// Create connection pool
const pool = mysql.createPool({
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
  acquireTimeout: 60000,
  timeout: 60000,
  debug: false, // Disable debug for production
  trace: false, // Disable trace for production
  multipleStatements: false,
  dateStrings: true
});

// Add connection error handler
pool.on('error', (err) => {
  console.error('Database pool error:', err);
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    console.error('Database connection was closed.');
  }
  if (err.code === 'ER_CON_COUNT_ERROR') {
    console.error('Database has too many connections.');
  }
  if (err.code === 'ECONNREFUSED') {
    console.error('Database connection was refused.');
  }
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
  try {
    const connection = await pool.getConnection();
    console.log('Database connected successfully via pool');
    
    // Test a simple query to verify connection
    try {
      const [result] = await connection.execute('SELECT 1 as test');
      console.log('Test query executed successfully:', result);
    } catch (queryError) {
      console.error('Test query failed:', queryError);
      connection.release();
      return false;
    }
    
    connection.release();
    return true;
  } catch (error) {
    console.error('Database connection failed:', error.message);
    
    // Suggest using mock database if in development
    if (process.env.NODE_ENV === 'development') {
      console.log('');
      console.log('To bypass database connection for testing, add MOCK_DB=true to your .env file');
      console.log('');
    }
    
    return false;
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
      timeout: 60000
    });
    
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
    console.error('Direct connection failed:', error);
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
      stack: error.stack
    });
    return false;
  }
};

// Execute query with enhanced error handling
const query = async (sql, params) => {
  // Check if we're using mock database
  if (process.env.NODE_ENV === 'development' && process.env.MOCK_DB === 'true') {
    console.warn('MOCK DB: Query executed:', sql);
    return []; // Return empty array as mock result
  }
  
  let connection = null;
  try {
    // Test connection before executing the query
    try {
      connection = await pool.getConnection();
      console.log('Connection acquired successfully');
    } catch (connError) {
      console.error('Connection acquisition failed:', connError);
      throw new Error(`Failed to get database connection: ${connError.message}`);
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
    
    // Now execute the query with direct error handling
    try {
      const [results] = await connection.execute(sql, params);
      console.log('Query executed successfully, result count:', Array.isArray(results) ? results.length : 'non-array result');
      return results;
    } catch (execError) {
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
    }
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
    return { mockTransaction: true }; // Return mock connection object
  }
  
  const connection = await pool.getConnection();
  await connection.beginTransaction();
  return connection;
};

// Commit transaction
const commitTransaction = async (connection) => {
  // Check if we're using mock database
  if (process.env.NODE_ENV === 'development' && process.env.MOCK_DB === 'true' && connection.mockTransaction) {
    console.warn('MOCK DB: Transaction committed');
    return;
  }
  
  await connection.commit();
  connection.release();
};

// Rollback transaction
const rollbackTransaction = async (connection) => {
  // Check if we're using mock database
  if (process.env.NODE_ENV === 'development' && process.env.MOCK_DB === 'true' && connection.mockTransaction) {
    console.warn('MOCK DB: Transaction rolled back');
    return;
  }
  
  await connection.rollback();
  connection.release();
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
      timeout: 60000,
      debug: process.env.DB_DEBUG === 'true',
      supportBigNumbers: true,
      bigNumberStrings: true
    });
    
    console.log('Direct connection established for query');
    console.log('Connection ID:', connection.threadId);
    
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
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
      sql: sql,
      params: JSON.stringify(params)
    });
    console.error('Stack trace:', error.stack);
    
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
  return await query(sql, params);
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
