const jwt = require('jsonwebtoken');
const { pool } = require('../config/database');
const BlacklistedTokenModel = require('../models/BlacklistedTokenModel');

/**
 * Get a database connection from the pool
 */
const getConnection = async () => {
  return await pool.getConnection();
};

/**
 * Verifies a user's authentication token in a serverless context
 * @param {Object} req - Next.js/Vercel request object
 * @returns {Promise<Object>} - Returns user object if authenticated or throws error
 */
const verifyAuth = async (req) => {
  let token;
  let connection;

  try {
    // Check for token in Authorization header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } 
    // Check for token in cookies as fallback
    else if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    // If no token found, throw error
    if (!token) {
      const error = new Error('Not authorized, no token provided');
      error.statusCode = 401;
      throw error;
    }
    
    // Check if token is blacklisted
    const isBlacklisted = await BlacklistedTokenModel.isBlacklisted(token);
    if (isBlacklisted) {
      const error = new Error('Token has been invalidated');
      error.statusCode = 401;
      throw error;
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user from database
    connection = await getConnection();
    const [users] = await connection.execute(
      'SELECT id, username, email, role, is_super_admin FROM users WHERE id = ?',
      [decoded.id]
    );

    if (users.length === 0) {
      const error = new Error('User not found');
      error.statusCode = 401;
      throw error;
    }

    // Return the user object
    return users[0];
  } catch (error) {
    // Handle specific JWT errors
    if (error.name === 'JsonWebTokenError') {
      const customError = new Error('Invalid token');
      customError.statusCode = 401;
      throw customError;
    }
    
    if (error.name === 'TokenExpiredError') {
      const customError = new Error('Token expired');
      customError.statusCode = 401;
      throw customError;
    }
    
    // Add statusCode if not already present
    if (!error.statusCode) {
      error.statusCode = 500;
      error.message = 'Authentication failed: ' + error.message;
    }
    
    throw error;
  } finally {
    // Always release the connection if it exists
    if (connection) await connection.release();
  }
};

/**
 * Checks if a user has admin privileges
 * @param {Object} user - User object from verifyAuth
 * @returns {boolean} - True if user is admin, throws error otherwise
 */
const verifyAdmin = (user) => {
  if (!user) {
    const error = new Error('User not authenticated');
    error.statusCode = 401;
    throw error;
  }

  if (user.role !== 'admin') {
    const error = new Error('Not authorized as admin');
    error.statusCode = 403;
    throw error;
  }

  return true;
};

/**
 * Helper function to handle authentication errors in API routes
 * @param {Error} error - Error object
 * @param {Object} res - Response object
 */
const handleAuthError = (error, res) => {
  console.error('Authentication error:', error);
  
  const statusCode = error.statusCode || 500;
  const message = error.message || 'Authentication failed';
  
  return res.status(statusCode).json({
    success: false,
    message
  });
};

module.exports = {
  verifyAuth,
  verifyAdmin,
  handleAuthError
};

