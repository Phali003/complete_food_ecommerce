const jwt = require('jsonwebtoken');
require('dotenv').config();

// JWT secret from environment variables
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

/**
 * Generate a JWT token for a user
 * @param {Object} user - User data to include in the token
 * @returns {String} JWT token
 */
const generateToken = (user) => {
  // Do not include sensitive information like password in the token
  const payload = {
    id: user.id,
    email: user.email,
    username: user.username,
    role: user.role
  };

  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

/**
 * Verify a JWT token
 * @param {String} token - JWT token to verify
 * @returns {Object|null} Decoded token data or null if invalid
 */
const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    console.error('JWT verification error:', error.message);
    return null;
  }
};

/**
 * Get token from request headers
 * @param {Object} req - Express request object
 * @returns {String|null} Token or null if not found
 */
const getTokenFromRequest = (req) => {
  // Check for token in authorization header
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.split(' ')[1];
  }
  
  // Check for token in cookies
  if (req.cookies && req.cookies.token) {
    return req.cookies.token;
  }
  
  return null;
};

module.exports = {
  generateToken,
  verifyToken,
  getTokenFromRequest
};

