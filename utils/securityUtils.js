/**
 * Security utilities for the Food E-commerce platform
 */
const crypto = require('crypto');

/**
 * Validates a setup code against the stored code in environment variables
 * 
 * @param {string} providedCode - The setup code provided by the user
 * @returns {boolean} Whether the code is valid
 */
function validateSetupCode(providedCode) {
  if (!providedCode) return false;
  
  const storedCode = process.env.INITIAL_ADMIN_SETUP_CODE;
  
  if (!storedCode) {
    console.warn('Warning: INITIAL_ADMIN_SETUP_CODE not set in environment variables');
    return false;
  }
  
  // Use constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(providedCode),
    Buffer.from(storedCode)
  );
}

/**
 * Generates a cryptographically secure random token
 * 
 * @param {number} length - The desired length of the token
 * @returns {string} A secure random token
 */
function generateSecureToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Hashes a password with a random salt using bcrypt algorithm
 * Note: This requires bcrypt to be installed
 * 
 * @param {string} password - The plaintext password to hash
 * @param {number} saltRounds - The number of salt rounds to use (default: 10)
 * @returns {Promise<string>} A promise that resolves to the hashed password
 */
async function hashPassword(password, saltRounds = 10) {
  try {
    const bcrypt = require('bcrypt');
    return await bcrypt.hash(password, saltRounds);
  } catch (error) {
    console.error('Error hashing password:', error);
    throw new Error('Password hashing failed');
  }
}

/**
 * Verifies a password against a hash
 * Note: This requires bcrypt to be installed
 * 
 * @param {string} password - The plaintext password to verify
 * @param {string} hash - The hash to verify against
 * @returns {Promise<boolean>} A promise that resolves to true if the password matches
 */
async function verifyPassword(password, hash) {
  try {
    const bcrypt = require('bcrypt');
    return await bcrypt.compare(password, hash);
  } catch (error) {
    console.error('Error verifying password:', error);
    throw new Error('Password verification failed');
  }
}

module.exports = {
  validateSetupCode,
  generateSecureToken,
  hashPassword,
  verifyPassword
};

