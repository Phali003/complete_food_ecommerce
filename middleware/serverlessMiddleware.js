const { verifyAuth, verifyAdmin, handleAuthError } = require('../utils/serverless-auth');
const BlacklistedTokenModel = require('../models/BlacklistedTokenModel');

/**
 * Higher-order function that wraps a handler with authentication
 * For use with Next.js API routes or Vercel serverless functions
 * 
 * @param {Function} handler - API route handler function
 * @returns {Function} - Protected handler function
 */
const withAuth = (handler) => async (req, res) => {
  try {
    // Authenticate user and add to request
    req.user = await verifyAuth(req);
    
    // Call the original handler
    return handler(req, res);
  } catch (error) {
    return handleAuthError(error, res);
  }
};

/**
 * Higher-order function that wraps a handler with admin-only authentication
 * For use with Next.js API routes or Vercel serverless functions
 * 
 * @param {Function} handler - API route handler function
 * @returns {Function} - Protected handler function with admin check
 */
const withAdmin = (handler) => async (req, res) => {
  try {
    // Authenticate user and add to request
    const user = await verifyAuth(req);
    
    // Verify admin status
    verifyAdmin(user);
    
    // Add user to request
    req.user = user;
    
    // Call the original handler
    return handler(req, res);
  } catch (error) {
    return handleAuthError(error, res);
  }
};

/**
 * Higher-order function that wraps a handler with super admin-only authentication
 * For use with Next.js API routes or Vercel serverless functions
 * 
 * @param {Function} handler - API route handler function
 * @returns {Function} - Protected handler function with super admin check
 */
const withSuperAdmin = (handler) => async (req, res) => {
  try {
    // Authenticate user and add to request
    const user = await verifyAuth(req);
    
    // Verify admin status first
    verifyAdmin(user);
    
    // Then verify super admin status
    if (!user.is_super_admin) {
      const error = new Error('Super admin privileges required');
      error.statusCode = 403;
      throw error;
    }
    
    // Add user to request
    req.user = user;
    
    // Call the original handler
    return handler(req, res);
  } catch (error) {
    return handleAuthError(error, res);
  }
};

/**
 * Higher-order function that creates a resource owner check middleware
 * Only allows the user to access their own resources or if they're an admin
 * 
 * @param {Function} getUserIdFromRequest - Function to extract the resource owner ID from the request
 * @returns {Function} - Higher-order function that wraps a handler with resource owner check
 */
const withResourceOwner = (getUserIdFromRequest) => (handler) => async (req, res) => {
  try {
    // Authenticate user and add to request
    const user = await verifyAuth(req);
    
    // Get the resource owner ID from the request
    const resourceOwnerId = getUserIdFromRequest(req);
    
    // Check if the user is accessing their own resource or is an admin
    if (user.role !== 'admin' && user.id.toString() !== resourceOwnerId.toString()) {
      const error = new Error('Not authorized to access this resource');
      error.statusCode = 403;
      throw error;
    }
    
    // Add user to request
    req.user = user;
    
    // Call the original handler
    return handler(req, res);
  } catch (error) {
    return handleAuthError(error, res);
  }
};

module.exports = {
  withAuth,
  withAdmin,
  withSuperAdmin,
  withResourceOwner
};

