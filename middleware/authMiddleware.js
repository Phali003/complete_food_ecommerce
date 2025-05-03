const { verifyToken, getTokenFromRequest } = require('../utils/jwt');

/**
 * Middleware to protect routes - only authenticated users can access
 */
const protect = async (req, res, next) => {
  try {
    // Get token from request
    const token = getTokenFromRequest(req);
    
    // Check if token exists
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized, no token provided'
      });
    }
    
    // Verify token
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized, token failed'
      });
    }
    
    // Add user info to request
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Authentication error:', error.message);
    return res.status(401).json({
      success: false,
      message: 'Not authorized, authentication failed'
    });
  }
};

/**
 * Middleware to restrict access to specific roles
 * @param {String[]} roles - Array of allowed roles
 */
const restrictTo = (...roles) => {
  return (req, res, next) => {
    // Check if user exists and has a role
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized, insufficient permissions'
      });
    }
    
    next();
  };
};

/**
 * Middleware to check if user is admin
 */
const isAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Admin access required'
    });
  }
  
  next();
};

/**
 * Middleware to check if user is accessing their own resource
 * @param {String} userIdParam - The parameter name containing the user ID
 */
const isResourceOwner = (userIdParam) => {
  return (req, res, next) => {
    const resourceUserId = req.params[userIdParam];
    
    // Allow admins to access any resource
    if (req.user.role === 'admin') {
      return next();
    }
    
    // Check if user is accessing their own resource
    if (req.user.id.toString() !== resourceUserId) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this resource'
      });
    }
    
    next();
  };
};

module.exports = {
  protect,
  restrictTo,
  isAdmin,
  isResourceOwner
};

