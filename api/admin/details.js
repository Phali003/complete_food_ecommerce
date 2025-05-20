const { getAdminDetails } = require('../auth');
const { protect } = require('../middleware/serverlessMiddleware');

/**
 * API route for getting detailed admin information
 * Protected by super admin middleware
 * @param {Object} req - HTTP request object
 * @param {Object} res - HTTP response object
 */
const adminDetailsHandler = async (req, res) => {
  if (req.method !== 'GET') {
    return res.status(405).json({
      success: false,
      message: 'Method not allowed'
    });
  }

  // Call the get admin details controller
  return getAdminDetails(req, res);
};

// Wrap the handler with authentication middleware
const wrappedHandler = (req, res) => {
  // Authenticate first
  protect(req, res, () => {
    // Then check if user is super admin
    if (!req.user || !req.user.is_super_admin) {
      return res.status(403).json({
        success: false,
        message: "Only super admins can access this resource"
      });
    }
    
    // If super admin, proceed to handler
    return adminDetailsHandler(req, res);
  });
};

module.exports = wrappedHandler;

