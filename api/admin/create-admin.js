const { createAdmin } = require('../../controllers/authController');
const { withSuperAdmin } = require('../../middleware/serverlessMiddleware');

/**
 * API route for creating a new admin
 * Protected by super admin middleware
 * @param {Object} req - HTTP request object
 * @param {Object} res - HTTP response object
 */
const createAdminHandler = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({
      success: false,
      message: 'Method not allowed'
    });
  }

  // Call the create admin controller
  return createAdmin(req, res);
};

// Wrap the handler with super admin authentication middleware
module.exports = withSuperAdmin(createAdminHandler);

