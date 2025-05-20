const { resetAdminPassword } = require('../../controllers/authController');
const { withSuperAdmin } = require('../../middleware/serverlessMiddleware');

/**
 * API route for resetting admin password
 * Protected by super admin middleware
 * @param {Object} req - HTTP request object
 * @param {Object} res - HTTP response object
 */
const resetPasswordHandler = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({
      success: false,
      message: 'Method not allowed'
    });
  }

  // Call the reset password controller
  return resetAdminPassword(req, res);
};

// Wrap the handler with super admin authentication middleware
module.exports = withSuperAdmin(resetPasswordHandler);

