const { updateAdminStatus } = require('../../controllers/authController');
const { withSuperAdmin } = require('../../middleware/serverlessMiddleware');

/**
 * API route for updating admin status
 * Protected by super admin middleware
 * @param {Object} req - HTTP request object
 * @param {Object} res - HTTP response object
 */
const updateStatusHandler = async (req, res) => {
  if (req.method !== 'PATCH') {
    return res.status(405).json({
      success: false,
      message: 'Method not allowed'
    });
  }

  // Call the update admin status controller
  return updateAdminStatus(req, res);
};

// Wrap the handler with super admin authentication middleware
module.exports = withSuperAdmin(updateStatusHandler);

