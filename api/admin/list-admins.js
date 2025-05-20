const { listAdmins } = require('../../controllers/authController');
const { withAdmin } = require('../../middleware/serverlessMiddleware');

/**
 * API route for listing all admins
 * Protected by admin middleware
 * @param {Object} req - HTTP request object
 * @param {Object} res - HTTP response object
 */
const listAdminsHandler = async (req, res) => {
  if (req.method !== 'GET') {
    return res.status(405).json({
      success: false,
      message: 'Method not allowed'
    });
  }

  // Call the list admins controller
  return listAdmins(req, res);
};

// Wrap the handler with admin authentication middleware
module.exports = withAdmin(listAdminsHandler);

