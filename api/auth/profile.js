const { getProfile } = require('../../controllers/authController');
const { withAuth } = require('../../middleware/serverlessMiddleware');

/**
 * API route for getting user profile
 * Protected by authentication middleware
 * @param {Object} req - HTTP request object
 * @param {Object} res - HTTP response object
 */
const profileHandler = async (req, res) => {
  if (req.method !== 'GET') {
    return res.status(405).json({
      success: false,
      message: 'Method not allowed'
    });
  }

  // Call the profile controller
  return getProfile(req, res);
};

// Wrap the handler with authentication middleware
module.exports = withAuth(profileHandler);

