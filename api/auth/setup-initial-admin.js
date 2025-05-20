const { setupInitialAdmin } = require('../../controllers/authController');

/**
 * API route for initial admin setup
 * @param {Object} req - HTTP request object
 * @param {Object} res - HTTP response object
 */
module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({
      success: false,
      message: 'Method not allowed'
    });
  }

  // Call the setup initial admin controller
  return setupInitialAdmin(req, res);
};

