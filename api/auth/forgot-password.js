const { forgotPassword } = require('../../controllers/authController');

/**
 * API route for requesting a password reset email
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

  // Call the forgot password controller
  return forgotPassword(req, res);
};
