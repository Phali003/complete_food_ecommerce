const { resetPassword } = require('../../controllers/authController');

/**
 * API route for resetting password with a valid token
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

  // Call the reset password controller
  return resetPassword(req, res);
};

