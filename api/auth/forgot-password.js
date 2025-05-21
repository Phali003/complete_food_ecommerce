import { forgotPassword } from '../../controllers/authController.js';

/**
 * API route for requesting a password reset email
 * @param {Object} req - HTTP request object
 * @param {Object} res - HTTP response object
 */
export default async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({
      success: false,
      message: 'Metho
