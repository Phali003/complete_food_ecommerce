const express = require("express");
const router = express.Router();
const { protect } = require("../middleware/auth");
const bcrypt = require("bcryptjs");
const pool = require("../config/database");
const crypto = require('crypto');
const emailService = require('../services/emailService');

const {
  // User authentication
  signup,
  login,
  logout,
  getProfile,

  // Admin management
  setupInitialAdmin,
  createAdmin,
  listAdmins,
  migrateAdmin,
  updateAdminStatus,
  getAdminDetails,
  resetAdminPassword,
} = require("../controllers/authController");

// Helper function to validate password complexity
const validatePasswordComplexity = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

  const errors = [];

  if (password.length < minLength) {
    errors.push(`Password must be at least ${minLength} characters long`);
  }

  if (!hasUpperCase) {
    errors.push("Password must contain at least one uppercase letter");
  }

  if (!hasLowerCase) {
    errors.push("Password must contain at least one lowercase letter");
  }

  if (!hasNumbers) {
    errors.push("Password must contain at least one number");
  }

  if (!hasSpecialChar) {
    errors.push("Password must contain at least one special character");
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
};

// (Helper function for password reset notification has been removed)

/**
 * Authentication Routes
 * Handle user registration, login, logout, and profile access
 */
router.post("/signup", signup);
router.post("/login", login);
router.post("/logout", logout);
router.get("/profile", protect, getProfile);


/**
 * Password Reset Routes
 * Handle forgot password and reset password functionality
 * 
 * Implementation Status:
 * - The forgot password and reset password routes are fully implemented
 * - Email configuration is set up with proper error handling and fallback options
 * - Reset tokens have 1-hour expiration
 * - Password complexity validation is in place
 * - Frontend pages (forgot-password.html and reset-password.html) are created and connected
 */

// Forgot Password Route - Using the main connection pool for efficiency
router.post('/forgot-password', async (req, res) => {
  let connection;
  let resetToken;
  const requestId = Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
  
  try {
    const { email } = req.body;
    console.log(`[${requestId}] Starting password reset process for: ${email}`);

    // Basic validation
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }
    
    // Pre-validate Resend API key configuration with more detailed error logging
    if (!process.env.RESEND_API_KEY) {
      console.error(`[${requestId}] CRITICAL CONFIG ERROR: Missing email configuration: RESEND_API_KEY`);
      console.error(`[${requestId}] Environment variables available: ${Object.keys(process.env).filter(key => !key.includes('KEY') && !key.includes('SECRET')).join(', ')}`);
      return res.status(500).json({
        success: false,
        message: 'Email service is not properly configured. Please contact support.',
        errorCode: 'EMAIL_CONFIG_MISSING'
      });
    }

    // Validate Resend API key format (basic check)
    if (!process.env.RESEND_API_KEY.startsWith('re_')) {
      console.error(`[${requestId}] CRITICAL CONFIG ERROR: Invalid Resend API key format. Keys should start with "re_"`);
      return res.status(500).json({
        success: false,
        message: 'Email service configuration is invalid. Please contact support.',
        errorCode: 'EMAIL_CONFIG_INVALID'
      });
    }

    // Validate EMAIL_DOMAIN (needed for CORS and proper email link generation)
    if (!process.env.EMAIL_DOMAIN) {
      console.warn(`[${requestId}] CONFIG WARNING: EMAIL_DOMAIN environment variable is not set. Using fallback domain from request.`);
      console.warn(`[${requestId}] This may cause issues with password reset links if the request domain doesn't match the deployed frontend.`);
      // We'll continue but log this warning
    } else {
      console.log(`[${requestId}] Using configured EMAIL_DOMAIN: ${process.env.EMAIL_DOMAIN}`);
    }

    // Get a connection from the pool
    try {
      console.log(`[${requestId}] Attempting to get database connection...`);
      connection = await pool.getConnection();
      console.log(`[${requestId}] Database connection established successfully`);
    } catch (dbConnError) {
      console.error(`[${requestId}] DATABASE CONNECTION ERROR:`, {
        message: dbConnError.message,
        code: dbConnError.code,
        errno: dbConnError.errno,
        sqlState: dbConnError.sqlState,
        sqlMessage: dbConnError.sqlMessage
      });
      return res.status(500).json({
        success: false,
        message: 'Unable to connect to the database. Please try again later.',
        errorCode: 'DB_CONNECTION_ERROR'
      });
    }
    
    // 1. Find user
    console.log(`[${requestId}] Finding user with email: ${email}`);
    try {
      const [rows] = await connection.execute(
        'SELECT id, username, email FROM users WHERE email = ?',
        [email]
      );
      console.log(`[${requestId}] Database query results:`, { 
        found: rows.length > 0, 
        count: rows.length,
        userId: rows.length > 0 ? rows[0].id : null
      });

      // Check if user exists and return appropriate response
      if (!rows || rows.length === 0) {
        // Email doesn't exist in the system
        console.log(`[${requestId}] User not found with email: ${email}`);
        return res.status(404).json({
          success: false,
          message: 'No account found with this email address',
          errorCode: 'USER_NOT_FOUND'
        });
      }

      // 2. User exists, generate and store token
      const user = rows[0];
      console.log(`[${requestId}] Found user:`, { 
        id: user.id, 
        username: user.username,
        email: user.email.substring(0, 3) + '***' + user.email.substring(user.email.indexOf('@'))
      });
      
      // Generate token with improved randomness
      try {
        resetToken = crypto.randomBytes(32).toString('hex'); // Increased from 20 to 32 bytes for more security
        const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour
        console.log(`[${requestId}] Token generated with expiry:`, resetTokenExpiry);
      } catch (cryptoError) {
        console.error(`[${requestId}] CRYPTO ERROR: Failed to generate secure token:`, cryptoError);
        return res.status(500).json({
          success: false,
          message: 'Error generating secure reset token. Please try again.',
          errorCode: 'TOKEN_GENERATION_ERROR'
        });
      }

      try {
        // Update user with reset token
        console.log(`[${requestId}] Updating user with reset token...`);
        const updateStart = Date.now();
        const [updateResult] = await connection.execute(
          'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?',
          [resetToken, resetTokenExpiry, user.id]
        );
        console.log(`[${requestId}] Token update completed in ${Date.now() - updateStart}ms, affected rows:`, updateResult.affectedRows);
        
        if (updateResult.affectedRows !== 1) {
          throw new Error(`Expected to update 1 row, but updated ${updateResult.affectedRows} rows instead`);
        }

        // Verify token storage
        console.log(`[${requestId}] Verifying token storage...`);
        const [verifyResult] = await connection.execute(
          'SELECT reset_token, reset_token_expiry FROM users WHERE id = ?',
          [user.id]
        );
        
        const tokenStored = verifyResult[0].reset_token === resetToken;
        const expiryValid = new Date(verifyResult[0].reset_token_expiry) > new Date();
        
        console.log(`[${requestId}] Token verification result:`, {
          token_stored: tokenStored,
          expiry_valid: expiryValid,
          expiry_time: verifyResult[0].reset_token_expiry,
          token_length: verifyResult[0].reset_token?.length
        });
        
        if (!tokenStored || !expiryValid) {
          console.error(`[${requestId}] DATABASE ERROR: Token verification failed:`, {
            tokenStored,
            expiryValid,
            userId: user.id
          });
          throw new Error('Failed to verify stored token integrity');
        }
        // Determine domain to use (prefer EMAIL_DOMAIN env var, fallback to request host)
        const domain = process.env.EMAIL_DOMAIN || `${req.protocol}://${req.get('host')}`;
        console.log(`[${requestId}] Using domain for reset URL:`, domain);
        
        // Log request details to help debug domain/CORS issues
        console.log(`[${requestId}] Request details:`, {
          protocol: req.protocol,
          originalUrl: req.originalUrl,
          host: req.get('host'),
          origin: req.get('origin'),
          referer: req.get('referer')
        });
        
        // Create reset URL with the proper domain
        const resetUrl = `${domain}/reset-password.html?token=${resetToken}`;
        console.log(`[${requestId}] Generated reset URL: ${resetUrl.substring(0, resetUrl.indexOf('token=') + 6)}[TOKEN-REDACTED]`);

        // Email sending block
        try {
          console.log(`[${requestId}] Preparing to send password reset email to:`, user.email);
          
          // Time the email operation for performance monitoring
          const emailStartTime = Date.now();
          
          // Check if Resend service is operational with preventive logging
          if (!emailService || typeof emailService.sendPasswordResetEmail !== 'function') {
            console.error(`[${requestId}] EMAIL SERVICE ERROR: Email service is not properly initialized or missing sendPasswordResetEmail function`);
            return res.status(500).json({
              success: false,
              message: 'Email service is not available at the moment. Please try again later or contact support.',
              errorCode: 'EMAIL_SERVICE_ERROR'
            });
          }
          
          try {
            // Send password reset email using the email service
            await emailService.sendPasswordResetEmail({
              to: user.email,
              resetToken: resetToken,
              resetUrl: resetUrl
            });
            
            const emailDuration = Date.now() - emailStartTime;
            console.log(`[${requestId}] Password reset email sent successfully to: ${user.email} (took ${emailDuration}ms)`);
            
            // Return success for valid email with reset instructions sent
            return res.status(200).json({
              success: true,
              message: 'Password reset instructions have been sent to your email',
              // Only in development mode, return the token for testing
              ...(process.env.NODE_ENV === 'development' ? {
                resetToken: resetToken,
                resetUrl: resetUrl
              } : {})
            });
          } catch (emailSendError) {
            console.error(`[${requestId}] Failed to send password reset email:`, emailSendError);
            throw new Error(`Failed to send email: ${emailSendError.message}`);
          }
        } catch (emailServiceError) {
          console.error(`[${requestId}] Email service error:`, emailServiceError);
          return res.status(500).json({
            success: false,
            message: 'Unable to send password reset email. Please try again later or contact support.',
            errorCode: 'EMAIL_SEND_FAILED'
          });
        }
      } catch (dbError) {
        console.error('Database error during token storage:', dbError);
        throw new Error(`Database error: ${dbError.message}`);
      }
    } catch (dbError) {
      console.error('Database error during user lookup:', dbError);
      throw new Error(`Database error: ${dbError.message}`);
    }
  } catch (error) {
    console.error('Password reset error:', {
      message: error.message,
      stack: error.stack,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
    });
    
    return res.status(500).json({
      success: false,
      message: 'Error processing password reset request. Please try again later.',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  } finally {
    // Make sure to release the connection when done
    if (connection) {
      connection.release();
    }
  }
});

// Reset Password Route - Updated to use the main pool connection
router.post('/reset-password', async (req, res) => {
    let connection;

    try {
        // Log the request for debugging
        console.log('Reset password request received:', {
            hasToken: !!req.query.token,
            hasPassword: !!req.body.password,
            tokenLength: req.query.token?.length
        });

        const token = req.query.token;
        const { password, confirmPassword } = req.body;

        // Basic validation
        if (!token || !password || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Token, password and confirm password are required'
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Passwords do not match'
            });
        }

        // Log validation steps for debugging
        console.log('Validating password requirements');

        // Validate password complexity
        const passwordValidation = validatePasswordComplexity(password);
        if (!passwordValidation.isValid) {
            return res.status(400).json({
                success: false,
                message: 'Password does not meet complexity requirements',
                errors: passwordValidation.errors
            });
        }

        // Only validate token when actually resetting the password
        console.log('Checking token validity');
        
        // Get a connection from the pool
        connection = await pool.getConnection();
        
        // Find user with valid reset token
        const [rows] = await connection.execute(
            'SELECT id, email, username FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()',
            [token]
        );

        if (!rows || rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired reset token'
            });
        }

        const user = rows[0];
        console.log('User found, proceeding with password reset');

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Update password and clear reset token
        await connection.execute(
            'UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
            [hashedPassword, user.id]
        );

        // Store in password history
        await connection.execute(
            'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
            [user.id, user.password_hash || 'password_reset']
        );

        console.log('Password reset successful');
        return res.status(200).json({
            success: true,
            message: 'Password has been reset successfully'
        });

    } catch (error) {
        console.error('Reset password error:', error);
        return res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again later.',
            ...(process.env.NODE_ENV === 'development' ? { error: error.message } : {})
        });
    } finally {
        // Release the connection rather than ending the pool
        if (connection) {
            connection.release();
        }
    }
});

/**
 * Admin Management Routes
 * Handle admin creation, management, and password reset functionality
 */
router.post("/setup-initial-admin", setupInitialAdmin);
router.post("/create-admin", protect, createAdmin);
router.get("/list-admins", listAdmins); // Consider adding protect middleware for production
router.post("/migrate-admin", migrateAdmin);
router.patch("/admin/update-status", protect, updateAdminStatus);
router.get("/admin/details", protect, getAdminDetails);

// Custom implementation of password reset route with security improvements
router.post("/admin/reset-password", protect, async (req, res) => {
  const connection = await pool.getConnection();

  try {
    const { username, newPassword, confirmPassword, confirmReset } = req.body;
    const resetRequestIP = req.ip || req.connection.remoteAddress;

    // Verify super admin status
    if (!req.user.is_super_admin) {
      // Log unauthorized attempt
      await connection.execute(
        "INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)",
        [
          req.user.id,
          "UNAUTHORIZED_RESET_ATTEMPT",
          `User attempted to reset password for ${username}`,
          resetRequestIP,
        ]
      );

      return res.status(403).json({
        success: false,
        message: "Only super admins can reset passwords",
      });
    }

    // Check if confirmation parameter is provided and valid
    if (!confirmReset || confirmReset !== "CONFIRM") {
      return res.status(400).json({
        success: false,
        message:
          "Password reset requires explicit confirmation. Please provide 'CONFIRM' in the confirmReset field.",
      });
    }

    // Confirm passwords match
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "New password and confirmation password do not match",
      });
    }

    // Validate password complexity
    const passwordValidation = validatePasswordComplexity(newPassword);
    if (!passwordValidation.isValid) {
      return res.status(400).json({
        success: false,
        message: "Password does not meet complexity requirements",
        errors: passwordValidation.errors,
      });
    }

    // Check rate limits for password resets
    const [rateLimitCheck] = await connection.execute(
      "SELECT * FROM password_reset_attempts WHERE target_username = ? AND attempt_window_start > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
      [username]
    );

    if (rateLimitCheck.length > 0 && rateLimitCheck[0].attempt_count >= 3) {
      // Log rate limit exceeded
      await connection.execute(
        "INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)",
        [
          req.user.id,
          "RATE_LIMIT_EXCEEDED",
          `Rate limit exceeded for password reset attempts on ${username}`,
          resetRequestIP,
        ]
      );

      return res.status(429).json({
        success: false,
        message: "Rate limit exceeded. Please try again later.",
      });
    }

    // Get the target user's details and current password for history check
    const [userDetails] = await connection.execute(
      "SELECT id, email, password_hash FROM users WHERE username = ? AND role = ?",
      [username, "admin"]
    );

    if (userDetails.length === 0) {
      // Update rate limit tracking for non-existent users to prevent user enumeration
      if (rateLimitCheck.length === 0) {
        await connection.execute(
          "INSERT INTO password_reset_attempts (target_username, initiated_by, attempt_count, attempt_window_start, ip_address) VALUES (?, ?, 1, NOW(), ?)",
          [username, req.user.id, resetRequestIP]
        );
      } else {
        await connection.execute(
          "UPDATE password_reset_attempts SET attempt_count = attempt_count + 1, last_attempt_timestamp = NOW() WHERE target_username = ? AND attempt_window_start > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
          [username]
        );
      }

      return res.status(404).json({
        success: false,
        message: "Admin user not found",
      });
    }

    const targetUserId = userDetails[0].id;
    const targetUserEmail = userDetails[0].email;
    const currentPasswordHash = userDetails[0].password_hash;

    // Check if new password matches the current password
    const isSameAsCurrent = await bcrypt.compare(
      newPassword,
      currentPasswordHash
    );
    if (isSameAsCurrent) {
      return res.status(400).json({
        success: false,
        message: "New password cannot be the same as the current password",
      });
    }

    // Check password history to prevent reuse
    const [passwordHistory] = await connection.execute(
      "SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 3",
      [targetUserId]
    );

    // Check against previous passwords
    for (const history of passwordHistory) {
      const isPasswordReused = await bcrypt.compare(
        newPassword,
        history.password_hash
      );
      if (isPasswordReused) {
        return res.status(400).json({
          success: false,
          message: "Cannot reuse recent passwords",
        });
      }
    }

    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Begin transaction to ensure data consistency
    await connection.beginTransaction();

    try {
      // Update the user's password
      await connection.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        [hashedPassword, targetUserId]
      );

      // Store the old password in password history
      await connection.execute(
        "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
        [targetUserId, currentPasswordHash]
      );

      // Reset password attempt counter or create new entry
      if (rateLimitCheck.length === 0) {
        await connection.execute(
          "INSERT INTO password_reset_attempts (target_username, initiated_by, attempt_count, attempt_window_start, ip_address) VALUES (?, ?, 1, NOW(), ?)",
          [username, req.user.id, resetRequestIP]
        );
      } else {
        await connection.execute(
          "UPDATE password_reset_attempts SET attempt_count = attempt_count + 1, last_attempt_timestamp = NOW() WHERE target_username = ? AND attempt_window_start > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
          [username]
        );
      }

      // Log successful password reset
      await connection.execute(
        "INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)",
        [
          req.user.id,
          "PASSWORD_RESET_SUCCESS",
          `Password reset for ${username} (ID: ${targetUserId})`,
          resetRequestIP,
        ]
      );

      // Commit the transaction
      await connection.commit();

      // Password reset was successful - send response without email notification
      return res.json({
        success: true,
        message: "Password reset successfully"
      });
    } catch (error) {
      // Rollback if any error occurs
      await connection.rollback();
      throw error;
    }
  } catch (error) {
    console.error("Password reset error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to reset password",
      error: error.message,
    });
  } finally {
    if (connection) connection.release();
  }
});

module.exports = router;
