const express = require("express");
const router = express.Router();
const { protect } = require("../middleware/auth");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const pool = require("../config/database");
const crypto = require('crypto');  // Add this line

const {
  // User authentication
  signup,
  login,
  logout,
  getProfile,

  // Test endpoints
  testSuccess,
  testError,
  testDatabase,
  testCreateUser,

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

// Import emailTester utility for email configuration validation
const { testEmailConfig, getEmailTroubleshooting } = require('../utils/emailTester');

// Forgot Password Route - Using the same connection handling as our successful test
router.post('/forgot-password', async (req, res) => {
  // Create a new pool for this request
  const mysql = require('mysql2/promise');
  const newPool = await mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });
  
  let resetToken;
  
  try {
    const { email } = req.body;
    console.log('Starting password reset process for:', email);

    // Basic validation
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    // 1. Find user
    console.log('Finding user...');
    const [rows] = await newPool.execute(
      'SELECT id, username, email FROM users WHERE email = ?',
      [email]
    );
    console.log('Database query results:', { found: rows.length > 0 });

    // Check if user exists and return appropriate response
    if (!rows || rows.length === 0) {
      // Email doesn't exist in the system
      return res.status(404).json({
        success: false,
        message: 'No account found with this email address'
      });
    }

    // 2. User exists, generate and store token
    const user = rows[0];
    console.log('Found user:', { id: user.id, username: user.username });
    
    // Generate token
    resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour
    console.log('Token generated:', resetToken);

    // Update user with reset token
    console.log('Updating user with reset token...');
    await newPool.execute(
      'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?',
      [resetToken, resetTokenExpiry, user.id]
    );

    // Verify token storage
    console.log('Verifying token storage...');
    const [verifyResult] = await newPool.execute(
      'SELECT reset_token, reset_token_expiry FROM users WHERE id = ?',
      [user.id]
    );
    console.log('Token verification:', verifyResult[0]);

    // Create reset URL
    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password.html?token=${resetToken}`;
    
    try {
      console.log('Configuring email transport...');
      const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT),
        secure: process.env.EMAIL_SECURE === 'true',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD
        }
      });

      console.log('Sending password reset email...');
      const mailResult = await transporter.sendMail({
        from: `"Fresh Eats Market" <${process.env.EMAIL_USER}>`,
        to: user.email,
        subject: 'Password Reset Request',
        html: `
          <h1>Password Reset Request</h1>
          <p>Hello ${user.username},</p>
          <p>You requested to reset your password. Please click the link below to reset it:</p>
          <a href="${resetUrl}">Reset Password</a>
          <p>This link will expire in 1 hour.</p>
          <p>If you didn't request this, please ignore this email.</p>
        `
      });
      console.log('Email sent successfully:', mailResult.messageId);
    } catch (emailError) {
      console.error('Failed to send email:', emailError.message);
      return res.status(500).json({
        success: false,
        message: 'Failed to send reset email. Please try again later.'
      });
    }

    // Return success for valid email with reset instructions sent
    return res.status(200).json({
      success: true,
      message: 'Password reset instructions have been sent to your email',
      // Only in development mode, return the token for testing
      ...(process.env.NODE_ENV === 'development' ? {
        resetToken: resetToken,
        resetUrl: `${req.protocol}://${req.get('host')}/reset-password.html?token=${resetToken}`
      } : {})
    });

  } catch (error) {
    console.error('Password reset error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error processing password reset request'
    });
  } finally {
    // Make sure to end the pool when done
    await newPool.end();
  }
});

// Reset Password Route - Using exact implementation from successful debug test
router.post('/reset-password', async (req, res) => {
    // Create a new pool specifically for this request
    const mysql = require('mysql2/promise');
    const pool = await mysql.createPool({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    });

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
        
        // Find user with valid reset token
        const [rows] = await pool.execute(
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
        await pool.execute(
            'UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
            [hashedPassword, user.id]
        );

        // Store in password history
        await pool.execute(
            'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
            [user.id, hashedPassword]
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
        await pool.end();
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

/**
 * Test Endpoints
 * Used for testing API functionality
 */
router.get("/test-success", testSuccess);
router.get("/test-error", testError);
router.get("/test-db", testDatabase);
router.post("/test-create-user", testCreateUser);

// (Test endpoints related to reset password functionality have been removed)

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
