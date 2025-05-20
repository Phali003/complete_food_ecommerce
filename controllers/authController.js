/**
 * Authentication controller for user management and authentication
 */
const { pool } = require('../config/database');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { generateSecureToken, hashPassword, verifyPassword } = require('../utils/securityUtils');
const emailService = require('../services/emailService');
const BlacklistedTokenModel = require('../models/BlacklistedTokenModel');

/**
 * Register a new user
 * @param {Object} req - HTTP request object
 * @param {Object} res - HTTP response object
 * @returns {Object} JSON response
 */
const signup = async (req, res) => {
  const { username, email, password, confirm_password } = req.body;
  
  try {
    console.log('Processing signup request for:', email);
    
    // Input validation
    if (!username || !email || !password || !confirm_password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide all required fields'
      });
    }
    
    if (password !== confirm_password) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }
    
    // Password strength validation
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        success: false,
        message: 'Password must contain at least 8 characters, including uppercase, lowercase, number and special character'
      });
    }
    
    let connection;
    try {
      connection = await pool.getConnection();
      
      // Check if user already exists
      const [existingUsers] = await connection.execute(
        'SELECT * FROM users WHERE email = ? OR username = ?',
        [email, username]
      );
      
      if (existingUsers.length > 0) {
        const existingUser = existingUsers[0];
        if (existingUser.email === email) {
          return res.status(400).json({
            success: false,
            message: 'Email already in use'
          });
        }
        if (existingUser.username === username) {
          return res.status(400).json({
            success: false,
            message: 'Username already taken'
          });
        }
      }
      
      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);
      
      // Insert new user
      const [result] = await connection.execute(
        'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
        [username, email, hashedPassword, 'user']
      );
      
      // Generate token
      const token =

/**
 * authController.js - Authentication and user management
 * Handles user authentication, admin management, and test endpoints
 */

// --------------------------------------
// Imports
// --------------------------------------
const UserModel = require('../models/UserModel');
const BlacklistedTokenModel = require('../models/BlacklistedTokenModel');
const { generateToken } = require('../utils/jwt');
const Joi = require('joi');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { pool } = require('../config/database');

// --------------------------------------
// Database Helpers
// --------------------------------------

/**
 * Get a database connection from the pool
 */
const getConnection = async () => {
  return await pool.getConnection();
};

/**
 * Execute code within a transaction and handle commit/rollback
 */
const withTransaction = async (connection, callback) => {
  try {
    await connection.beginTransaction();
    const result = await callback(connection);
    await connection.commit();
    return result;
  } catch (error) {
    await connection.rollback();
    throw error;
  }
};

/**
 * Standard error handler for controllers
 */
const handleError = (res, error, message) => {
  console.error(`${message}:`, error);
  return res.status(500).json({
    success: false,
    message: message,
    error: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
};

// --------------------------------------
// Validation Schemas
// --------------------------------------

const validationSchemas = {
  /**
   * Validate user registration data
   */
  signup: Joi.object({
    username: Joi.string().min(3).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).max(50).required(),
    confirm_password: Joi.ref('password')
  }).with('password', 'confirm_password'),

  /**
   * Validate user login data
   */
  login: Joi.object({
    identifier: Joi.string().required()
      .messages({
        'any.required': 'Email or username is required'
      }),
    password: Joi.string().required()
      .messages({
        'any.required': 'Password is required'
      })
  }).required(),

  /**
   * Validate admin creation data
   */
  adminCreation: Joi.object({
    username: Joi.string().min(3).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).max(50).required(),
    setupCode: Joi.string().when('isInitialSetup', {
      is: true,
      then: Joi.required()
    }),
    isInitialSetup: Joi.boolean().default(false)
  }),

  /**
   * Validate admin status update
   */
  adminStatus: Joi.object({
    adminId: Joi.number().integer().required(),
    isActive: Joi.boolean().required()
  }),

  /**
   * Validate password reset
   */
  passwordReset: Joi.object({
    username: Joi.string().required(),
    newPassword: Joi.string().min(8).required(),
    confirmPassword: Joi.string().valid(Joi.ref('newPassword')).required()
      .messages({ 'any.only': 'Passwords do not match' }),
    confirmReset: Joi.string().valid('CONFIRM').required()
      .messages({ 'any.only': 'Must provide CONFIRM to reset password' })
  })
};

// --------------------------------------
// Helper Functions
// --------------------------------------

/**
 * Helper function to validate password complexity
 */
const validatePasswordComplexity = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  const errors = [];
  
  if (password.length < minLength) {
    errors.push(`Password must be at least ${minLength} characters long`);
  }
  
  if (!hasUpperCase) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!hasLowerCase) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!hasNumbers) {
    errors.push('Password must contain at least one number');
  }
  
  if (!hasSpecialChar) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Helper function to send password reset notification email
 */
const sendPasswordResetNotification = async (email, username, resetBy) => {
  try {
    // Create a transporter
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    // Setup email data
    const mailOptions = {
      from: `"Food E-commerce Security" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your Admin Password Has Been Reset',
      html: `
        <h1>Password Reset Notification</h1>
        <p>Hello ${username},</p>
        <p>Your admin account password was reset by ${resetBy} on ${new Date().toLocaleString()}.</p>
        <p>If you did not authorize this change, please contact the super admin immediately.</p>
        <p>Regards,<br>Food E-commerce Security Team</p>
      `
    };

    // Send the email
    await transporter.sendMail(mailOptions);
    console.log(`Password reset notification sent to ${email}`);
    return true;
  } catch (error) {
    console.error('Failed to send password reset notification email:', error);
    return false;
  }
};
/**
 * Helper function to get admin list with different detail levels
 */
const getAdminList = async (connection, detailed = false) => {
  const query = `
    SELECT id, username, email, created_at, is_super_admin, is_active
    ${detailed ? ', last_login, created_by' : ''}
    FROM users 
    WHERE role = ?
  `;
  
  const [admins] = await connection.execute(query, ['admin']);
  return admins;
};

// --------------------------------------
// Authentication Controllers
// --------------------------------------

/**
 * User registration controller
 */
const signup = async (req, res) => {
  try {
    console.log('Starting user registration process');
    // Validate input data
    const { error } = validationSchemas.signup.validate(req.body);
    if (error) {
      console.log('Validation error:', error.details[0].message);
      return res.status(400).json({
        success: false,
        message: error.details[0].message
      });
    }

    const { username, email, password } = req.body;
    console.log('Registering user with username:', username, 'and email:', email);
    // Check if user already exists with this email
    const userExists = await UserModel.exists(email);
    if (userExists) {
      console.log('User already exists with email:', email);
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email'
      });
    }

    // Check if username is already taken
    const usernameExists = await UserModel.findByUsername(username);
    if (usernameExists) {
      console.log('Username already taken:', username);
      return res.status(400).json({
        success: false,
        message: 'Username is already taken'
      });
    }

    // Create user
    const user = await UserModel.createUser({ username, email, password });
    console.log('User created successfully with ID:', user.id);
    // Generate token
    const token = generateToken(user);

    // Set cookie with improved settings for cross-origin authentication
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: parseInt(process.env.COOKIE_MAX_AGE) || 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      path: '/',
      domain: process.env.NODE_ENV === 'production' ? '.onrender.com' : undefined
    });

    // Log cookie settings for debugging
    console.log('Setting auth cookie on signup with config:', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      domain: process.env.NODE_ENV === 'production' ? '.onrender.com' : undefined,
      env: process.env.NODE_ENV
    });

    // Return user data and token
    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        },
        token
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    return handleError(res, error, 'Server error during registration');
  }
};

/**
 * User login controller
 * Supports login with either email or username
 */
const login = async (req, res) => {
  // Get a database connection for rate limiting and audit logging
  let connection = null;
  const clientIP = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  
  try {
    console.log('Starting login process with detailed logging');
    console.log('Database config:', {
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      database: process.env.DB_NAME,
      ssl: process.env.DB_SSL,
      port: process.env.DB_PORT
    });

    // Validate input data
    const { error } = validationSchemas.login.validate(req.body);
    if (error) {
      console.log('Login validation error:', error.details[0].message);
      return res.status(400).json({
        success: false,
        message: error.details[0].message
      });
    }

    const { identifier, password } = req.body;
    console.log('Login attempt with identifier:', identifier);

    // Get connection for checking rate limits
    connection = await getConnection();
    
    // Check rate limiting by IP and identifier to prevent brute force attacks
    const [loginAttempts] = await connection.execute(
      'SELECT COUNT(*) as count FROM login_attempts WHERE identifier = ? AND ip_address = ? AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)',
      [identifier, clientIP]
    );
    
    // Rate limit: 5 attempts per 15 minutes from the same IP for the same identifier
    if (loginAttempts[0].count >= 5) {
      console.log(`Rate limit exceeded for ${identifier} from IP ${clientIP}`);
      
      // Log the rate limit event
      await connection.execute(
        'INSERT INTO audit_log (event_type, event_description, ip_address) VALUES (?, ?, ?)',
        ['RATE_LIMIT_EXCEEDED', `Login rate limit exceeded for ${identifier}`, clientIP]
      );
      
      return res.status(429).json({
        success: false,
        message: 'Too many login attempts. Please try again later.',
        retryAfter: 900 // 15 minutes in seconds
      });
    }

    // Record login attempt for rate limiting
    await connection.execute(
      'INSERT INTO login_attempts (identifier, ip_address, user_agent) VALUES (?, ?, ?)',
      [identifier, clientIP, req.headers['user-agent'] || 'unknown']
    );

    // Find user by email or username with specific error handling
    let user = null;
    try {
      if (identifier.includes('@')) {
        console.log('Attempting login with email');
        user = await UserModel.findByEmail(identifier);
      } else {
        console.log('Attempting login with username');
        user = await UserModel.findByUsername(identifier);
      }
    } catch (dbError) {
      console.error('Database error during user lookup:', dbError);
      throw new Error('Database error during authentication');
    }

    if (!user) {
      console.log('No user found for identifier:', identifier);
      // Log failed login attempt in audit log
      if (connection) {
        await connection.execute(
          'INSERT INTO audit_log (event_type, event_description, ip_address) VALUES (?, ?, ?)',
          ['FAILED_LOGIN', `No user found for identifier: ${identifier}`, clientIP]
        );
      }
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    console.log('User found:', {
      id: user.id,
      username: user.username,
      hasPassword: !!user.password_hash
    });

    // Check if account is locked or inactive
    if (user.is_locked || (user.is_active === false)) {
      console.log(`Account is ${user.is_locked ? 'locked' : 'inactive'} for user:`, user.username);
      
      // Log event
      if (connection) {
        await connection.execute(
          'INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)',
          [user.id, 'ACCESS_DENIED', `Login attempt on ${user.is_locked ? 'locked' : 'inactive'} account`, clientIP]
        );
      }
      
      return res.status(403).json({
        success: false,
        message: user.is_locked ? 
          'This account has been temporarily locked. Please contact support or try again later.' : 
          'This account is inactive. Please contact an administrator.'
      });
    }

    // Verify password with specific error handling
    let isPasswordValid = false;
    try {
      isPasswordValid = await UserModel.verifyPassword(password, user.password_hash);
    } catch (pwError) {
      console.error('Password verification error:', pwError);
      throw new Error('Error verifying credentials');
    }

    if (!isPasswordValid) {
      console.log('Invalid password for user:', user.username);
      
      // Log failed login in audit log
      if (connection) {
        await connection.execute(
          'INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)',
          [user.id, 'FAILED_LOGIN', 'Invalid password', clientIP]
        );
        
        // Check for consecutive failed attempts to implement account locking
        const [failedAttempts] = await connection.execute(
          'SELECT COUNT(*) as count FROM audit_log WHERE user_id = ? AND event_type = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)',
          [user.id, 'FAILED_LOGIN']
        );
        
        // If more than 5 failed attempts in the last hour, lock the account
        if (failedAttempts[0].count >= 5) {
          await connection.execute(
            'UPDATE users SET is_locked = TRUE, locked_at = NOW() WHERE id = ?',
            [user.id]
          );
          
          // Log account lock event
          await connection.execute(
            'INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)',
            [user.id, 'ACCOUNT_LOCKED', 'Account locked after consecutive failed login attempts', clientIP]
          );
        }
      }
      
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Handle successful login - update last login timestamp
    await connection.execute(
      'UPDATE users SET last_login = NOW(), login_count = IFNULL(login_count, 0) + 1, is_locked = FALSE, locked_at = NULL WHERE id = ?',
      [user.id]
    );
    
    // Log successful login in audit log
    await connection.execute(
      'INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)',
      [user.id, 'SUCCESSFUL_LOGIN', `Login from ${req.headers['user-agent'] || 'unknown browser'}`, clientIP]
    );
    
    // Clear failed login attempts for this identifier and IP
    await connection.execute(
      'DELETE FROM login_attempts WHERE identifier = ? AND ip_address = ?',
      [identifier, clientIP]
    );

    // Generate token
    const token = generateToken(user);

    // Set cookie with improved settings for cross-origin authentication
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: parseInt(process.env.COOKIE_MAX_AGE) || 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      path: '/',
      domain: process.env.NODE_ENV === 'production' ? '.onrender.com' : undefined
    });
    
    // Log cookie settings for debugging
    console.log('Setting auth cookie on login with config:', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      domain: process.env.NODE_ENV === 'production' ? '.onrender.com' : undefined,
      env: process.env.NODE_ENV
    });

    // Return user data with token
    return res.status(200).json({
      success: true,
      message: 'Login successful',
      token,
      userId: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      isAdmin: user.role === 'admin'
    });
  } catch (error) {
    console.error('Login error:', error);
    return handleError(res, error, 'Server error during login');
  } finally {
    // Always release the connection to prevent connection leaks
    if (connection) {
      connection.release();
    }
  }
};

/**
 * User logout controller
 */
const logout = async (req, res) => {
  try {
    console.log('Processing logout request');
    
    // Get token from request
    const token = req.cookies.token || 
               (req.headers.authorization && req.headers.authorization.split(' ')[1]);
    
    // Blacklist the token if it exists and user is authenticated
    if (token && req.user) {
      await BlacklistedTokenModel.blacklistToken(token, req.user.id);
      console.log(`Token blacklisted for user ID: ${req.user.id}`);
    }
    
    // Clear cookie
    res.clearCookie('token');

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error during logout'
    });
  }
};

/**
 * Get current user profile
 */
const getProfile = async (req, res) => {
  try {
    console.log('Fetching user profile');
    // Get user from request (set by auth middleware)
    const userId = req.user.id;

    // Find user by ID
    const user = await UserModel.findById(userId);
    if (!user) {
      console.log('User not found for ID:', userId);
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    console.log('Profile retrieved for user:', user.username);
    // Return user data
    return res.status(200).json({
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          created_at: user.created_at
        }
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while fetching profile'
    });
  }
};

/**
 * Reset admin password with security checks
 */
const resetAdminPassword = async (req, res) => {
  const connection = await getConnection();
  
  try {
    const { username, newPassword, confirmPassword, confirmReset } = req.body;
    const resetRequestIP = req.ip || req.connection.remoteAddress;
    
    // Verify super admin status
    if (!req.user.is_super_admin) {
      // Log unauthorized attempt
      await connection.execute(
        'INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)',
        [req.user.id, 'UNAUTHORIZED_RESET_ATTEMPT', `User attempted to reset password for ${username}`, resetRequestIP]
      );
      
      return res.status(403).json({
        success: false,
        message: "Only super admins can reset passwords"
      });
    }

    // Check if confirmation parameter is provided and valid
    if (!confirmReset || confirmReset !== 'CONFIRM') {
      return res.status(400).json({
        success: false,
        message: "Password reset requires explicit confirmation. Please provide 'CONFIRM' in the confirmReset field."
      });
    }
    
    // Confirm passwords match
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "New password and confirmation password do not match"
      });
    }

    // Validate password complexity
    const passwordValidation = validatePasswordComplexity(newPassword);
    if (!passwordValidation.isValid) {
      return res.status(400).json({
        success: false,
        message: "Password does not meet complexity requirements",
        errors: passwordValidation.errors
      });
    }

    // Check rate limits for password resets
    const [rateLimitCheck] = await connection.execute(
      'SELECT * FROM password_reset_attempts WHERE target_username = ? AND attempt_window_start > DATE_SUB(NOW(), INTERVAL 1 HOUR)',
      [username]
    );

    if (rateLimitCheck.length > 0 && rateLimitCheck[0].attempt_count >= 3) {
      // Log rate limit exceeded
      await connection.execute(
        'INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)',
        [req.user.id, 'RATE_LIMIT_EXCEEDED', `Rate limit exceeded for password reset attempts on ${username}`, resetRequestIP]
      );
      
      return res.status(429).json({
        success: false,
        message: "Rate limit exceeded. Please try again later."
      });
    }

    // Get the target user's details and current password for history check
    const [userDetails] = await connection.execute(
      'SELECT id, email, password_hash FROM users WHERE username = ? AND role = ?',
      [username, 'admin']
    );

    if (userDetails.length === 0) {
      // Update rate limit tracking for non-existent users to prevent user enumeration
      if (rateLimitCheck.length === 0) {
        await connection.execute(
          'INSERT INTO password_reset_attempts (target_username, initiated_by, attempt_count, attempt_window_start, ip_address) VALUES (?, ?, 1, NOW(), ?)',
          [username, req.user.id, resetRequestIP]
        );
      } else {
        await connection.execute(
          'UPDATE password_reset_attempts SET attempt_count = attempt_count + 1, last_attempt_timestamp = NOW() WHERE target_username = ? AND attempt_window_start > DATE_SUB(NOW(), INTERVAL 1 HOUR)',
          [username]
        );
      }
      
      return res.status(404).json({
        success: false,
        message: "Admin user not found"
      });
    }

    const targetUserId = userDetails[0].id;
    const targetUserEmail = userDetails[0].email;
    const currentPasswordHash = userDetails[0].password_hash;
    
    // Check if new password matches the current password
    const isSameAsCurrent = await bcrypt.compare(newPassword, currentPasswordHash);
    if (isSameAsCurrent) {
      return res.status(400).json({
        success: false,
        message: "New password cannot be the same as the current password"
      });
    }

    // Check password history to prevent reuse
    const [passwordHistory] = await connection.execute(
      'SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 3',
      [targetUserId]
    );

    // Check against previous passwords
    for (const history of passwordHistory) {
      const isPasswordReused = await bcrypt.compare(newPassword, history.password_hash);
      if (isPasswordReused) {
        return res.status(400).json({
          success: false,
          message: "Cannot reuse recent passwords"
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
        'UPDATE users SET password_hash = ? WHERE id = ?',
        [hashedPassword, targetUserId]
      );

      // Store the old password in password history
      await connection.execute(
        'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
        [targetUserId, currentPasswordHash]
      );

      // Reset password attempt counter or create new entry
      if (rateLimitCheck.length === 0) {
        await connection.execute(
          'INSERT INTO password_reset_attempts (target_username, initiated_by, attempt_count, attempt_window_start, ip_address) VALUES (?, ?, 1, NOW(), ?)',
          [username, req.user.id, resetRequestIP]
        );
      } else {
        await connection.execute(
          'UPDATE password_reset_attempts SET attempt_count = attempt_count + 1, last_attempt_timestamp = NOW() WHERE target_username = ? AND attempt_window_start > DATE_SUB(NOW(), INTERVAL 1 HOUR)',
          [username]
        );
      }

      // Log successful password reset
      await connection.execute(
        'INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)',
        [req.user.id, 'PASSWORD_RESET_SUCCESS', `Password reset for ${username} (ID: ${targetUserId})`, resetRequestIP]
      );

      // Commit the transaction
      await connection.commit();

      // Send notification email (after successful transaction)
      const emailSent = await sendPasswordResetNotification(
        targetUserEmail, 
        username, 
        req.user.username
      );

      return res.json({
        success: true,
        message: "Password reset successfully",
        emailSent: emailSent
      });
    } catch (error) {
      // Rollback if any error occurs
      await connection.rollback();
      throw error;
    }
  } catch (error) {
    return handleError(res, error, "Failed to reset password");
  } finally {
    if (connection) connection.release();
  }
};


/**
 * Admin Management Functions
 */
const setupInitialAdmin = async (req, res) => {
    const connection = await getConnection();
    try {
        const { username, email, password, setupCode } = req.body;
        
        if (!setupCode || setupCode !== process.env.INITIAL_ADMIN_SETUP_CODE) {
            return res.status(403).json({
                success: false,
                message: "Invalid setup code"
            });
        }
        
        const [admins] = await connection.execute(
            'SELECT COUNT(*) as count FROM users WHERE role = ?', 
            ['admin']
        );

        if (admins[0].count > 0) {
            return res.status(400).json({
                success: false,
                message: "Admin account already exists"
            });
        }
        
        const user = await UserModel.createUser({ 
            username, 
            email, 
            password, 
            role: 'admin',
            is_super_admin: true 
        });
        
        return res.status(201).json({
            success: true,
            message: "Initial admin account created successfully",
            userId: user.id
        });
    } catch (error) {
        return handleError(res, error, "Failed to setup initial admin");
    } finally {
        connection.release();
    }
};

const createAdmin = async (req, res) => {
    const connection = await getConnection();
    try {
        // Verify that the requesting user is a super admin
        if (!req.user.is_super_admin) {
            return res.status(403).json({
                success: false,
                message: "Only super admins can create new administrators"
            });
        }

        // Validate input fields against adminCreation schema
        const { error, value } = validationSchemas.adminCreation.validate(req.body);
        if (error) {
            return res.status(400).json({
                success: false,
                message: error.details[0].message
            });
        }

        const { username, email, password } = value;
        
        // Check for duplicate email
        const emailExists = await UserModel.exists(email);
        if (emailExists) {
            return res.status(400).json({
                success: false,
                message: "Email is already in use"
            });
        }

        // Check for duplicate username
        const usernameExists = await UserModel.findByUsername(username);
        if (usernameExists) {
            return res.status(400).json({
                success: false,
                message: "Username is already taken"
            });
        }
        
        // Create the admin user
        const user = await UserModel.createUser({ 
            username, 
            email, 
            password, 
            role: 'admin',
            created_by: req.user.id
        });

        return res.status(201).json({
            success: true,
            message: "Admin user created successfully",
            userId: user.id
        });
    } catch (error) {
        return handleError(res, error, "Failed to create admin user");
    } finally {
        if (connection) connection.release();
    }
};

const listAdmins = async (req, res) => {
    const connection = await getConnection();
    try {
        const admins = await getAdminList(connection, false);
        return res.status(200).json({
            success: true,
            admins
        });
    } catch (error) {
        return handleError(res, error, "Failed to fetch admin list");
    } finally {
        connection.release();
    }
};

const migrateAdmin = async (req, res) => {
    const connection = await getConnection();
    try {
        return await withTransaction(connection, async (conn) => {
            const [columns] = await conn.execute(`
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'users' 
                AND COLUMN_NAME = 'is_super_admin'
            `);

            if (columns.length === 0) {
                await conn.execute(`
                    ALTER TABLE users
                    ADD COLUMN is_super_admin BOOLEAN DEFAULT FALSE
                `);

                await conn.execute(`
                    UPDATE users 
                    SET is_super_admin = TRUE 
                    WHERE username = ? AND role = 'admin'
                `, [process.env.SUPER_ADMIN_USERNAME]);
            }

            return res.json({
                success: true,
                message: "Migration completed successfully"
            });
        });
    } catch (error) {
        return handleError(res, error, "Migration failed");
    } finally {
        connection.release();
    }
};

const updateAdminStatus = async (req, res) => {
    const connection = await getConnection();
    try {
        // Verify that the requesting user is a super admin
        if (!req.user.is_super_admin) {
            return res.status(403).json({
                success: false,
                message: "Only super admins can update admin status"
            });
        }

        // Validate input against schema
        const { error, value } = validationSchemas.adminStatus.validate(req.body);
        if (error) {
            return res.status(400).json({
                success: false,
                message: error.details[0].message
            });
        }

        const { adminId, isActive } = value;
        
        // Update the user status using connection.execute for consistency
        await connection.execute(
            'UPDATE users SET is_active = ? WHERE id = ? AND role = ?',
            [isActive, adminId, 'admin']
        );

        return res.json({
            success: true,
            message: `Admin account ${isActive ? 'activated' : 'deactivated'} successfully`
        });
    } catch (error) {
        return handleError(res, error, "Failed to update admin status");
    } finally {
        if (connection) connection.release();
    }
};

const getAdminDetails = async (req, res) => {
    const connection = await getConnection();
    try {
        // Ensure the requester has super admin rights
        if (!req.user.is_super_admin) {
            return res.status(403).json({
                success: false,
                message: "Only super admins can view detailed admin information"
            });
        }

        // Use the getAdminList helper with detailed=true to get comprehensive info
        const admins = await getAdminList(connection, true);

        return res.json({
            success: true,
            admins: admins
        });
    } catch (error) {
        return handleError(res, error, "Failed to fetch admin details");
    } finally {
        if (connection) connection.release();
    }
};

/**
 * Initiates the password reset process by generating a token and sending an email
 * @param {Object} req - HTTP request object
 * @param {Object} res - HTTP response object
 * @returns {Object} JSON response
 */
const forgotPassword = async (req, res) => {
  const connection = await getConnection();
  const clientIP = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  
  try {
    console.log('Processing forgot password request');
    
    // Validate the email from request body
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }
    
    // Check rate limiting to prevent abuse
    const [resetAttempts] = await connection.execute(
      'SELECT COUNT(*) as count FROM password_reset_tokens WHERE email = ? AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)',
      [email]
    );
    
    if (resetAttempts[0].count >= 3) {
      // Log rate limit exceeded
      await connection.execute(
        'INSERT INTO audit_log (event_type, event_description, ip_address) VALUES (?, ?, ?)',
        ['RATE_LIMIT_EXCEEDED', `Rate limit exceeded for password reset attempts on ${email}`, clientIP]
      );
      
      return res.status(429).json({
        success: false,
        message: 'Too many reset attempts. Please try again later.',
        retryAfter: 900 // 15 minutes in seconds
      });
    }
    
    // Check if user exists
    const [users] = await connection.execute(
      'SELECT id, username FROM users WHERE email = ?',
      [email]
    );
    
    // Always return success whether account exists or not to prevent user enumeration
    if (users.length === 0) {
      console.log(`Password reset requested for non-existent email: ${email}`);
      
      // Log the attempt for non-existent user
      await connection.execute(
        'INSERT INTO audit_log (event_type, event_description, ip_address) VALUES (?, ?, ?)',
        ['PASSWORD_RESET_REQUEST', `Password reset requested for non-existent email: ${email}`, clientIP]
      );
      
      return res.status(200).json({
        success: true,
        message: 'If an account exists with that email, a password reset link will be sent.'
      });
    }
    
    const user = users[0];
    
    // Generate secure token for password reset
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    
    // Store token in database (invalidating any previous tokens)
    await connection.execute(
      'DELETE FROM password_reset_tokens WHERE email = ?',
      [email]
    );
    
    // Set expiration to 1 hour from now
    const tokenExpiry = new Date(Date.now() + 3600000); // 1 hour
    
    await connection.execute(
      'INSERT INTO password_reset_tokens (email, token, expires_at, user_id) VALUES (?, ?, ?, ?)',
      [email, tokenHash, tokenExpiry, user.id]
    );
    
    // Create a reset link with the token
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    
    // Send the email using the emailService
    const emailResult = await emailService.sendPasswordResetEmail({
      email,
      username: user.username,
      resetUrl
    });
    
    if (!emailResult.success) {
      console.error('Failed to send password reset email:', emailResult.error);
      throw new Error('Failed to send password reset email');
    }
    
    // Log the password reset request
    await connection.execute(
      'INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)',
      [user.id, 'PASSWORD_RESET_REQUEST', 'Password reset email sent', clientIP]
    );
    
    return res.status(200).json({
      success: true,
      message: 'If an account exists with that email, a password reset link will be sent.'
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    return handleError(res, error, 'Error processing password reset request');
  } finally {
    if (connection) connection.release();
  }
};

/**
 * Resets a user's password using a valid token
 * @param {Object} req - HTTP request object
 * @param {Object} res - HTTP response object
 * @returns {Object} JSON response
 */
const resetPassword = async (req, res) => {
  const connection = await getConnection();
  const clientIP = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  
  try {
    console.log('Processing password reset');
    
    const { token, password, confirmPassword } = req.body;
    
    // Validate required fields
    if (!token || !password || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Token, password and confirm password are required'
      });
    }
    
    // Check if passwords match
    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }
    
    // Validate password complexity
    const passwordValidation = validatePasswordComplexity(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({
        success: false,
        message: 'Password does not meet complexity requirements',
        errors: passwordValidation.errors
      });
    }
    
    // Hash the incoming token
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    
    // Find the token record
    const [tokenRecords] = await connection.execute(
      'SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > NOW()',
      [tokenHash]
    );
    
    if (tokenRecords.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired password reset token'
      });
    }
    
    const tokenRecord = tokenRecords[0];
    
    // Retrieve the user
    const [users] = await connection.execute(
      'SELECT id, email, username, password_hash FROM users WHERE id = ?',
      [tokenRecord.user_id]
    );
    
    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const user = users[0];
    
    // Check if new password matches current password
    const isSameAsCurrent = await bcrypt.compare(password, user.password_hash);
    if (isSameAsCurrent) {
      return res.status(400).json({
        success: false,
        message: 'New password cannot be the same as the current password'
      });
    }
    
    // Check password history to prevent reuse
    const [passwordHistory] = await connection.execute(
      'SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 3',
      [user.id]
    );
    
    // Check against previous passwords
    for (const history of passwordHistory) {
      const isPasswordReused = await bcrypt.compare(password, history.password_hash);
      if (isPasswordReused) {
        return res.status(400).json({
          success: false,
          message: 'Cannot reuse recent passwords'
        });
      }
    }
    
    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Start a transaction for updating password and related operations
    await connection.beginTransaction();
    
    try {
      // Update the user's password
      await connection.execute(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        [hashedPassword, user.id]
      );
      
      // Store the old password in password history
      await connection.execute(
        'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
        [user.id, user.password_hash]
      );
      
      // Delete the used token
      await connection.execute(
        'DELETE FROM password_reset_tokens WHERE token = ?',
        [tokenHash]
      );
      
      // Log the successful password reset
      await connection.execute(
        'INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)',
        [user.id, 'PASSWORD_RESET_SUCCESS', 'Password reset completed successfully', clientIP]
      );
      
      // Commit the transaction
      await connection.commit();
      
      return res.status(200).json({
        success: true,
        message: 'Password has been reset successfully'
      });
    } catch (error) {
      // Rollback if any error occurs
      await connection.rollback();
      throw error;
    }
  } catch (error) {
    console.error('Reset password error:', error);
    return handleError(res, error, 'Error resetting password');
  } finally {
    if (connection) connection.release();
  }
};

// Export all controller methods
module.exports = {
  // User authentication
  signup,
  login,
  logout,
  getProfile,
  forgotPassword,
  resetPassword,
  
  
  // Admin management
  setupInitialAdmin,
  createAdmin,
  listAdmins,
  migrateAdmin,
  updateAdminStatus,
  getAdminDetails,
  resetAdminPassword
};

