/**
 * authController.js - Authentication and user management
 * Handles user authentication, admin management, and test endpoints
 */

// --------------------------------------
// Imports
// --------------------------------------
const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Joi = require('joi');
const nodemailer = require('nodemailer');
// Import required models
const { UserModel } = require('../models/UserModel');
const { BlacklistedTokenModel } = require('../models/BlacklistedTokenModel');
// Import email service 
const { sendPasswordResetEmail, testEmailConfig } = require('../services/emailService');
const { generateToken } = require('../utils/jwt');

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
  let connection = null;
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
    
    // Create a connection from the pool
    connection = await pool.getConnection();
    console.log('Connection 1 acquired');
    
    // Start a transaction for data consistency
    await connection.beginTransaction();
    console.log('Transaction started for signup');
    
    try {
      // Check if user already exists with this email - direct query for transaction safety
      const [emailExists] = await connection.query(
        'SELECT COUNT(*) as count FROM users WHERE LOWER(email) = LOWER(?)',
        [email]
      );
      
      if (emailExists && emailExists[0] && emailExists[0].count > 0) {
        console.log('User already exists with email:', email);
        await connection.rollback();
        return res.status(400).json({
          success: false,
          message: 'User already exists with this email'
        });
      }

      // Check if username is already taken - direct query for transaction safety
      const [usernameExists] = await connection.query(
        'SELECT COUNT(*) as count FROM users WHERE LOWER(username) = LOWER(?)',
        [username]
      );
      
      if (usernameExists && usernameExists[0] && usernameExists[0].count > 0) {
        console.log('Username already taken:', username);
        await connection.rollback();
        return res.status(400).json({
          success: false,
          message: 'Username is already taken'
        });
      }

      // Hash the password
      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash(password, salt);
      
      // Insert the user
      const [result] = await connection.execute(
        'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
        [username, email, passwordHash, 'user']
      );
      
      const userId = result.insertId;
      
      // Verify the user was created
      const [userRows] = await connection.query(
        'SELECT id, username, email, role, created_at FROM users WHERE id = ?',
        [userId]
      );
      
      if (!userRows || userRows.length === 0) {
        throw new Error('User creation failed - unable to retrieve new user');
      }
      
      const user = userRows[0];
      console.log('User created successfully with ID:', user.id);
      
      // Commit the transaction
      await connection.commit();
      console.log('Transaction committed for signup');
      
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
    } catch (txError) {
      // Rollback on transaction error
      console.error('Transaction error during signup:', txError);
      if (connection) {
        await connection.rollback();
        console.log('Transaction rolled back due to error');
      }
      throw txError;
    }
  } catch (error) {
    console.error('Registration error:', error);
    return handleError(res, error, 'Server error during registration');
  } finally {
    // Always release connection in finally block
    if (connection) {
      try {
        connection.release();
        console.log('Connection 1 released');
      } catch (releaseError) {
        console.error('Error releasing connection:', releaseError);
      }
    }
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
  // Generate a unique request ID for tracking this specific request through logs
  const requestId = crypto.randomBytes(4).toString('hex');
  console.log(`[${requestId}] Processing forgot password request`);
  
  // Log database connection settings at the start
  console.log(`[${requestId}] Database config:`, {
    host: process.env.DB_HOST || 'not set',
    database: process.env.DB_NAME || 'not set',
    ssl: process.env.DB_SSL || 'not set',
    port: process.env.DB_PORT || 'not set',
    sslMode: process.env.DB_SSL_MODE || 'not set'
  });
  
  let connection = null;
  let transactionStarted = false;
  let connectionAcquired = false;
  
  try {
    const { email } = req.body;
    
    // Validate email
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required',
        requestId: requestId
      });
    }
    
    // Get client IP for rate limiting
    const clientIP = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    console.log(`[${requestId}] Request from IP: ${clientIP}`);
    
    // Get a database connection from the pool with full SSL verification
    try {
      console.log(`[${requestId}] Attempting to acquire database connection...`);
      connection = await pool.getConnection();
      connectionAcquired = true;
      console.log(`[${requestId}] Database connection acquired successfully`);
      
      // Check connection configuration details
      console.log(`[${requestId}] Connection config:`, {
        ssl: connection.config?.ssl ? 'Configured' : 'Not Configured',
        sslMode: process.env.DB_SSL_MODE || 'not set',
        certPath: process.env.SSL_CERT_PATH || 'not set',
        connectTimeout: connection.config?.connectTimeout || 'default',
        connectionLimit: pool.config?.connectionLimit || 'unknown'
      });
      
      // Verify the connection works with a simple query
      const [connectionTest] = await connection.query('SELECT 1 as connection_test');
      console.log(`[${requestId}] Connection test successful:`, connectionTest[0]);
      
      // Check SSL status and ciphers if possible
      try {
        const [sslStatus] = await connection.query(`
          SHOW STATUS LIKE 'Ssl_cipher'
        `);
        
        if (sslStatus && sslStatus.length > 0) {
          console.log(`[${requestId}] SSL Status: ${sslStatus[0].Variable_name} = ${sslStatus[0].Value}`);
          // Additional SSL verification
          const [sslVersion] = await connection.query(`SHOW STATUS LIKE 'Ssl_version'`);
          if (sslVersion && sslVersion.length > 0) {
            console.log(`[${requestId}] ${sslVersion[0].Variable_name} = ${sslVersion[0].Value}`);
          }
          
          // Check more comprehensive SSL status
          const [sslParams] = await connection.query(`
            SHOW STATUS WHERE Variable_name LIKE 'ssl%'
          `);
          if (sslParams && sslParams.length > 0) {
            console.log(`[${requestId}] Full SSL parameters:`, 
              sslParams.reduce((obj, item) => {
                obj[item.Variable_name] = item.Value;
                return obj;
              }, {})
            );
          }
        } else {
          console.warn(`[${requestId}] WARNING: SSL may not be enabled for this connection`);
        }
      } catch (sslCheckError) {
        console.error(`[${requestId}] Error checking SSL status:`, sslCheckError);
      }
      
    } catch (connectionError) {
      console.error(`[${requestId}] ERROR ACQUIRING CONNECTION:`, connectionError);
      throw new Error(`Database connection failed: ${connectionError.message}`);
    }
    
    // Log connection pool status if available
    try {
      if (pool && typeof pool.getConnectionCount === 'function') {
        const poolStatus = await pool.getConnectionCount().catch(err => ({ error: err.message }));
        console.log(`[${requestId}] Current pool status:`, poolStatus);
      } else {
        console.log(`[${requestId}] Pool status check not available`);
      }
    } catch (poolError) {
      console.error(`[${requestId}] Failed to check pool status:`, poolError);
    }
    
    // Begin transaction for data consistency
    try {
      console.log(`[${requestId}] Starting transaction...`);
      await connection.beginTransaction();
      transactionStarted = true;
      console.log(`[${requestId}] Transaction started successfully`);
      
      // Log transaction isolation level for debugging
      const [isolationLevel] = await connection.query('SELECT @@transaction_isolation as level');
      console.log(`[${requestId}] Transaction isolation level:`, isolationLevel[0].level);
    } catch (transactionError) {
      console.error(`[${requestId}] Transaction start failed:`, transactionError);
      throw new Error(`Failed to start transaction: ${transactionError.message}`);
    }
    
    try {
      // Check rate limiting for this IP to prevent abuse
      console.log(`[${requestId}] Checking rate limits for IP: ${clientIP}`);
      const [rateLimitCheck] = await connection.execute(
        'SELECT COUNT(*) as count FROM password_reset_attempts WHERE ip_address = ? AND attempt_timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)',
        [clientIP]
      );
      console.log(`[${requestId}] Rate limit check result:`, rateLimitCheck[0]);
      
      // If more than 5 attempts in the last hour from this IP, rate limit
      if (rateLimitCheck[0].count >= 5) {
        console.log(`[${requestId}] Rate limit exceeded for IP ${clientIP}: ${rateLimitCheck[0].count} attempts`);
        
        if (transactionStarted) {
          await connection.rollback();
          console.log(`[${requestId}] Transaction rolled back due to rate limit`);
        }
        
        return res.status(429).json({
          success: false,
          message: 'Too many password reset requests. Please try again later.',
          retryAfter: 3600 // 1 hour in seconds
        });
      }
      
      // Record this attempt regardless of whether the email exists
      await connection.execute(
        'INSERT INTO password_reset_attempts (ip_address, email, attempt_timestamp) VALUES (?, ?, NOW())',
        [clientIP, email]
      );
      console.log(`[${requestId}] Recorded password reset attempt for tracking`);
      
      // Check if the email exists in our system
      console.log(`[${requestId}] Checking if email exists: ${email}`);
      const [userRows] = await connection.execute(
        'SELECT id, username, email FROM users WHERE LOWER(email) = LOWER(?)',
        [email]
      );
      
      // Don't reveal whether or not the email exists for security
      // Always pretend we found the user and sent the email
      if (userRows.length === 0) {
        console.log(`[${requestId}] Email not found in system: ${email}`);
        
        // Commit transaction even though we won't send an email
        await connection.commit();
        transactionStarted = false;
        console.log(`[${requestId}] Transaction committed (no user found case)`);
        
        // Return success message to prevent user enumeration
        return res.status(200).json({
          success: true,
          message: 'If your email is registered in our system, you will receive password reset instructions shortly',
          requestId: requestId
        });
      }
      
      // At this point we have a valid user
      const user = userRows[0];
      console.log(`[${requestId}] User found with ID: ${user.id}`);
      
      // Generate a secure random token
      const resetToken = crypto.randomBytes(32).toString('hex');
      
      // Create a hash of the token to store in the database
      const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
      console.log(`[${requestId}] Reset token generated for user ID: ${user.id}`);
      
      // Set token expiration (1 hour)
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 1);
      
      // Delete any existing tokens for this user
      await connection.execute(
        'DELETE FROM password_reset_tokens WHERE user_id = ?',
        [user.id]
      );
      console.log(`[${requestId}] Deleted any existing reset tokens for user`);
      
      // Save the token in the database
      await connection.execute(
        'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
        [user.id, resetTokenHash, expiresAt]
      );
      console.log(`[${requestId}] New reset token stored in database with expiry: ${expiresAt.toISOString()}`);
      
      // Commit the transaction
      await connection.commit();
      transactionStarted = false;
      console.log(`[${requestId}] Database transaction committed successfully`);
      
      // Generate reset URL for the frontend
      const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
      console.log(`[${requestId}] Reset URL generated: ${resetUrl.substring(0, 30)}...`);
      
      try {
        // Send email with reset link outside of transaction
        console.log(`[${requestId}] Attempting to send password reset email to: ${user.email}`);
        
        // Use the sendPasswordResetEmail function (imported directly)
        // Pass the parameters as an object as expected by the service
        const emailResult = await sendPasswordResetEmail({
          email: user.email,
          username: user.username,
          resetUrl: resetUrl,
          requestId: requestId // Explicitly pass the requestId for better tracing
        }).catch(error => {
          console.error(`[${requestId}] Email sending error caught:`, error);
          return { success: false, error: error.message || 'Unknown email error' };
        });
        
        console.log(`[${requestId}] Email sending result:`, emailResult);
        
        if (!emailResult || !emailResult.success) {
          console.error(`[${requestId}] Failed to send email:`, emailResult?.error || 'No result returned from email service');
          throw new Error(`Email sending failed: ${emailResult?.error || 'Email service error'}`);
        }
        
        console.log(`[${requestId}] Password reset email sent successfully to: ${user.email}`);
        
      } catch (emailError) {
        console.error(`[${requestId}] Email service error:`, emailError);
        
        // Check specifically for Resend API permission errors
        const isResendPermissionError = 
          emailError.message?.includes('only allows sending to verified email addresses') ||
          emailError.message?.includes('not a permitted address');
          
        if (isResendPermissionError && process.env.NODE_ENV === 'development') {
          console.warn(`[${requestId}] Resend API test mode restriction detected: ${emailError.message}`);
        }
        
        // Log the error but don't fail the request - the user can request another reset
        // The token is already saved in the database
        return res.status(200).json({
          success: true,
          message: 'If your email is registered in our system, you will receive password reset instructions shortly',
          warning: process.env.NODE_ENV === 'development' ? 'Email sending failed, but token was created. Check server logs.' : undefined,
          requestId: requestId
        });
      }
      
      // Return success response
      return res.status(200).json({
        success: true,
        message: 'If your email is registered in our system, you will receive password reset instructions shortly',
        requestId: requestId
      });
      
    } catch (dbError) {
      console.error(`[${requestId}] Database error:`, dbError);
      
      // Log detailed information about the error for better diagnostics
      console.error(`[${requestId}] Database error details:`, {
        code: dbError.code || 'No error code',
        sqlState: dbError.sqlState || 'No SQL state',
        sqlMessage: dbError.sqlMessage || 'No SQL message',
        stack: dbError.stack || 'No stack trace'
      });
      
      // Check for specific MySQL error codes related to SSL
      if (dbError.code === 'ER_SSL_CONNECTION_ERROR' || 
          dbError.sqlMessage?.includes('SSL') || 
          dbError.sqlMessage?.includes('certificate')) {
        console.error(`[${requestId}] SSL connection error detected. Check certificate configuration.`);
      }
      
      // Rollback if transaction was started
      if (transactionStarted && connection) {
        try {
          await connection.rollback();
          transactionStarted = false;
          console.log(`[${requestId}] Transaction rolled back after database error`);
        } catch (rollbackError) {
          console.error(`[${requestId}] Failed to rollback transaction:`, rollbackError);
        }
      }
      
      throw new Error(`Database operation failed: ${dbError.message}`);
    }
    
  } catch (error) {
    console.error(`[${requestId}] Forgot password critical error:`, error);
    
    // Capture error details for debugging
    const errorDetails = {
      message: error.message,
      code: error.code || 'No error code',
      stack: process.env.NODE_ENV === 'development' ? error.stack : 'Hidden in production',
      timestamp: new Date().toISOString(),
      requestId: requestId
    };
    console.error(`[${requestId}] Error details:`, errorDetails);
    
    // Ensure we rollback any open transaction
    if (transactionStarted && connection) {
      try {
        await connection.rollback();
        console.log(`[${requestId}] Transaction rolled back in error handler`);
      } catch (rollbackError) {
        console.error(`[${requestId}] Rollback error in error handler:`, rollbackError);
      }
    }
    
    // Determine specific error message based on error type
    let errorMessage = 'An error occurred processing your request';
    let errorCategory = 'GENERAL_ERROR';
    
    if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
      errorMessage = 'Database connection error. Please try again later.';
      errorCategory = 'DB_CONNECTION_ERROR';
    } else if (error.message.includes('SSL') || error.message.includes('certificate')) {
      errorMessage = 'Secure connection issue. Please try again later.';
      errorCategory = 'SSL_ERROR';
    } else if (error.message.includes('handshake') || error.message.includes('Client does not support authentication protocol')) {
      errorMessage = 'Database authentication failed. Please try again later.';
      errorCategory = 'DB_AUTH_ERROR';
    } else if (error.message.includes('email') || error.message.includes('sending')) {
      // Check for Resend API specific errors
      if (error.message.includes('only allows sending to verified email addresses') || 
          error.message.includes('not a permitted address')) {
        console.warn(`[${requestId}] Resend test mode restriction detected in error handler`);
        // In production, we don't want to reveal the real issue to maintain security
        errorMessage = process.env.NODE_ENV === 'development' ? 
          'Email service in test mode - can only send to verified addresses. Use a verified test email address.' :
          'Error sending email. Your reset token was created, but the email could not be sent.';
        errorCategory = 'EMAIL_RESTRICTION_ERROR';
      } else {
        errorMessage = 'Error sending email. Your reset token was created, but the email could not be sent.';
        errorCategory = 'EMAIL_SEND_ERROR';
      }
    }
    
    return res.status(500).json({
      success: false,
      message: errorMessage,
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      category: errorCategory,
      requestId: requestId
    });
  } finally {
    // Always release the connection in finally block
    if (connection && connectionAcquired) {
      try {
        console.log(`[${requestId}] Releasing database connection`);
        await connection.release();
        console.log(`[${requestId}] Database connection released successfully`);
      } catch (releaseError) {
        console.error(`[${requestId}] Error releasing database connection:`, releaseError);
        // Don't throw error here, as it would override any error in the main try-catch
      }
    }
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
    console.error('Forgot password error:', error);
    return handleError(res, error, 'Error processing password reset request');
  } finally {
    if (connection) {
      try {
        connection.release();
        console.log('Connection 2 released');
      } catch (releaseError) {
        console.error('Error releasing connection:', releaseError);
      }
    }
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

