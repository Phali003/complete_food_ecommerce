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
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate token
    const token = generateToken(user);

      // Set cookie with improved settings for cross-origin authentication
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: parseInt(process.env.COOKIE_MAX_AGE) || 24 * 60 * 60 * 1000, // 24 hours
        path: '/',
        domain: process.env.NODE_ENV === 'production' ? '.onrender.com' : undefined
      });

      // Log cookie settings for debugging
      console.log('Setting auth cookie with config:', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        domain: process.env.NODE_ENV === 'production' ? '.onrender.com' : undefined,
        env: process.env.NODE_ENV
      });

    console.log('Successful login for user:', user.username);
    console.log('Cookie settings:', {
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      domain: process.env.NODE_ENV === 'production' ? '.onrender.com' : undefined
    });

    // Return user data and token
    return res.status(200).json({
      success: true,
      message: 'Logged in successfully',
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
    console.error('Login error:', error);
    console.error('Error details:', {
      name: error.name,
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage
    });
    
    // Return a specific status code and message based on the error
    return res.status(500).json({
      success: false,
      message: 'Server error during login',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
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
 * Test Endpoints
 */
const testSuccess = (req, res) => {
    return res.status(200).json({
        success: true,
        message: "Test endpoint successful",
        timestamp: new Date().toISOString()
    });
};

const testError = (req, res) => {
    return res.status(500).json({
        success: false,
        message: "Test error endpoint",
        error: "This is a test error"
    });
};

const testDatabase = async (req, res) => {
    try {
        const connection = await pool.testDirectConnection();
        return res.status(200).json({
            success: true,
            message: "Database connection test",
            result: connection ? "successful" : "failed"
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Database connection test failed",
            error: error.message
        });
    }
};

const testCreateUser = async (req, res) => {
    try {
        const testUser = {
            username: `test_${Date.now()}`,
            email: `test_${Date.now()}@example.com`,
            password: "Test123!"
        };
        
        const user = await UserModel.createUser(testUser);
        
        return res.status(201).json({
            success: true,
            message: "Test user created successfully",
            userId: user.id,
            username: user.username
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Failed to create test user",
            error: error.message
        });
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

// Export all controller methods
module.exports = {
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
  resetAdminPassword
};

