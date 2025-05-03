const UserModel = require('../models/UserModel');
const { generateToken } = require('../utils/jwt');
const Joi = require('joi');

/**
 * Validate user registration data
 */
const validateSignup = (data) => {
  const schema = Joi.object({
    username: Joi.string().min(3).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).max(50).required(),
    confirm_password: Joi.ref('password')
  }).with('password', 'confirm_password');

  return schema.validate(data);
};

/**
 * Validate user login data
 * Supports login with a single identifier field (email or username)
 */
const validateLogin = (data) => {
  const schema = Joi.object({
    identifier: Joi.string().required(),
    password: Joi.string().required()
  }).required();

  return schema.validate(data);
};
/**
 * User registration controller
 */
const signup = async (req, res) => {
  try {
    console.log('Starting user registration process');
    // Validate input data
    const { error } = validateSignup(req.body);
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

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
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
    return res.status(500).json({
      success: false,
      message: 'Server error during registration',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * User login controller
 * Supports login with either email or username
 */
const login = async (req, res) => {
  try {
    console.log('Starting login process');
    // Validate input data
    const { error } = validateLogin(req.body);
    if (error) {
      console.log('Login validation error:', error.details[0].message);
      return res.status(400).json({
        success: false,
        message: error.details[0].message
      });
    }

    const { identifier, password } = req.body;
    console.log('Login attempt with identifier:', identifier);

    // Find user by email or username
    let user = null;
    // Check if identifier is email
    if (identifier.includes('@')) {
      console.log('Attempting login with email');
      user = await UserModel.findByEmail(identifier);
    } else {
      console.log('Attempting login with username');
      user = await UserModel.findByUsername(identifier);
    }

    if (!user) {
      console.log('No user found for identifier:', identifier);
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Verify password
    const isPasswordValid = await UserModel.verifyPassword(password, user.password_hash);
    if (!isPasswordValid) {
      console.log('Invalid password for user:', user.username);
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate token
    const token = generateToken(user);

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    console.log('Successful login for user:', user.username);

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
const logout = (req, res) => {
  try {
    console.log('Processing logout request');
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

module.exports = {
  signup,
  login,
  logout,
  getProfile
};

