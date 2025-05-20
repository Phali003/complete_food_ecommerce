const express = require('express');
const router = express.Router();
const path = require('path');
const jwt = require('jsonwebtoken');
const pool = require('../api/config/database');

/**
 * Middleware to authenticate JWT token
 */
function authenticateToken(req, res, next) {
  // Get token from cookie or Authorization header
  const token = req.cookies.token || 
    (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  
  if (!token) {
    return res.redirect('/login');
  }
  
  // Verify token
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Token verification error:', err.message);
      res.clearCookie('token');
      return res.redirect('/login');
    }
    
    // Add user info to request
    req.user = user;
    next();
  });
}

/**
 * Middleware to check if user is admin
 */
async function isAdmin(req, res, next) {
  if (!req.user) {
    return res.redirect('/login');
  }
  
  try {
    // Get user from database
    let connection;
    try {
      connection = await pool.getConnection();
      const [users] = await connection.execute(
        'SELECT role FROM users WHERE id = ?',
        [req.user.userId]
      );
      
      if (users.length === 0) {
        return res.redirect('/login');
      }
      
      // Check if user is admin
      if (users[0].role !== 'admin') {
        return res.redirect('/unauthorized');
      }
      
      next();
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('Error in admin check middleware:', error);
    res.status(500).sendFile(path.join(__dirname, '../public/error.html'));
  }
}

/**
 * Helper function to check if admin exists
 * @returns {Promise<boolean>} True if admin exists, false otherwise
 */
const checkAdminExists = async () => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT COUNT(*) as count FROM users WHERE role = ?',
      ['admin']
    );
    return rows[0].count > 0;
  } catch (error) {
    console.error('Error checking admin existence:', error);
    throw error;
  } finally {
    if (connection) connection.release();
  }
};

// Home page
router.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../index.html'));
});

// Login page
router.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../Signing/login.html'));
});

// Signup page
router.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, '../Signing/signup.html'));
});

// Admin Setup page
router.get('/admin-setup', async (req, res) => {
  res.sendFile(path.join(__dirname, '../admin/admin-setup.html'));
});

// Admin dashboard page (protected route, should be handled with middleware)
router.get('/admin/dashboard', authenticateToken, isAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../admin/dashboard.html'));
});

// User dashboard page (protected route)
router.get('/user/dashboard', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, '../user/dashboard.html'));
});

// Check admin existence API endpoint
router.get('/api/auth/check-admin-exists', async (req, res) => {
  try {
    const adminExists = await checkAdminExists();
    res.json({ exists: adminExists });
  } catch (error) {
    console.error('Error checking admin existence:', error);
    res.status(500).json({ 
      error: 'Server error while checking admin existence',
      exists: true // Default to true for security reasons if there's an error
    });
  }
});

// Unauthorized access page
router.get('/unauthorized', (req, res) => {
  res.sendFile(path.join(__dirname, '../error/unauthorized.html'));
});

// Not Found handler - must be registered at the end
router.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '../error/404.html'));
});

// Module exports

module.exports = router;

