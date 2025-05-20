const express = require('express');
const router = express.Router();
const pool = require('../config/database');
const { protect, isAdmin } = require('../middleware/auth');

// Debug middleware to log route access
router.use((req, res, next) => {
  console.log(`[DEBUG] Products route accessed: ${req.method} ${req.path}`);
  next();
});

// PUBLIC ROUTES - No authentication required

/**
 * @route   GET /api/products
 * @desc    Get all products with filtering and pagination
 * @access  Public
 */
router.get('/', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    try {
      // Simple query without pagination first to ensure basic functionality
      const [products] = await connection.query('SELECT * FROM products WHERE stock_quantity > 0 ORDER BY id DESC');
      
      return res.status(200).json({
        success: true,
        products
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('Error fetching products:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching products',
      error: error.message
    });
  }
});

/**
 * @route   GET /api/products/categories
 * @desc    Get all product categories
 * @access  Public
 */
router.get('/categories', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    try {
      const [categories] = await connection.execute(
        'SELECT DISTINCT category FROM products WHERE stock_quantity > 0'
      );
      
      return res.status(200).json({
        success: true,
        categories: categories.map(c => c.category)
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('Error fetching categories:', error);
    return res.status(500).json({
      success: false, 
      message: 'Error fetching categories',
      error: error.message
    });
  }
});

/**
 * @route   GET /api/products/search
 * @desc    Search products by name or description
 * @access  Public
 */
router.get('/search', async (req, res) => {
  try {
    const { query: searchQuery } = req.query;
    
    if (!searchQuery) {
      return res.status(400).json({
        success: false,
        message: 'Search query is required'
      });
    }
    
    const connection = await pool.getConnection();
    try {
      const [products] = await connection.execute(
        'SELECT * FROM products WHERE (name LIKE ? OR description LIKE ?) AND stock_quantity > 0',
        [`%${searchQuery}%`, `%${searchQuery}%`]
      );
      
      return res.status(200).json({
        success: true,
        products,
        count: products.length
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('Error searching products:', error);
    return res.status(500).json({
      success: false,
      message: 'Error searching products',
      error: error.message
    });
  }
});

/**
 * @route   GET /api/products/:id
 * @desc    Get a single product by ID
 * @access  Public
 */
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const connection = await pool.getConnection();
    try {
      const [products] = await connection.execute(
        'SELECT * FROM products WHERE id = ?',
        [id]
      );
      
      if (products.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'Product not found'
        });
      }
      
      return res.status(200).json({
        success: true,
        product: products[0]
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('Error fetching product:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching product',
      error: error.message
    });
  }
});
// PROTECTED ROUTES - Admin only
// Apply protect and isAdmin middleware only to admin routes
router.use(protect, isAdmin);

/**
 * @route   POST /api/products
 * @desc    Create a new product
 * @access  Private/Admin
 */
router.post('/', async (req, res) => {
  try {
    const { name, description, price, category, stock_quantity, image_url } = req.body;
    
    // Validate required fields
    if (!name || !price || !category) {
      return res.status(400).json({
        success: false,
        message: 'Name, price, and category are required'
      });
    }
    
    const connection = await pool.getConnection();
    try {
      const [result] = await connection.execute(
        'INSERT INTO products (name, description, price, category, stock_quantity, image_url) VALUES (?, ?, ?, ?, ?, ?)',
        [name, description || '', parseFloat(price), category, parseInt(stock_quantity) || 0, image_url || '']
      );
      
      return res.status(201).json({
        success: true,
        message: 'Product created successfully',
        productId: result.insertId
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('Error creating product:', error);
    return res.status(500).json({
      success: false,
      message: 'Error creating product',
      error: error.message
    });
  }
});
/**
 * @route   PUT /api/products/:id
 * @desc    Update a product
 * @access  Private/Admin
 */
router.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price, category, stock_quantity, image_url } = req.body;
    
    const connection = await pool.getConnection();
    try {
      const [result] = await connection.execute(
        'UPDATE products SET name = ?, description = ?, price = ?, category = ?, stock_quantity = ?, image_url = ? WHERE id = ?',
        [name, description, parseFloat(price), category, parseInt(stock_quantity), image_url, id]
      );
      
      if (result.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: 'Product not found'
        });
      }
      
      return res.status(200).json({
        success: true,
        message: 'Product updated successfully'
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('Error updating product:', error);
    return res.status(500).json({
      success: false,
      message: 'Error updating product',
      error: error.message
    });
  }
});
/**
 * @route   DELETE /api/products/:id
 * @desc    Delete a product
 * @access  Private/Admin
 */
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const connection = await pool.getConnection();
    try {
      const [result] = await connection.execute(
        'DELETE FROM products WHERE id = ?',
        [id]
      );
      
      if (result.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: 'Product not found'
        });
      }
      
      return res.status(200).json({
        success: true,
        message: 'Product deleted successfully'
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('Error deleting product:', error);
    return res.status(500).json({
      success: false,
      message: 'Error deleting product',
      error: error.message
    });
  }
});
/**
 * @route   PATCH /api/products/:id/stock
 * @desc    Update product stock
 * @access  Private/Admin
 */
router.patch('/:id/stock', async (req, res) => {
  try {
    const { id } = req.params;
    const { stock_quantity } = req.body;
    
    if (stock_quantity === undefined) {
      return res.status(400).json({
        success: false,
        message: 'Stock quantity is required'
      });
    }
    
    const connection = await pool.getConnection();
    try {
      const [result] = await connection.execute(
        'UPDATE products SET stock_quantity = ? WHERE id = ?',
        [parseInt(stock_quantity), id]
      );
      
      if (result.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: 'Product not found'
        });
      }
      
      return res.status(200).json({
        success: true,
        message: 'Product stock updated successfully'
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('Error updating product stock:', error);
    return res.status(500).json({
      success: false,
      message: 'Error updating product stock',
      error: error.message
    });
  }
});

module.exports = router;

