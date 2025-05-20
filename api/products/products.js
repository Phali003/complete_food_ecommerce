const express = require('express');
const router = express.Router();
const { pool } = require('../../config/database');

/**
 * @desc    Get all products with filtering and pagination
 * @route   GET /api/products
 * @access  Public - Any user can view products
 */
// Product controller imports
const ProductModel = require('../../models/ProductModel');
const Joi = require('joi');

/**
 * Validate product data
 */
const validateProduct = (data) => {
  const schema = Joi.object({
    name: Joi.string().min(3).max(100).required(),
    description: Joi.string().allow('', null),
    price: Joi.number().min(0).required(),
    category: Joi.string().min(2).max(50).required(),
    stock_quantity: Joi.number().integer().min(0).required(),
    image_url: Joi.string().allow('', null)
  });

  return schema.validate(data);
};
/**
 * Get all products with optional filtering and pagination
 */

/**
 * Get all products with optional filtering and pagination
 */
const getProducts = async (req, res) => {
  try {
    // Extract query parameters
    const {
      category,
      minPrice,
      maxPrice,
      search,
      sort,
      order,
      page = 1,
      limit = 10
    } = req.query;

    // Calculate offset for pagination
    const offset = (page - 1) * limit;

    // Build options object for model
    const options = {
      category,
      minPrice,
      maxPrice,
      search,
      sort,
      order,
      limit: parseInt(limit),
      offset: parseInt(offset)
    };

    // Get products and count
    const products = await ProductModel.getAllProducts(options);
    const totalProducts = await ProductModel.countProducts({
      category,
      minPrice,
      maxPrice,
      search
    });

    // Calculate pagination metadata
    const totalPages = Math.ceil(totalProducts / limit);

    // Return response
    return res.status(200).json({
      success: true,
      data: {
        products,
        pagination: {
          total: totalProducts,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages
        }
      }
    });
  } catch (error) {
    console.error('Error getting products:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while fetching products'
    });
  }
};

/**
 * Get a single product by ID
 */
const getProductById = async (req, res) => {
  try {
    const { id } = req.params;

    // Get product
    const product = await ProductModel.getProductById(id);

    // Check if product exists
    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    // Return response
    return res.status(200).json({
      success: true,
      data: { product }
    });
  } catch (error) {
    console.error('Error getting product:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while fetching product'
    });
  }
};

/**
 * Create a new product (admin only)
 */
const createProduct = async (req, res) => {
  try {
    // Validate input
    const { error } = validateProduct(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message
      });
    }

    // Create product
    const product = await ProductModel.createProduct(req.body);

    // Return response
    return res.status(201).json({
      success: true,
      message: 'Product created successfully',
      data: { product }
    });
  } catch (error) {
    console.error('Error creating product:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while creating product'
    });
  }
};

/**
 * Update a product (admin only)
 */
const updateProduct = async (req, res) => {
  try {
    const { id } = req.params;

    // Validate input
    const { error } = validateProduct(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message
      });
    }

    // Check if product exists
    const existingProduct = await ProductModel.getProductById(id);
    if (!existingProduct) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    // Update product
    const success = await ProductModel.updateProduct(id, req.body);

    // Return response
    if (success) {
      const updatedProduct = await ProductModel.getProductById(id);
      return res.status(200).json({
        success: true,
        message: 'Product updated successfully',
        data: { product: updatedProduct }
      });
    } else {
      return res.status(400).json({
        success: false,
        message: 'Failed to update product'
      });
    }
  } catch (error) {
    console.error('Error updating product:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while updating product'
    });
  }
};

/**
 * Delete a product (admin only)
 */
const deleteProduct = async (req, res) => {
  try {
    const { id } = req.params;

    // Check if product exists
    const existingProduct = await ProductModel.getProductById(id);
    if (!existingProduct) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    // Delete product
    const success = await ProductModel.deleteProduct(id);

    // Return response
    if (success) {
      return res.status(200).json({
        success: true,
        message: 'Product deleted successfully'
      });
    } else {
      return res.status(400).json({
        success: false,
        message: 'Failed to delete product'
      });
    }
  } catch (error) {
    console.error('Error deleting product:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while deleting product'
    });
  }
};

/**
 * Get all product categories
 */
const getProductCategories = async (req, res) => {
  try {
    // Get categories
    const categories = await ProductModel.getAllCategories();

    // Return response
    return res.status(200).json({
      success: true,
      data: { categories }
    });
  } catch (error) {
    console.error('Error getting categories:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while fetching categories'
    });
  }
};

/**
 * Search products by name or description
 */
const searchProducts = async (req, res) => {
  try {
    const { term, page = 1, limit = 10 } = req.query;

    if (!term) {
      return res.status(400).json({
        success: false,
        message: 'Search term is required'
      });
    }

    // Calculate offset for pagination
    const offset = (page - 1) * limit;

    // Search products
    const products = await ProductModel.searchProducts(term, parseInt(limit), parseInt(offset));
    
    // Count total results for pagination
    const options = { search: term };
    const totalProducts = await ProductModel.countProducts(options);
    const totalPages = Math.ceil(totalProducts / limit);

    // Return response
    return res.status(200).json({
      success: true,
      data: {
        products,
        pagination: {
          total: totalProducts,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages
        }
      }
    });
  } catch (error) {
    console.error('Error searching products:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while searching products'
    });
  }
};

/**
 * Update product stock
 */
const updateProductStock = async (req, res) => {
  try {
    const { id } = req.params;
    const { quantity } = req.body;

    // Validate input
    if (!quantity || isNaN(quantity)) {
      return res.status(400).json({
        success: false,
        message: 'Valid quantity is required'
      });
    }

    // Check if product exists
    const existingProduct = await ProductModel.getProductById(id);
    if (!existingProduct) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    // Update stock
    const success = await ProductModel.updateStock(id, parseInt(quantity));

    // Return response
    if (success) {
      const updatedProduct = await ProductModel.getProductById(id);
      return res.status(200).json({
        success: true,
        message: 'Product stock updated successfully',
        data: { product: updatedProduct }
      });
    } else {
      return res.status(400).json({
        success: false,
        message: 'Failed to update product stock. Insufficient stock for deduction.'
      });
    }
  } catch (error) {
    console.error('Error updating product stock:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while updating product stock'
    });
  }
};

// Define routes
router.get('/', getProducts);
router.get('/categories', getProductCategories);
router.get('/search', searchProducts);
router.get('/:id', getProductById);
router.post('/', createProduct);
router.put('/:id', updateProduct);
router.delete('/:id', deleteProduct);
router.patch('/:id/stock', updateProductStock);

module.exports = router;

