const { query } = require('../config/database');

/**
 * Product Model - Handles all product-related database operations
 */
class ProductModel {
  /**
   * Create a new product
   * @param {Object} productData - Product data
   * @returns {Object} Created product
   */
  static async createProduct(productData) {
    const { name, description, price, category, stock_quantity, image_url } = productData;
    
    const sql = `
      INSERT INTO products (name, description, price, category, stock_quantity, image_url)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    
    const result = await query(sql, [name, description, price, category, stock_quantity, image_url]);
    
    return {
      id: result.insertId,
      name,
      description,
      price,
      category,
      stock_quantity,
      image_url
    };
  }
  
  /**
   * Get all products with optional filtering and pagination
   * @param {Object} options - Filter and pagination options
   * @returns {Array} List of products
   */
  static async getAllProducts(options = {}) {
    const {
      category,
      minPrice,
      maxPrice,
      search,
      sort = 'name',
      order = 'ASC',
      limit = 10,
      offset = 0
    } = options;
    
    let sql = `SELECT * FROM products WHERE 1=1`;
    const params = [];
    
    // Apply filters if provided
    if (category) {
      sql += ` AND category = ?`;
      params.push(category);
    }
    
    if (minPrice) {
      sql += ` AND price >= ?`;
      params.push(minPrice);
    }
    
    if (maxPrice) {
      sql += ` AND price <= ?`;
      params.push(maxPrice);
    }
    
    if (search) {
      sql += ` AND (name LIKE ? OR description LIKE ?)`;
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm);
    }
    
    // Apply sorting
    const validSortColumns = ['name', 'price', 'category', 'created_at'];
    const validOrderDirections = ['ASC', 'DESC'];
    
    const sortColumn = validSortColumns.includes(sort) ? sort : 'name';
    const orderDirection = validOrderDirections.includes(order.toUpperCase()) ? order : 'ASC';
    
    sql += ` ORDER BY ${sortColumn} ${orderDirection}`;
    
    // Apply pagination - use direct values instead of parameters for LIMIT and OFFSET
    const limitInt = parseInt(limit);
    const offsetInt = parseInt(offset);
    sql += ` LIMIT ${limitInt} OFFSET ${offsetInt}`;
    
    return await query(sql, params);
  }
  
  /**
   * Get a product by ID
   * @param {Number} id - Product ID
   * @returns {Object|null} Product data or null if not found
   */
  static async getProductById(id) {
    const sql = `SELECT * FROM products WHERE id = ?`;
    
    const products = await query(sql, [id]);
    
    return products.length > 0 ? products[0] : null;
  }
  
  /**
   * Get products by category
   * @param {String} category - Product category
   * @param {Number} limit - Maximum number of products to return
   * @param {Number} offset - Offset for pagination
   * @returns {Array} List of products
   */
  static async getProductsByCategory(category, limit = 10, offset = 0) {
    // Parse limit and offset as integers
    const limitInt = parseInt(limit);
    const offsetInt = parseInt(offset);
    
    const sql = `
      SELECT *
      FROM products
      WHERE category = ?
      LIMIT ${limitInt} OFFSET ${offsetInt}
    `;
    
    return await query(sql, [category]);
  }
  
  /**
   * Update a product
   * @param {Number} id - Product ID
   * @param {Object} productData - Product data to update
   * @returns {Boolean} Success status
   */
  static async updateProduct(id, productData) {
    const { name, description, price, category, stock_quantity, image_url } = productData;
    
    const sql = `
      UPDATE products
      SET name = ?, description = ?, price = ?, category = ?, stock_quantity = ?, image_url = ?
      WHERE id = ?
    `;
    
    const result = await query(sql, [name, description, price, category, stock_quantity, image_url, id]);
    
    return result.affectedRows > 0;
  }
  
  /**
   * Delete a product
   * @param {Number} id - Product ID
   * @returns {Boolean} Success status
   */
  static async deleteProduct(id) {
    const sql = `DELETE FROM products WHERE id = ?`;
    
    const result = await query(sql, [id]);
    
    return result.affectedRows > 0;
  }
  
  /**
   * Update product stock quantity
   * @param {Number} id - Product ID
   * @param {Number} quantity - Quantity to add (positive) or subtract (negative)
   * @returns {Boolean} Success status
   */
  static async updateStock(id, quantity) {
    const sql = `
      UPDATE products
      SET stock_quantity = stock_quantity + ?
      WHERE id = ? AND stock_quantity + ? >= 0
    `;
    
    const result = await query(sql, [quantity, id, quantity]);
    
    return result.affectedRows > 0;
  }
  
  /**
   * Check if a product has sufficient stock
   * @param {Number} id - Product ID
   * @param {Number} requiredQuantity - Required quantity
   * @returns {Boolean} True if sufficient stock is available
   */
  static async hasSufficientStock(id, requiredQuantity) {
    const sql = `
      SELECT stock_quantity
      FROM products
      WHERE id = ?
    `;
    
    const products = await query(sql, [id]);
    
    if (products.length === 0) {
      return false;
    }
    
    return products[0].stock_quantity >= requiredQuantity;
  }
  
  /**
   * Get all product categories
   * @returns {Array} List of unique product categories
   */
  static async getAllCategories() {
    const sql = `
      SELECT DISTINCT category
      FROM products
      ORDER BY category
    `;
    
    return await query(sql);
  }
  
  /**
   * Search products by name or description
   * @param {String} searchTerm - Search term
   * @param {Number} limit - Maximum number of products to return
   * @param {Number} offset - Offset for pagination
   * @returns {Array} List of products
   */
  static async searchProducts(searchTerm, limit = 10, offset = 0) {
    // Parse limit and offset as integers
    const limitInt = parseInt(limit);
    const offsetInt = parseInt(offset);
    
    const sql = `
      SELECT *
      FROM products
      WHERE name LIKE ? OR description LIKE ?
      LIMIT ${limitInt} OFFSET ${offsetInt}
    `;
    
    const search = `%${searchTerm}%`;
    
    return await query(sql, [search, search]);
  }
  
  /**
   * Count products with optional filtering
   * @param {Object} options - Filter options
   * @returns {Number} Product count
   */
  static async countProducts(options = {}) {
    const { category, minPrice, maxPrice, search } = options;
    
    let sql = `SELECT COUNT(*) as count FROM products WHERE 1=1`;
    const params = [];
    
    if (category) {
      sql += ` AND category = ?`;
      params.push(category);
    }
    
    if (minPrice) {
      sql += ` AND price >= ?`;
      params.push(minPrice);
    }
    
    if (maxPrice) {
      sql += ` AND price <= ?`;
      params.push(maxPrice);
    }
    
    if (search) {
      sql += ` AND (name LIKE ? OR description LIKE ?)`;
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm);
    }
    
    const result = await query(sql, params);
    
    return result[0].count;
  }
}

module.exports = ProductModel;

