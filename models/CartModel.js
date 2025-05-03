const { query, beginTransaction, commitTransaction, rollbackTransaction } = require('../config/database');

/**
 * Cart Model - Handles all cart-related database operations
 */
class CartModel {
  /**
   * Add an item to the user's cart
   * @param {Number} userId - User ID
   * @param {Number} productId - Product ID
   * @param {Number} quantity - Quantity to add
   * @returns {Object} Added cart item
   */
  static async addToCart(userId, productId, quantity) {
    // Check if product exists in the cart
    const existingItem = await this.getCartItem(userId, productId);
    
    if (existingItem) {
      // Update quantity if item already exists
      const newQuantity = existingItem.quantity + quantity;
      return await this.updateCartItemQuantity(userId, productId, newQuantity);
    }
    
    // Add new item if it doesn't exist
    const sql = `
      INSERT INTO cart_items (user_id, product_id, quantity)
      VALUES (?, ?, ?)
    `;
    
    const result = await query(sql, [userId, productId, quantity]);
    
    return {
      id: result.insertId,
      user_id: userId,
      product_id: productId,
      quantity
    };
  }
  
  /**
   * Get a specific cart item
   * @param {Number} userId - User ID
   * @param {Number} productId - Product ID
   * @returns {Object|null} Cart item or null if not found
   */
  static async getCartItem(userId, productId) {
    const sql = `
      SELECT *
      FROM cart_items
      WHERE user_id = ? AND product_id = ?
    `;
    
    const cartItems = await query(sql, [userId, productId]);
    
    return cartItems.length > 0 ? cartItems[0] : null;
  }
  
  /**
   * Update the quantity of a cart item
   * @param {Number} userId - User ID
   * @param {Number} productId - Product ID
   * @param {Number} quantity - New quantity
   * @returns {Object|null} Updated cart item or null if not found
   */
  static async updateCartItemQuantity(userId, productId, quantity) {
    // If quantity is 0 or less, remove the item
    if (quantity <= 0) {
      await this.removeFromCart(userId, productId);
      return null;
    }
    
    const sql = `
      UPDATE cart_items
      SET quantity = ?
      WHERE user_id = ? AND product_id = ?
    `;
    
    await query(sql, [quantity, userId, productId]);
    
    // Return updated item
    return await this.getCartItem(userId, productId);
  }
  
  /**
   * Remove an item from the cart
   * @param {Number} userId - User ID
   * @param {Number} productId - Product ID
   * @returns {Boolean} Success status
   */
  static async removeFromCart(userId, productId) {
    const sql = `
      DELETE FROM cart_items
      WHERE user_id = ? AND product_id = ?
    `;
    
    const result = await query(sql, [userId, productId]);
    
    return result.affectedRows > 0;
  }
  
  /**
   * Get all items in a user's cart with product details
   * @param {Number} userId - User ID
   * @returns {Array} Cart items with product details
   */
  static async getCart(userId) {
    const sql = `
      SELECT ci.id, ci.user_id, ci.product_id, ci.quantity, ci.created_at,
             p.name, p.price, p.image_url, p.category, p.stock_quantity
      FROM cart_items ci
      JOIN products p ON ci.product_id = p.id
      WHERE ci.user_id = ?
      ORDER BY ci.created_at DESC
    `;
    
    return await query(sql, [userId]);
  }
  
  /**
   * Calculate the total price of items in a user's cart
   * @param {Number} userId - User ID
   * @returns {Number} Total price
   */
  static async getCartTotal(userId) {
    const sql = `
      SELECT SUM(p.price * ci.quantity) as total
      FROM cart_items ci
      JOIN products p ON ci.product_id = p.id
      WHERE ci.user_id = ?
    `;
    
    const result = await query(sql, [userId]);
    
    return result[0].total || 0;
  }
  
  /**
   * Get the number of items in a user's cart
   * @param {Number} userId - User ID
   * @returns {Number} Number of items
   */
  static async getCartItemCount(userId) {
    const sql = `
      SELECT COUNT(*) as count
      FROM cart_items
      WHERE user_id = ?
    `;
    
    const result = await query(sql, [userId]);
    
    return result[0].count || 0;
  }
  
  /**
   * Clear all items from a user's cart
   * @param {Number} userId - User ID
   * @returns {Boolean} Success status
   */
  static async clearCart(userId) {
    const sql = `
      DELETE FROM cart_items
      WHERE user_id = ?
    `;
    
    const result = await query(sql, [userId]);
    
    return result.affectedRows > 0;
  }
  
  /**
   * Check if all items in the cart have sufficient stock
   * @param {Number} userId - User ID
   * @returns {Boolean} True if all items have sufficient stock
   */
  static async checkCartItemsStock(userId) {
    const sql = `
      SELECT ci.product_id, ci.quantity, p.stock_quantity
      FROM cart_items ci
      JOIN products p ON ci.product_id = p.id
      WHERE ci.user_id = ? AND ci.quantity > p.stock_quantity
    `;
    
    const insufficientItems = await query(sql, [userId]);
    
    // If any items have insufficient stock, return false
    return insufficientItems.length === 0;
  }
  
  /**
   * Transfer cart items to order
   * @param {Number} userId - User ID
   * @param {Number} orderId - Order ID
   * @returns {Boolean} Success status
   */
  static async transferCartToOrder(userId, orderId) {
    const connection = await beginTransaction();
    
    try {
      // Get cart items
      const cartSql = `
        SELECT ci.product_id, ci.quantity, p.price
        FROM cart_items ci
        JOIN products p ON ci.product_id = p.id
        WHERE ci.user_id = ?
      `;
      
      const cartItems = await connection.execute(cartSql, [userId]).then(([results]) => results);
      
      // Add items to order_items
      for (const item of cartItems) {
        const { product_id, quantity, price } = item;
        
        // Add to order_items
        const orderItemSql = `
          INSERT INTO order_items (order_id, product_id, quantity, unit_price)
          VALUES (?, ?, ?, ?)
        `;
        
        await connection.execute(orderItemSql, [orderId, product_id, quantity, price]);
        
        // Update product stock
        const stockSql = `
          UPDATE products
          SET stock_quantity = stock_quantity - ?
          WHERE id = ?
        `;
        
        await connection.execute(stockSql, [quantity, product_id]);
      }
      
      // Clear cart
      const clearCartSql = `
        DELETE FROM cart_items
        WHERE user_id = ?
      `;
      
      await connection.execute(clearCartSql, [userId]);
      
      // Commit transaction
      await commitTransaction(connection);
      
      return true;
    } catch (error) {
      // Rollback transaction on error
      await rollbackTransaction(connection);
      console.error('Error transferring cart to order:', error.message);
      throw error;
    }
  }
}

module.exports = CartModel;

