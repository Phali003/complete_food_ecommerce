const CartModel = require('../models/CartModel');
const ProductModel = require('../models/ProductModel');
const Joi = require('joi');

/**
 * Validate cart item data
 */
const validateCartItem = (data) => {
  const schema = Joi.object({
    product_id: Joi.number().integer().required(),
    quantity: Joi.number().integer().min(1).required()
  });

  return schema.validate(data);
};

/**
 * Get the current user's cart
 */
const getCart = async (req, res) => {
  try {
    const userId = req.user.id;

    // Get cart items with product details
    const cartItems = await CartModel.getCart(userId);
    const total = await CartModel.getCartTotal(userId);

    return res.status(200).json({
      success: true,
      data: {
        items: cartItems,
        total,
        item_count: cartItems.length
      }
    });
  } catch (error) {
    console.error('Error getting cart:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while fetching cart'
    });
  }
};

/**
 * Add a product to the cart
 */
const addToCart = async (req, res) => {
  try {
    // Validate input
    const { error } = validateCartItem(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message
      });
    }

    const userId = req.user.id;
    const { product_id, quantity } = req.body;

    // Check if product exists
    const product = await ProductModel.getProductById(product_id);
    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    // Check if product has sufficient stock
    if (product.stock_quantity < quantity) {
      return res.status(400).json({
        success: false,
        message: `Only ${product.stock_quantity} units available in stock`
      });
    }

    // Add to cart
    const cartItem = await CartModel.addToCart(userId, product_id, quantity);

    // Get updated cart
    const cartItems = await CartModel.getCart(userId);
    const total = await CartModel.getCartTotal(userId);

    return res.status(200).json({
      success: true,
      message: 'Product added to cart',
      data: {
        cart_item: cartItem,
        cart: {
          items: cartItems,
          total,
          item_count: cartItems.length
        }
      }
    });
  } catch (error) {
    console.error('Error adding to cart:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while adding to cart'
    });
  }
};

/**
 * Update cart item quantity
 */
const updateCartItem = async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;
    const { quantity } = req.body;

    // Validate quantity
    if (!quantity || isNaN(quantity) || quantity < 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid quantity is required'
      });
    }

    // Check if cart item exists
    const cartItem = await CartModel.getCartItem(userId, id);
    if (!cartItem) {
      return res.status(404).json({
        success: false,
        message: 'Cart item not found'
      });
    }

    // If quantity is 0, remove the item
    if (quantity === 0) {
      await CartModel.removeFromCart(userId, id);
      
      // Get updated cart
      const cartItems = await CartModel.getCart(userId);
      const total = await CartModel.getCartTotal(userId);
      
      return res.status(200).json({
        success: true,
        message: 'Item removed from cart',
        data: {
          items: cartItems,
          total,
          item_count: cartItems.length
        }
      });
    }

    // Check if product has sufficient stock
    const product = await ProductModel.getProductById(id);
    if (!product || product.stock_quantity < quantity) {
      return res.status(400).json({
        success: false,
        message: `Only ${product ? product.stock_quantity : 0} units available in stock`
      });
    }

    // Update cart item
    const updatedItem = await CartModel.updateCartItemQuantity(userId, id, quantity);

    // Get updated cart
    const cartItems = await CartModel.getCart(userId);
    const total = await CartModel.getCartTotal(userId);

    return res.status(200).json({
      success: true,
      message: 'Cart item updated',
      data: {
        cart_item: updatedItem,
        cart: {
          items: cartItems,
          total,
          item_count: cartItems.length
        }
      }
    });
  } catch (error) {
    console.error('Error updating cart item:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while updating cart item'
    });
  }
};

/**
 * Remove an item from the cart
 */
const removeFromCart = async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;

    // Remove from cart
    const success = await CartModel.removeFromCart(userId, id);

    if (!success) {
      return res.status(404).json({
        success: false,
        message: 'Cart item not found'
      });
    }

    // Get updated cart
    const cartItems = await CartModel.getCart(userId);
    const total = await CartModel.getCartTotal(userId);

    return res.status(200).json({
      success: true,
      message: 'Item removed from cart',
      data: {
        items: cartItems,
        total,
        item_count: cartItems.length
      }
    });
  } catch (error) {
    console.error('Error removing from cart:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while removing from cart'
    });
  }
};

/**
 * Clear the cart
 */
const clearCart = async (req, res) => {
  try {
    const userId = req.user.id;

    // Clear cart
    await CartModel.clearCart(userId);

    return res.status(200).json({
      success: true,
      message: 'Cart cleared',
      data: {
        items: [],
        total: 0,
        item_count: 0
      }
    });
  } catch (error) {
    console.error('Error clearing cart:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Server error while clearing cart'
    });
  }
};

module.exports = {
  getCart,
  addToCart,
  updateCartItem,
  removeFromCart,
  clearCart
};

