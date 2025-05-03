const express = require('express');
const router = express.Router();
const {
  getCart,
  addToCart,
  updateCartItem,
  removeFromCart,
  clearCart
} = require('../controllers/cartController');
const { protect } = require('../middleware/authMiddleware');

// Apply authentication middleware to all cart routes
router.use(protect);

/**
 * @route   GET /api/cart
 * @desc    Get the current user's cart
 * @access  Private
 */
router.get('/', getCart);

/**
 * @route   POST /api/cart/items
 * @desc    Add an item to the cart
 * @access  Private
 */
router.post('/items', addToCart);

/**
 * @route   PUT /api/cart/items/:id
 * @desc    Update an item in the cart
 * @access  Private
 */
router.put('/items/:id', updateCartItem);

/**
 * @route   DELETE /api/cart/items/:id
 * @desc    Remove an item from the cart
 * @access  Private
 */
router.delete('/items/:id', removeFromCart);

/**
 * @route   DELETE /api/cart
 * @desc    Clear the cart
 * @access  Private
 */
router.delete('/', clearCart);

module.exports = router;

