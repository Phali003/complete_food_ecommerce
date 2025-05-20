const express = require('express');
const router = express.Router();

// Admin dashboard route
router.get('/dashboard', (req, res) => {
    res.status(200).json({ message: 'Admin dashboard accessed successfully' });
});

// Admin products management route
router.get('/products', (req, res) => {
    res.status(200).json({ message: 'Admin products management accessed successfully' });
});

// Admin orders management route
router.get('/orders', (req, res) => {
    res.status(200).json({ message: 'Admin orders management accessed successfully' });
});

// Admin users management route
router.get('/users', (req, res) => {
    res.status(200).json({ message: 'Admin users management accessed successfully' });
});

module.exports = router;

