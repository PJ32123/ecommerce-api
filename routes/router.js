const express = require('express');
const router = express.Router();
const authRouter = require('./auth');
const profileRouter = require('./profile');
const productsRouter = require('./products');
const cartRouter = require('./cart');
const ordersRouter = require('./orders');

router.use('/auth', authRouter);
router.use('/profile', profileRouter);
router.use('/products', productsRouter);
router.use('/cart', cartRouter);
router.use('/orders', ordersRouter);

module.exports = router;
