const express = require('express');
const productsRouter = express.Router();
const db = require('../db');
const authenticateToken = require('../middleware/authenticateToken');



module.exports = productsRouter;