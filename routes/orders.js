const express = require('express');
const ordersRouter = express.Router();
const db = require('../db');
const authenticateToken = require('../middleware/authenticateToken');



module.exports = ordersRouter;