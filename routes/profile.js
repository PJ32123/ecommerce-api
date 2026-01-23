const express = require('express');
const profileRouter = express.Router();
const db = require('../db');
const authenticateToken = require('../middleware/authenticateToken');

// GET /api/profile - protected route returning current user profile
profileRouter.get('/', authenticateToken, async (req, res, next) => {
    try {
        const userId = req.user.userId;

        // Get user
        const userQuery = `SELECT id, email, first_name, last_name FROM users WHERE id = $1`;
        const userResult = await db.query(userQuery, [userId]);

        if (userResult.rows.length === 0) {
            const error = new Error("User not found");
            error.statusCode = 404;
            throw error;
        }

        // Get address(may be null)
        const addressQuery = `SELECT street_address, city, state, postal_code FROM addresses WHERE user_id = $1`;
        const addressResult = await db.query(addressQuery, [userId]);

        res.json({
            user: userResult.rows[0],
            address: addressResult.rows[0] || null
        });

    } catch (err) {
        next(err);
    }
});

profileRouter.put('/', authenticateToken, async (req, res, next) => {

});

profileRouter.put('/address', authenticateToken, (req, res, next) => {

});

module.exports = profileRouter;