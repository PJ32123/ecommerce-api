const express = require('express');
const router = express.Router();
const db = require('../db');
const bcrypt = require('bcryptjs');
require('dotenv').config();

router.post('/register', async (req, res, next) => {
    try {
        console.log("deconstruct");
        const { email, password, first_name, last_name } = req.body;

        if (!email || !password || !first_name || !last_name) {
            const error = new Error("Please provide all required fields: email, password, username, first name and last name");
            error.statusCode = 400;
            throw error;
        };
        console.log("hash password");
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const queryText = `
            INSERT INTO users (email, password_hash, first_name, last_name)
            VALUES ($1, $2, $3, $4)
            RETURNING id, email, first_name
        `;
        console.log("db query");
        const values = [email, hashedPassword, first_name, last_name];
        const result = await db.query(queryText, values);

        console.log("good response");
        res.status(201).json({
            message: "Registration successful",
            user: result.rows[0]
        });
        
    } catch (err) {
        next(err);
    }
});



// Default export of what is inside router, not router as an object
module.exports = router;