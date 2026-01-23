const express = require('express');
const authRouter = express.Router();
const db = require('../db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authenticateToken = require('../middleware/authenticateToken');

// POST /api/auth/register
authRouter.post('/register', async (req, res, next) => {
    try {
        // items are deconstructed from req.body
        const { email, password, first_name, last_name } = req.body;

        // If all required information isn't received in req.body, throw error
        if (!email || !password || !first_name || !last_name) {
            const error = new Error("Please provide all required fields: email, password, username, first name and last name");
            error.statusCode = 400;
            throw error;
        }

        const normalizedEmail = email.trim().toLowerCase()

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(normalizedEmail)) {
            const error = new Error("Please provide a valid email address");
            error.statusCode = 400;
            throw error;
        }

        // Validate password strength (min 8 chars, at least 1 uppercase, 1 lowercase, 1 number)
        if (password.length < 8) {
            const error = new Error("Password must be at least 8 characters long");
            error.statusCode = 400;
            throw error;
        }
        if (!/[A-Z]/.test(password)) {
            const error = new Error("Password must contain at least one uppercase letter");
            error.statusCode = 400;
            throw error;
        }
        if (!/[a-z]/.test(password)) {
            const error = new Error("Password must contain at least one lowercase letter");
            error.statusCode = 400;
            throw error;
        }
        if (!/[0-9]/.test(password)) {
            const error = new Error("Password must contain at least one number");
            error.statusCode = 400;
            throw error;
        }

        // Check if email already exists
        const emailCheckQuery = `SELECT id FROM users WHERE email = $1`;
        // db.query expects an array as the second argument
        const emailCheckResult = await db.query(emailCheckQuery, [normalizedEmail]);
        if (emailCheckResult.rows.length > 0) {
            console.log(`Registration failed for ${normalizedEmail}: Email already exists`);
            const error = new Error("Email already registered");
            error.statusCode = 409; // Conflict
            throw error;
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const queryText = `
            INSERT INTO users (email, password_hash, first_name, last_name)
            VALUES ($1, $2, $3, $4)
            RETURNING id, email, first_name
        `;
        // An array of values from req.body to be used in db.query with queryText
        const values = [normalizedEmail, hashedPassword, first_name, last_name];
        const result = await db.query(queryText, values);

        // sends created successful response if db.query is successful
        console.log(`New user registered: ${normalizedEmail}`);
        res.status(201).json({
            message: "Registration successful",
            user: result.rows[0]
        });
        
    } catch (err) {
        next(err);
    }
});

// DELETE /api/auth/deleteaccount
authRouter.delete('/deleteaccount', authenticateToken, async (req, res, next) => {
    try {
        const {password} = req.body;

        // Check that password was received with request
        if (!password) {
            const error = new Error("Please enter password.");
            error.statusCode = 401;
            throw error;
        }

        // Get password_hash for user from database based on the userId received from authenticateToken
        const passwordCheckQuery = `SELECT password_hash FROM users WHERE id = $1`;
        const passwordCheckResult = await db.query(passwordCheckQuery, [req.user.userId]);
        if (passwordCheckResult.rows.length === 0) {
            const error = new Error("User not found");
            error.statusCode = 404;
            throw error;
        }

        // Verify password entered matches the hashed_password for the user signed in
        const storedHash = passwordCheckResult.rows[0].password_hash;
        const passwordMatch = await bcrypt.compare(password, storedHash);
        if (!passwordMatch) {
            const error = new Error("Invalid email or password");
            error.statusCode = 401;
            throw error;
        }

        // No errors have been thrown, password is valid, send delete query
        const deleteQuery = `DELETE FROM users WHERE id = $1`;
        const deleteResult = await db.query(deleteQuery, [req.user.userId]);
        
        if (deleteResult.rowCount > 0) {
            console.log(`Account deleted for email: ${req.user.email}`);
            res.clearCookie('token');
            res.json({message: "Account deleted successfully"});
        } else {
            const error = new Error("Invalid username or password. Account not deleted.");
            error.statusCode = 401;
            throw error;
        }

    } catch (err) {
        next(err);
    }
});

// POST /api/auth/signin
authRouter.post('/signin', async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            const error = new Error("Please enter username and password.");
            error.statusCode = 401;
            throw error;
        }

        const normalizedEmail = email.trim().toLowerCase();

        // Validate email format. .test is built in for testing regex patters
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(normalizedEmail)) {
            const error = new Error("Please provide a valid email address");
            error.statusCode = 400;
            throw error;
        }

        // Check signin attempts
        const signinQuery = `
            SELECT attempt_count, last_attempt_timestamp, is_locked
            FROM signin_attempts
            WHERE email = $1
        `;
        const signinResult = await db.query(signinQuery, [normalizedEmail]);
        let attemptRow = signinResult.rows[0];
        const now = new Date();
        
        // If email isn't already in table, insert signin attempt
        if (signinResult.rowCount === 0) {
            const insertAttemptQuery = `INSERT INTO signin_attempts
                (email, attempt_count, last_attempt_timestamp, is_locked)
                VALUES ($1, $2, $3, $4)
                RETURNING attempt_count, last_attempt_timestamp, is_locked
            `;
            const queryValues = [normalizedEmail, 0, now, false];
            const insertResults = await db.query(insertAttemptQuery, queryValues);
            attemptRow = insertResults.rows[0];
        }

        if (attemptRow.is_locked) {
            if (now - attemptRow.last_attempt_timestamp > 15 * 60 * 1000) {
                const resetAttemptsQuery = `
                    UPDATE signin_attempts 
                    SET attempt_count = 0, 
                    last_attempt_timestamp = $1,
                    is_locked = false
                    WHERE email = $2
                    RETURNING attempt_count, last_attempt_timestamp, is_locked;
                `;
                const queryValues = [now, normalizedEmail];
                const updateAttempts = await db.query(resetAttemptsQuery, queryValues);
                attemptRow = updateAttempts.rows[0];
            } else {
                console.log(now - attemptRow.last_attempt_timestamp);
                const error = new Error("Too many login attempts. Try again later.");
                error.statusCode = 429;
                throw error;
            }
        } else {
            if (now - signinResult.last_attempt_timestamp > 15 * 60 * 1000) {
                const resetAttemptsQuery = `
                    UPDATE signin_attempts 
                    SET attempt_count = 0, 
                    last_attempt_timestamp = $1,
                    is_locked = false
                    WHERE email = $2
                    RETURNING attempt_count, last_attempt_timestamp, is_locked;
                `;
                const queryValues = [now, normalizedEmail];
                const updateAttempts = await db.query(resetAttemptsQuery, queryValues);
                attemptRow = updateAttempts.rows[0];
            }
        }

        // Look up user by email and check if email account under email exists
        const userQuery = `SELECT id, email, password_hash, first_name, last_name FROM users WHERE email = $1`;
        const userResult = await db.query(userQuery, [normalizedEmail]);
        if (userResult.rows.length === 0) {
            const error = new Error("Invalid email or password");
            error.statusCode = 401;
            throw error;
        }

        const user = userResult.rows[0];

        // Validate password against stored hash
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            const incrementAttemptsQuery = `
                    UPDATE signin_attempts 
                    SET attempt_count = $1, 
                    last_attempt_timestamp = $2,
                    is_locked = $3
                    WHERE email = $4;
                `;

            let queryValues = [attemptRow.attempt_count + 1, now, false, normalizedEmail];

            if (attemptRow.attempt_count < 3) {
                await db.query(incrementAttemptsQuery, queryValues);
                const error = new Error("Invalid email or password");
                error.statusCode = 401;
                throw error;
            } 
            else if (attemptRow.attempt_count === 3) {
                queryValues = [attemptRow.attempt_count + 1, now, false, normalizedEmail];
                await db.query(incrementAttemptsQuery, queryValues);
                const error = new Error("Invalid email or password. One attempt remaining.");
                error.statusCode = 401;
                throw error;
            } 
            else if (attemptRow.attempt_count >= 4) {
                queryValues = [attemptRow.attempt_count + 1, now, true, normalizedEmail];
                await db.query(incrementAttemptsQuery, queryValues);
                const error = new Error("Invalid email or password. No attempts remaining.");
                error.statusCode = 429;
                throw error;
            } 
        }

        // Ensure we have a JWT secret configured
        if (!process.env.JWT_SECRET) {
            const error = new Error("Server misconfigured: JWT_SECRET is missing");
            error.statusCode = 500;
            throw error;
        }

        // Create short-lived access token
        // .sign is a function of jsonWebToken used to create a token
        // 3 parameters- 
        // 1. payload(data encoded in token)
        // 2. secretkey used to sign token
        // 3. options (includes expiration, issuer, audience, subject, algorithm)
        // payload(userid, email, expiration) is converted to base64
        // only signature is encrypted with sha256, when decrypted, checks validity
        // by making sure payload matches, expiration isn't expired and secret key matches
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );

        // Reset signin attempts on successful login
        const resetSuccessQuery = `
            UPDATE signin_attempts 
            SET attempt_count = 0, is_locked = false, last_attempt_timestamp = NOW()
            WHERE email = $1
        `;
        await db.query(resetSuccessQuery, [normalizedEmail]);

        // Send token as httpOnly cookie
        // parameters of res.cookie:
        // 1. cookie identifier, when returned used to access cookie (req.cookies.token)
        // 2. cookie data to store, in this case the JWT token
        // 3. options object- congifuration for the cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 15 * 60 * 1000, // 15 minutes
        });

        res.json({
            message: "User signed in",
            user: {
                id: user.id,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
            },
        });

    } catch (err) {
        next(err);
    }
});

// POST /api/auth/signout
authRouter.post('/signout', authenticateToken, async (req, res, next) => {
    try {
        // Clear auth cookie on signout by sending empty cookie to users browser
        res.clearCookie('token');
        res.json({message: "User signed out"})
    } catch (err) {
        next(err);
    }
});

// PUT /api/auth/email
authRouter.put('/email', authenticateToken, async (req, res, next) => {
    try {
        const {email, password} = req.body;

        if (!email) {
            const error = new Error("Please enter new email");
            error.statusCode = 400;
            throw error;
        }

        if (!password) {
            const error = new Error("Please enter password");
            error.statusCode = 401;
            throw error;
        }

        const normalizedEmail = email.trim().toLowerCase();

        // Check that email entered doesn't match current email
        if (normalizedEmail === req.user.email) {
            const error = new Error("Email entered matches current email");
            error.statusCode = 409;
            throw error;
        }
        
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(normalizedEmail)) {
            const error = new Error("Please provide a valid email address");
            error.statusCode = 400;
            throw error;
        }

        // Get password_hash from database for signed in account
        const passwordQuery = `SELECT password_hash FROM users WHERE id = $1`;
        const passwordResults = await db.query(passwordQuery, [req.user.userId]);
        const passwordMatch = await bcrypt.compare(password, passwordResults.rows[0].password_hash);
        if (!passwordMatch) {
            const error = new Error("Invalid password");
            error.statusCode = 401;
            throw error;
        }

        // Check if new email already exists
        const emailQuery = `SELECT id FROM users WHERE email = $1`;
        const emailResults = await db.query(emailQuery, [normalizedEmail]);
        if (emailResults.rows.length > 0) {
            const error = new Error("Email already in use");
            error.statusCode = 409;
            throw error;
        }

        // Update email
        const updateEmailQuery = `UPDATE users SET email = $1 WHERE id = $2`;
        const updateResults = await db.query(updateEmailQuery, [normalizedEmail, req.user.userId]);

        if (updateResults.rowCount === 0) {
            const error = new Error("Couldn't update email");
            error.statusCode = 400;
            throw error;
        } else {
            res.json({
                message: "Email updated successfully",
                email: normalizedEmail
            });
        }
    } catch(err) {
        next(err);
    }
});

authRouter.put('password', authenticateToken, (req, res, next) => {

});


// Default export of what is inside router, not router as an object
module.exports = authRouter;