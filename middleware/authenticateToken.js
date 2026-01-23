const jwt = require('jsonwebtoken');
require('dotenv').config();

// Middleware to verify JWT token from cookie
const authenticateToken = (req, res, next) => {
    try {
        // Read token from cookie
        const token = req.cookies.token;

        // If no token provided, return 401
        if (!token) {
            const error = new Error("Access denied. Please sign in.");
            error.statusCode = 401;
            throw error;
        }

        // Verify token is valid and not expired
        // If not valid, an error is thrown
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Attach user info to request object for use in route handlers
        // This only happens if token is valid(jwt.verify doesn't throw an error)
        req.user = {
            userId: decoded.userId,
            email: decoded.email
        };

        // Continue to next middleware/route handler
        next();

    } catch (err) {
        // Handle JWT-specific errors
        // More specific error should go first
        if (err.name === 'TokenExpiredError') {
            err.message = "Token expired. Please sign in again.";
            err.statusCode = 401;
        } else if (err.name === 'JsonWebTokenError') {
            err.message = "Invalid token. Please sign in again.";
            err.statusCode = 401;
        };
        
        // Pass error to error handler
        next(err);
    }
};

module.exports = authenticateToken;
