const errorHandler = (err, req, res, next) => {
    // console.error can be used as a trigger to send an email to the developer
    console.error("Error detected", err.stack);
    const statusCode = err.statusCode || 500;
    // Mark as an error and put json data inside
    res.status(statusCode).json({
        success: false,
        message: err.message || "Internal server error",
        // If api is in production, doesn't send error message to front end because that could be private information
        stack: process.env.NODE_ENV === 'production' ? null : err.stack,
    });
};

module.exports = errorHandler;