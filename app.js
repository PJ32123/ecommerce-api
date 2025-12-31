const express = require('express');
const app = express();

const authRouter = require('./routes/auth');
const errorHandler = require('./middleware/errorhandler');

// No longer have to import body-parser, middleware to format json data
app.use(express.json());

app.use('/api/auth', authRouter);

// Delete this eventually
app.get('/', (req, res) => {
    res.send('The e-commerce API is alive!');
});

// If no route above matches
app.use((req, res, next) => {
  const error = new Error("Requested resource not found");
  error.statusCode = 404;
  next(error);
});

app.use(errorHandler)

module.exports = app;