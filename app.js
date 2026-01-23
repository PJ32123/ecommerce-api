const express = require('express');
const cookieParser = require('cookie-parser');
// Creates an instance of express with a factory function pattern instead of a 
// traditional class constructor otherwise it would be new express()
const app = express();

// imports dotenv library that reads .env file and makes variables accessible via process.env.VARIABLE
require('dotenv').config();

const router = require('./routes/router');
const errorHandler = require('./middleware/errorHandler');

// No longer have to import body-parser, middleware to format json data
// parses JSON from incoming requests - specifically req.body
app.use(express.json());
app.use(cookieParser());

app.use('/api', router);

// Delete this eventually
app.get('/', (req, res) => {
    res.send('The e-commerce API is alive!');
});

// If no route above matches, should always be after all other routes except errorHandler
app.use((req, res, next) => {
  const error = new Error("Requested resource not found");
  error.statusCode = 404;
  next(error);
});

app.use(errorHandler)

module.exports = app;