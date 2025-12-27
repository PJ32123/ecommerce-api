const { Pool } = require('pg');
require('dotenv').config();

// We create a new Pool instance
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE, // This should be 'ecommerce'
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// We export a helper function to run queries
module.exports = {
  query: (text, params) => pool.query(text, params),
};