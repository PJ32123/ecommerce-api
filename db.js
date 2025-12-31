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
  // Use this for single queries (90% of your app)
  query: async (text, params) => {
    const start = Date.now();
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    console.log('Executed Query:', { text, duration, rows: res.rowCount });
    return res;
  },

  // Use this to check out a client for Transactions
  connect: () => pool.connect() 
};