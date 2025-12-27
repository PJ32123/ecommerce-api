const express = require('express');
const db = require('./db');
const app = express();

// No longer have to import body-parser
app.use(express.json());

app.get('/', (req, res) => {
    res.send('The e-commerce API is alive!');
});

app.get('/test-db', async (req, res) => {
  try {
    const result = await db.query('SELECT NOW()');
    res.json({ message: "Database connected!", time: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).send("Database connection failed.");
  }
});

module.exports = app;