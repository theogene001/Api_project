const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// ===== MIDDLEWARES =====
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===== MYSQL DATABASE CONNECTION =====
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

connection.connect((err) => {
  if (err) {
    console.error('❌ Database connection failed:', err.stack);
    return;
  }
  console.log('✅ Connected to Clever Cloud MySQL database.');
});

// ===== JWT MIDDLEWARE =====
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// ===== SIGNUP (No Hashing) =====
app.post('/signup', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required');
  }

  const checkQuery = 'SELECT * FROM users WHERE username = ?';
  connection.query(checkQuery, [username], (err, results) => {
    if (err) return res.status(500).send('Server error');
    if (results.length > 0) return res.status(409).send('Username already exists');

    const insertQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';
    connection.query(insertQuery, [username, password], (err, result) => {
      if (err) return res.status(500).send('Failed to create user');

      const user = { user_id: result.insertId, username };
      const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.status(201).json({ message: 'User created successfully', token });
    });
  });
});

// ===== LOGIN (Plain Text) =====
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required');
  }

  const query = 'SELECT * FROM users WHERE username = ?';
  connection.query(query, [username], (err, results) => {
    if (err) return res.status(500).send('Server error');
    if (results.length === 0) return res.status(401).send('Invalid credentials');

    const user = results[0];

    if (password !== user.password) {
      return res.status(401).send('Invalid credentials');
    }

    const token = jwt.sign({ user_id: user.user_id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: '1h'
    });

    res.json({ message: 'Login successful', token });
  });
});

// ===== PRODUCTS ROUTES =====
app.get('/products', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM products';
  connection.query(query, (err, results) => {
    if (err) return res.status(500).send('Failed to retrieve products');
    res.json(results);
  });
});

app.post('/products', authenticateToken, (req, res) => {
  const { productName, description, quantity, price } = req.body;

  if (!productName || !description || quantity == null || price == null) {
    return res.status(400).send('All fields are required: productName, description, quantity, price');
  }

  const query = `
    INSERT INTO products (productName, description, quantity, price)
    VALUES (?, ?, ?, ?)
  `;
  connection.query(query, [productName, description, quantity, price], (err, results) => {
    if (err) return res.status(500).send('Failed to add product');
    res.status(201).json({ message: 'Product added successfully', productID: results.insertId });
  });
});

app.put('/products/:id', authenticateToken, (req, res) => {
  const productID = req.params.id;
  const { productName, description, quantity, price } = req.body;

  if (!productName || !description || quantity == null || price == null) {
    return res.status(400).send('All fields are required: productName, description, quantity, price');
  }

  const query = `
    UPDATE products
    SET productName = ?, description = ?, quantity = ?, price = ?
    WHERE productID = ?
  `;
  connection.query(query, [productName, description, quantity, price, productID], (err, results) => {
    if (err) return res.status(500).send('Failed to update product');
    if (results.affectedRows === 0) return res.status(404).send('Product not found');
    res.send('Product updated successfully');
  });
});

app.patch('/products/:id', authenticateToken, (req, res) => {
  const productID = req.params.id;
  const fields = req.body;

  const keys = Object.keys(fields);
  if (keys.length === 0) {
    return res.status(400).send('At least one field must be provided for update');
  }

  const setClause = keys.map(key => `${key} = ?`).join(', ');
  const values = keys.map(key => fields[key]);

  const query = `UPDATE products SET ${setClause} WHERE productID = ?`;
  connection.query(query, [...values, productID], (err, results) => {
    if (err) return res.status(500).send('Failed to update product');
    if (results.affectedRows === 0) return res.status(404).send('Product not found');
    res.send('Product updated successfully (partial)');
  });
});

app.delete('/products/:id', authenticateToken, (req, res) => {
  const productID = req.params.id;
  const query = 'DELETE FROM products WHERE productID = ?';
  connection.query(query, [productID], (err, results) => {
    if (err) return res.status(500).send('Failed to delete product');
    if (results.affectedRows === 0) return res.status(404).send('Product not found');
    res.send('Product deleted successfully');
  });
});

// ===== START SERVER =====
app.listen(port, () => {
  console.log(`🚀 Server is running at http://localhost:${port}`);
});
