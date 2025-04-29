const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = 3000;

// Middleware to parse JSON
app.use(express.json());

// MySQL database connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'api'
});

connection.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err.stack);
    return;
  }
  console.log('✅ Connected to the api database.');
});

// JWT Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user;
    next();
  });
}

// SIGNUP - Register new user
app.post('/signup', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required');
  }

  const checkQuery = 'SELECT * FROM users WHERE username = ?';
  connection.query(checkQuery, [username], (err, results) => {
    if (err) {
      console.error('Error checking user:', err.message);
      return res.status(500).send('Server error');
    }

    if (results.length > 0) {
      return res.status(409).send('Username already exists');
    }

    const insertQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';
    connection.query(insertQuery, [username, password], (err, result) => {
      if (err) {
        console.error('Error inserting user:', err.message);
        return res.status(500).send('Failed to create user');
      }

      const user = { user_id: result.insertId, username };
      const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.status(201).json({ message: 'User created successfully', token });
    });
  });
});

// LOGIN - Authenticate user
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required');
  }

  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  connection.query(query, [username, password], (err, results) => {
    if (err) {
      console.error('Error querying database:', err.message);
      return res.status(500).send('Server error');
    }

    if (results.length === 0) {
      return res.status(401).send('Invalid credentials');
    }

    const user = results[0];
    const token = jwt.sign({ user_id: user.user_id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: '1h'
    });

    res.json({ message: 'Login successful', token });
  });
});

// GET all products
app.get('/products', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM products';
  connection.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching products:', err);
      return res.status(500).send('Failed to retrieve products');
    }
    res.json(results);
  });
});

// POST - Add a new product
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
    if (err) {
      console.error('Error inserting product:', err);
      return res.status(500).send('Failed to add product');
    }
    res.status(201).json({ message: 'Product added successfully', productID: results.insertId });
  });
});

// PUT - Full update product
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
    if (err) {
      console.error('Error updating product:', err);
      return res.status(500).send('Failed to update product');
    }
    if (results.affectedRows === 0) {
      return res.status(404).send('Product not found');
    }
    res.send('Product updated successfully');
  });
});

// PATCH - Partial update product
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
    if (err) {
      console.error('Error partially updating product:', err);
      return res.status(500).send('Failed to update product');
    }
    if (results.affectedRows === 0) {
      return res.status(404).send('Product not found');
    }
    res.send('Product updated successfully (partial)');
  });
});

// DELETE - Remove product
app.delete('/products/:id', authenticateToken, (req, res) => {
  const productID = req.params.id;
  const query = 'DELETE FROM products WHERE productID = ?';
  connection.query(query, [productID], (err, results) => {
    if (err) {
      console.error('Error deleting product:', err);
      return res.status(500).send('Failed to delete product');
    }
    if (results.affectedRows === 0) {
      return res.status(404).send('Product not found');
    }
    res.send('Product deleted successfully');
  });
});

// Start the server
app.listen(port, () => {
  console.log(`🚀 Server is running at http://localhost:${port}`);
});
