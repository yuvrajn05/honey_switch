// Real Backend Server - Express.js
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const port = 3001;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Sample user data
const users = [
  { id: 1, username: 'alice', email: 'alice@example.com' },
  { id: 2, username: 'bob', email: 'bob@example.com' }
];

// Routes
app.get('/', (req, res) => {
  res.json({ message: 'Real Backend Server is running!' });
});

// Get all users
app.get('/api/users', (req, res) => {
  res.json(users);
});

// Get user by ID
app.get('/api/users/:id', (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// Create user
app.post('/api/users', (req, res) => {
  const newUser = {
    id: users.length + 1,
    username: req.body.username,
    email: req.body.email
  };
  users.push(newUser);
  res.status(201).json(newUser);
});

// Start server
app.listen(port, () => {
  console.log(`Real backend server running at http://localhost:${port}`);
});