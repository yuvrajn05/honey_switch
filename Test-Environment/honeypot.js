// Honeypot Backend Server - Express.js
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const port = 3002;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Log every request
app.use((req, res, next) => {
  console.log(`[HONEYPOT] Received ${req.method} request to ${req.url}`);
  console.log('[HONEYPOT] Headers:', req.headers);
  console.log('[HONEYPOT] Query parameters:', req.query);
  console.log('[HONEYPOT] Body:', req.body);
  next();
});

// Routes - Return fake data for all endpoints
app.all('*', (req, res) => {
  // Delay response to simulate processing and make attacker waste time
  setTimeout(() => {
    res.json({
      status: 'success',
      message: 'Operation completed successfully',
      // Return fake data that looks legitimate
      data: {
        users: [
          { id: 1, username: 'user1', email: 'user1@example.com' },
          { id: 2, username: 'user2', email: 'user2@example.com' }
        ]
      }
    });
  }, 2000);
});

// Start server
app.listen(port, () => {
  console.log(`Honeypot server running at http://localhost:${port}`);
});