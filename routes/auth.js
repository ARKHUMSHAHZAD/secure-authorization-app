const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const authMiddleware = require('../middleware/auth');

const router = express.Router();

// Register Route
router.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if user exists
    let user = await User.findOne({ username });
    if (user) return res.status(400).json({ msg: 'User already exists' });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    user = new User({ username, password: hashedPassword });
    await user.save();

    res.status(201).send('User registered successfully');
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Login Route
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find user
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    // Create JWT
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({ token });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Protected Route Example
router.get('/protected', authMiddleware, (req, res) => {
  res.send('This is a protected route');
});

module.exports = router;
