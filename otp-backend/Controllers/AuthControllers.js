const User = require('../models/User'); // adjust path if needed
const jwt = require('jsonwebtoken');

// Generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET || 'supersecretkey',
    { expiresIn: '7d' }
  );
};

// Signup Controller
exports.SignupPage = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    const newUser = await User.create({ name, email, password });
    const token = generateToken(newUser);

    res.status(201).json({
      message: 'Signup successful. Please login.',
      user: newUser,
      token
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Login Controller
exports.LoginPage = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = generateToken(user);

    res.status(200).json({
      message: 'Login successful',
      user,
      token
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
