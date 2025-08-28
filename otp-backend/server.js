// server.js - Main server file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();


const app = express();

// Middleware
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/otp_rental', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.log('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  mobile: { type: String, required: true },
  password: { type: String, required: true },
  resetPasswordOTP: { type: String, default: null },
  resetPasswordExpires: { type: Date, default: null }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

// Email configuration using nodemailer - FIXED: Correct method name is 'createTransport'
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Alternative service-based config (uncomment if above doesn't work)
/*
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});
*/

// Utility function to generate OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Routes

// 1. SIGNUP ROUTE
app.post('/api/SignupPage', async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;
    
    // Validation
    if (!name || !email || !mobile || !password) {
      return res.status(400).json({ 
        message: 'All fields are required',
        success: false 
      });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        message: 'User already exists with this email',
        success: false 
      });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create new user
    const newUser = new User({
      name,
      email,
      mobile,
      password: hashedPassword
    });
    
    await newUser.save();
    
    res.status(201).json({ 
      message: 'Signup completed, please login',
      success: true 
    });
    
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      message: 'Server error during signup',
      success: false 
    });
  }
});

// 2. LOGIN ROUTE
app.post('/api/LoginPage', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        message: 'Email and password are required',
        success: false 
      });
    }
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ 
        message: 'User not found',
        success: false 
      });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        message: 'Incorrect password',
        success: false 
      });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      message: 'Login successful',
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        mobile: user.mobile
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      message: 'Server error during login',
      success: false 
    });
  }
});

// 3. FORGOT PASSWORD - SEND OTP - FIXED ROUTE PATH
app.post('/api/Auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        message: 'Email is required',
        success: false 
      });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        message: 'Please enter a valid email address',
        success: false 
      });
    }
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ 
        message: 'No account found with this email address',
        success: false 
      });
    }
    
    // Generate OTP
    const otp = generateOTP();
    
    // Save OTP and expiration time (15 minutes from now)
    user.resetPasswordOTP = otp;
    user.resetPasswordExpires = Date.now() + 15 * 60 * 1000; // 15 minutes
    await user.save();
    
    // FIXED: Email sending with detailed error logging
    try {
      console.log('Email configuration check:');
      console.log('EMAIL_USER:', process.env.EMAIL_USER ? 'Set' : 'NOT SET');
      console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? 'Set' : 'NOT SET');
      
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset OTP - OTP Rental',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #4f46e5;">Password Reset Request</h2>
            <p>Hello ${user.name},</p>
            <p>You requested to reset your password. Please use the following OTP:</p>
            <div style="background-color: #f3f4f6; padding: 20px; text-align: center; margin: 20px 0;">
              <h1 style="color: #1f2937; font-size: 32px; letter-spacing: 5px; margin: 0;">${otp}</h1>
            </div>
            <p style="color: #6b7280;">This OTP will expire in 15 minutes.</p>
            <p style="color: #6b7280;">If you didn't request this, please ignore this email.</p>
          </div>
        `
      };
      
      console.log('Attempting to send email to:', email);
      await transporter.sendMail(mailOptions);
      console.log(`✅ OTP sent successfully to ${email}: ${otp}`);
      
    } catch (emailError) {
      console.error('❌ Detailed email error:', {
        message: emailError.message,
        code: emailError.code,
        command: emailError.command,
        response: emailError.response,
        responseCode: emailError.responseCode
      });
      
      // Clear the OTP if email fails
      user.resetPasswordOTP = null;
      user.resetPasswordExpires = null;
      await user.save();
      
      return res.status(500).json({ 
        message: `Failed to send OTP email: ${emailError.message}`,
        success: false,
        error: emailError.code || 'EMAIL_CONFIG_ERROR'
      });
    }
    
    res.json({
      message: 'OTP sent to your email successfully',
      success: true
    });
    
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      message: 'Error sending OTP. Please try again.',
      success: false 
    });
  }
});

// BACKUP ROUTE for the old endpoint (temporary compatibility)
app.post('/api/ForgotPasswordPage', async (req, res) => {
  // Redirect to the new endpoint
  req.url = '/api/Auth/forgot-password';
  return app._router.handle(req, res);
});

// 4. VERIFY OTP AND RESET PASSWORD - FIXED ROUTE PATH
app.post('/api/Auth/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ 
        message: 'Email, OTP, and new password are required',
        success: false 
      });
    }

    // Validate OTP format (6 digits)
    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ 
        message: 'OTP must be 6 digits',
        success: false 
      });
    }

    // Validate password length
    if (newPassword.length < 6) {
      return res.status(400).json({ 
        message: 'Password must be at least 6 characters long',
        success: false 
      });
    }
    
    // Find user and check OTP
    const user = await User.findOne({
      email,
      resetPasswordOTP: otp,
      resetPasswordExpires: { $gt: Date.now() } // Check if OTP hasn't expired
    });
    
    if (!user) {
      return res.status(400).json({ 
        message: 'Invalid or expired OTP',
        success: false 
      });
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    // Update password and clear reset fields
    user.password = hashedPassword;
    user.resetPasswordOTP = null;
    user.resetPasswordExpires = null;
    await user.save();
    
    res.json({
      message: 'Password reset successfully',
      success: true
    });
    
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      message: 'Server error during password reset',
      success: false 
    });
  }
});

// 5. PROTECTED ROUTE MIDDLEWARE
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      message: 'Access token required',
      success: false 
    });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        message: 'Invalid or expired token',
        success: false 
      });
    }
    req.user = user;
    next();
  });
};

// 6. DASHBOARD ROUTE (PROTECTED)
app.get('/api/Dashboard', authenticateToken, async (req, res) => {
  try {
    // Get user details (excluding password)
    const user = await User.findById(req.user.userId).select('-password -resetPasswordOTP -resetPasswordExpires');
    
    res.json({
      message: 'Dashboard data',
      success: true,
      user
    });
    
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ 
      message: 'Server error',
      success: false 
    });
  }
});

// 7. GET USER PROFILE (PROTECTED)
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password -resetPasswordOTP -resetPasswordExpires');
    res.json({ success: true, user });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ 
      message: 'Server error',
      success: false 
    });
  }
});

// Test email configuration endpoint with multiple configurations
app.post('/api/test-email', async (req, res) => {
  try {
    console.log('Testing email configuration...');
    console.log('EMAIL_USER:', process.env.EMAIL_USER);
    console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? '[SET]' : '[NOT SET]');

    // Test with the current transporter first
    try {
      const testMail = {
        from: process.env.EMAIL_USER,
        to: process.env.EMAIL_USER,
        subject: 'Email Configuration Test',
        text: 'If you receive this email, your nodemailer configuration is working correctly!',
        html: '<h3>✅ Email Configuration Test Successful!</h3><p>Your nodemailer setup is working properly.</p>'
      };

      await transporter.sendMail(testMail);
      return res.json({ 
        success: true, 
        message: 'Test email sent successfully with current configuration!' 
      });
      
    } catch (currentError) {
      console.log('Current config failed, trying alternative configurations...');
      
      // Try alternative configuration with explicit SMTP settings
      const altTransporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 587,
        secure: false, // true for 465, false for other ports
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        },
        tls: {
          rejectUnauthorized: false
        }
      });

      const testMail = {
        from: process.env.EMAIL_USER,
        to: process.env.EMAIL_USER,
        subject: 'Email Configuration Test (Alternative)',
        html: '<h3>✅ Email Test Successful with Alternative Config!</h3>'
      };

      await altTransporter.sendMail(testMail);
      
      return res.json({ 
        success: true, 
        message: 'Test email sent with alternative configuration!',
        note: 'Consider updating your main transporter config'
      });
    }
    
  } catch (error) {
    console.error('All email configurations failed:', {
      message: error.message,
      code: error.code,
      command: error.command
    });
    
    res.status(500).json({ 
      success: false, 
      message: 'Email configuration error',
      error: error.message,
      code: error.code,
      troubleshooting: {
        gmail: 'Make sure you\'re using an App Password, not your regular password',
        twoFactor: 'Enable 2-factor authentication first',
        appPassword: 'Generate App Password from Google Account settings'
      }
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    message: 'Something went wrong!',
    success: false 
  });
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Environment variables needed:');
  console.log('- MONGODB_URI (optional, defaults to localhost)');
  console.log('- JWT_SECRET (optional, uses default)');
  console.log('- EMAIL_USER (your email for sending OTP)');
  console.log('- EMAIL_PASS (your email password/app password)');
  console.log('\nFixed Issues:');
  console.log('✓ Route paths now match frontend calls');
  console.log('✓ Email transporter variable name corrected');
  console.log('✓ Better error handling for email sending');
  console.log('✓ Input validation added');
  console.log('✓ Consistent success/error response format');
});