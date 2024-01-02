const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path'); // Import the 'path' module
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8000;

mongoose.connect(process.env.MONGODB_URI);
const db = mongoose.connection;

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  name: { type: String, required: true },
  password: { type: String, required: true },
  resetToken: String,
});

const User = mongoose.model('User', userSchema);

app.use(express.json());
app.use(cors({
  origin: ['http://localhost:3000', 'https://prf-b50.netlify.app'],
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
}));

// Handle the GET request for token validation
app.get('/resetpassword', async (req, res) => {
    const { token } = req.query;
  
    console.log('Received token:', token);
  
    try {
      // Find the user by the reset token
      const user = await User.findOne({ resetToken: token });
  
      // Check if the user exists and the token is valid
      if (!user || !user.resetToken) {
        return res.status(404).json({ message: 'Invalid or expired token.' });
      }
  
      // Render the Reset Password page
      res.sendFile(path.join(__dirname, 'resetpassword.html'));
    } catch (error) {
      console.error('Error during password reset token validation:', error);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });

  // Handle the POST request for password reset
  app.patch('/resetpassword', async (req, res) => {
    const { token, newPassword, confirmPassword } = req.body;
  
    try {
      // Find the user by the reset token
      const user = await User.findOne({ resetToken: token });
  
      // Check if the user exists and the token is valid
      if (!user || !user.resetToken) {
        return res.status(404).json({ message: 'Invalid or expired token.' });
      }
  
      // Check if the new password and confirm password match
      if (newPassword !== confirmPassword) {
        return res.status(400).json({ message: 'New password and confirm password do not match.' });
      }
  
      // Hash the new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);
  
      // Update the user's password and reset token in the database using PATCH
      await User.findByIdAndUpdate(user._id, { password: hashedPassword, resetToken: null });
  
      // Send a response indicating successful password reset
      res.json({ message: 'Password reset successful.' });
    } catch (error) {
      console.error('Error during password reset:', error);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });
  

// Signup endpoint
app.post('/signup', async (req, res) => {
  const { email, name, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Passwords do not match' });
  }

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      email,
      name,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Forgot password endpoint
app.post('/forgotpassword', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'Email not found' });
    }

    const resetToken = crypto.randomBytes(20).toString('hex');

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.USER_EMAIL,
        pass: process.env.USER_EMAIL_PASSWORD,
      },
    });

    const resetLink = `https://localhost:8000/resetpassword?token=${resetToken}`;
    const mailOptions = {
      from: `"Nikhil" <${process.env.USER_EMAIL}>`,
      to: email,
      subject: 'Password Reset',
      html: `
    <html>
      <head>
        <style>
          body {
            font-family: 'Arial', sans-serif; 
            background-color: #f4f4f4;
            padding: 20px;
          }
          .container {
            background-color: #ffffff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
          }
          h2 {
            color: #333333;
          }
          p {
            color: #555555;
          }
          a {
            color: #007bff;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Password Reset</h2>
          <p>Hello,</p>
          <p>We received a request to reset your password. Click the link below to reset it:</p>
          <p><a href="${resetLink}">Reset Password</a></p>
          <p>If you didn't request a password reset, you can ignore this email.</p>
        </div>
      </body>
    </html>
  `,
};

    await transporter.sendMail(mailOptions);

    await User.findByIdAndUpdate(user._id, { resetToken });

    res.status(200).json({ message: 'Password reset link sent to your email' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// Signin endpoint
app.post('/signin', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    res.status(200).json({ message: 'Signin successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
