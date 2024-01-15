const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy"); // For 2FA
const { validationResult } = require("express-validator");
const User = require("../models/userModel");

// Function to hash passwords
async function hashPassword(password) {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}

// Function to generate JWT access tokens
const generateAccessToken = (user) => {
  return jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
}

// Function to verify JWT access tokens
const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// User registration
async function registerUser(req, res, next) {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;
  const hashedPassword = await hashPassword(password);

  try {
    // Check if the user already exists by username
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists." });
    }

    const newUser = new User({
      username,
      password: hashedPassword,
      role: "user",
    });

    await newUser.save();

    res.status(201).json({ message: "User registered successfully." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error registering user." });
  }
}

// User login
async function loginUser(req, res, next) {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials." });
    }

    // Generate a JWT token
    const token = generateAccessToken(user);

    // Generate a refresh token
    const refreshToken = speakeasy.generateSecret().base32;

    user.refreshTokens.push(refreshToken);
    await user.save();

    res.json({ token, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error logging in." });
  }
}

async function validateToken(req, res) {
  // Extract the token from the request headers or other means
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
      return res.status(401).json({ message: "No token provided." });
  }

  try {
      // Verify the token using the same secret used to sign the JWT
      const decoded = verifyAccessToken(token);

      if (!decoded) {
          return res.status(401).json({ message: "Invalid or expired token." });
      }

      // Optionally, you can add additional checks here, e.g., checking user existence in DB

      // If token is valid
      res.json({ message: "Token is valid.", userId: decoded.userId });
  } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Error verifying token." });
  }
}

// Enable Two-Factor Authentication (2FA)
async function enableTwoFactorAuth(req, res) {
  const { twoFactorSecret } = req.body;

  try {
    // Update the user's two-factor secret
    req.user.twoFactorSecret = twoFactorSecret;
    await req.user.save();

    res.json({ message: "2FA is enabled and configured." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error enabling 2FA." });
  }
}

module.exports = {
  registerUser,
  loginUser,
  enableTwoFactorAuth,
  validateToken
};
