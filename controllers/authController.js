const { body, validationResult } = require("express-validator");
const User = require("../models/userModel.js");
const { generateRefreshToken } = require("../utils/tokenUtils.js");
const xss = require("xss"); // Import the xss library
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// Function to handle user registration
async function registerUser(req, res) {
  const { username, password } = req.body; // Include userId in the request body

  try {
    // Validate user input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: "Invalid input.", errors: errors.array() });
    }

    // Sanitize the username
    const sanitizedUsername = xss(username);

    // Hash the password securely
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if the user already exists by userId before attempting to insert
    const existingUser = await User.findOne({ username: username }); // Use userId for checking
    if (existingUser) {
      return res.status(400).json({ message: "User already exists." });
    }

    // Create a new user
    const newUser = new User({
      username: sanitizedUsername,
      password: hashedPassword,
      role: "user",
    });

    // Save the user to the database
    await newUser.save();

    res.status(201).json({ message: "User registered successfully." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error registering user." });
  }
}


// Function to handle user login
async function loginUser(req, res) {
  const { username, password } = req.body;

  try {
    // Sanitize the username
    const sanitizedUsername = xss(username);

    // Find the user by username
    const user = await User.findOne({ username: sanitizedUsername });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Compare the provided password with the hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials." });
    }

    // Generate a JWT token
    const token = jwt.sign(
      { username: sanitizedUsername },
      process.env.SECRET_KEY,
      {
        expiresIn: "1h",
      }
    );

    // Generate a refresh token
    const refreshToken = generateRefreshToken();

    // Store the refresh token with the user
    user.refreshTokens.push(refreshToken);
    await user.save();

    res.json({ token, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error logging in." });
  }
}

// Function to enable two-factor authentication (2FA)
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
};
