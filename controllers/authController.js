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

//
//Function to verify JWT access tokens
const verifyAccessToken = (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return { valid: true, decoded };
  } catch (error) {
    console.error("Token verification error:", error);
    return { valid: false, error };
  }
};

// const verifyAccessToken = (token) => {
//   try {
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     return { valid: true, decoded };
//   } catch (error) {
//     if (error.name !== 'TokenExpiredError') {
//       console.error("Token verification error:", error);
//     }
//     return { valid: false, error };
//   }
// };



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
    console.log('token is ',token)

    // Generate a refresh token
    const refreshToken = speakeasy.generateSecret().base32;
    console.log('refresh token is ',refreshToken)

    user.refreshTokens.push(refreshToken);
    await user.save();

    res.json({ token, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error logging in." });
  }
}


const validateToken = (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided." });
  }

  const result = verifyAccessToken(token);
  if (!result.valid) {
    if (result.error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: "Token expired." });
    } else {
      return res.status(401).json({ message: "Invalid token." });
    }
  }

  // Token is valid
  res.json({ message: "Token is valid.", userId: result.decoded.userId });
};
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
