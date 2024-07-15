const { body, validationResult } = require('express-validator');
const User = require('../models/userModel.js');
const { generateRefreshToken } = require('../utils/tokenUtils.js');
const xss = require('xss'); // Import the xss library
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
async function registerUser(req, res) {
  const { username, password } = req.body;

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res
      .status(400)
      .json({ message: 'Invalid input.', errors: errors.array() });
  }

  const sanitizedUsername = xss(username);

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({
    username: sanitizedUsername,
    password: hashedPassword,
    role: 'user',
  });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error registering user.' });
  }
}

// User login
async function loginUser(req, res, next) {
  const { username, password } = req.body;
  console.log('attempting to login');
  console.log(username, password);
  const sanitizedUsername = xss(username);

  const user = await User.findOne({ username: sanitizedUsername });
  if (!user) {
    return res.status(404).json({ message: 'User not found.' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Invalid credentials.' });
  }

  const token = jwt.sign(
    { username: sanitizedUsername },
    process.env.SECRET_KEY,
    {
      expiresIn: '1h',
    }
  );
  const refreshToken = generateRefreshToken();

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

  res.json({ message: '2FA is enabled and configured.' });
}

module.exports = {
  registerUser,
  loginUser,
  enableTwoFactorAuth,
  validateToken
};
