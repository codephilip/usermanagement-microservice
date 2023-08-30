const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const xss = require("xss");
const { body, validationResult } = require("express-validator");
const speakeasy = require("speakeasy");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = "your-secret-key";

// Connect to MongoDB securely
mongoose
  .connect("mongodb://localhost:27017/user-management", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB:", err);
  });

// Define User schema and model
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  refreshTokens: [String], // Store refresh tokens
  role: String, // User role (e.g., 'user' or 'admin')
  twoFactorSecret: String, // Store user's 2FA secret
});

const User = mongoose.model("User", userSchema);

app.use(cors()); // Set up CORS to control cross-origin requests
app.use(helmet()); // Enhance security with HTTP headers
app.use(express.json()); // Parse JSON bodies

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});

app.use(limiter);

// Register a new user
app.post(
  "/register",
  [
    body("username").isLength({ min: 3 }).trim().escape(),
    body("password").isLength({ min: 8 }),
  ],
  async (req, res) => {
    const { username, password } = req.body;

    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res
        .status(400)
        .json({ message: "Invalid input.", errors: errors.array() });
    }

    // Sanitize inputs
    const sanitizedUsername = xss(username);

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username: sanitizedUsername,
      password: hashedPassword,
      role: "user",
    });

    try {
      await newUser.save();
      res.status(201).json({ message: "User registered successfully." });
    } catch (err) {
      res.status(500).json({ message: "Error registering user." });
    }
  }
);

// User login with 2FA
app.post("/login", async (req, res) => {
  const { username, password, twoFactorCode } = req.body;

  // Sanitize inputs
  const sanitizedUsername = xss(username);

  const user = await User.findOne({ username: sanitizedUsername });
  if (!user) {
    return res.status(404).json({ message: "User not found." });
  }

  // Validate password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: "Invalid credentials." });
  }

  // Implement 2FA verification
  const isTwoFactorValid = verifyTwoFactor(user, twoFactorCode);
  if (!isTwoFactorValid) {
    return res.status(401).json({ message: "Invalid two-factor code." });
  }

  // Generate access token and refresh token
  const token = jwt.sign({ username: sanitizedUsername }, SECRET_KEY, {
    expiresIn: "1h",
  });
  const refreshToken = generateRefreshToken();

  // Save refresh token to user's account for future use
  user.refreshTokens.push(refreshToken);
  await user.save();

  res.json({ token, refreshToken });
});

// Verify Two-Factor Authentication Code
function verifyTwoFactor(user, code) {
  // Use speakeasy library to verify the two-factor code
  const verified = speakeasy.totp.verify({
    secret: user.twoFactorSecret, // Store user's two-factor secret in the database
    encoding: "base32",
    token: code,
  });

  return verified;
}

// Middleware for Role-Based Access Control (RBAC)
function authorizeRoles(roles) {
  return (req, res, next) => {
    // Check if user has the required role
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied." });
    }
    next();
  };
}

// Middleware for Attribute-Based Access Control (ABAC)
function authorizeAttributes(attributes) {
  return (req, res, next) => {
    // Implement logic to check if user's attributes match the required attributes
    const userAttributes = getUserAttributes(req.user.username); // Function to fetch user's attributes
    const hasRequiredAttributes = userAttributes.some((attribute) =>
      attributes.includes(attribute)
    );
    if (!hasRequiredAttributes) {
      return res.status(403).json({ message: "Access denied." });
    }
    next();
  };
}

// Protected route accessible based on user's attributes
app.get(
  "/restricted",
  authenticateToken,
  authorizeAttributes(["special_access"]),
  (req, res) => {
    res.json({ message: "Welcome to the restricted area!" });
  }
);

// Dynamic Role Assignment
app.post(
  "/assign-role/:username/:role",
  authenticateToken,
  authorizeRoles(["admin"]),
  async (req, res) => {
    const { username, role } = req.params;
    try {
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(404).json({ message: "User not found." });
      }
      user.role = role; // Assign the specified role
      await user.save();
      res.json({ message: `Role ${role} assigned to user ${username}.` });
    } catch (err) {
      res.status(500).json({ message: "Error assigning role." });
    }
  }
);

// Placeholder for Centralized Identity and Access Management (IAM)
// Implement a separate IAM microservice to manage user identities, roles, and permissions

// ... (other routes and code)

// Middleware for JWT authentication
function authenticateToken(req, res, next) {
  // Verify JWT token and attach user to request object
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token is missing." });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Access token is invalid." });
    }
    req.user = user;
    next();
  });
}

// Generate refresh token using speakeasy library
function generateRefreshToken() {
  const secret = speakeasy.generateSecret({ length: 20 }).base32;
  return secret;
}

// Protected route: Retrieve user profile
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }
    const userProfile = { username: user.username, email: "user@example.com" };
    res.json(userProfile);
  } catch (err) {
    res.status(500).json({ message: "Error fetching user profile." });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`User Management Microservice is running on port ${PORT}`);
});
