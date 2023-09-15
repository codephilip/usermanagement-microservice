require("dotenv").config();
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
const SECRET_KEY = "your-secret-key"; // Replace with an environment variable

// Connect to MongoDB securely
mongoose
  .connect(process.env.MONGO_URI, {
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
  refreshTokens: [String],
  role: String,
  twoFactorSecret: String,
});

const User = mongoose.model("User", userSchema);

// Middleware
app.use(cors()); // Enable CORS
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

    try {
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

      await newUser.save();
      res.status(201).json({ message: "User registered successfully." });
    } catch (err) {
      console.error(err); // Log the error
      res.status(500).json({ message: "Error registering user." });
    }
  }
);

// User login with 2FA
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
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
    // const isTwoFactorValid = verifyTwoFactor(user, twoFactorCode);
    // if (!isTwoFactorValid) {
    //   return res.status(401).json({ message: "Invalid two-factor code." });
    // }

    // Generate access token and refresh token
    const token = jwt.sign({ username: sanitizedUsername }, SECRET_KEY, {
      expiresIn: "1h",
    });
    const refreshToken = generateRefreshToken();

    // Save refresh token to user's account for future use
    user.refreshTokens.push(refreshToken);
    await user.save();

    res.json({ token, refreshToken });
  } catch (err) {
    console.error(err); // Log the error
    res.status(500).json({ message: "Error during login." });
  }
});

// Rest of your routes and middleware

// Start the server
app.listen(PORT, () => {
  console.log(`User Management Microservice is running on port ${PORT}`);
});

// Helper function to generate refresh tokens
function generateRefreshToken() {
  const secret = speakeasy.generateSecret({ length: 20 }).base32;
  return secret;
}
