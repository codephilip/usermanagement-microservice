const express = require("express");
const authController = require("../controllers/authController.js");
const { authenticateToken } = require("../middleware/authentication.js");

const { generateRefreshToken } = require("../utils/tokenUtils.js");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");

const router = express.Router();


// Validation middleware for user registration
const registrationValidation = [
  body("username").isLength({ min: 3 }).trim().escape(),
  body("password").isLength({ min: 8 }),
];

router.post("/register", registrationValidation, async (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // If validation passes, call the controller method
    await authController.registerUser(req, res, next);
  } catch (err) {
    console.error("Error registering user:", err);
    res.status(500).json({ message: "Error registering user." });
  }
});


router.post("/login", authController.loginUser);
// Route for validating tokens
router.post('/validateToken', authController.validateToken);

router.post('/refreshToken', async (req, res) => {
  const refreshToken = req.body.refreshToken;
  if (!refreshToken) return res.status(401).json({ message: "Refresh Token is required." });

  try {
    const user = await validateRefreshToken(refreshToken);
    if (!user) return res.status(403).json({ message: "Invalid Refresh Token" });

    const newAccessToken = generateAccessToken(user);
    res.json({ accessToken: newAccessToken });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

router.post(
  "/enable-2fa",
  authenticateToken,
  authController.enableTwoFactorAuth
);



// ... (other routes)

module.exports = router;
