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

router.post(
  "/enable-2fa",
  authenticateToken,
  authController.enableTwoFactorAuth
);

// ... (other routes)

module.exports = router;
