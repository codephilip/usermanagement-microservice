const express = require("express");
const { body, validationResult } = require("express-validator");
const authController = require("../controllers/authController.js");
const { authenticateToken } = require("../middleware/authentication.js");

const router = express.Router();

router.post(
  "/register",
  [
    body("username").isLength({ min: 3 }).trim().escape(),
    body("password").isLength({ min: 8 }),
  ],
  (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // If validation passes, call the controller method
    authController.registerUser(req, res, next);
  }
);

router.post("/login", authController.loginUser);

router.post(
  "/enable-2fa",
  authenticateToken,
  authController.enableTwoFactorAuth
);

// ... (other routes)

module.exports = router;
