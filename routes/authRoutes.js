const express = require("express");
const authController = require("../controllers/authController.js");
const { authenticateToken } = require("../middleware/authentication.js");
const { registrationValidation } = require("../utils/validate.js"); // Separated validation logic
const asyncHandler = require('../middleware/asyncHandler.js'); // Async error handling middleware

const router = express.Router();

// User registration
router.post("/register", registrationValidation, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  await authController.registerUser(req, res);
}));

// User login
router.post("/login", asyncHandler(authController.loginUser));

// Token validation
router.post('/validateToken', asyncHandler(authController.validateToken));

// Enable 2FA
router.post("/enable-2fa", authenticateToken, asyncHandler(authController.enableTwoFactorAuth));

// ... (other routes)

module.exports = router;

// router.post('/refreshToken', async (req, res) => {
//   const refreshToken = req.body.refreshToken;
//   if (!refreshToken) return res.status(401).json({ message: "Refresh Token is required." });

//   try {
//     const user = await validateRefreshToken(refreshToken);
//     if (!user) return res.status(403).json({ message: "Invalid Refresh Token" });

//     const newAccessToken = generateAccessToken(user);
//     res.json({ accessToken: newAccessToken });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });


