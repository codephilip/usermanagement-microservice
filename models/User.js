const mongoose = require("mongoose");

// Define User schema and model
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    refreshTokens: [String], // Store refresh tokens
    role: String, // User role (e.g., 'user' or 'admin')
    twoFactorSecret: String, // Store user's 2FA secret
});

const User = mongoose.model("User", userSchema);

//export the user model
module.exports = User;