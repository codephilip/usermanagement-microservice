const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String, //TODO: Add validation for username
    unique: true, // Make the username field unique
  },
  password: String,
  refreshTokens: [String],
  role: String,
  twoFactorSecret: String,
});

const User = mongoose.model('User', userSchema);

module.exports = User;
