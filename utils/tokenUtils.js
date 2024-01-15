const speakeasy = require("speakeasy");

function generateRefreshToken() {
  const secret = speakeasy.generateSecret({ length: 20 }).base32;
  console.log(secret);
  return secret;
}

module.exports = { generateRefreshToken };
