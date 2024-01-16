const jwt = require("jsonwebtoken");
const User = require("../models/userModel.js");
const { SECRET_KEY } = process.env; // Use the environment variable for the secret key

const authenticateToken = function (req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  console.log("token",token)  
  console.log("authHeader",authHeader)
  if (!token) {
    return res.status(401).json({ message: "Access token is missing." });
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
    if (err) {
      // Handle JWT verification errors more explicitly
      if (err.name === "TokenExpiredError") {
        console.log("Token expired.")
        return res.status(401).json({ message: "Access token has expired." });
      } else if (err.name === "JsonWebTokenError") {
        console.log("Token invalid.")
        return res.status(403).json({ message: "Access token is invalid." });
      } else {
        console.log("Token error.")
        return res.status(500).json({ message: "Internal server error." });
      }
    }

    // If the token is valid, attach the user information to the request
    req.user = user;
    next();
  });
};

module.exports = { authenticateToken };
