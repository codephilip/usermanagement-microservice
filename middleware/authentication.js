const jwt = require("jsonwebtoken");
const User = require("../models/userModel.js");
const { SECRET_KEY } = process.env; // Use the environment variable for the secret key

authenticateToken = function (req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1]; if (!token) { return res.status(401).json({ message: "Access token is missing." });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Access token is invalid." });
    }
    req.user = user;
    next();
  });
};
module.exports = { authenticateToken };
