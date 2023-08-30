const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = "your-secret-key";

// Connect to MongoDB securely
mongoose
  .connect("mongodb://localhost:27017/user-management", {
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
});

const User = mongoose.model("User", userSchema);

app.use(cors()); // Set up CORS to control cross-origin requests
app.use(helmet()); // Enhance security with HTTP headers
app.use(express.json()); // Parse JSON bodies

// Register a new user
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required." });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword });

  try {
    await newUser.save();
    res.status(201).json({ message: "User registered successfully." });
  } catch (err) {
    res.status(500).json({ message: "Error registering user." });
  }
});

// User login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) {
    return res.status(404).json({ message: "User not found." });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: "Invalid credentials." });
  }

  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });

  res.json({ token });
});

// Protected route: Retrieve user profile
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }
    const userProfile = { username: user.username, email: "user@example.com" };
    res.json(userProfile);
  } catch (err) {
    res.status(500).json({ message: "Error fetching user profile." });
  }
});

// Middleware for authentication
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token is missing." });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Access token is invalid." });
    }
    req.user = user;
    next();
  });
}

// Start the server
app.listen(PORT, () => {
  console.log(`User Management Microservice is running on port ${PORT}`);
});
