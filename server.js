<<<<<<< HEAD
// Import required modules and packages

const express = require("express");
const mongoose = require("mongoose"); // MongoDB driver
const cors = require("cors"); // Cross-Origin Resource Sharing
const helmet = require("helmet"); // Security headers middleware
const rateLimit = require("express-rate-limit"); // Rate limiting for requests
const authRoutes = require("./routes/authRoutes.js"); // Authentication routes
const dotenv = require('dotenv');
dotenv.config();
=======
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const authRoutes = require('./routes/authRoutes.js');
>>>>>>> feature/semantic-release

// Create an Express application
const app = express();
<<<<<<< HEAD
const PORT = process.env.PORT || 3001; // Define the port to listen on
const MONGO_URI = process.env.MONGO_URI; // MongoDB connection URI

// Connect to MongoDB database
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  dbName: "clist3", // Specify your actual database name here
})
=======
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
//comment
// Connect to MongoDB
mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
>>>>>>> feature/semantic-release
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((err) => {
<<<<<<< HEAD
    console.error("Error connecting to MongoDB:", err);
    console.log("error"); // Uncomment to terminate the application on database connection error
=======
    console.error('Error connecting to MongoDB:', err);
    process.exit(1); // Terminate the application on database connection error
>>>>>>> feature/semantic-release
  });

// Parse JSON and URL-encoded request bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

<<<<<<< HEAD
// Middleware setup
app.use(cors()); // Enable Cross-Origin Resource Sharing
app.use(helmet()); // Set security headers for the app

// Enable rate limiting for incoming requests
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit to 100 requests per windowMs
});
app.use(limiter);

// Define routes for authentication
app.use("/auth", authRoutes);
=======
app.use('/auth', authRoutes);
>>>>>>> feature/semantic-release

// Define a test route
app.get("/test", (req, res) => {
  res.send("Server is up and running!");
});

// Start the Express server and listen on the specified port
app.listen(PORT, () => {
  console.log(`User Management Microservice is running on port ${PORT}`);
});
