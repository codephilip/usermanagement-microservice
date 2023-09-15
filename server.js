require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const authRoutes = require("./routes/authRoutes.js");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = "your-secret-key"; // Set your secret key here
const MONGO_URI = process.env.MONGO_URI; // Set your MongoDB URI here
const bodyParser = require("body-parser");

mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB:", err);
  });

// Parse JSON bodies
app.use(bodyParser.json());

// Parse URL-encoded bodies (for forms)
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors());
app.use(helmet());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

app.use("/auth", authRoutes);

app.listen(PORT, () => {
  console.log(`User Management Microservice is running on port ${PORT}`);
});
