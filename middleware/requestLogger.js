const { model } = require("mongoose");

const requestLogger = (req, res, next) => {
    if (req.method === 'POST') {
      console.log(`POST request made to ${req.path}`);
    }
    next();
  };
  
model.exports = {requestLogger}  