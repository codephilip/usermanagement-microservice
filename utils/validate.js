const { body } = require('express-validator');

const registrationValidation = [
    body('username')
        .isLength({ min: 3 })
        .withMessage('Username must be at least 3 characters long.')
        .trim()
        .escape(),

    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long.')
];

const loginValidation = [
    body('username')
        .notEmpty()
        .withMessage('Username is required.')
        .trim()
        .escape(),

    body('password')
        .notEmpty()
        .withMessage('Password is required.')
];

// Add more validation chains for other user-related functionalities if needed

module.exports = {
    registrationValidation,
    loginValidation,
    // export other validations here
};
