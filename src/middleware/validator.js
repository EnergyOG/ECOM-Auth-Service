import { body, query, validationResult } from 'express-validator';

// Validation error handler
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array().map(err => ({
        field: err.path,
        message: err.msg,
        value: err.value
      }))
    });
  }
  
  next();
};

// Sign up validation
export const signUpValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  
  body('email')
    .trim()
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required')
    .isLength({ max: 100 })
    .withMessage('Email too long'),
  
  body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be 8-128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number'),
  
  handleValidationErrors
];

// Sign in validation
export const signInValidation = [
  body('email')
    .trim()
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  
  handleValidationErrors
];

// Update profile validation
export const updateProfileValidation = [
  body('username')
    .optional()
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  
  body('email')
    .optional()
    .trim()
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  
  handleValidationErrors
];

// Change password validation
export const changePasswordValidation = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  
  body('newPassword')
    .isLength({ min: 8, max: 128 })
    .withMessage('New password must be 8-128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number'),
  
  body('newPassword')
    .custom((value, { req }) => value !== req.body.currentPassword)
    .withMessage('New password must be different from current password'),
  
  handleValidationErrors
];

// Forgot password validation
export const forgotPasswordValidation = [
  body('email')
    .trim()
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  
  handleValidationErrors
];

// Verify password reset email validation
export const verifyPasswordResetValidation = [
  query('token')
    .exists()
    .withMessage('Reset token is required')
    .isString()
    .withMessage('Reset token must be a string')
    .isLength({ min: 20 })
    .withMessage('Reset token is invalid'),

  handleValidationErrors
];

// Reset password validation
export const resetPasswordValidation = [
  body('resetSessionId')
    .notEmpty()
    .withMessage('Reset session ID is required')
    .isString()
    .withMessage('Reset session ID must be a string'),

  body('newPassword')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be 8-128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number'),

  handleValidationErrors
];

// Verify email validation
export const verifyEmailValidation = [
  query('token')
    .notEmpty()
    .withMessage('Verification token is required')
    .isLength({ min: 10, max: 100 })
    .withMessage('Invalid verification token'),

  handleValidationErrors
];