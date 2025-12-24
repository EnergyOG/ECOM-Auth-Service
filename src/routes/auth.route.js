import express from "express";
import {
  register,
  login,
  refreshToken,
  verifyPasswordResetEmail,
  logout,
  getProfile,
  updateProfile,
  changePassword,
  forgotPassword,
  resetPassword,
  sendVerificationEmail,
  verifyEmail,
  getAllUsers,
  softDeleteUser,
} from "../controllers/auth.controller.js";

import {
  signUpValidation,
  signInValidation,
  updateProfileValidation,
  changePasswordValidation,
  forgotPasswordValidation,
  verifyPasswordResetValidation,
  resetPasswordValidation,
  verifyEmailValidation,
} from "../middleware/validator.js";

import { requireAdmin, verifyToken } from "../middleware/auth.js";
import { authLimiter, strictAuthLimiter } from "../middleware/rateLimiter.js";

const router = express.Router();

router.post("/register", strictAuthLimiter, signUpValidation, register);

router.get("/all-users", strictAuthLimiter, getAllUsers)

router.post("/login", strictAuthLimiter, signInValidation, login);

router.post("/refresh", authLimiter, refreshToken);

router.post("/forgot-password", strictAuthLimiter, forgotPasswordValidation, forgotPassword);

router.get("/verify-password-reset", strictAuthLimiter, verifyPasswordResetValidation, verifyPasswordResetEmail);

router.post("/reset-password", strictAuthLimiter, resetPasswordValidation, resetPassword);

router.post("/logout", verifyToken, logout);

router.get("/profile", verifyToken, getProfile);

router.patch("/profile", verifyToken, updateProfileValidation,  updateProfile);

router.post("/change-password", verifyToken, authLimiter, changePasswordValidation, changePassword);

router.post("/send-verification", verifyToken, authLimiter, sendVerificationEmail);

router.get("/verify-email", verifyEmailValidation, verifyEmail);

router.patch("/admin/users/:userId/role", verifyToken, requireAdmin, changePassword);

router.delete("/admin/users/:userId", verifyToken, requireAdmin, softDeleteUser);

router.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Auth service is running",
    timestamp: new Date(),
    uptime: process.uptime(),
  });
});

export default router;