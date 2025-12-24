import crypto from "crypto";
import bcrypt from "bcrypt";
import User from "../model/auth.model.js";
import { generateTokenPair, verifyRefreshToken } from "../config/jwt.js";
import { redisHelpers } from "../config/redis.js";
import { sendVerificationEmail as sendEmail } from "../services/email.service.js";

export const register = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: "Email already registered",
      });
    }

    let role = "user";
    const adminExists = await User.exists({ role: "admin" });

    if (!adminExists && email === process.env.SUPER_ADMIN_EMAIL) {
      role = "admin";
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      role,
    });

    const tokens = generateTokenPair({
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
    });

    await redisHelpers.setEx(
      `refresh_token:${user._id}`,
      tokens.refreshToken,
      7 * 24 * 60 * 60
    );

    res
      .status(201)
      .cookie("refreshToken", tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .json({
        success: true,
        message: "Account created successfully",
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
          },
          accessToken: tokens.accessToken,
        },
      });
  } catch (err) {
    next(err);
  }
};

export const getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find();
    if (users.length === 0) {
      return res.status(400).json({
        message: "No users found",
      });
    }
    return res.status(200).json({
      message: "Users found successfully",
      data: users,
    });
  } catch (err) {
    console.log("Error", err);
    res.status(500).json({
      message: "Internal Server Error",
      error: err.message,
    });
  }
};

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select("+password");
    if (!user || user.isDeleted) {
      return res.status(401).json({
        success: false,
        error: "Invalid email or password",
      });
    }

    if (user.status === "suspended") {
      return res.status(403).json({
        success: false,
        error: "Account suspended",
      });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({
        success: false,
        error: "Invalid email or password",
      });
    }

    const tokens = generateTokenPair({
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
    });

    await redisHelpers.setEx(
      `refresh_token:${user._id}`,
      tokens.refreshToken,
      7 * 24 * 60 * 60
    );

    user.lastLogin = new Date();
    await user.save();

    res
      .status(200)
      .cookie("refreshToken", tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .json({
        success: true,
        message: "Login successful",
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
          },
          accessToken: tokens.accessToken,
        },
      });
  } catch (err) {
    next(err);
  }
};

export const refreshToken = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ error: "Refresh token missing" });
    }

    const decoded = verifyRefreshToken(refreshToken);
    const storedToken = await redisHelpers.get(
      `refresh_token:${decoded.userId}`
    );

    if (!storedToken || storedToken !== refreshToken) {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    const user = await User.findById(decoded.userId);
    if (!user || user.isDeleted) {
      return res.status(401).json({ error: "User not found" });
    }

    const tokens = generateTokenPair({
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
    });

    await redisHelpers.setEx(
      `refresh_token:${user._id}`,
      tokens.refreshToken,
      7 * 24 * 60 * 60
    );

    res
      .status(200)
      .cookie("refreshToken", tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .json({ success: true, data: { accessToken: tokens.accessToken } });
  } catch (err) {
    next(err);
  }
};

export const logout = async (req, res, next) => {
  try {
    const userId = req.user.id;

    await redisHelpers.del(`refresh_token:${userId}`);
    await redisHelpers.del(`user:${userId}`);

    res.clearCookie("refreshToken").json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (err) {
    next(err);
  }
};

export const changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.id).select("+password");
    const comparePassword = await bcrypt.compare(
      currentPassword,
      user.password
    );

    if (!user || !comparePassword) {
      return res.status(401).json({
        success: false,
        error: "Current password incorrect",
      });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    await redisHelpers.del(`refresh_token:${user._id}`);
    await redisHelpers.del(`user:${user._id}`);

    res.status(200).json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (err) {
    next(err);
  }
};

export const forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(200).json({
        success: true,
        message: "If that email exists, a link has been sent",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    await redisHelpers.setEx(
      `password_reset_verify:${hashedToken}`,
      user._id.toString(),
      15 * 60
    );

    await sendEmail(user.email, rawToken);

    res.status(200).json({
      success: true,
      ...(process.env.NODE_ENV === "development" && {
        dev_token: rawToken,
      }),
    });
  } catch (err) {
    next(err);
  }
};

export const verifyPasswordResetEmail = async (req, res, next) => {
  try {
    const { token } = req.query;

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const userId = await redisHelpers.get(
      `password_reset_verify:${hashedToken}`
    );

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: "Invalid or expired token",
      });
    }

    const resetSessionId = crypto.randomUUID();

    await redisHelpers.setEx(
      `password_reset_session:${resetSessionId}`,
      userId,
      10 * 60
    );

    await redisHelpers.del(`password_reset_verify:${hashedToken}`);

    res.status(200).json({
      success: true,
      resetSessionId,
    });
  } catch (err) {
    next(err);
  }
};

export const resetPassword = async (req, res, next) => {
  try {
    const { resetSessionId, newPassword } = req.body;

    const userId = await redisHelpers.get(
      `password_reset_session:${resetSessionId}`
    );

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: "Invalid or expired reset session",
      });
    }

    await User.findByIdAndUpdate(userId, {
      password: await bcrypt.hash(newPassword, 12),
    });

    await redisHelpers.del(`password_reset_session:${resetSessionId}`);
    await redisHelpers.del(`refresh_token:${userId}`);

    res.status(200).json({
      success: true,
      message: "Password reset successful",
    });
  } catch (err) {
    next(err);
  }
};

export const sendVerificationEmail = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || user.isEmailVerified) {
      return res.status(400).json({
        success: false,
        error: "Invalid request",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    await redisHelpers.setEx(
      `verify_email:${hashedToken}`,
      user._id.toString(),
      24 * 60 * 60 //24 hrs
    );

    await sendEmail(user.email, rawToken);

    res.status(200).json({
      success: true,
      ...(process.env.NODE_ENV === "development" && {
        dev_verificationToken: rawToken,
      }),
    });
  } catch (err) {
    next(err);
  }
};

export const verifyEmail = async (req, res, next) => {
  try {
    const { token } = req.query;

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const userId = await redisHelpers.get(`verify_email:${hashedToken}`);
    if (!userId) {
      return res.status(400).json({
        success: false,
        error: "Invalid or expired token",
      });
    }

    await User.findByIdAndUpdate(userId, { isEmailVerified: true });
    await redisHelpers.del(`verify_email:${hashedToken}`);

    res.status(200).json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (err) {
    next(err);
  }
};

export const getProfile = async (req, res, next) => {
  try {
    const userId = req.user.id;

    const cachedUser = await redisHelpers.get(`user:${userId}`);
    if (cachedUser) {
      return res.status(200).json({
        success: true,
        data: { user: cachedUser },
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    const userResponse = {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      status: user.status,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt,
    };

    await redisHelpers.setEx(`user:${userId}`, userResponse, 3600);

    res.status(200).json({
      success: true,
      data: { user: userResponse },
    });
  } catch (error) {
    next(error);
  }
};

export const updateProfile = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { email, username } = req.body;

    if (email || username) {
      const existingUser = await User.findOne({
        _id: { $ne: userId },
        $or: [...(email ? [{ email }] : [])],
      });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          error: "Email already in use",
        });
      }
    }

    const user = await User.findByIdAndUpdate(
      userId,
      {
        ...(email && { email }),
        ...(username && { username }),
      },
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    await redisHelpers.del(`user:${userId}`);

    const userResponse = {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      status: user.status,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt,
    };

    res.status(200).json({
      success: true,
      message: "Profile updated successfully",
      data: { user: userResponse },
    });
  } catch (error) {
    next(error);
  }
};

export const changeUserRole = async (req, res) => {
  const { role } = req.body;

  if (!["user", "admin"].includes(role)) {
    return res.status(400).json({ message: "Invalid role" });
  }

  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ message: "User not found" });

  user.role = role;
  user.tokenVersion += 1; // invalidate old tokens
  await user.save();

  res.json({ message: `User role updated to ${role}` });
};

export const softDeleteUser = async (req, res, next) => {
  try {
    const { userId } = req.params;

    if (req.user.id === userId) {
      return res.status(400).json({
        success: false,
        error: "You cannot delete your own account",
      });
    }

    const user = await User.findById(userId);
    if (!user || user.isDeleted) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    if (user.email === process.env.SUPER_ADMIN_EMAIL) {
      return res.status(403).json({
        success: false,
        error: "Super admin account cannot be deleted",
      });
    }

    user.isDeleted = true;
    user.deletedAt = new Date();
    await user.save();

    await redisHelpers.del(`refresh_token:${userId}`);

    try {
      await sendAccountDeletionEmail(user.email, user.username);
    } catch (e) {
      console.error("Deletion email failed:", e.message);
    }

    console.log({
      action: "SOFT_DELETE_USER",
      actor: req.user.id,
      target: userId,
      role: user.role,
      time: new Date(),
    });

    res.status(200).json({
      success: true,
      message: "User account has been deactivated",
    });
  } catch (err) {
    next(err);
  }
}

export const ensureActiveUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user || user.isDeleted) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    req.currentUser = user;
    next();
  } catch (err) {
    next(err);
  }
};

export const updateUserStatus = async (req, res, next) => {
  try {
    const { status } = req.body;
    const { userId } = req.params;

    if (!["active", "suspended"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    const user = await User.findById(userId);
    if (!user || user.isDeleted) {
      return res.status(404).json({ error: "User not found" });
    }

    if (user.email === process.env.SUPER_ADMIN_EMAIL) {
      return res.status(403).json({
        error: "Super admin status cannot be changed",
      });
    }

    user.status = status;
    await user.save();

    // Force logout if suspended
    if (status === "suspended") {
      await redisHelpers.del(`refresh_token:${userId}`);
    }

    res.status(200).json({
      success: true,
      message: `User ${status} successfully`,
    });
  } catch (err) {
    next(err);
  }
};



export default {
  register,
  login,
  refreshToken,
  logout,
  changePassword,
  forgotPassword,
  verifyPasswordResetEmail,
  resetPassword,
  sendVerificationEmail,
  verifyEmail,
};