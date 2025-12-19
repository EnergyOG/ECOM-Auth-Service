import bcrypt from 'bcrypt';
import User from '../model/auth.model.js';
import { generateTokenPair, verifyRefreshToken } from '../config/jwt.js';
import { redisHelpers } from '../config/redis.js';

export const register = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;
    
    const existingUser = await User.findOne({ email });
    
    if (existingUser) {
      return res.status(409).json({ 
        success: false,
        error: 'Email already registered' 
      });
    }
    
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const user = await User.create({
      username,
      email,
      password: hashedPassword
    });
    
    const tokens = generateTokenPair({
      userId: user._id.toString(),
      email: user.email,
      role: user.role
    });
    
    await redisHelpers.setEx(
      `refresh_token:${user._id}`,
      tokens.refreshToken,
      7 * 24 * 60 * 60
    );
    
    const response = {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      accessToken: tokens.accessToken
    };
    
    res.status(201)
      .cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
      })
      .json({
        success: true,
        message: 'Account created successfully',
        data: response
      });
      
  } catch (error) {
    next(error);
  }
};

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }
    
    if (user.status === 'suspended') {
      return res.status(403).json({
        success: false,
        error: 'Account suspended. Please contact support.'
      });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }
    
    const tokens = generateTokenPair({
      userId: user._id.toString(),
      email: user.email,
      role: user.role
    });
    
    await redisHelpers.setEx(
      `refresh_token:${user._id}`,
      tokens.refreshToken,
      7 * 24 * 60 * 60
    );
    
    user.lastLogin = new Date();
    await user.save();
    
    const response = {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      accessToken: tokens.accessToken
    };
    
    res.status(200)
      .cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
      })
      .json({
        success: true,
        message: 'Login successful',
        data: response
      });
  } catch (error) {
    next(error);
  }
};

export const refreshToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        error: 'Refresh token is required'
      });
    }

    const decoded = verifyRefreshToken(refreshToken);

    const storedToken = await redisHelpers.get(`refresh_token:${decoded.userId}`);

    if (!storedToken || storedToken !== refreshToken) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or expired refresh token. Please login again.'
      });
    }

    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User not found. Please login again.'
      });
    }

    const tokens = generateTokenPair({
      userId: user._id.toString(),
      email: user.email,
      role: user.role
    });

    await redisHelpers.setEx(
      `refresh_token:${user._id}`,
      tokens.refreshToken,
      7 * 24 * 60 * 60
    );

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken
      }
    });

  } catch (error) {
    if (error.message.includes('expired') || error.message.includes('invalid')) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or expired refresh token. Please login again.'
      });
    }
    next(error);
  }
};

export const logout = async (req, res, next) => {
  try {
    const userId = req.user.id;

    await redisHelpers.del(`refresh_token:${userId}`);

    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      await redisHelpers.setEx(`blacklist:${token}`, 'true', 15 * 60);
    }

    res.status(200)
    .clearCookie('refreshToken')
    .json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    next(error);
  }
};

export const getProfile = async (req, res, next) => {
  try {
    const userId = req.user.id;

    const cachedUser = await redisHelpers.get(`user:${userId}`);
    
    if (cachedUser) {
      return res.status(200).json({
        success: true,
        data: { user: cachedUser }
      });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Manual response formatting (replaces UserResponseDTO)
    const userResponse = {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      status: user.status,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt
    };

    await redisHelpers.setEx(`user:${userId}`, userResponse, 3600);

    res.status(200).json({
      success: true,
      data: { user: userResponse }
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
        $or: [...(email ? [{ email }] : [])]
      });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          error: 'Email already in use' 
        });
      }
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { 
        ...(email && { email }),
        ...(username && { username })
      },
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    await redisHelpers.del(`user:${userId}`);

    // Manual response formatting (replaces UserResponseDTO)
    const userResponse = {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      status: user.status,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt
    };

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: { user: userResponse }
    });

  } catch (error) {
    next(error);
  }
};

export const changePassword = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(userId).select('+password');

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        error: 'Current password is incorrect'
      });
    }

    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    await redisHelpers.del(`refresh_token:${userId}`);

    res.status(200).json({
      success: true,
      message: 'Password changed successfully. Please login again.'
    });

  } catch (error) {
    next(error);
  }
};

export const forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(200).json({
        success: true,
        message: 'If that email exists, a reset link has been sent.'
      });
    }

    const resetToken = Math.random().toString(36).substring(2, 15);
    const hashedToken = await bcrypt.hash(resetToken, 10);

    await redisHelpers.setEx(
      `reset_token:${user._id}`,
      hashedToken,
      3600
    );

    // TODO: Send email with reset link
    // await emailService.sendPasswordReset(user.email, resetToken);

    res.status(200).json({
      success: true,
      message: 'If that email exists, a reset link has been sent.',
      // Remove in production:
      dev_resetToken: resetToken
    });

  } catch (error) {
    next(error);
  }
};

export const resetPassword = async (req, res, next) => {
  try {
    const { email, resetToken, newPassword } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or expired reset token'
      });
    }

    // Get stored token from Redis
    const storedToken = await redisHelpers.get(`reset_token:${user._id}`);

    if (!storedToken) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or expired reset token'
      });
    }

    // Verify token
    const isTokenValid = await bcrypt.compare(resetToken, storedToken);

    if (!isTokenValid) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or expired reset token'
      });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    // Delete reset token
    await redisHelpers.del(`reset_token:${user._id}`);

    // Invalidate all sessions
    await redisHelpers.del(`refresh_token:${user._id}`);

    res.status(200).json({
      success: true,
      message: 'Password reset successfully. Please login with your new password.'
    });

  } catch (error) {
    next(error);
  }
};

export const sendVerificationEmail = async (req, res, next) => {
  try {
    const userId = req.user.id;

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    if (user.isEmailVerified) {
      return res.status(400).json({
        success: false,
        error: 'Email already verified'
      });
    }

    // Generate verification token
    const verificationToken = Math.random().toString(36).substring(2, 15);
    
    // Store in Redis (valid for 24 hours)
    await redisHelpers.setEx(
      `verify_email:${user._id}`,
      verificationToken,
      24 * 60 * 60
    );

    // TODO: Send verification email
    // await emailService.sendVerification(user.email, verificationToken);

    res.status(200).json({
      success: true,
      message: 'Verification email sent',
      // Remove in production:
      dev_verificationToken: verificationToken
    });

  } catch (error) {
    next(error);
  }
};

export const verifyEmail = async (req, res, next) => {
  try {
    const { token } = req.body;
    const userId = req.user.id;

    const storedToken = await redisHelpers.get(`verify_email:${userId}`);

    if (!storedToken || storedToken !== token) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or expired verification token'
      });
    }

    // Update user
    const user = await User.findByIdAndUpdate(
      userId,
      { isEmailVerified: true },
      { new: true }
    );

    // Delete verification token
    await redisHelpers.del(`verify_email:${userId}`);

    // Clear user cache
    await redisHelpers.del(`user:${userId}`);

    // Manual response formatting (replaces UserResponseDTO)
    const userResponse = {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      status: user.status,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt
    };

    res.status(200).json({
      success: true,
      message: 'Email verified successfully',
      data: { user: userResponse }
    });

  } catch (error) {
    next(error);
  }
};

export default {
  register,
  login,
  refreshToken,
  logout,
  getProfile,
  updateProfile,
  changePassword,
  forgotPassword,
  resetPassword,
  sendVerificationEmail,
  verifyEmail
};