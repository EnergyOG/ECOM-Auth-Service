# 🔐 Auth Service

A production-ready authentication and authorization microservice built with **Node.js, Express, MongoDB, Redis, and JWT**.  
This service handles user authentication, role-based access control, email verification, password recovery, session management, and admin operations using secure best practices.

---

## 🚀 Features

### Authentication
- User registration & login
- Secure password hashing (bcrypt)
- JWT access & refresh tokens
- Refresh token rotation
- Logout with token invalidation

### Authorization
- Role-based access control (User / Admin)
- First admin bootstrap via environment variable
- Admin-only user management routes

### Account Management
- Email verification
- Forgot / Reset password flow
- Change password
- Update profile
- Last login tracking

### Security
- Soft delete (accounts are never permanently removed)
- Suspended account handling
- Redis-backed token storage
- HTTP-only secure cookies
- Token invalidation on password change

### Email Services
- Email verification
- Password reset email
- Account deletion notification

### Performance
- Redis caching for user sessions
- Optimized database queries
- Centralized middleware validation

---

## 🏗️ Tech Stack

| Technology | Usage |
|----------|------|
| Node.js | Runtime |
| Express | HTTP server |
| MongoDB | Database |
| Mongoose | ODM |
| Redis | Token storage & caching |
| JWT | Authentication |
| bcrypt | Password hashing |
| Nodemailer | Email delivery |
| Yup | Request validation |

---

## 📁 Project Structure

