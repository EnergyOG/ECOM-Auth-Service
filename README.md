# Auth Service

**Authentication Service** for the **E-Commerce Microservices Backend**.  
Handles **user registration, login, JWT authentication, refresh tokens, and role-based access control**.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [API Endpoints](#api-endpoints)
- [Authentication Flow](#authentication-flow)
- [Testing](#testing)
- [CI/CD](#cicd)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This service is a **core authentication microservice** in the e-commerce platform.  
It is designed to work with multiple services such as **user-service, order-service, and payment-service**, providing secure access and authorization.

---

## Features

- User **registration** and **login**
- **JWT-based authentication** (Access & Refresh Tokens)
- **Role-based access control (RBAC)**
- Password **hashing and encryption**
- Middleware for **authorization checks**
- Scalable **microservices design**
- **Dockerized** for containerized deployments
- Designed for **CI/CD pipelines**

---

## Tech Stack

- **Node.js** / **Express.js**
- **MongoDB** / Mongoose
- **JWT** for authentication
- **Bcrypt** for password hashing
- **Docker** for containerization
- **GitHub Actions** for CI/CD
- **ESLint** / **Prettier** for code quality

---

## Architecture

