import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { connectRedis } from './src/config/redis.js';
import connectDB from './src/config/database.js';
import { notFound, errorHandler } from './src/middleware/errorHandler.js';
import cookieParser from 'cookie-parser';
import dotenv from "dotenv-flow";

dotenv.config();

const app = express();

const PORT = process.env.NODE_ENV === "production"
  ? (process.env.PROD_PORT) 
  : (process.env.DEV_PORT);

app.use(helmet());

app.use(cors({
  origin: `http:localhost:${PORT}`,
  credentials: true
}));

app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Auth Service API',
    version: '1.0.0',
    endpoints: {
      health: '/api/auth/health',
      register: 'POST /api/auth/register',
      login: 'POST /api/auth/login',
      profile: 'GET /api/auth/profile'
    }
  });
});


const startServer = async () => {
  try {
    await connectRedis();
    await connectDB();
    
    const authRoutes = (await import('./src/routes/auth.route.js')).default;
    app.use('/api/auth', authRoutes);
    
    app.use(notFound);
    app.use(errorHandler);
    
    app.listen(PORT, () => {
      console.log(`Auth Service running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

export default app;