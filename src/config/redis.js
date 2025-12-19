import { createClient } from "redis";
import dotenv from "dotenv";

dotenv.config();

const redisURL = process.env.REDIS_URL;
const redisPassword = process.env.REDIS_PASSWORD;

const redisClient = createClient({
  url: redisURL,
  password: redisPassword,
  maxRetriesPerRequest: 3,
  socket: {
    connectTimeout: 5000,
    reconnectStrategy: (retries) => {
      if (retries > 10) {
        console.error("Too many Redis reconnection attempts");
        return new Error("Redis reconnection failed");
      }
      return Math.min(retries * 100, 3000);
    },
  },
});

redisClient.on("connect", () => {
  console.log("Connecting to Redis...");
});

redisClient.on("ready", () => {
  console.log("Redis Connected");
});

redisClient.on("error", (err) => {
  console.error("Redis Error:", err);
});

redisClient.on("reconnecting", () => {
  console.log("Redis Reconnecting...");
});

redisClient.on("end", () => {
  console.log("Redis Connection Closed");
});

const connectRedis = async () => {
  try {
    await redisClient.connect();
  } catch (err) {
    console.error("Redis connection failed:", err.message);
  }
};

export const redisHelpers = {
  async setEx(key, value, ttl = 3600) {
    try {
      await redisClient.setEx(key, ttl, JSON.stringify(value));
    } catch (err) {
      console.error("Redis SET error:", err);
    }
  },

  async get(key) {
    try {
      const data = await redisClient.get(key);
      return data ? JSON.parse(data) : null;
    } catch (err) {
      console.error("Redis GET error:", err);
      return null;
    }
  },

  async del(key) {
    try {
      await redisClient.del(key);
    } catch (error) {
      console.error("Redis DEL error:", error);
    }
  },

  async exists(key) {
    try {
      return await redisClient.exists(key);
    } catch (error) {
      console.error("Redis EXISTS error:", error);
      return false;
    }
  },

  async mset(keyValuePairs) {
    try {
      const pairs = Object.entries(keyValuePairs).flat();
      if (!keyValuePairs || typeof keyValuePairs !== "object") {
        throw new Error("Invalid key-value object");
      }
      await redisClient.mSet(pairs);
    } catch (error) {
      console.error("Redis MSET error:", error);
    }
  },
  async blacklistToken(token, ttl) {
    try {
      await redisClient.setEx(`blacklist:${token}`, ttl, "true");
    } catch (err) {
      console.error("Redis BLACKLIST error:", err);
    }
  },

  async isTokenBlacklisted(token) {
    try {
      return await redisClient.exists(`blacklist:${token}`);
    } catch (err) {
      console.error("Redis CHECK BLACKLIST error:", err);
      return false;
    }
  },
};

process.on("SIGINT", async () => {
  await redisClient.quit();
  console.log("Redis connection closed");
  process.exit(0);
});

export { redisClient, connectRedis };
