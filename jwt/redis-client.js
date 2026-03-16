// redis-client.js
import Redis from 'ioredis';

const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  password: process.env.REDIS_PASSWORD,
  maxRetriesPerRequest: null,
  connectTimeout: 180000,
  enableReadyCheck: true,
});

redis.on('error', (err) => {
  console.error('Redis connection error:', err);
});

export default redis;
