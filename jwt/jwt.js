import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import redis from './redis-client.js'; // Предполагается, что этот файл настроен

// Импорты моделей
import RefreshToken from './models/refreshToken.model.js';
import User from './models/user.model.js';
import Currencies from './models/currency.model.js';
import Company from './models/company.model.js';

// --- УЛУЧШЕНО: Централизованная конфигурация ---
const config = {
  jwt: {
    expiresIn: process.env.TOKEN_EXPIRATION_MINUTES || '15',
    privateKeyPath: './keys/private.key' // Путь относительно этого файла
  },
  redis: {
    lockTtlMs: 5000,
    resultTtlS: 10,
    pollingIntervalMs: 200,
    pollingAttempts: 25
  },
  headers: {
    deviceId: 'x-device-id',
    authToken: 'x-authentication-token'
  },
  cookies: {
    refreshTokenName: 'refreshToken'
  },
  refreshTokenLifetimeDays: 60,
};

// --- ИСПРАВЛЕНО: Надежное определение пути к ключу ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const privateKey = fs.readFileSync(path.resolve(__dirname, config.jwt.privateKeyPath), 'utf8');

// --- ИСПРАВЛЕНО: Кастомные классы ошибок ---
class TokenRefreshFailedError extends Error {
  constructor(message) { super(message); this.name = 'TokenRefreshFailedError'; }
}
class TokenRefreshTimeoutError extends Error {
  constructor(message) { super(message); this.name = 'TokenRefreshTimeoutError'; }
}

/**
 * Основная функция обновления токена, использующая распределенную блокировку Redis.
 */
const RefreshTokenUpdate = async (request, reply) => {
  const { headers, cookies } = request;
  const oldRefreshToken = cookies[config.cookies.refreshTokenName];

  const lockKey = `lock:refresh:${oldRefreshToken}`;
  const resultKey = `result:refresh:${oldRefreshToken}`;

  const lockAcquired = await redis.set(lockKey, 'locked', 'PX', config.redis.lockTtlMs, 'NX');

  if (lockAcquired) {
    // --- ПОБЕДИТЕЛЬ ---
    try {
      const result = await findRefreshTokenAndUpdated(oldRefreshToken, headers[config.headers.deviceId]);
      
      if (!result) {
        await removeInvalidRefreshToken(oldRefreshToken);
        throw new TokenRefreshFailedError('Refresh token not found or expired');
      }

      await redis.set(resultKey, JSON.stringify(result), 'EX', config.redis.resultTtlS);
      applyRefreshResult(request, reply, result);

    } catch (error) {
      await redis.set(resultKey, JSON.stringify({ error: true, message: error.message }), 'EX', config.redis.resultTtlS);
      throw error;
    } finally {
      await redis.del(lockKey);
    }
  } else {
    // --- ОЖИДАЮЩИЙ ---
    const result = await waitForRefreshResult(resultKey);
    applyRefreshResult(request, reply, result);
  }
};

/**
 * Ожидает результат обновления от "победившего" процесса.
 */
async function waitForRefreshResult(resultKey) {
  for (let i = 0; i < config.redis.pollingAttempts; i++) {
    await new Promise(resolve => setTimeout(resolve, config.redis.pollingIntervalMs));
    
    const resultData = await redis.get(resultKey);
    if (resultData) {
      const result = JSON.parse(resultData);
      if (result.error) {
        throw new TokenRefreshFailedError(`Another process failed to refresh token: ${result.message}`);
      }
      return result;
    }
  }
  throw new TokenRefreshTimeoutError('Timed out waiting for token refresh result.');
}

const findRefreshTokenAndUpdated = async (refreshToken, deviceId) => {
  const currentDate = new Date();
  const expiredDate = new Date(currentDate.getTime() + (1000 * 60 * 60 * 24 * config.refreshTokenLifetimeDays));

  return RefreshToken.findOneAndUpdate(
    { token: refreshToken, deviceId, expired_at: { $gte: currentDate } },
    { $set: { token: uuidv4(), updated_at: currentDate, expired_at: expiredDate } },
    { new: true, lean: true, fields: { token: 1, userId: 1 } }
  ).populate({ 
      path: 'userId', 
      select: 'email phone telegram notification roles active name avatar company', 
      model: User,
      populate: {
        path: 'company', 
        select: 'currency', 
        model: Company,
        populate: {
          path: 'currency', 
          select: 'code', 
          model: Currencies,
        }
      }
    });
};

const applyRefreshResult = (request, reply, refreshResult) => {
  const { userId, token: newRefreshToken } = refreshResult;
  
  request.accessToken = generateAccessToken(userId);
  request.session = {
    _id: userId._id,
    company: userId.company._id,
    deviceId: request.headers[config.headers.deviceId]
  };
  
  setRefreshTokenCookie(reply, newRefreshToken);
};

const generateAccessToken = (payload) => {
  return jwt.sign(payload, privateKey, {
    expiresIn: `${config.jwt.expiresIn}m`,
    algorithm: 'RS256'
  });
};

const removeInvalidRefreshToken = async (refreshToken) => {
  try {
    await RefreshToken.findOneAndDelete({ token: refreshToken });
  } catch (err) {
    console.error(`Failed to remove invalid refresh token: ${err.message}`);
  }
};

const setRefreshTokenCookie = (reply, token) => {
  const expiresTime = new Date(Date.now() + (1000 * 60 * 60 * 24 * config.refreshTokenLifetimeDays));
  reply.setCookie(config.cookies.refreshTokenName, token, {
    expires: expiresTime,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    domain: process.env.DOMAIN,
    path: '/'
  });
};

const handleServerError = (reply, error) => {
  console.error('Unhandled Authentication Error:', error);
  return reply.status(500).send({ success: false, code: 500, msg: 'Internal Server Error' });
};

const handleRefreshTokenNotUpdate = (reply) => {
  reply.setCookie(config.cookies.refreshTokenName, '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    domain: process.env.DOMAIN,
    path: '/',
    expires: new Date(0)
  });
  return reply.status(401).send({ success: false, code: 401, msg: 'Invalid or expired session. Please login again.' });
};

/**
 * Главный хук аутентификации для Fastify
 */
export default () => {
  const authHook = async (request, reply) => {
    
    // Внутренняя функция для вызова логики обновления и обработки ее специфичных ошибок
    const performTokenRefresh = async () => {
      try {
        await RefreshTokenUpdate(request, reply);
      } catch (error) {
        if (error instanceof TokenRefreshFailedError || error instanceof TokenRefreshTimeoutError) {
          // Эти ошибки означают, что сессия невалидна
          return handleRefreshTokenNotUpdate(reply);
        }
        // Все остальные непредвиденные ошибки (например, сбой Redis)
        return handleServerError(reply, error);
      }
    };

    const { headers, cookies } = request;
    const refreshToken = cookies[config.cookies.refreshTokenName];
    const deviceId = headers[config.headers.deviceId];

    if (!deviceId || !refreshToken) {
      return reply.status(401).send({ success: false, code: 401, msg: 'Missing credentials' });
    }

    const accessToken = headers[config.headers.authToken];
    if (accessToken) {
      try {
        const payload = jwt.verify(accessToken, privateKey, { algorithms: ['RS256'] });
        request.accessToken = accessToken;
        request.session = { _id: payload._id, company: payload.company?._id, deviceId }; // Добавлена проверка company
        return; // Токен валиден, продолжаем
      } catch (error) {
        if (error.name === 'TokenExpiredError') {
          return await performTokenRefresh();
        }
        // Неверный accessToken (плохая подпись, неверный формат и т.д.) - прекращаем сессию
        return handleRefreshTokenNotUpdate(reply);
      }
    } else {
      // Access token отсутствует
      return await performTokenRefresh();
    }
  };

  return authHook;
};
