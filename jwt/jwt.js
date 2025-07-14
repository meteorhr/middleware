import fs from 'fs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import redis from './redis-client.js'; // Импортируем наш клиент Redis

// Импорты моделей
import RefreshToken from './models/refreshToken.model.js';
import User from './models/user.model.js';
import Currencies from './models/currency.model.js';
import Company from './models/company.model.js';

// --- КОНСТАНТЫ И НАСТРОЙКИ ---
const privateKey = fs.readFileSync('./keys/private.key', 'utf8');
const expires = process.env.TOKEN_EXPIRATION_MINUTES;

const HEADER_DEVICE_ID = 'x-device-id';
const HEADER_AUTH_TOKEN = 'x-authentication-token';

// Настройки для распределенной блокировки
const LOCK_TTL_MS = 5000; // 5 секунд - время жизни замка (защита от сбоев)
const RESULT_TTL_S = 10;  // 10 секунд - время жизни результата в кеше
const POLLING_INTERVAL_MS = 200; // Интервал ожидания для других процессов
const POLLING_ATTEMPTS = 20;     // Количество попыток ожидания

/**
 * Основная функция обновления токена, использующая распределенную блокировку Redis.
 */
const RefreshTokenUpdate = async (request, reply) => {
  const { headers, cookies } = request;
  const oldRefreshToken = cookies.refreshToken;

  const lockKey = `lock:refresh:${oldRefreshToken}`;
  const resultKey = `result:refresh:${oldRefreshToken}`;

  // 1. Попытка захватить замок
  const lockAcquired = await redis.set(lockKey, 'locked', 'PX', LOCK_TTL_MS, 'NX');

  if (lockAcquired) {
    // --- МЫ "ПОБЕДИТЕЛЬ" ---
    // Мы успешно установили замок, значит, мы первые.
    try {
      // Выполняем основную работу: идем в базу данных
      const result = await findRefreshTokenAndUpdated(oldRefreshToken, headers[HEADER_DEVICE_ID]);
      
      if (!result) {
        throw new Error('Refresh token not found or expired');
      }

      // Сохраняем результат в Redis для других процессов
      await redis.set(resultKey, JSON.stringify(result), 'EX', RESULT_TTL_S);
      
      // Применяем результат к текущему запросу
      applyRefreshResult(request, reply, result);
      return; // Успешно, продолжаем выполнение
    } catch (error) {
      // Если произошла ошибка, нам нужно сообщить об этом другим ожидающим процессам
      // Сохраняем ошибку в кеш
      await redis.set(resultKey, JSON.stringify({ error: true, message: error.message }), 'EX', RESULT_TTL_S);
      throw error; // Пробрасываем ошибку дальше, чтобы ее обработал внешний try-catch
    } finally {
      // Важно! Всегда освобождаем замок после выполнения работы.
      await redis.del(lockKey);
    }
  } else {
    // --- МЫ "ОЖИДАЮЩИЙ" ---
    // Замок уже захвачен другим процессом. Ждем результат.
    try {
      const result = await waitForRefreshResult(resultKey);
      applyRefreshResult(request, reply, result);
      return; // Успешно, продолжаем выполнение
    } catch (error) {
      throw error; // Пробрасываем ошибку дальше
    }
  }
};

/**
 * Ожидает результат обновления от "победившего" процесса.
 * @param {string} resultKey - Ключ в Redis, где ожидается результат.
 */
async function waitForRefreshResult(resultKey) {
  for (let i = 0; i < POLLING_ATTEMPTS; i++) {
    await new Promise(resolve => setTimeout(resolve, POLLING_INTERVAL_MS));
    
    const resultData = await redis.get(resultKey);

    if (resultData) {
      const result = JSON.parse(resultData);
      if (result.error) {
        throw new Error(`Another process failed to refresh token: ${result.message}`);
      }
      return result;
    }
  }
  throw new Error('Timed out waiting for token refresh result.');
}


// --- ХЕЛПЕРЫ (большинство без изменений, кроме RefreshTokenUpdate) ---

// Эта функция остается как есть, она работает с MongoDB
const findRefreshTokenAndUpdated = async (refreshToken, deviceId) => { /* ... ваш код ... */ };

// Эта функция остается как есть
const applyRefreshResult = (request, reply, refreshResult) => { /* ... ваш код ... */ };

// Эта функция остается как есть
const generateAccessToken = (payload) => { /* ... ваш код ... */ };

// ... все остальные ваши хелперы (`handleServerError`, `setRefreshTokenCookie` и т.д.) ...

// Обработчики ошибок для Fastify
const handleServerError = (reply, error) => {
  console.error(error);
  return reply.status(500).send({ success: false, code: 500, msg: 'Server error' });
};

const handleRefreshTokenNotUpdate = (reply) => {
  reply.setCookie('refreshToken', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    expires: new Date(0)
  });
  return reply.status(401).send({ success: false, code: 401, msg: 'Invalid or expired session. Please login again.' });
};


/*
 *  ЭКСПОРТ И ИСПОЛЬЗОВАНИЕ В FASTIFY
 *  (Основной хук, который теперь вызывает новую логику)
 */
export default () => {
  const authHook = async (request, reply) => {
    try {
      const { headers, cookies } = request;
      const refreshToken = cookies.refreshToken;
      const deviceId = headers[HEADER_DEVICE_ID];

      if (!deviceId || !refreshToken) {
        return reply.status(401).send({ success: false, code: 401, msg: 'Missing credentials' });
      }

      const accessToken = headers[HEADER_AUTH_TOKEN];
      if (accessToken) {
        try {
          const payload = jwt.verify(accessToken, privateKey, { algorithms: ['RS256'] });
          request.accessToken = accessToken;
          request.session = { _id: payload._id, company: payload.company._id, deviceId };
          return;
        } catch (error) {
          if (error.name === 'TokenExpiredError') {
            // Токен истек, запускаем логику обновления с распределенной блокировкой
            await RefreshTokenUpdate(request, reply);
            return;
          }
          return handleRefreshTokenNotUpdate(reply);
        }
      } else {
        // Access Token отсутствует, запускаем логику обновления
        await RefreshTokenUpdate(request, reply);
        return;
      }
    } catch (error) {
      // Здесь мы поймаем ошибки как от основного процесса, так и от ожидания
      if (error.message.includes('not found or expired') || error.message.includes('Timed out')) {
          return handleRefreshTokenNotUpdate(reply);
      }
      return handleServerError(reply, error);
    }
  };

  return authHook;
};
