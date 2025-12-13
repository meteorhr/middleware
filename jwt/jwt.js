import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import redis from './redis-client.js';

// Модели
import RefreshToken from './models/refreshToken.model.js';
import User from './models/user.model.js';
import Currencies from './models/currency.model.js';
import Company from './models/company.model.js';

// ----- Конфигурация -----
const config = {
  jwt: {
    // Кол-во минут жизни access-токена
    expiresIn: process.env.TOKEN_EXPIRATION_MINUTES || '15',
    // Путь к приватному ключу (RS256)
    privateKeyPath: './keys/private.key',
  },
  redis: {
    lockTtlMs: 5000,
    resultTtlS: 10,
    pollingIntervalMs: 200,
    pollingAttempts: 25,
  },
  headers: {
    deviceId: 'x-device-id',
    authToken: 'x-authentication-token',
  },
  cookies: {
    refreshTokenName: 'refreshToken',
  },
  refreshTokenLifetimeDays: 60,
};

// ----- Ключ подписи -----
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const privateKey = fs.readFileSync(
  path.resolve(__dirname, config.jwt.privateKeyPath),
  'utf8',
);

// ----- Классы ошибок -----
class TokenRefreshFailedError extends Error {
  constructor(message) {
    super(message);
    this.name = 'TokenRefreshFailedError';
  }
}
class TokenRefreshTimeoutError extends Error {
  constructor(message) {
    super(message);
    this.name = 'TokenRefreshTimeoutError';
  }
}

// ----- Утилиты: анализ Origin/Host -----
function getHostnameFromRequest(request) {
  // Логируем заголовки для отладки
  const hostHdr = request?.headers?.['x-forwarded-host'] || request?.headers?.host;

  // Для отладки в консоли
  // console.log('[jwt] incoming host:', hostHdr, 'origin:', request?.headers?.origin);

  if (hostHdr) return hostHdr.split(':')[0].toLowerCase();

  const origin = request?.headers?.origin;
  if (origin) {
    try {
      return new URL(origin).hostname.toLowerCase();
    } catch {
      // игнор
    }
  }
  if (request?.hostname) return String(request.hostname).toLowerCase();
  return '';
}

/**
 * Вычисляет параметры Cookie в зависимости от окружения.
 * Исправлено: добавлена логика для localhost -> production API.
 */
function computeCookieOptionsByHost(hostname, request, expiresTime) {
  const origin = request?.headers?.origin || '';

  // Определяем, является ли клиент локальным (разработчик)
  const isClientLocalhost = origin.includes('localhost') || origin.includes('127.0.0.1');

  // Определяем серверы
  const isLocalhostServer = hostname === 'localhost' || hostname === '127.0.0.1';
  const isMeteorServer = hostname.endsWith('.meteorhr.com') || hostname === 'meteorhr.com';

  const base = { httpOnly: true, path: '/', expires: expiresTime };

  // 1. Полностью локальная разработка (бэк на localhost)
  if (isLocalhostServer || hostname === '') {
    return { ...base, secure: false, sameSite: 'Lax' };
  }

  // 2. ГИБРИДНЫЙ РЕЖИМ: Бэк на проде (api.meteorhr.com), Фронт локально (localhost)
  if (isMeteorServer && isClientLocalhost) {
    console.log('[jwt] Setting Cross-Site cookie for Localhost development');
    // ВАЖНО: 
    // - secure: true (так как API на https)
    // - sameSite: 'None' (чтобы кука летала между разными доменами)
    // - domain: НЕ ЗАДАЕМ! (Пусть будет Host Only для api.meteorhr.com, иначе браузер на localhost заблокирует куку для .meteorhr.com)
    return { ...base, secure: true, sameSite: 'None' };
  }

  // 3. ПРОДАКШН: Бэк на проде, Фронт на проде
  if (isMeteorServer) {
    // Здесь нужен domain, чтобы кука была доступна и на api.* и на app.*
    return { ...base, domain: '.meteorhr.com', secure: true, sameSite: 'None' };
  }

  // Дефолт (неизвестный хост, считаем, что HTTPS)
  return { ...base, secure: true, sameSite: 'Lax' };
}

// ----- Генерация access-токена -----
function generateAccessToken(payload) {
  return jwt.sign(payload, privateKey, {
    expiresIn: `${config.jwt.expiresIn}m`,
    algorithm: 'RS256',
  });
}

// ----- Cookie helpers -----
function setRefreshTokenCookie(request, reply, token) {
  const expiresTime = new Date(
    Date.now() + 1000 * 60 * 60 * 24 * config.refreshTokenLifetimeDays,
  );
  const hostname = getHostnameFromRequest(request);

  // !!! Исправлено: передаем request вторым параметром
  const cookieOpts = computeCookieOptionsByHost(hostname, request, expiresTime);

  console.log('[jwt] setRefreshTokenCookie hostname:', hostname, 'opts:', JSON.stringify(cookieOpts));
  reply.setCookie(config.cookies.refreshTokenName, token, cookieOpts);
}

function clearRefreshTokenCookie(request, reply) {
  const hostname = getHostnameFromRequest(request);
  const domains = [];
  if (hostname.endsWith('.meteorhr.com') || hostname === 'meteorhr.com') domains.push('.meteorhr.com');
  if (hostname.endsWith('.cloudworkstations.dev') || hostname === 'cloudworkstations.dev') domains.push('.cloudworkstations.dev');

  // Если домен определён, чистим только доменную куку (не создавая host-only дубликат)
  if (domains.length > 0) {
    for (const d of domains) {
      reply.setCookie(config.cookies.refreshTokenName, '', {
        path: '/',
        domain: d,
        expires: new Date(0),
        httpOnly: true,
        secure: true,
        sameSite: 'None',
      });
    }
  } else {
    // Локальный хост — чистим host-only
    reply.setCookie(config.cookies.refreshTokenName, '', {
      path: '/',
      expires: new Date(0),
      httpOnly: true,
    });
  }
}

// ----- Применение результата refresh -----
function applyRefreshResult(request, reply, refreshResult) {
  const { userId, token: newRefreshToken } = refreshResult;
  const newAccessToken = generateAccessToken(userId);
  request.accessToken = newAccessToken;
  request.session = {
    _id: userId._id,
    company: userId.company?._id,
    deviceId: request.headers[config.headers.deviceId],
  };
  setRefreshTokenCookie(request, reply, newRefreshToken);
  // Отдаём новый access-токен в заголовке для фронта
  reply.header(config.headers.authToken, newAccessToken);
}

// ----- Ожидание результата refresh из другого процесса -----
async function waitForRefreshResult(resultKey) {
  for (let i = 0; i < config.redis.pollingAttempts; i++) {
    await new Promise((resolve) =>
      setTimeout(resolve, config.redis.pollingIntervalMs),
    );
    const resultData = await redis.get(resultKey);
    if (resultData) {
      const result = JSON.parse(resultData);
      if (result.error) {
        throw new TokenRefreshFailedError(
          `Another process failed to refresh token: ${result.message}`,
        );
      }
      return result;
    }
  }
  throw new TokenRefreshTimeoutError('Timed out waiting for token refresh result.');
}

// ----- Ротация refresh-токена -----
const findRefreshTokenAndUpdated = async (refreshToken, deviceId) => {
  const currentDate = new Date();

  const oldTokenDoc = await RefreshToken.findOneAndDelete({
    token: refreshToken,
    deviceId,
    expired_at: { $gte: currentDate },
  }).populate({
    path: 'userId',
    select: 'email phone telegram notification roles active name avatar company',
    model: User,
    populate: {
      path: 'company',
      select: 'currency',
      model: Company,
      populate: { path: 'currency', select: 'code', model: Currencies },
    },
  });

  if (!oldTokenDoc) {
    console.error(
      `[Auth] Refresh token rotation failed. Token not found or expired. Token: ${refreshToken}, DeviceID: ${deviceId}`,
    );
    return null;
  }
  if (!oldTokenDoc.userId) {
    console.error(
      `[Auth] Orphaned refresh token found and deleted. Token: ${refreshToken}`,
    );
    return null;
  }

  const expiredDate = new Date(
    currentDate.getTime() + 1000 * 60 * 60 * 24 * config.refreshTokenLifetimeDays,
  );

  const newRefreshToken = new RefreshToken({
    token: uuidv4(),
    userId: oldTokenDoc.userId._id,
    deviceId,
    expired_at: expiredDate,
  });
  await newRefreshToken.save();

  return { userId: oldTokenDoc.userId.toObject(), token: newRefreshToken.token };
};

// ----- Основной refresh-процесс с распределённым локом -----
const RefreshTokenUpdate = async (request, reply) => {
  const { headers, cookies } = request;
  const oldRefreshToken = cookies[config.cookies.refreshTokenName];
  const deviceId = headers[config.headers.deviceId];
  console.log('[jwt] RefreshTokenUpdate start deviceId:', deviceId, 'refresh exists:', !!oldRefreshToken);

  const lockKey = `lock:refresh:${oldRefreshToken}`;
  const resultKey = `result:refresh:${oldRefreshToken}`;

  const lockAcquired = await redis.set(
    lockKey,
    'locked',
    'PX',
    config.redis.lockTtlMs,
    'NX',
  );

  if (lockAcquired) {
    console.log('[jwt] refresh lock acquired');
    try {
      const result = await findRefreshTokenAndUpdated(oldRefreshToken, deviceId);
      if (!result) {
        throw new TokenRefreshFailedError(
          'Refresh token not found, expired, or already used',
        );
      }
      await redis.set(resultKey, JSON.stringify(result), 'EX', config.redis.resultTtlS);
      applyRefreshResult(request, reply, result);
    } catch (error) {
      console.error('[jwt] refresh failed:', error?.message);
      await redis.set(
        resultKey,
        JSON.stringify({ error: true, message: error.message }),
        'EX',
        config.redis.resultTtlS,
      );
      throw error;
    } finally {
      await redis.del(lockKey);
    }
  } else {
    console.log('[jwt] waiting for refresh result from another process');
    const result = await waitForRefreshResult(resultKey);
    applyRefreshResult(request, reply, result);
  }
};

// ----- Вспомогательные обработчики -----
function handleServerError(reply, error) {
  console.error('Unhandled Authentication Error:', error);
  return reply
    .status(500)
    .send({ success: false, code: 500, msg: 'Internal Server Error' });
}

function handleAuthFailure(request, reply) {
  console.warn('[jwt] auth failure, clearing cookies');
  clearRefreshTokenCookie(request, reply);
  return reply
    .status(401)
    .send({ success: false, code: 401, msg: 'Invalid or expired session. Please login again.' });
}

// ----- Экспортируемый хук Fastify -----
export default () => {
  const authHook = async (request, reply) => {
    // console.log('[jwt] >>> new request', request.url, 'host', request.headers.host, 'hasRefresh', !!request.cookies[config.cookies.refreshTokenName]);

    const performTokenRefresh = async () => {
      try {
        await RefreshTokenUpdate(request, reply);
        return;
      } catch (error) {
        if (
          error instanceof TokenRefreshFailedError ||
          error instanceof TokenRefreshTimeoutError
        ) {
          return handleAuthFailure(request, reply);
        }
        return handleServerError(reply, error);
      }
    };

    const { headers, cookies } = request;
    const refreshToken = cookies[config.cookies.refreshTokenName];
    const deviceId = headers[config.headers.deviceId];

    // Если нет deviceId или refresh-токена - сразу отбой
    if (!deviceId || !refreshToken) {
      // Здесь можно добавить лог для дебага, почему именно 401
      // console.log('[jwt] Missing credentials. DeviceId:', !!deviceId, 'RefreshToken:', !!refreshToken);
      return handleAuthFailure(request, reply);
    }

    const accessToken = headers[config.headers.authToken];
    if (accessToken) {
      try {
        const payloadFromToken = jwt.verify(accessToken, privateKey, {
          algorithms: ['RS256'],
        });
        // console.log('[jwt] access token valid');
        const payload = payloadFromToken.payload
          ? payloadFromToken.payload
          : payloadFromToken;

        request.accessToken = accessToken;
        request.session = {
          _id: payload._id,
          company: payload.company?._id,
          deviceId,
        };

        return; // Токен валиден — продолжаем
      } catch (error) {
        if (error.name === 'TokenExpiredError') {
          console.warn('[jwt] access token expired, refresh flow');
          return performTokenRefresh();
        }
        console.error('[jwt] access token verify error:', error?.message);
        return handleAuthFailure(request, reply);
      }
    } else {
      console.log('[jwt] access token missing, refresh flow');
      return performTokenRefresh();
    }
  };

  return authHook;
};
