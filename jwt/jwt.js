// authHook.js
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
    // Кол-во минут жизни access-токена. Ожидается число или строка вида "15".
    expiresIn: process.env.TOKEN_EXPIRATION_MINUTES || '15',
    // Путь к приватному ключу (RS256), относительно текущего файла:
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
  const origin = request?.headers?.origin;
  if (origin) {
    try {
      return new URL(origin).hostname.toLowerCase();
    } catch {
      // игнор
    }
  }
  const hostHdr = request?.headers?.['x-forwarded-host'] || request?.headers?.host;
  if (hostHdr) return hostHdr.split(':')[0].toLowerCase();
  if (request?.hostname) return String(request.hostname).toLowerCase();
  return '';
}

function computeCookieOptionsByHost(hostname, expiresTime) {
  const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';
  const isMeteor =
    hostname.endsWith('.meteorhr.com') || hostname === 'meteorhr.com';
  const isCloudworkstations =
    hostname.endsWith('.cloudworkstations.dev') ||
    hostname === 'cloudworkstations.dev';

  const base = { httpOnly: true, path: '/', expires: expiresTime };

  if (isLocalhost || hostname === '') {
    // host-only без domain
    return { ...base, secure: false, sameSite: 'Lax' };
  }

  if (isMeteor) {
    // Одна site-зона — достаточно Lax (если нет iframe/3rd-party сценариев)
    return { ...base, domain: '.meteorhr.com', secure: true, sameSite: 'Lax' };
  }

  if (isCloudworkstations) {
    // В таких окружениях часто нужен None+Secure
    return { ...base, domain: '.cloudworkstations.dev', secure: true, sameSite: 'None' };
  }

  // Дефолт: host-only, но Secure (почти наверняка HTTPS)
  return { ...base, secure: true, sameSite: 'Lax' };
}

// ----- Генерация access-токена -----
function generateAccessToken(payload) {
  return jwt.sign(payload, privateKey, {
    expiresIn: `${config.jwt.expiresIn}m`, // минутная гранулярность
    algorithm: 'RS256',
  });
}

// ----- Cookie helpers -----
function setRefreshTokenCookie(request, reply, token) {
  const expiresTime = new Date(
    Date.now() + 1000 * 60 * 60 * 24 * config.refreshTokenLifetimeDays,
  );
  const hostname = getHostnameFromRequest(request);
  const cookieOpts = computeCookieOptionsByHost(hostname, expiresTime);
  reply.setCookie(config.cookies.refreshTokenName, token, cookieOpts);
}

function clearRefreshTokenCookie(request, reply) {
  // Чистим host-only
  reply.setCookie(config.cookies.refreshTokenName, '', {
    path: '/',
    expires: new Date(0),
    httpOnly: true,
  });
  // И пробуем зачистить доменные (если ставились)
  const hostname = getHostnameFromRequest(request);
  const domains = [];
  if (hostname.endsWith('.meteorhr.com')) domains.push('.meteorhr.com');
  if (hostname.endsWith('.cloudworkstations.dev')) domains.push('.cloudworkstations.dev');
  for (const d of domains) {
    reply.setCookie(config.cookies.refreshTokenName, '', {
      path: '/',
      domain: d,
      expires: new Date(0),
      httpOnly: true,
      secure: true,
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

  const lockKey = `lock:refresh:${oldRefreshToken}`;
  const resultKey = `result:refresh:${oldRefreshToken}`;

  // ВАЖНО: синтаксис redis.set зависит от клиента. Ниже форма для node-redis@3/early-4.
  // Если у вас node-redis@4 с объектом опций, используйте:
  // await redis.set(lockKey, 'locked', { PX: config.redis.lockTtlMs, NX: true });
  const lockAcquired = await redis.set(
    lockKey,
    'locked',
    'PX',
    config.redis.lockTtlMs,
    'NX',
  );

  if (lockAcquired) {
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
    const result = await waitForRefreshResult(resultKey);
    applyRefreshResult(request, reply, result);
  }
};

// ----- Вспомогательные обработчики -----
async function removeInvalidRefreshToken(refreshToken) {
  try {
    await RefreshToken.findOneAndDelete({ token: refreshToken });
  } catch (err) {
    console.error(`Failed to remove invalid refresh token: ${err.message}`);
  }
}

function handleServerError(reply, error) {
  console.error('Unhandled Authentication Error:', error);
  return reply
    .status(500)
    .send({ success: false, code: 500, msg: 'Internal Server Error' });
}

function handleAuthFailure(request, reply) {
  clearRefreshTokenCookie(request, reply);
  return reply
    .status(401)
    .send({ success: false, code: 401, msg: 'Invalid or expired session. Please login again.' });
}

// ----- Экспортируемый хук Fastify -----
export default () => {
  const authHook = async (request, reply) => {
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

    if (!deviceId || !refreshToken) {
      return handleAuthFailure(request, reply);
    }

    const accessToken = headers[config.headers.authToken];
    if (accessToken) {
      try {
        const payloadFromToken = jwt.verify(accessToken, privateKey, {
          algorithms: ['RS256'],
        });
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
          return performTokenRefresh();
        }
        return handleAuthFailure(request, reply);
      }
    } else {
      return performTokenRefresh();
    }
  };

  return authHook;
};
