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
    expiresIn: process.env.TOKEN_EXPIRATION_MINUTES || '15',
    privateKeyPath: './keys/private.key',
    publicKeyPath: './keys/public.key',
  },
  redis: {
    lockTtlMs: 5000,
    resultTtlS: 120,
    pollingIntervalMs: 200,
    pollingAttempts: 25,
    channelPrefix: 'refresh:done:',
  },
  // Grace period (ms) during which a used refresh token still resolves to its
  // replacement.  Covers the case when the response carrying new cookies was
  // lost (504 / ERR_FAILED) and the client retries with the old token.
  refreshGracePeriodMs: 120_000,
  headers: {
    deviceId: 'x-device-id',
    authToken: 'x-authentication-token',
  },
  cookies: {
    refreshTokenName: 'refreshToken',
    accessTokenName: 'accessToken',
    deviceIdName: 'deviceId',
    secret: process.env.COOKIE_SECRET,
  },
  refreshTokenLifetimeDays: 60,
  deviceIdMaxLength: 128,
};

// ----- Ключи подписи / верификации -----
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const privateKey = fs.readFileSync(
  path.resolve(__dirname, config.jwt.privateKeyPath),
  'utf8',
);
const publicKey = fs.readFileSync(
  path.resolve(__dirname, config.jwt.publicKeyPath),
  'utf8',
);

if (!config.cookies.secret) {
  throw new Error('COOKIE_SECRET is required');
}

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

// ----- Утилиты -----

/**
 * Валидация deviceId — только допустимые символы, ограничение длины.
 */
function isValidDeviceId(deviceId) {
  if (!deviceId || typeof deviceId !== 'string') return false;
  if (deviceId.length > config.deviceIdMaxLength) return false;
  return /^[a-zA-Z0-9\-_.]+$/.test(deviceId);
}

/**
 * Получает чистый hostname из запроса.
 */
function getHostnameFromRequest(request) {
  const hostHdr = request?.headers?.['x-forwarded-host'] || request?.headers?.host;
  if (hostHdr) return hostHdr.split(':')[0].toLowerCase();

  if (request?.hostname) return String(request.hostname).toLowerCase();
  return '';
}

/**
 * Конфигурация куки с учётом хоста/протокола.
 * ВАЖНО: Эта логика ДУБЛИРОВАНА в ident/app/utils/auth-cookie.js.
 * При изменении здесь — обязательно обновить и там (и наоборот).
 * TODO: вынести в общий npm-пакет @meteorhr/auth-cookie для единого источника правды.
 *
 * - localhost/127.0.0.1/.local (по hostname ИЛИ Origin): secure=false, sameSite=Lax
 * - Все остальные (https): secure=true, sameSite=None (host-only)
 */
function computeCookieOptions(request, expiresTime) {
  const base = { httpOnly: true, path: '/', expires: expiresTime };

  // Учитываем Origin, чтобы cross-origin запросы с localhost тоже получали Lax
  let originHost = '';
  if (request?.headers?.origin) {
    try {
      originHost = new URL(request.headers.origin).hostname.toLowerCase();
    } catch {
      // ignore invalid origin
    }
  }

  const hostname = getHostnameFromRequest(request);
  const isLocal =
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname.endsWith('.local') ||
    originHost === 'localhost' ||
    originHost === '127.0.0.1';

  if (isLocal) {
    return { ...base, secure: false, sameSite: 'Lax' };
  }

  return { ...base, secure: true, sameSite: 'None' };
}

function getAccessTokenLifetimeMs() {
  const parsed = parseInt(String(config.jwt.expiresIn), 10);
  const tokenLifetimeMinutes = Number.isFinite(parsed) && parsed > 0 ? parsed : 15;
  return tokenLifetimeMinutes * 60 * 1000;
}

/**
 * Безопасный JSON.parse с обработкой ошибок.
 */
function safeJsonParse(data) {
  try {
    return JSON.parse(data);
  } catch {
    return null;
  }
}

function parseRefreshResultFromCache(rawValue, errorPrefix = 'Another process failed to refresh token') {
  const parsed = safeJsonParse(rawValue);
  if (!parsed) {
    throw new TokenRefreshFailedError('Corrupted refresh result data');
  }

  if (parsed.error) {
    throw new TokenRefreshFailedError(`${errorPrefix}: ${parsed.message}`);
  }

  return parsed;
}

// ----- Проверка доступности Redis -----
let redisAvailable = true;

redis.on('error', () => {
  redisAvailable = false;
});

redis.on('ready', () => {
  redisAvailable = true;
});

redis.on('connect', () => {
  redisAvailable = true;
});

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

  const cookieOpts = computeCookieOptions(request, expiresTime);
  reply.setCookie(config.cookies.refreshTokenName, token, {
    ...cookieOpts,
    signed: true,
  });
}

function setAccessTokenCookie(request, reply, token) {
  const expiresTime = new Date(Date.now() + getAccessTokenLifetimeMs());
  const cookieOpts = computeCookieOptions(request, expiresTime);
  reply.setCookie(config.cookies.accessTokenName, token, {
    ...cookieOpts,
    signed: true,
  });
}

function setDeviceIdCookie(request, reply, deviceId) {
  const expiresTime = new Date(
    Date.now() + 1000 * 60 * 60 * 24 * config.refreshTokenLifetimeDays,
  );
  const cookieOpts = computeCookieOptions(request, expiresTime);
  reply.setCookie(config.cookies.deviceIdName, deviceId, {
    ...cookieOpts,
    signed: true,
  });
}

function getSignedCookieValue(request, name) {
  const rawCookieValue = request?.cookies?.[name];
  if (!rawCookieValue) return null;
  if (typeof request.unsignCookie !== 'function') return null;

  const { valid, value } = request.unsignCookie(rawCookieValue);
  if (!valid) return null;
  return value;
}

// ----- Применение результата refresh -----
function applyRefreshResult(request, reply, refreshResult) {
  const { userId, token: newRefreshToken } = refreshResult;
  const newAccessToken = generateAccessToken(userId);

  const deviceId = getSignedCookieValue(request, config.cookies.deviceIdName)
    || request.headers[config.headers.deviceId];

  request.accessToken = newAccessToken;
  request.session = {
    _id: userId._id,
    company: userId.company?._id,
    deviceId,
  };
  setAccessTokenCookie(request, reply, newAccessToken);
  setRefreshTokenCookie(request, reply, newRefreshToken);
  if (deviceId) {
    setDeviceIdCookie(request, reply, deviceId);
  }
  reply.header(config.headers.authToken, newAccessToken);
}

// ----- Lua-скрипт для атомарного удаления лока (только если он наш) -----
const RELEASE_LOCK_SCRIPT = `
  if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
  else
    return 0
  end
`;

// ----- Ожидание результата refresh через pub/sub + polling fallback -----
async function waitForRefreshResult(resultKey, channel) {
  // Сначала проверяем, есть ли уже результат
  const existingResult = await redis.get(resultKey);
  if (existingResult) {
    return parseRefreshResultFromCache(existingResult);
  }

  // Используем pub/sub + polling для ожидания результата
  return new Promise((resolve, reject) => {
    let settled = false;
    let pollTimer;
    let timeoutTimer;
    const subscriber = redis.duplicate();

    const cleanup = () => {
      if (settled) return;
      settled = true;
      clearTimeout(pollTimer);
      clearTimeout(timeoutTimer);
      subscriber.unsubscribe(channel).catch(() => {});
      subscriber.disconnect();
    };

    const handleResult = (result) => {
      if (result.error) {
        cleanup();
        return reject(
          new TokenRefreshFailedError(`Another process failed: ${result.message}`),
        );
      }
      cleanup();
      return resolve(result);
    };

    // Pub/sub — мгновенное получение результата
    subscriber.subscribe(channel).then(() => {
      subscriber.on('message', (_ch, message) => {
        if (settled) return;
        try {
          const result = parseRefreshResultFromCache(message, 'Another process failed');
          return handleResult(result);
        } catch (error) {
          cleanup();
          return reject(error);
        }
      });
    }).catch(() => {
      // Если pub/sub недоступен — полагаемся на polling
    });

    // Polling fallback с setTimeout (не setInterval) — предотвращает наложение
    // async-вызовов, когда Redis.get() занимает больше pollingIntervalMs
    let attempts = 0;
    const poll = async () => {
      if (settled) return;
      attempts++;
      try {
        const resultData = await redis.get(resultKey);
        if (resultData) {
          try {
            const result = parseRefreshResultFromCache(resultData, 'Another process failed');
            return handleResult(result);
          } catch (error) {
            cleanup();
            return reject(error);
          }
        }
      } catch {
        // Redis read error — continue polling
      }

      if (attempts >= config.redis.pollingAttempts) {
        cleanup();
        return reject(new TokenRefreshTimeoutError('Timed out waiting for token refresh result.'));
      }

      // Планируем следующую попытку ПОСЛЕ завершения текущей
      if (!settled) {
        pollTimer = setTimeout(poll, config.redis.pollingIntervalMs);
      }
    };

    // Запускаем первый poll
    pollTimer = setTimeout(poll, config.redis.pollingIntervalMs);

    // Абсолютный таймаут
    timeoutTimer = setTimeout(() => {
      cleanup();
      reject(new TokenRefreshTimeoutError('Timed out waiting for token refresh result.'));
    }, config.redis.lockTtlMs + 1000);
  });
}

// ----- Populate-конфигурация для User → Company → Currency -----
const userPopulateOpts = {
  path: 'userId',
  select: '_id company',
  model: User,
  populate: {
    path: 'company',
    select: 'currency',
    model: Company,
    populate: { path: 'currency', select: 'code', model: Currencies },
  },
};

// ----- Ротация refresh-токена -----
/**
 * Находит refresh-токен в БД по token + deviceId, помечает его как
 * использованный (usedAt) и создаёт новый.
 *
 * Вместо findOneAndDelete используется «мягкая ротация» с grace-периодом:
 * если ответ с новыми cookies не дошёл до клиента (504 / net::ERR_FAILED),
 * клиент повторно пришлёт старый refresh token. В течение grace-периода
 * (config.refreshGracePeriodMs) повторный запрос получит тот же результат
 * (replacedBy), не вызывая hard 401.
 *
 * Populate User включает поля, необходимые для JWT payload — аналогично
 * тому, что ident кладёт в sessionPayload при логине.
 */
const findRefreshTokenAndUpdated = async (refreshToken, deviceId) => {
  const currentDate = new Date();

  // Phase 1: Atomically claim the token (set usedAt if not yet set).
  // {usedAt: null} matches both explicit null and missing field.
  const oldTokenDoc = await RefreshToken.findOneAndUpdate(
    {
      token: refreshToken,
      deviceId,
      expired_at: { $gte: currentDate },
      usedAt: null,
    },
    { $set: { usedAt: currentDate } },
  ).populate(userPopulateOpts);

  if (oldTokenDoc && oldTokenDoc.userId) {
    // Winner — create replacement token
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

    // Record replacement pointer so retries can resolve it
    await RefreshToken.updateOne(
      { token: refreshToken },
      { $set: { replacedBy: newRefreshToken.token } },
    );

    return { userId: oldTokenDoc.userId.toObject(), token: newRefreshToken.token };
  }

  // Phase 2: Token already claimed — check grace period for client retry.
  // The winner may still be writing replacedBy, so poll briefly.
  const graceFloor = new Date(currentDate.getTime() - config.refreshGracePeriodMs);
  for (let attempt = 0; attempt < 5; attempt++) {
    const usedDoc = await RefreshToken.findOne({
      token: refreshToken,
      deviceId,
      usedAt: { $gte: graceFloor },
      replacedBy: { $ne: null },
    }).populate(userPopulateOpts);

    if (usedDoc && usedDoc.userId) {
      return { userId: usedDoc.userId.toObject(), token: usedDoc.replacedBy };
    }

    // Winner may still be processing — wait before retrying
    if (attempt < 4) {
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  // No valid token found — truly expired / already used beyond grace period
  return null;
};

// ----- Основной refresh-процесс с распределённым локом -----
const RefreshTokenUpdate = async (request, reply) => {
  const { headers } = request;
  const oldRefreshToken = getSignedCookieValue(request, config.cookies.refreshTokenName);
  const deviceId = getSignedCookieValue(request, config.cookies.deviceIdName)
    || headers[config.headers.deviceId];

  if (!oldRefreshToken) {
    throw new TokenRefreshFailedError('Refresh token is missing or invalid');
  }

  if (!deviceId) {
    throw new TokenRefreshFailedError('Device ID is missing');
  }

  // Если Redis недоступен — выполняем refresh напрямую (без лока)
  if (!redisAvailable) {
    const result = await findRefreshTokenAndUpdated(oldRefreshToken, deviceId);
    if (!result) {
      throw new TokenRefreshFailedError(
        'Refresh token not found, expired, or already used',
      );
    }
    applyRefreshResult(request, reply, result);
    return;
  }

  const lockKey = `lock:refresh:${oldRefreshToken}`;
  const resultKey = `result:refresh:${oldRefreshToken}`;
  const channel = `${config.redis.channelPrefix}${oldRefreshToken}`;

  const getCachedRefreshResult = async () => {
    const cachedResult = await redis.get(resultKey);
    if (!cachedResult) {
      return null;
    }
    return parseRefreshResultFromCache(cachedResult);
  };

  // Быстрый путь: токен уже ротирован другим параллельным запросом.
  // Это закрывает окно гонки, когда старый refreshToken ещё в браузере,
  // но result уже лежит в Redis.
  try {
    const cachedResult = await getCachedRefreshResult();
    if (cachedResult) {
      applyRefreshResult(request, reply, cachedResult);
      return;
    }
  } catch (error) {
    throw error;
  }

  // Уникальный идентификатор владельца лока — защита от удаления чужого лока
  const lockOwner = `${process.pid}:${Date.now()}:${Math.random().toString(36).slice(2)}`;

  let lockAcquired;
  try {
    lockAcquired = await redis.set(
      lockKey,
      lockOwner,
      'PX',
      config.redis.lockTtlMs,
      'NX',
    );
  } catch {
    // Redis ошибка при попытке взять лок — выполняем без лока
    const result = await findRefreshTokenAndUpdated(oldRefreshToken, deviceId);
    if (!result) {
      throw new TokenRefreshFailedError(
        'Refresh token not found, expired, or already used',
      );
    }
    applyRefreshResult(request, reply, result);
    return;
  }

  if (lockAcquired) {
    try {
      // В случае, когда результат появился между проверкой выше и захватом лока.
      const cachedResult = await getCachedRefreshResult();
      if (cachedResult) {
        applyRefreshResult(request, reply, cachedResult);
        return;
      }

      const result = await findRefreshTokenAndUpdated(oldRefreshToken, deviceId);
      if (!result) {
        throw new TokenRefreshFailedError(
          'Refresh token not found, expired, or already used',
        );
      }

      const resultJson = JSON.stringify(result);

      // Сохраняем результат и публикуем для ожидающих процессов
      await Promise.all([
        redis.set(resultKey, resultJson, 'EX', config.redis.resultTtlS),
        redis.publish(channel, resultJson),
      ]);

      applyRefreshResult(request, reply, result);
    } catch (error) {
      const errorJson = JSON.stringify({ error: true, message: error.message });
      try {
        await Promise.all([
          redis.set(resultKey, errorJson, 'EX', config.redis.resultTtlS),
          redis.publish(channel, errorJson),
        ]);
      } catch {
        // Ignore Redis errors during error reporting
      }
      throw error;
    } finally {
      // Атомарное удаление лока — только если мы его владелец
      try {
        await redis.eval(RELEASE_LOCK_SCRIPT, 1, lockKey, lockOwner);
      } catch {
        // Ignore Redis errors during lock release
      }
    }
  } else {
    // Ожидаем результат от другого процесса через pub/sub + polling
    const result = await waitForRefreshResult(resultKey, channel);
    applyRefreshResult(request, reply, result);
  }
};

// ----- Вспомогательные обработчики -----
function handleServerError(reply, error) {
  console.error('Unhandled Authentication Error:', error?.message);
  return reply
    .status(500)
    .send({ success: false, code: 500, msg: 'Internal Server Error' });
}

/**
 * Мягкий сбой: очищаем только accessToken, возвращаем 503.
 * Используется для временных ошибок (Redis/DB недоступен) —
 * refreshToken и deviceId остаются, чтобы следующий запрос смог восстановить сессию.
 *
 * Возвращаем 503 (Service Unavailable) вместо 401, чтобы клиент
 * НЕ интерпретировал это как невалидную сессию и НЕ вызывал logout().
 * Клиентский 401-interceptor пропустит 503, ошибка дойдёт до вызывающего
 * кода, пользователь увидит «попробуйте позже», но останется залогиненным.
 */
function handleSoftAuthFailure(request, reply) {
  const expiredCookieOpts = computeCookieOptions(request, new Date(0));
  reply.setCookie(config.cookies.accessTokenName, '', {
    ...expiredCookieOpts,
    signed: true,
  });
  return reply
    .status(503)
    .send({ success: false, code: 503, msg: 'Temporary authentication service issue. Please retry.' });
}

/**
 * Жёсткий 401: очищаем ВСЕ auth-куки (accessToken + refreshToken + deviceId).
 * Используется когда refresh token подтверждённо невалиден (не найден в БД,
 * истёк, уже использован) — держать стухший refreshToken cookie бессмысленно,
 * он только вызывает лишние retry-циклы на клиенте.
 */
function handleHardAuthFailure(request, reply) {
  const expiredCookieOpts = computeCookieOptions(request, new Date(0));
  reply.setCookie(config.cookies.accessTokenName, '', {
    ...expiredCookieOpts,
    signed: true,
  });
  reply.setCookie(config.cookies.refreshTokenName, '', {
    ...expiredCookieOpts,
    signed: true,
  });
  reply.setCookie(config.cookies.deviceIdName, '', {
    ...expiredCookieOpts,
    signed: true,
  });
  return reply
    .status(401)
    .send({ success: false, code: 401, msg: 'Session expired. Please login again.' });
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
          // Если ошибка от таймаута Redis — мягкий 401 (refresh cookie ещё валиден)
          // Если refresh token не найден в БД — жёсткий 401 (cookie бесполезен)
          if (error instanceof TokenRefreshTimeoutError) {
            return handleSoftAuthFailure(request, reply);
          }
          return handleHardAuthFailure(request, reply);
        }
        return handleServerError(reply, error);
      }
    };

    const { headers } = request;
    const refreshToken = getSignedCookieValue(request, config.cookies.refreshTokenName);
    // Приоритет: httpOnly cookie > заголовок (fallback для логина/регистрации)
    const deviceId = getSignedCookieValue(request, config.cookies.deviceIdName)
      || headers[config.headers.deviceId];

    if (!refreshToken || !deviceId) {
      return handleHardAuthFailure(request, reply);
    }

    // Валидация deviceId
    if (!isValidDeviceId(deviceId)) {
      return handleHardAuthFailure(request, reply);
    }

    const accessToken = headers[config.headers.authToken]
      || getSignedCookieValue(request, config.cookies.accessTokenName);
    if (accessToken) {
      try {
        // Используем публичный ключ для верификации (не приватный)
        const payloadFromToken = jwt.verify(accessToken, publicKey, {
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
        return;
      } catch (error) {
        if (error.name === 'TokenExpiredError') {
          return performTokenRefresh();
        }
        // Невалидный токен (не expired, а corrupted/подделанный) — жёсткий 401
        return handleHardAuthFailure(request, reply);
      }
    } else {
      // Нет accessToken вообще, но есть refreshToken — пробуем обновить
      return performTokenRefresh();
    }
  };

  return authHook;
};
