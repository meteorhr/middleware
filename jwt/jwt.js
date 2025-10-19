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

// --- УЛУЧШЕНО: Надежное определение пути к ключу ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const privateKey = fs.readFileSync(path.resolve(__dirname, config.jwt.privateKeyPath), 'utf8');

// --- УЛУЧШЕНО: Кастомные классы ошибок ---
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
  const deviceId = headers[config.headers.deviceId];

  const lockKey = `lock:refresh:${oldRefreshToken}`;
  const resultKey = `result:refresh:${oldRefreshToken}`;

  const lockAcquired = await redis.set(lockKey, 'locked', 'PX', config.redis.lockTtlMs, 'NX');

  if (lockAcquired) {
    // --- ПОБЕДИТЕЛЬ ---
    try {
      const result = await findRefreshTokenAndUpdated(oldRefreshToken, deviceId);
      if (!result) {
        // Мы не вызываем removeInvalidRefreshToken, т.к. findOneAndDelete уже сделал это
        throw new TokenRefreshFailedError('Refresh token not found, expired, or already used');
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

// ----- ДОБАВИТЬ: утилиты для анализа Origin/хоста -----
function getHostnameFromRequest(request) {
  // Предпочитаем Origin (когда запрос к API идёт с фронта через CORS)
  const origin = request.headers.origin;
  if (origin) {
    try {
      return new URL(origin).hostname.toLowerCase();
    } catch {}
  }
  // Fallback на host заголовок/fastify hostname
  const hostHdr = request.headers['x-forwarded-host'] || request.headers.host;
  if (hostHdr) {
    // hostHdr может содержать порт
    return hostHdr.split(':')[0].toLowerCase();
  }
  if (request.hostname) return String(request.hostname).toLowerCase();
  return '';
}

function computeCookieOptionsByHost(hostname, expiresTime) {
  const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';
  const isMeteor = hostname.endsWith('.meteorhr.com') || hostname === 'meteorhr.com';
  const isCloudworkstations = hostname.endsWith('.cloudworkstations.dev') || hostname === 'cloudworkstations.dev';

  // Базовые опции
  const base = {
    httpOnly: true,
    path: '/',
    expires: expiresTime,
  };

  // ЛОКАЛЬНАЯ РАЗРАБОТКА
  if (isLocalhost || hostname === '') {
    // host-only cookie (НЕ указываем domain), без Secure
    return {
      ...base,
      secure: false,
      sameSite: 'Lax', // фронт и API обычно «односайтовые» при локалке
      // domain: НЕ УКАЗЫВАЕМ для localhost
    };
  }

  // PROD / TEST c HTTPS
  // По умолчанию считаем SameSite=Lax (если фронт и API в одной «site»-зоне).
  // Если реально сетап кросс-сайтовый (например, фронт на одном eTLD+1, API на другом, и вы хотите,
  // чтобы Set-Cookie работал из кросс-сайтового контекста) — понадобится SameSite=None и Secure=true.
  // Ниже оставляю Lax как безопасный дефолт. При необходимости поменяйте на 'None'.
  if (isMeteor) {
    return {
      ...base,
      domain: '.meteorhr.com',
      secure: true,
      sameSite: 'Lax', // если открываете cookie из третьей стороны/iframe — смените на 'None'
    };
  }
  if (isCloudworkstations) {
    return {
      ...base,
      domain: '.cloudworkstations.dev',
      secure: true,
      sameSite: 'Lax',
    };
  }

  // Если пришёл неожиданный хост (например, stage-домен) — делаем host-only, но с Secure,
  // т.к. почти наверняка это HTTPS.
  return {
    ...base,
    secure: true,
    sameSite: 'Lax',
    // domain НЕ ставим → host-only на конкретный хост
  };
}



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
  
  // Шаг 1: Атомарно найти и удалить старый токен.
  // Populate выполняется на уровне самого запроса, а не в цепочке после него.
  const oldTokenDoc = await RefreshToken.findOneAndDelete({ 
    token: refreshToken, 
    deviceId, 
    expired_at: { $gte: currentDate } 
  }).populate({ 
      path: 'userId', 
      select: 'email phone telegram notification roles active name avatar company', 
      model: User,
      populate: { path: 'company', select: 'currency', model: Company,
        populate: { path: 'currency', select: 'code', model: Currencies }
      }
    });

  // Если токен не найден или просрочен, oldTokenDoc будет null.
  if (!oldTokenDoc) {
    // Добавим диагностику для поиска причины
    console.error(`[Auth] Refresh token rotation failed. Token not found or expired. Token: ${refreshToken}, DeviceID: ${deviceId}`);
    // Можно добавить логику для обнаружения кражи токена здесь.
    return null;
  }
  
  // Если oldTokenDoc есть, но userId не был найден (например, удален), это тоже ошибка.
  if (!oldTokenDoc.userId) {
      console.error(`[Auth] Orphaned refresh token found and deleted. Token: ${refreshToken}`);
      return null;
  }

  // Шаг 2: Создать новый refresh-токен.
  const expiredDate = new Date(currentDate.getTime() + (1000 * 60 * 60 * 24 * config.refreshTokenLifetimeDays));
  const newRefreshToken = new RefreshToken({
    token: uuidv4(),
    userId: oldTokenDoc.userId._id, // userId здесь - это полный объект User
    deviceId: deviceId,
    expired_at: expiredDate,
  });
  await newRefreshToken.save();

  // Возвращаем полный объект пользователя и новый токен.
  return { 
    userId: oldTokenDoc.userId.toObject(), // Преобразуем Mongoose документ в plain object
    token: newRefreshToken.token 
  };
};

const applyRefreshResult = (request, reply, refreshResult) => {
  const { userId, token: newRefreshToken } = refreshResult;
  request.accessToken = generateAccessToken(userId);
  request.session = {
    _id: userId._id,
    company: userId.company?._id,
    deviceId: request.headers[config.headers.deviceId]
  };
  setRefreshTokenCookie(request, reply, newRefreshToken);
};

const setRefreshTokenCookie = (reply, token) => {
  const expiresTime = new Date(Date.now() + (1000 * 60 * 60 * 24 * config.refreshTokenLifetimeDays));
  const hostname = getHostnameFromRequest(request);
  const cookieOpts = computeCookieOptionsByHost(hostname, expiresTime);

  reply.setCookie(config.cookies.refreshTokenName, token, cookieOpts);
};

// ИСПРАВЛЕНО: Пейлоад не оборачивается в лишний объект
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



const handleServerError = (reply, error) => {
  console.error('Unhandled Authentication Error:', error);
  return reply.status(500).send({ success: false, code: 500, msg: 'Internal Server Error' });
};

const handleAuthFailure = (reply) => {
  reply.setCookie(config.cookies.refreshTokenName, '', {
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
    
    const performTokenRefresh = async () => {
      try {
        await RefreshTokenUpdate(request, reply);
        return; 
      } catch (error) {
        if (error instanceof TokenRefreshFailedError || error instanceof TokenRefreshTimeoutError) {
            return handleAuthFailure(reply);
        }
        return handleServerError(reply, error);
      }
    };

    const { headers, cookies } = request;
    const refreshToken = cookies[config.cookies.refreshTokenName];
    const deviceId = headers[config.headers.deviceId];

    if (!deviceId || !refreshToken) {
     return handleAuthFailure(reply);
    }

    const accessToken = headers[config.headers.authToken];
    if (accessToken) {
      try {
        const payloadFromToken = jwt.verify(accessToken, privateKey, { algorithms: ['RS256'] });
        const payload = payloadFromToken.payload ? payloadFromToken.payload : payloadFromToken;
        
        request.accessToken = accessToken;
        request.session = { 
          _id: payload._id, 
          company: payload.company?._id, 
          deviceId 
        };
        
        return; // Токен валиден, продолжаем
      } catch (error) {
        if (error.name === 'TokenExpiredError') {
         return performTokenRefresh();
        }
        return handleAuthFailure(reply);
      }
    } else {
       return performTokenRefresh();
    }
  };

  return authHook;
};
