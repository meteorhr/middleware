import fs from 'fs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import RefreshToken from './models/refreshToken.model.js';
import User from './models/user.model.js';
import Currencies from './models/currency.model.js';
import Company from './models/company.model.js';

const privateKey = fs.readFileSync('./keys/private.key', 'utf8');
const expires = process.env.TOKEN_EXPIRATION_MINUTES;
const expiresTimeAsMs = Date.now() + (1000 * 60 * 60 * 24 * 60);

const HEADER_DEVICE_ID = 'x-device-id';
const HEADER_AUTH_TOKEN = 'x-authentication-token';


const RefreshTokenUpdate = async (req, res, next) => {
  try {
    const { headers, cookies } = req;
    const refreshToken = cookies.refreshToken;
    const deviceId = headers[HEADER_DEVICE_ID];

    //console.info('Device ID Headers: ' + deviceId);
    //console.info('Refresh Token Cookies: ' + refreshToken);
    //console.info('Find refresh token');

    const findAndUpdate = await findRefreshTokenAndUpdated(refreshToken, deviceId);

    if(!findAndUpdate){
      await removeInvalidRefreshToken(refreshToken);
      const errorResponse =  handleRefreshTokenNotUpdate(res);  
      return res.send(errorResponse);
    }

    // Создание нового AccessToken
    const payload = findAndUpdate.userId;
    req.accessToken = generateAccessToken(payload);
    req.session = {
      _id: payload._id,
      company: payload.company._id,
      deviceId: deviceId
    }
    
    // Установка обновленного RefreshToken в куки
    setRefreshTokenCookie(res, findAndUpdate.token);
    
    return next;
  } catch (error) {
    return res.send(handleServerError(res, error));
  }
};

const generateAccessToken = (payload) => {
  return jwt.sign({ payload }, privateKey, {
    expiresIn: `${expires}m`,
    algorithm: 'RS256'
  });
};

const findRefreshTokenAndUpdated = async (refreshToken, deviceId) => {
  const currentDate = new Date();
  const expiredDate = new Date(currentDate.getTime() + 86400000 * 60);

  const findDoc = {
    token: refreshToken,
    deviceId: deviceId,
    expired_at: { $gte: currentDate }
  }
  
  const doc = {
    token:  uuidv4(), // New Refresh Token
    updated_at: currentDate, // Current Date 
    expired_at: expiredDate, // Current Data + 60 days
  }  


  const update = await RefreshToken
    .findOneAndUpdate(findDoc, {$set: doc}, {
      new: true,
      fields: { token:1, userId: 1 },
    })
    .populate(
      { 
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
      }
    );

  return update;
}

const removeInvalidRefreshToken = async (refreshToken) => {
  return await RefreshToken.findOneAndDelete({ token: refreshToken });
};

const handleServerError = (res) => {
  return setCookieAndSendErrorMessage(res, 'Server error');
};

const handleRefreshTokenNotUpdate = (res) => {
  return setCookieAndSendErrorMessage(res, 'Refresh token not updated');
};

const setCookieAndSendErrorMessage = (res, errorMsg) => {
  res.setCookie('refreshToken', '', {
    httpOnly: false,
    secure: false,
    domain: process.env.DOMAIN,
    path: '/',
  });
  res.status(401);
  return { success: false, code: 401, msg: errorMsg };
};

const setRefreshTokenCookie = (res, token) => {
  res.setCookie('refreshToken', token, {
    expires: expiresTimeAsMs,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    domain: process.env.DOMAIN,
    path: '/'
  });
};

/* 
*
*  Любой запрос на доступ к авторизированному ресурсу должен содержать:
*  cookies: refreshToken
*  headers: x-device-id
*
**/

export default () => {
  const middleware = async (req, res, next) => {
    try { 
      // Получения headers, cookies из запроса 
      const {headers, cookies} = req;
      // Получения refreshToken
      const refreshToken = cookies.refreshToken;
      //console.log(cookies);
      //console.log("Refresh Token: " + refreshToken);
      // Если отсутствует Device ID в запросе, обнулить куки, поставить статус ответа 401, направить сообще об ошибки в формате JSON
      if(!headers[HEADER_DEVICE_ID]){
        return res.send(setCookieAndSendErrorMessage(res, 'Headers not found device id'));
      }
      // Если отсутствует Refresh Token в запросе, обнулить куки, поставить статус ответа 401, направить сообще об ошибки в формате JSON
      if(!refreshToken){
        return res.send(setCookieAndSendErrorMessage(res, 'Refresh Token not found'));
      } 

      // Если существует Access Token
      if(headers[HEADER_AUTH_TOKEN]){
          const accessToken = headers[HEADER_AUTH_TOKEN];
          const {exp, payload} = jwt.decode(accessToken, privateKey);
          const expirationTime = exp * 1000
          // Дата токена больше текущей даты
          if (Date.now() <= expirationTime) {
              try {
                req.accessToken = generateAccessToken(payload);
                req.session = {
                  _id: payload._id,
                  company: payload.company._id,
                  deviceId: headers[HEADER_DEVICE_ID]
                }
                return next;
              } catch(error){
                return res.send(handleServerError(res, error));
              }
          } else {
            // console.log('Update refresh token, expiration time access token');
            return await RefreshTokenUpdate(req, res, next);
          }
      } else {
          // console.log('Update refresh token, access token not found');
          return await RefreshTokenUpdate(req, res, next);
      }  
    } catch(error) {
      return res.send(handleServerError(res, error));
    } 
  }

  return middleware;
}
