// middlewares/security.middleware.js
const csrf = require('csurf');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const config = require('../config/env.config');
const { ApiError } = require('./errorHandler.middleware');

/**
 * Configuração do middleware Helmet para segurança de cabeçalhos HTTP
 */
const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://www.google.com/recaptcha/', 'https://www.gstatic.com/recaptcha/'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameSrc: ["'self'", 'https://www.google.com/recaptcha/'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false, // Permitir incorporação de recursos de terceiros (reCAPTCHA)
  xssFilter: true,
  hsts: {
    maxAge: 31536000, // 1 ano em segundos
    includeSubDomains: true,
    preload: true
  }
});

/**
 * Configuração para proteção CSRF
 */
const csrfProtection = csrf({
  cookie: {
    key: config.security.csrf.cookie.key,
    httpOnly: config.security.csrf.cookie.httpOnly,
    sameSite: config.security.csrf.cookie.sameSite,
    secure: config.security.csrf.cookie.secure,
  }
});

/**
 * Middleware para fornecer o token CSRF ao cliente
 */
const csrfToken = (req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
};

/**
 * Handler de erros CSRF
 */
const csrfErrorHandler = (err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return next(new ApiError(403, 'Falha na validação CSRF'));
  }
  next(err);
};

/**
 * Rate Limiter global
 */
const globalRateLimit = rateLimit({
  windowMs: config.security.rateLimit.windowMs,
  max: config.security.rateLimit.max,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Muitas requisições deste IP, tente novamente mais tarde'
});

/**
 * Rate Limiter específico para login
 */
const loginRateLimit = rateLimit({
  windowMs: config.security.rateLimit.windowMs,
  max: config.security.rateLimit.loginMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Muitas tentativas de login. Tente novamente mais tarde.'
});

/**
 * Middleware para validar origem das requisições (CORS)
 */
const validateOrigin = (req, res, next) => {
  const origin = req.headers.origin;
  
  // Se não tiver origem (como API calls diretas) ou estiver na lista de permitidos
  if (!origin || config.security.cors.allowedOrigins.includes(origin)) {
    return next();
  }
  
  // Registrar tentativa de acesso não permitido
  req.logger.warn(`Tentativa de acesso CORS bloqueada: ${origin}`);
  return next(new ApiError(403, 'Origem não permitida'));
};

/**
 * Verifica autenticidade do APP_KEY
 */
const verifyAppKey = (req, res, next) => {
  const appKey = req.headers['x-app-key'];
  
  if (!appKey || appKey !== config.app.appKey) {
    return next(new ApiError(403, 'Chave de aplicação inválida'));
  }
  
  next();
};

/**
 * Middlewares para prevenção de brute-force em endpoints sensíveis
 */
const sensitiveRouteProtection = {
  // Rate limit para redefinição de senha
  passwordReset: rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hora
    max: 3, // 3 tentativas por hora por IP
    message: 'Muitas solicitações de redefinição de senha. Tente novamente mais tarde.'
  }),
  
  // Rate limit para configuração de 2FA
  twoFactorSetup: rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 24 horas
    max: 5, // 5 tentativas por dia por IP
    message: 'Muitas solicitações para configurar 2FA. Tente novamente mais tarde.'
  })
};

module.exports = {
  helmetConfig,
  csrfProtection,
  csrfToken,
  csrfErrorHandler,
  globalRateLimit,
  loginRateLimit,
  validateOrigin,
  verifyAppKey,
  sensitiveRouteProtection
};
