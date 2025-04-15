// src/infrastructure/security/security.config.js
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const config = require('../config');

/**
 * Configurações de segurança para a aplicação
 */
const securityConfig = {
  /**
   * Configuração do Helmet para cabeçalhos de segurança
   */
  helmet: helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://www.google.com/recaptcha/',
          'https://www.gstatic.com/recaptcha/'
        ],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        frameSrc: ["'self'", 'https://www.google.com/recaptcha/'],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: config.app.env === 'production' ? [] : null
      }
    },
    crossOriginEmbedderPolicy: false, // Permitir incorporação de recursos externos (reCAPTCHA)
    xssFilter: true,
    hsts: {
      maxAge: 31536000, // 1 ano em segundos
      includeSubDomains: true,
      preload: true
    },
    frameguard: {
      action: 'deny' // Impedir que a aplicação seja exibida em um iframe
    },
    noSniff: true, // Evitar que o navegador faça sniffing do tipo MIME
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
  }),

  /**
   * Rate limiter global para todas as requisições
   */
  globalRateLimit: rateLimit({
    windowMs: config.security.rateLimit.windowMs,
    max: config.security.rateLimit.max,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Muitas requisições deste IP, tente novamente mais tarde',
    skipSuccessfulRequests: false
  }),

  /**
   * Rate limiter específico para autenticação
   */
  authRateLimit: rateLimit({
    windowMs: config.security.rateLimit.windowMs,
    max: config.security.rateLimit.loginMax,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Muitas tentativas de autenticação. Tente novamente mais tarde.',
    skipSuccessfulRequests: false
  }),

  /**
   * Limitador para rotas sensíveis (redefinição de senha, etc)
   */
  sensitiveRateLimit: rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hora
    max: 5, // 5 solicitações por hora
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Limite excedido para operações sensíveis. Tente novamente mais tarde.',
    skipSuccessfulRequests: false
  }),

  /**
   * Speed limiter - Torna as respostas progressivamente mais lentas
   * Útil para prevenir brute force mesmo respeitando rate limits
   */
  speedLimiter: slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutos
    delayAfter: 30, // permitir 30 requisições normais
    delayMs: (hits) => hits * 100, // adiciona 100ms para cada requisição após o limite
    maxDelayMs: 10000 // máximo de 10 segundos de delay
  }),

  /**
   * Cross-Origin Resource Sharing options
   */
  corsOptions: {
    origin: (origin, callback) => {
      const allowedOrigins = config.security.cors.allowedOrigins;
      
      // Se não tiver origem (requisições do mesmo site) ou a origem for permitida
      if (!origin || allowedOrigins.includes(origin) || 
          (config.app.env === 'development' && allowedOrigins.includes('*'))) {
        callback(null, true);
      } else {
        callback(new Error('Não permitido por CORS'));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: config.security.cors.credentials,
    maxAge: 86400 // Cache preflight por 24 horas
  }
};

module.exports = securityConfig;