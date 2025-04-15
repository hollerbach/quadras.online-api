// src/interfaces/api/middlewares/index.js
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const passport = require('passport');
const rateLimit = require('express-rate-limit');
const config = require('../../../infrastructure/config');
const logger = require('../../../infrastructure/logging/logger');

/**
 * Configurar middlewares globais para a aplicação Express
 * @param {Express} app Instância do Express
 */
const setupMiddlewares = (app) => {
  // Configurações de segurança para cabeçalhos HTTP
  app.use(helmet({
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
        upgradeInsecureRequests: []
      }
    },
    crossOriginEmbedderPolicy: false, // Permitir incorporação de recursos de terceiros (reCAPTCHA)
    xssFilter: true,
    hsts: {
      maxAge: 31536000, // 1 ano em segundos
      includeSubDomains: true,
      preload: true
    }
  }));

  // Parsers para corpo da requisição
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Parser de cookies
  app.use(cookieParser());

  // Configuração CORS
  app.use(cors({
    origin: (origin, callback) => {
      if (!origin || config.security.cors.allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        logger.warn(`Tentativa de acesso CORS bloqueada: ${origin}`);
        callback(new Error('Não permitido por CORS'));
      }
    },
    credentials: config.security.cors.credentials
  }));

  // Rate limiting global
  app.use(rateLimit({
    windowMs: config.security.rateLimit.windowMs,
    max: config.security.rateLimit.max,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Muitas requisições deste IP, tente novamente mais tarde'
  }));

  // Inicialização do Passport
  require('../../../infrastructure/security/passport');
  app.use(passport.initialize());

  // Health check - rota simples para verificar se API está rodando
  app.get('/health', (req, res) => {
    res.status(200).json({
      status: 'UP',
      timestamp: new Date().toISOString()
    });
  });
};

module.exports = setupMiddlewares;