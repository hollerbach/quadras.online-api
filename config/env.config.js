// config/env.config.js
const logger = require('../services/logger');

// Lista de variáveis de ambiente obrigatórias
const requiredEnvVars = [
  'JWT_SECRET',
  'JWT_EXPIRES_IN',
  'JWT_REFRESH_EXPIRES_IN',
  'DB_USER',
  'DB_PASS',
  'DB_NAME',
  'MONGODB_CLUSTER',
  'MONGODB_APP',
  'EMAIL_HOST',
  'EMAIL_PORT',
  'EMAIL_USER',
  'EMAIL_PASS',
  'RECAPTCHA_SECRET',
  'APP_KEY'
];

// Verificar variáveis obrigatórias
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    logger.error(`Variável de ambiente ${envVar} não definida`);
    if (process.env.NODE_ENV === 'production') {
      throw new Error(`Variável de ambiente ${envVar} não definida`);
    }
  }
}

// Configurações organizadas por contexto
module.exports = {
  app: {
    env: process.env.NODE_ENV || 'development',
    port: process.env.PORT || 3000,
    appKey: process.env.APP_KEY,
    baseUrl: process.env.BASE_URL || 'http://localhost:3000'
  },
  
  db: {
    uri: `mongodb+srv://${encodeURIComponent(process.env.DB_USER)}:${encodeURIComponent(process.env.DB_PASS)}@${process.env.MONGODB_CLUSTER}/${process.env.DB_NAME}?retryWrites=true&w=majority&appName=${process.env.MONGODB_APP}`,
    options: {
      // Manter apenas opções específicas necessárias para seu caso de uso
      // Como retryWrites, w, etc. se você precisar delas
    }
  },
  
  auth: {
    jwt: {
      secret: process.env.JWT_SECRET,
      expiresIn: process.env.JWT_EXPIRES_IN || '1h',
      refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d'
    },
    recaptcha: {
      secret: process.env.RECAPTCHA_SECRET,
      scoreThreshold: 0.5
    },
    password: {
      saltRounds: 10,
      resetTokenExpiry: 15 * 60 * 1000 // 15 minutos
    },
    verification: {
      tokenExpiry: 30 * 60 * 1000 // 30 minutos
    }
  },
  
  email: {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT, 10),
    secure: parseInt(process.env.EMAIL_PORT, 10) === 465,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    },
    from: `"Mercearia Digital" <${process.env.EMAIL_USER}>`
  },
  
  security: {
    cors: {
      allowedOrigins: (process.env.ALLOWED_ORIGINS || 'https://mercearia.digital').split(','),
      credentials: true
    },
    rateLimit: {
      windowMs: 15 * 60 * 1000, // 15 minutos
      max: 100, // limite por IP
      loginMax: 10 // limite específico para login
    },
    csrf: {
      cookie: {
        key: 'csrf-token',
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production'
      }
    }
  }
};