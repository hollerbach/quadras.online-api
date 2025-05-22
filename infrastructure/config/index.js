// src/infrastructure/config/index.js
const logger = require('../logging/logger');

// Lista de variáveis de ambiente obrigatórias em produção
const requiredEnvVars = [
  'NODE_ENV',
  'PORT',
  'APP_KEY',
  'ALLOWED_ORIGINS',
  'BASE_URL',
  'JWT_SECRET',
  'JWT_EXPIRES_IN',
  'JWT_REFRESH_EXPIRES_IN',
  'EMAIL_HOST',
  'EMAIL_PORT',
  'EMAIL_USER',
  'EMAIL_PASS',
  'RECAPTCHA_SECRET',
  'APP_KEY',
  'DB_NAME',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET'
];

// Lista de variáveis de banco de dados que são opcionais em desenvolvimento
const dbEnvVars = [
  'DB_USER',
  'DB_PASS',
  'DB_HOST',
  'DB_PORT'
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

// Verificar variáveis de banco de dados
for (const envVar of dbEnvVars) {
  if (!process.env[envVar]) {
    if (process.env.NODE_ENV === 'production') {
      logger.warn(`Variável de ambiente ${envVar} não definida`);
      throw new Error(`Variável de ambiente ${envVar} não definida`);
    }
  }
}

// Configuração da conexão MySQL
const getMySQLConfig = () => {
  return {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    database: process.env.DB_NAME || 'quadras_online',
    username: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    dialect: 'mysql',
    dialectOptions: {
      connectTimeout: 60000 // 60 segundos
    },
    pool: {
      max: 10, // máximo de conexões
      min: 0, // mínimo de conexões
      acquire: 30000, // tempo máximo em ms para adquirir uma conexão
      idle: 10000 // tempo máximo em ms que uma conexão pode estar ociosa
    },
    define: {
      underscored: true, // transforma camelCase em snake_case
      timestamps: true, // timestamps automáticos
      paranoid: true, // soft delete
      freezeTableName: false, // pluralizar nomes de tabelas
      charset: 'utf8mb4',
      collate: 'utf8mb4_unicode_ci',
      engine: 'InnoDB'
    },
    logging: process.env.NODE_ENV === 'development' ? 
      (msg) => logger.debug(msg) : false
  };
};

// Configurações organizadas por contexto
module.exports = {
  app: {
    env: process.env.NODE_ENV,
    port: process.env.PORT,
    appKey: process.env.APP_KEY,
    baseUrl: process.env.BASE_URL,
    frontendUrl: process.env.FRONTEND_URL
  },

  db: {
    mysql: getMySQLConfig()
  },

  auth: {
    jwt: {
      secret: process.env.JWT_SECRET,
      expiresIn: process.env.JWT_EXPIRES_IN,
      refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN
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

  // Adicionar configurações OAuth
  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackUrl: `${process.env.BASE_URL}/auth/google/callback`,
      redirectUrl: process.env.FRONTEND_URL || process.env.BASE_URL
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
    from: `"Agendamento de Quadras" <${process.env.EMAIL_USER}>`
  },

  security: {
    cors: {
      allowedOrigins: (process.env.ALLOWED_ORIGINS).split(','),
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