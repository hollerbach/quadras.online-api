// config/env.config.js (atualizado com configurações OAuth)
const logger = require('../services/logger');

// Lista de variáveis de ambiente obrigatórias em produção
const requiredEnvVars = [
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
  'MONGODB_CLUSTER'
];

// Lista de variáveis de banco de dados que são opcionais em desenvolvimento
const dbEnvVars = [
  'DB_USER',
  'DB_PASS',
  'MONGODB_APP'
];

// Lista de variáveis OAuth que são opcionais em desenvolvimento
const oauthEnvVars = [
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'OAUTH_REDIRECT_URL'
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
    logger.warn(`Variável de ambiente ${envVar} não definida`);
    if (process.env.NODE_ENV === 'production') {
      throw new Error(`Variável de ambiente ${envVar} não definida`);
    }
  }
}

// Verificar variáveis OAuth
for (const envVar of oauthEnvVars) {
  if (!process.env[envVar]) {
    logger.warn(`Variável de ambiente OAuth ${envVar} não definida. Funcionalidades OAuth podem não funcionar corretamente.`);
  }
}

// Valores padrão para ambiente de desenvolvimento
const getMongoURI = () => {
  // Se estamos em desenvolvimento e faltam credenciais, usamos uma conexão local
  if (process.env.NODE_ENV !== 'production' && 
     (!process.env.DB_USER || !process.env.DB_PASS || !process.env.MONGODB_CLUSTER)) {
    logger.info('Usando conexão MongoDB local para ambiente de desenvolvimento');
    return `mongodb://localhost:27017/${process.env.DB_NAME || 'mercearia_dev'}`;
  }
  
  // Caso contrário, usamos a conexão Atlas com credenciais
  return `mongodb+srv://${encodeURIComponent(process.env.DB_USER)}:${encodeURIComponent(process.env.DB_PASS)}@${process.env.MONGODB_CLUSTER}/${process.env.DB_NAME}?retryWrites=true&w=majority${process.env.MONGODB_APP ? `&appName=${process.env.MONGODB_APP}` : ''}`;
};

// Configurações organizadas por contexto
module.exports = {
  app: {
    env: process.env.NODE_ENV || 'development',
    port: process.env.PORT || 3000,
    appKey: process.env.APP_KEY || 'dev_app_key_default',
    baseUrl: process.env.BASE_URL || 'http://localhost:3000'
  },

  db: {
    uri: getMongoURI(),
    options: {
      // Opções de conexão podem ser definidas aqui se necessário
    }
  },

  auth: {
    jwt: {
      secret: process.env.JWT_SECRET || (process.env.NODE_ENV !== 'production' ? 'dev_jwt_secret' : undefined),
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

  // Novas configurações para OAuth
  oauth: {
    google: {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET
    },
    redirectUrl: process.env.OAUTH_REDIRECT_URL || 'http://localhost:3000/auth/callback'
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
      allowedOrigins: (process.env.ALLOWED_ORIGINS || 'https://mercearia.digital,http://localhost:3000').split(','),
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