// app.js
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const passport = require('passport');
const config = require('./config/env.config');
const healthController = require('./controllers/health.controller');

// Inicializar serviços OAuth
require('./services/googleAuth.service');

// Middlewares de segurança
const {
  helmetConfig,
  csrfProtection,
  csrfToken,
  csrfErrorHandler,
  globalRateLimit,
  validateOrigin
} = require('./middlewares/security.middleware');

// Middlewares de manipulação de erros
const {
  errorHandler,
  notFoundHandler
} = require('./middlewares/errorHandler.middleware');

// Rotas
const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/user.routes');

// Logger
const logger = require('./services/logger');

// Documentação Swagger
const swaggerDocument = YAML.load('./docs/swagger.yaml');

// Inicializar aplicação
const app = express();

// Middleware de logging de requisições
app.use((req, res, next) => {
  req.logger = logger;
  logger.info(`[${req.method}] ${req.url}`);
  next();
});

// Middlewares globais
app.use(helmetConfig); // Configurações de segurança para cabeçalhos HTTP
app.use(express.json()); // Parser de corpo JSON
app.use(express.urlencoded({ extended: true })); // Parser de corpo de formulário
app.use(cookieParser()); // Parser de cookies
// app.use(unhandledPromiseRejection); // Capturar rejeições de promises não tratadas

// Inicialização do Passport
app.use(passport.initialize());

// Configuração de CORS personalizada
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || config.security.cors.allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        logger.warn(`Tentativa de acesso CORS bloqueada: ${origin}`);
        callback(new Error('Não permitido por CORS'));
      }
    },
    credentials: config.security.cors.credentials
  })
);

// Rate limiting global
app.use(globalRateLimit);

// Rotas públicas (não necessitam CSRF)
app.use(
  '/api/docs',
  swaggerUi.serve,
  swaggerUi.setup(swaggerDocument, {
    customCss: '.swagger-ui .topbar { display: none }'
  })
);

// Aplicar proteção CSRF para rotas não públicas
// Observação: CSRF não deve ser aplicado a APIs puras RESTful
// Se estiver servindo páginas web juntamente com a API, habilite o comentário abaixo
// app.use(csrfProtection);
// app.use(csrfToken);
// app.use(csrfErrorHandler);

// Definição de rotas
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// Rota de verificação de saúde
app.get('/api/health', healthController.checkHealth);

// Middleware para rotas não encontradas
app.use(notFoundHandler);

// Middleware de tratamento de erros (deve ser o último)
app.use(errorHandler);

module.exports = app;