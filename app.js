// app.js (atualizado com inicialização do Passport)
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const passport = require('passport'); // Adicionar importação do passport
const config = require('./config/env.config');
const healthController = require('./controllers/health.controller');

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

// Serviços OAuth (isso inicializará as estratégias Passport)
require('./services/oauth.service');

// Documentação Swagger
const swaggerDocument = YAML.load('./docs/swagger.yaml');