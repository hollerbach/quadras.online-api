// src/app.js
const express = require('express');
const logger = require('./infrastructure/logging/logger');
const config = require('./infrastructure/config');

// Middlewares globais
const setupMiddlewares = require('./interfaces/api/middlewares');

// Rotas da API
const setupRoutes = require('./interfaces/api/routes');

// Manipulação de erros
const {
  errorHandler,
  notFoundHandler
} = require('./interfaces/api/middlewares/error.middleware');

/**
 * Inicializa e configura a aplicação Express
 */
const initializeApp = () => {
  const app = express();

  // Middleware de logging de requisições
  app.use((req, res, next) => {
    req.logger = logger;
    logger.info(`[${req.method}] ${req.url}`);
    next();
  });

  // Configurar middlewares globais
  setupMiddlewares(app);

  // Configurar rotas
  setupRoutes(app);

  // Middleware para rotas não encontradas (404)
  app.use(notFoundHandler);

  // Middleware de tratamento de erros (deve ser o último)
  app.use(errorHandler);

  return app;
};

// Inicializar a aplicação
const app = initializeApp();

module.exports = { app };