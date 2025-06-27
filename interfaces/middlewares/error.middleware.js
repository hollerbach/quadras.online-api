// src/interfaces/api/middlewares/error.middleware.js
const logger = require('../../infrastructure/logging/logger');
const { ApiError, NotFoundError } = require('../../shared/errors/api-error');

/**
 * Middleware para tratar erros centralizadamente
 */
const errorHandler = (err, req, res, next) => {
  // Se o erro já for um ApiError, use suas propriedades
  // Caso contrário, assuma erro interno 500
  let error = err;
  if (!(err instanceof ApiError)) {
    const statusCode = err.statusCode || 500;
    const message = err.message || 'Erro interno do servidor';
    error = new ApiError(statusCode, message, false);
  }

  // Log detalhado apenas para erros do servidor ou não operacionais
  if (error.statusCode >= 500 || !error.isOperational) {
    logger.error(`[${req.method}] ${req.path} >> ${error.stack}`);
  } else {
    logger.warn(`[${req.method}] ${req.path} >> ${error.message}`);
  }

  // Resposta padronizada
  const response = {
    status: 'error',
    message: error.message,
    // Em ambiente de desenvolvimento, inclua o stack trace
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack }),
    // Incluir detalhes de validação se disponíveis
    ...(error.errors && { errors: error.errors })
  };

  res.status(error.statusCode).json(response);
};

/**
 * Middleware para capturar rotas não existentes
 */
const notFoundHandler = (req, res, next) => {
  next(new NotFoundError(`Rota não encontrada - ${req.originalUrl}`));
};

/**
 * Middleware para capturar exceções em controladores assíncronos
 * @param {Function} fn Função controladora assíncrona
 * @returns {Function} Middleware com tratamento de erro
 */
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = {
  errorHandler,
  notFoundHandler,
  asyncHandler
};