// middleware/errorHandler.middleware.js
const logger = require('../services/logger');

// Classe customizada de erro para a API
class ApiError extends Error {
  constructor(statusCode, message, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Middleware de tratamento de erros centralizado
const errorHandler = (err, req, res, next) => {
  // Se o erro já for um ApiError, use suas propriedades
  // Caso contrário, assuma erro interno 500
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Erro interno do servidor';
  
  // Log detalhado apenas para erros do servidor
  if (statusCode >= 500) {
    logger.error(`[${req.method}] ${req.path} >> ${err.stack}`);
  } else {
    logger.warn(`[${req.method}] ${req.path} >> ${err.message}`);
  }
  
  // Resposta padronizada
  const response = {
    status: 'error',
    message,
    // Em ambiente de desenvolvimento, inclua o stack trace
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
    // Incluir detalhes de validação se disponíveis
    ...(err.errors && { errors: err.errors })
  };
  
  res.status(statusCode).json(response);
};

// Middleware para capturar erros de promises não tratadas
const unhandledPromiseRejection = (req, res, next) => {
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    throw reason;
  });
  
  next();
};

// Middleware para capturar endpoints não existentes
const notFoundHandler = (req, res, next) => {
  const error = new ApiError(404, `Rota não encontrada - ${req.originalUrl}`);
  next(error);
};

module.exports = {
  ApiError,
  errorHandler,
  unhandledPromiseRejection,
  notFoundHandler
};
