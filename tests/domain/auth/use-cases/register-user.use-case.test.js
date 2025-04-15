// src/interfaces/api/middlewares/validation.middleware.js
const { validationResult } = require('express-validator');
const { BadRequestError } = require('../../../shared/errors/api-error');
const logger = require('../../../infrastructure/logging/logger');

/**
 * Middleware para verificar resultados de validação
 * @param {Request} req Express Request
 * @param {Response} res Express Response
 * @param {NextFunction} next Express Next
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    // Formatar erros para um formato consistente e amigável
    const formattedErrors = errors.array().map(err => ({
      field: err.path,
      message: err.msg,
      value: err.value ? (
        // Remover ou mascarar valores sensíveis antes de incluir no log
        ['password', 'token', 'secret'].includes(err.path) ? '[REDACTED]' : err.value
      ) : undefined
    }));
    
    // Registrar os erros de validação no log
    logger.warn(`Erro de validação: ${req.method} ${req.originalUrl}`, {
      ip: req.ip,
      errors: formattedErrors
    });
    
    // Lançar erro com lista formatada de erros
    throw new BadRequestError('Erro de validação nos dados fornecidos', formattedErrors);
  }
  
  next();
};

/**
 * Factory para criar middlewares de validação específicos
 * @param {Array} validationChain Cadeia de validadores
 * @returns {Array} Middlewares de validação
 */
const createValidator = (validationChain) => {
  return [...validationChain, validate];
};

/**
 * Sanitiza dados de entrada removendo campos não permitidos
 * @param {Array} allowedFields Lista de campos permitidos
 * @returns {Function} Middleware para sanitizar
 */
const sanitize = (allowedFields) => {
  return (req, res, next) => {
    // Aplicar apenas a dados no corpo
    if (req.body && typeof req.body === 'object') {
      const sanitizedBody = {};
      
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          sanitizedBody[field] = req.body[field];
        }
      }
      
      req.body = sanitizedBody;
    }
    
    next();
  };
};

/**
 * Validator específico para payloads JSON
 * Verifica se o corpo da requisição é JSON válido
 */
const validateJsonBody = (req, res, next) => {
  // Express já faz o parsing do JSON, este middleware
  // apenas garante que não houve problemas no parser
  if (req.method !== 'GET' && req.method !== 'DELETE' && 
      req.headers['content-type']?.includes('application/json') && 
      !req.body) {
    throw new BadRequestError('JSON inválido no corpo da requisição');
  }
  next();
};

module.exports = {
  validate,
  createValidator,
  sanitize,
  validateJsonBody
};