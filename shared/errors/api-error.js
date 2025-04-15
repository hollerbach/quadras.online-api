// src/shared/errors/api-error.js

/**
 * Classe base para erros da API
 * Permite definir o código HTTP e se o erro é operacional ou de programação
 */
class ApiError extends Error {
    /**
     * Cria uma nova instância de ApiError
     * @param {number} statusCode - Código de status HTTP
     * @param {string} message - Mensagem de erro
     * @param {boolean} isOperational - Se é um erro operacional (true) ou de programação (false)
     * @param {Object} errors - Erros detalhados (opcional)
     */
    constructor(statusCode, message, isOperational = true, errors = null) {
      super(message);
      this.statusCode = statusCode;
      this.isOperational = isOperational;
      this.errors = errors;
      this.name = this.constructor.name;
      
      Error.captureStackTrace(this, this.constructor);
    }
  }
  
  /**
   * Cria um erro 400 Bad Request
   */
  class BadRequestError extends ApiError {
    constructor(message = 'Requisição inválida', errors = null) {
      super(400, message, true, errors);
    }
  }
  
  /**
   * Cria um erro 401 Unauthorized
   */
  class UnauthorizedError extends ApiError {
    constructor(message = 'Não autorizado') {
      super(401, message, true);
    }
  }
  
  /**
   * Cria um erro 403 Forbidden
   */
  class ForbiddenError extends ApiError {
    constructor(message = 'Acesso negado') {
      super(403, message, true);
    }
  }
  
  /**
   * Cria um erro 404 Not Found
   */
  class NotFoundError extends ApiError {
    constructor(message = 'Recurso não encontrado') {
      super(404, message, true);
    }
  }
  
  /**
   * Cria um erro 409 Conflict
   */
  class ConflictError extends ApiError {
    constructor(message = 'Conflito de recursos') {
      super(409, message, true);
    }
  }
  
  /**
   * Cria um erro 429 Too Many Requests
   */
  class TooManyRequestsError extends ApiError {
    constructor(message = 'Muitas requisições. Tente novamente mais tarde.') {
      super(429, message, true);
    }
  }
  
  /**
   * Cria um erro 500 Internal Server Error
   */
  class InternalServerError extends ApiError {
    constructor(message = 'Erro interno do servidor', isOperational = false) {
      super(500, message, isOperational);
    }
  }
  
  module.exports = {
    ApiError,
    BadRequestError,
    UnauthorizedError,
    ForbiddenError,
    NotFoundError,
    ConflictError,
    TooManyRequestsError,
    InternalServerError
  };