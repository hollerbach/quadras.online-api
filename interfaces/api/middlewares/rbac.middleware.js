// src/interfaces/api/middlewares/rbac.middleware.js
const { ForbiddenError } = require('../../../shared/errors/api-error');

/**
 * Middleware para autorização baseada em papel (RBAC)
 * @param {string[]} roles Array de papéis permitidos
 * @returns {Function} Middleware de autorização
 */
const authorize = (roles = []) => {
  if (typeof roles === 'string') {
    roles = [roles];
  }
  
  return (req, res, next) => {
    if (!req.user) {
      return next(new ForbiddenError('Usuário não autenticado'));
    }
    
    if (roles.length && !roles.includes(req.user.role)) {
      return next(new ForbiddenError('Permissão negada: papel não autorizado'));
    }
    
    next();
  };
};

module.exports = {
  authorize
};