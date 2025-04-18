// src/interfaces/api/middlewares/rbac.middleware.js
const { ForbiddenError } = require('../../../shared/errors/api-error');
const userRepository = require('../../../infrastructure/database/mongodb/repositories/user.repository');
const rbacRepository = require('../../../infrastructure/database/mongodb/repositories/rbac.repository');
const logger = require('../../../infrastructure/logging/logger');

/**
 * Middleware para autorização baseada em papel clássico
 * @param {string[]|string} roles Array de papéis permitidos
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

/**
 * Middleware para autorização baseada em papel (RBAC)
 * @param {string} permissionCode Código da permissão requerida
 * @param {Object} options Opções adicionais
 * @returns {Function} Middleware de autorização
 */
const requirePermission = (permissionCode, options = {}) => {
  const { resourcePath = null, allowAdmin = true } = options;

  return async (req, res, next) => {
    try {
      if (!req.user) {
        return next(new ForbiddenError('Usuário não autenticado'));
      }

      const userId = req.user.id;

      // Verificar se é um admin (quando permitido)
      if (allowAdmin && req.user.role === 'admin') {
        return next();
      }

      // Buscar usuário com seus papéis
      const user = await userRepository.findById(userId);
      
      if (!user) {
        return next(new ForbiddenError('Usuário não encontrado'));
      }

      // Verificar se o usuário tem a permissão através de seus papéis
      let hasPermission = false;

      // Para compatibilidade com o sistema antigo, garantir que o papel legado seja verificado
      if (user.role === 'admin' && allowAdmin) {
        hasPermission = true;
      } else {
        // Verificar na nova estrutura RBAC
        if (user.roles && user.roles.length > 0) {
          for (const roleAssignment of user.roles) {
            const roleId = roleAssignment.role;
            const hasRolePermission = await rbacRepository.roleHasPermission(
              roleId,
              permissionCode,
              resourcePath
            );
            
            if (hasRolePermission) {
              hasPermission = true;
              break;
            }
          }
        }
      }

      if (hasPermission) {
        return next();
      }

      // Registrar tentativa de acesso não autorizado
      logger.warn(`Acesso negado: usuário ${user.email} tentou acessar recurso com permissão ${permissionCode}`);
      return next(new ForbiddenError('Permissão negada para este recurso'));
    } catch (error) {
      logger.error(`Erro na verificação de permissão: ${error.message}`);
      return next(new ForbiddenError('Erro ao verificar permissões'));
    }
  };
};

/**
 * Middleware para verificar se o usuário tem pelo menos um dos papéis especificados
 * @param {Array|string} roles Array de papéis ou nome do papel
 * @returns {Function} Middleware de autorização
 */
const hasRole = (roles) => {
  if (typeof roles === 'string') {
    roles = [roles];
  }
  
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return next(new ForbiddenError('Usuário não autenticado'));
      }
      
      const userId = req.user.id;
      
      // Para compatibilidade com o sistema antigo
      if (roles.includes(req.user.role)) {
        return next();
      }
      
      // Buscar usuário com seus papéis
      const user = await userRepository.findById(userId);
      
      if (!user) {
        return next(new ForbiddenError('Usuário não encontrado'));
      }
      
      // Verificar os papéis do usuário na nova estrutura RBAC
      if (user.roles && user.roles.length > 0) {
        // Buscar todos os papéis do usuário
        const userRoles = await user.getRoles();
        
        // Verificar se o usuário tem pelo menos um dos papéis especificados
        for (const roleAssignment of userRoles.roles) {
          const role = roleAssignment.role;
          
          if (role && roles.includes(role.name)) {
            return next();
          }
        }
      }
      
      // Registrar tentativa de acesso não autorizado
      logger.warn(`Acesso negado: usuário ${user.email} não tem os papéis necessários [${roles.join(', ')}]`);
      return next(new ForbiddenError('Permissão negada: papel não autorizado'));
    } catch (error) {
      logger.error(`Erro na verificação de papel: ${error.message}`);
      return next(new ForbiddenError('Erro ao verificar papéis'));
    }
  };
};

/**
 * Middleware para verificar se o usuário tem um papel específico com escopo específico
 * @param {string} roleName Nome do papel
 * @param {string} scope Escopo do papel ('global', 'store', 'department')
 * @param {Function} getScopeId Função para extrair o ID do escopo da requisição
 * @returns {Function} Middleware de autorização
 */
const hasScopedRole = (roleName, scope, getScopeId) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return next(new ForbiddenError('Usuário não autenticado'));
      }
      
      const userId = req.user.id;
      
      // Obter o ID do escopo da requisição
      const scopeId = getScopeId ? getScopeId(req) : null;
      
      if (scope !== 'global' && !scopeId) {
        return next(new ForbiddenError('ID do escopo não fornecido'));
      }
      
      // Buscar usuário com seus papéis
      const user = await userRepository.findById(userId);
      
      if (!user) {
        return next(new ForbiddenError('Usuário não encontrado'));
      }
      
      // Verificar se é admin (para compatibilidade)
      if (req.user.role === 'admin') {
        return next();
      }
      
      // Verificar papéis com escopo
      if (user.roles && user.roles.length > 0) {
        // Buscar todos os papéis do usuário
        const userRoles = await user.getRoles();
        
        // Verificar se o usuário tem o papel com o escopo correto
        for (const roleAssignment of userRoles.roles) {
          const role = roleAssignment.role;
          
          if (role && role.name === roleName && 
              roleAssignment.scope === scope &&
              (scope === 'global' || 
               (roleAssignment.scopeId && roleAssignment.scopeId.toString() === scopeId.toString()))) {
            return next();
          }
        }
      }
      
      // Registrar tentativa de acesso não autorizado
      logger.warn(`Acesso negado: usuário ${user.email} não tem o papel ${roleName} no escopo ${scope}:${scopeId}`);
      return next(new ForbiddenError('Permissão negada: papel com escopo não autorizado'));
    } catch (error) {
      logger.error(`Erro na verificação de papel com escopo: ${error.message}`);
      return next(new ForbiddenError('Erro ao verificar papéis'));
    }
  };
};

// Exportação dos middlewares
module.exports = {
  authorize,
  requirePermission,
  hasRole,
  hasScopedRole
};