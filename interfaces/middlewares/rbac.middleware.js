// src/interfaces/api/middlewares/rbac.middleware.js
const { ForbiddenError } = require('../../shared/errors/api-error');
const authService = require('../../infrastructure/security/auth.service');
const logger = require('../../infrastructure/logging/logger');
const { asyncHandler } = require('./error.middleware');

/**
 * Middleware para verificação de papéis e permissões
 * Centraliza toda a lógica de autorização RBAC
 * Utiliza o serviço centralizado de autenticação
 */
class RbacMiddleware {
  /**
   * Middleware para autorização baseada em papel clássico
   * @param {string[]|string} roles Array de papéis permitidos
   * @returns {Function} Middleware de autorização
   */
  authorize(roles = []) {
    if (typeof roles === 'string') {
      roles = [roles];
    }
    
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return next(new ForbiddenError('Usuário não autenticado'));
      }
      
      // Usar serviço centralizado para verificar papéis
      const hasRole = await authService.hasRole(req.user.id, roles);
      
      if (!hasRole) {
        this._logAccessDenied(req, 'Papel não autorizado', { 
          requiredRoles: roles 
        });
        return next(new ForbiddenError('Permissão negada: papel não autorizado'));
      }
      
      next();
    });
  }

  /**
   * Middleware para autorização baseada em permissão (RBAC)
   * @param {string} permissionCode Código da permissão requerida
   * @param {Object} options Opções adicionais
   * @returns {Function} Middleware de autorização
   */
  requirePermission(permissionCode, options = {}) {
    const { resourcePath = null, allowAdmin = true } = options;

    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return next(new ForbiddenError('Usuário não autenticado'));
      }

      const userId = req.user.id;

      // Usar serviço centralizado para verificar permissão
      const hasPermission = await authService.hasPermission(
        userId, 
        permissionCode,
        this._resolveResourcePath(resourcePath, req),
        { allowAdmin }
      );
      
      if (hasPermission) {
        return next();
      }

      // Registrar tentativa de acesso não autorizado
      this._logAccessDenied(req, 'Permissão negada', {
        permissionCode,
        resourcePath
      });
      
      return next(new ForbiddenError('Permissão negada para este recurso'));
    });
  }

  /**
   * Middleware para verificar se o usuário tem pelo menos um dos papéis especificados
   * @param {Array|string} roles Array de papéis ou nome do papel
   * @returns {Function} Middleware de autorização
   */
  hasRole(roles) {
    if (typeof roles === 'string') {
      roles = [roles];
    }
    
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return next(new ForbiddenError('Usuário não autenticado'));
      }
      
      // Usar serviço centralizado para verificar papéis
      const hasRequiredRole = await authService.hasRole(req.user.id, roles);
      
      if (hasRequiredRole) {
        return next();
      }
      
      // Registrar tentativa de acesso não autorizado
      this._logAccessDenied(req, 'Papel não autorizado', {
        requiredRoles: roles
      });
      
      return next(new ForbiddenError('Permissão negada: papel não autorizado'));
    });
  }

  /**
   * Middleware para verificar se o usuário tem um papel específico com escopo específico
   * @param {string} roleName Nome do papel
   * @param {string} scope Escopo do papel ('global', 'store', 'department')
   * @param {Function|string} scopeIdResolver Função para extrair o ID do escopo da requisição ou caminho de parâmetro
   * @returns {Function} Middleware de autorização
   */
  hasScopedRole(roleName, scope, scopeIdResolver) {
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return next(new ForbiddenError('Usuário não autenticado'));
      }
      
      // Obter o ID do escopo da requisição
      const scopeId = this._resolveScopeId(scopeIdResolver, req);
      
      if (scope !== 'global' && !scopeId) {
        return next(new ForbiddenError('ID do escopo não fornecido'));
      }
      
      // Usar serviço centralizado para verificar papel com escopo
      const hasScopedRole = await authService.hasRole(
        req.user.id, 
        roleName, 
        { scope, scopeId }
      );
      
      if (hasScopedRole) {
        return next();
      }
      
      // Registrar tentativa de acesso não autorizado
      this._logAccessDenied(req, 'Papel com escopo não autorizado', {
        roleName,
        scope,
        scopeId
      });
      
      return next(new ForbiddenError('Permissão negada: papel com escopo não autorizado'));
    });
  }

  /**
   * Middleware para avaliar uma política de acesso complexa
   * @param {Function} policyFn Função que avalia a política de acesso
   * @returns {Function} Middleware de autorização
   */
  checkPolicy(policyFn) {
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return next(new ForbiddenError('Usuário não autenticado'));
      }
      
      // Avaliação de política personalizada
      // Esta função permite criar regras complexas que não se encaixam
      // nos middlewares padrão
      const result = await policyFn(req, req.user);
      
      if (result.allowed) {
        return next();
      }
      
      // Registrar tentativa de acesso não autorizado
      this._logAccessDenied(req, result.reason || 'Política de acesso negou permissão', {
        policy: policyFn.name || 'anonymous',
        details: result.details
      });
      
      return next(new ForbiddenError(result.message || 'Permissão negada pela política de acesso'));
    });
  }

  /**
   * Middleware para verificar se o usuário tem todas as permissões especificadas
   * @param {Array|string} permissionCodes Array de códigos de permissão ou código único
   * @param {Object} options Opções adicionais
   * @returns {Function} Middleware de autorização
   */
  requireAllPermissions(permissionCodes, options = {}) {
    if (typeof permissionCodes === 'string') {
      permissionCodes = [permissionCodes];
    }
    
    const { resourcePath = null, allowAdmin = true } = options;
    
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return next(new ForbiddenError('Usuário não autenticado'));
      }
      
      // Usar serviço centralizado para verificar todas as permissões
      const hasAllPermissions = await authService.hasAllPermissions(
        req.user.id,
        permissionCodes,
        this._resolveResourcePath(resourcePath, req),
        { allowAdmin }
      );
      
      if (hasAllPermissions) {
        return next();
      }
      
      // Registrar tentativa de acesso não autorizado
      this._logAccessDenied(req, 'Permissões necessárias não atendidas', {
        requiredPermissions: permissionCodes,
        resourcePath: this._resolveResourcePath(resourcePath, req)
      });
      
      return next(new ForbiddenError('Permissão negada: faltam permissões necessárias'));
    });
  }

  /**
   * Middleware para verificar se o usuário tem pelo menos uma das permissões especificadas
   * @param {Array} permissionCodes Array de códigos de permissão
   * @param {Object} options Opções adicionais
   * @returns {Function} Middleware de autorização
   */
  requireAnyPermission(permissionCodes, options = {}) {
    const { resourcePath = null, allowAdmin = true } = options;
    
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return next(new ForbiddenError('Usuário não autenticado'));
      }
      
      // Usar serviço centralizado para verificar qualquer permissão
      const hasAnyPermission = await authService.hasAnyPermission(
        req.user.id,
        permissionCodes,
        this._resolveResourcePath(resourcePath, req),
        { allowAdmin }
      );
      
      if (hasAnyPermission) {
        return next();
      }
      
      // Registrar tentativa de acesso não autorizado
      this._logAccessDenied(req, 'Nenhuma permissão atendida', {
        requiredAnyOf: permissionCodes,
        resourcePath: this._resolveResourcePath(resourcePath, req)
      });
      
      return next(new ForbiddenError('Permissão negada: nenhuma permissão suficiente'));
    });
  }

  /**
   * Middleware para verificar ownership de um recurso
   * @param {Function|string} resourceIdResolver Função para extrair o ID do recurso ou caminho de parâmetro
   * @param {string} resourceType Tipo do recurso
   * @param {Object} options Opções adicionais
   * @returns {Function} Middleware de autorização
   */
  checkOwnership(resourceIdResolver, resourceType, options = {}) {
    const { 
      allowAdmin = true, 
      bypassPermission = null 
    } = options;
    
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return next(new ForbiddenError('Usuário não autenticado'));
      }
      
      const userId = req.user.id;
      
      // Verificar se é admin (quando permitido)
      if (allowAdmin && req.user.role === 'admin') {
        return next();
      }
      
      // Verificar permissão de bypass, se definida
      if (bypassPermission) {
        const hasPermission = await authService.hasPermission(
          userId, 
          bypassPermission
        );
        
        if (hasPermission) {
          return next();
        }
      }
      
      // Obter o ID do recurso
      const resourceId = this._resolveResourceId(resourceIdResolver, req);
      
      if (!resourceId) {
        return next(new ForbiddenError('ID do recurso não fornecido'));
      }
      
      // Verificar ownership usando o serviço centralizado
      const isOwner = await authService.isResourceOwner(userId, resourceType, resourceId);
      
      if (isOwner) {
        return next();
      }
      
      // Registrar tentativa de acesso não autorizado
      this._logAccessDenied(req, 'Usuário não é proprietário do recurso', {
        resourceId,
        resourceType,
        bypassPermission
      });
      
      return next(new ForbiddenError('Permissão negada: você não é o proprietário deste recurso'));
    });
  }

  /**
   * Extrai o ID do recurso da requisição
   * @private
   * @param {Function|string} resolver Função ou caminho de parâmetro
   * @param {Request} req Objeto de requisição Express
   * @returns {string|null} ID do recurso ou null
   */
  _resolveResourceId(resolver, req) {
    if (typeof resolver === 'function') {
      return resolver(req);
    } else if (typeof resolver === 'string') {
      return req.params[resolver];
    }
    
    return null;
  }

  /**
   * Extrai o ID do escopo da requisição
   * @private
   * @param {Function|string} resolver Função ou caminho de parâmetro
   * @param {Request} req Objeto de requisição Express
   * @returns {string|null} ID do escopo ou null
   */
  _resolveScopeId(resolver, req) {
    if (typeof resolver === 'function') {
      return resolver(req);
    } else if (typeof resolver === 'string') {
      return req.params[resolver];
    }
    
    return null;
  }

  /**
   * Resolve o caminho do recurso, substituindo parâmetros
   * @private
   * @param {string|null} resourcePath Caminho do recurso com placeholders
   * @param {Request} req Objeto de requisição Express
   * @returns {string|null} Caminho resolvido ou null
   */
  _resolveResourcePath(resourcePath, req) {
    if (!resourcePath) return null;
    
    // Substituir parâmetros no caminho (ex: /api/resources/:id)
    return resourcePath.replace(/:(\w+)/g, (match, paramName) => {
      return req.params[paramName] || match;
    });
  }

  /**
   * Registra uma tentativa de acesso negada
   * @private
   * @param {Request} req Objeto de requisição Express
   * @param {string} reason Motivo da negação
   * @param {Object} details Detalhes adicionais
   */
  _logAccessDenied(req, reason, details = {}) {
    logger.warn(`Acesso negado: ${req.user.email} - ${reason}`, {
      userId: req.user.id,
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      details
    });
    
    // Log no serviço de auditoria se necessário
    try {
      authService.logAuthEvent('ACCESS_DENIED', req.user, req.ip, {
        reason,
        ...details,
        path: req.originalUrl,
        method: req.method
      });
    } catch (error) {
      // Ignorar erros no log de auditoria para não interromper o fluxo
      logger.error(`Erro ao registrar auditoria de acesso negado: ${error.message}`);
    }
  }
}

// Criar instância singleton
const rbacMiddleware = new RbacMiddleware();

// Exportar métodos individualmente para compatibilidade com código existente
module.exports = {
  authorize: rbacMiddleware.authorize.bind(rbacMiddleware),
  requirePermission: rbacMiddleware.requirePermission.bind(rbacMiddleware),
  hasRole: rbacMiddleware.hasRole.bind(rbacMiddleware),
  hasScopedRole: rbacMiddleware.hasScopedRole.bind(rbacMiddleware),
  checkPolicy: rbacMiddleware.checkPolicy.bind(rbacMiddleware),
  requireAllPermissions: rbacMiddleware.requireAllPermissions.bind(rbacMiddleware),
  requireAnyPermission: rbacMiddleware.requireAnyPermission.bind(rbacMiddleware),
  checkOwnership: rbacMiddleware.checkOwnership.bind(rbacMiddleware),
  
  // Exportar a instância completa também para uso avançado
  rbacMiddleware
};