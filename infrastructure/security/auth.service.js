// src/infrastructure/security/auth.service.js
const tokenService = require('./token.service');
const permissionCache = require('../cache/permission-cache');
const { UnauthorizedError, ForbiddenError, TooManyRequestsError } = require('../../shared/errors/api-error');
const logger = require('../logging/logger');

/**
 * Serviço centralizado para autenticação e autorização
 * 
 * Este serviço encapsula toda lógica de:
 * - Validação de tokens
 * - Verificação de estado do usuário
 * - Verificação de permissões e papéis
 * - Lógica de blacklist de tokens
 */
class AuthService {
  constructor(userRepository, rbacRepository, auditService = null) {
    this.userRepository = userRepository;
    this.rbacRepository = rbacRepository;
    this.auditService = auditService;
  }

  /**
   * Verifica a autenticação a partir de um token JWT
   * Utiliza o tokenService centralizado para verificação
   * 
   * @param {string} token Token JWT a ser verificado
   * @param {Object} options Opções adicionais
   * @returns {Promise<Object>} Payload decodificado
   * @throws {UnauthorizedError} Se o token for inválido ou estiver na blacklist
   */
  async verifyToken(token, options = {}) {
    // Usa o tokenService centralizado para verificar o token
    return await tokenService.verifyAndDecodeToken(token, options);
  }

  /**
   * Verifica se um usuário existe e está em estado válido
   * Método centralizado para verificar ativa, verificada, não bloqueada
   * 
   * @param {string} userId ID do usuário
   * @param {Object} options Opções de verificação
   * @returns {Object} Usuário validado
   * @throws {UnauthorizedError|ForbiddenError} Se o usuário não estiver válido
   */
  async verifyUser(userId, options = {}) {
    const { 
      requireVerified = true, 
      requireActive = true, 
      checkLocked = true 
    } = options;

    // Buscar usuário
    const user = await this.userRepository.findById(userId);
    
    if (!user) {
      throw new UnauthorizedError('Usuário não encontrado');
    }

    // Verificar se a conta está ativa
    if (requireActive && !user.active) {
      throw new ForbiddenError('Conta desativada');
    }

    // Verificar se o email foi verificado
    if (requireVerified && !user.verified) {
      throw new ForbiddenError('Conta não verificada');
    }

    // Verificar se a conta está bloqueada
    if (checkLocked && user.isLocked()) {
      throw new TooManyRequestsError('Conta temporariamente bloqueada por excesso de tentativas', {
        lockUntil: user.lockUntil
      });
    }

    return user;
  }

  /**
   * Verifica credenciais de usuário (email/senha)
   * 
   * @param {string} email Email do usuário
   * @param {string} password Senha do usuário
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Object} Usuário autenticado
   * @throws {UnauthorizedError} Se as credenciais forem inválidas
   */
  async verifyCredentials(email, password, ipAddress) {
    // Buscar usuário por email
    const user = await this.userRepository.findByEmail(email);

    // Verificar se o usuário existe
    if (!user) {
      this._logFailedAttempt(null, email, ipAddress, 'Usuário não encontrado');
      throw new UnauthorizedError('Credenciais inválidas');
    }

    // Verificar se a conta está bloqueada
    if (user.isLocked()) {
      this._logFailedAttempt(user.id, email, ipAddress, 'Conta bloqueada');
      throw new TooManyRequestsError('Conta temporariamente bloqueada por excesso de tentativas', {
        lockUntil: user.lockUntil
      });
    }

    // Verificar senha
    const isPasswordValid = await this.userRepository.validatePassword(user.id, password);

    if (!isPasswordValid) {
      // Incrementar contador de falhas de login
      const updatedUser = await this.userRepository.incrementLoginAttempts(user.id);
      
      this._logFailedAttempt(user.id, email, ipAddress, 'Senha inválida', {
        attemptsRemaining: Math.max(0, 5 - updatedUser.loginAttempts),
        isLocked: updatedUser.isLocked()
      });
      
      throw new UnauthorizedError('Credenciais inválidas');
    }

    // Resetar contagem de tentativas após login bem-sucedido
    await this.userRepository.resetLoginAttempts(user.id);

    return user;
  }

  /**
   * Verifica se o usuário tem uma permissão específica
   * 
   * @param {string} userId ID do usuário
   * @param {string} permissionCode Código da permissão
   * @param {string|null} resourcePath Caminho do recurso (opcional)
   * @param {Object} options Opções adicionais
   * @returns {Promise<boolean>} Verdadeiro se o usuário tem a permissão
   */
  async hasPermission(userId, permissionCode, resourcePath = null, options = {}) {
    const { allowAdmin = true, useCache = true } = options;

    // Verificar no cache primeiro se estiver habilitado
    if (useCache) {
      const cacheKey = `user:${userId}:${permissionCode}:${resourcePath || 'global'}`;
      const cachedResult = permissionCache.get(cacheKey);
      
      if (cachedResult !== undefined) {
        return cachedResult;
      }
    }

    // Buscar usuário
    const user = await this.userRepository.findById(userId);
    
    if (!user) {
      if (useCache) {
        permissionCache.set(`user:${userId}:${permissionCode}:${resourcePath || 'global'}`, false);
      }
      return false;
    }

    // Verificação rápida para administradores (quando permitido)
    if (allowAdmin && user.role === 'admin') {
      if (useCache) {
        permissionCache.set(`user:${userId}:${permissionCode}:${resourcePath || 'global'}`, true);
      }
      return true;
    }

    // Verificar se o usuário tem um papel com esta permissão
    const hasPermission = await this.rbacRepository.userHasPermission(
      userId, permissionCode, resourcePath
    );

    // Armazenar no cache se habilitado
    if (useCache) {
      permissionCache.set(
        `user:${userId}:${permissionCode}:${resourcePath || 'global'}`, 
        hasPermission,
        300 // Cache por 5 minutos
      );
    }

    return hasPermission;
  }

  /**
   * Verifica se o usuário tem um papel específico
   * 
   * @param {string} userId ID do usuário
   * @param {string|Array} roleName Nome do papel ou array de nomes de papéis
   * @param {Object} options Opções adicionais
   * @returns {Promise<boolean>} Verdadeiro se o usuário tem o papel
   */
  async hasRole(userId, roleName, options = {}) {
    const { scope = 'global', scopeId = null, allowAdmin = true } = options;
    const roleNames = Array.isArray(roleName) ? roleName : [roleName];

    // Buscar usuário
    const user = await this.userRepository.findById(userId);
    
    if (!user) {
      return false;
    }

    // Verificação rápida para administradores (quando permitido)
    if (allowAdmin && user.role === 'admin') {
      return true;
    }

    // Para verificação de compatibilidade com o sistema antigo
    if (roleNames.includes(user.role)) {
      return true;
    }

    // Verificar papéis no novo sistema RBAC
    const userRoles = await this.rbacRepository.getUserRoles(userId);

    // Verificar se o usuário tem o papel no escopo correto
    return userRoles.some(roleAssignment => {
      // Verificar se o papel está na lista de papéis permitidos
      if (!roleNames.includes(roleAssignment.role?.name)) {
        return false;
      }

      // Se um escopo específico foi solicitado, verificar escopo
      if (scope === 'global') {
        return roleAssignment.scope === 'global';
      } else {
        return roleAssignment.scope === scope && 
               (!scopeId || roleAssignment.scopeId?.toString() === scopeId.toString());
      }
    });
  }

  /**
   * Verifica se o usuário tem qualquer uma das permissões especificadas
   * 
   * @param {string} userId ID do usuário
   * @param {Array} permissionCodes Array de códigos de permissão
   * @param {string|null} resourcePath Caminho do recurso (opcional)
   * @param {Object} options Opções adicionais
   * @returns {Promise<boolean>} Verdadeiro se o usuário tem pelo menos uma das permissões
   */
  async hasAnyPermission(userId, permissionCodes, resourcePath = null, options = {}) {
    // Verificação rápida para admin
    if (options.allowAdmin !== false) {
      const user = await this.userRepository.findById(userId);
      if (user && user.role === 'admin') {
        return true;
      }
    }

    // Verificar cada permissão
    for (const code of permissionCodes) {
      const hasPermission = await this.hasPermission(
        userId, code, resourcePath, { ...options, allowAdmin: false }
      );
      
      if (hasPermission) {
        return true;
      }
    }

    return false;
  }

  /**
   * Verifica se o usuário tem todas as permissões especificadas
   * 
   * @param {string} userId ID do usuário
   * @param {Array} permissionCodes Array de códigos de permissão
   * @param {string|null} resourcePath Caminho do recurso (opcional)
   * @param {Object} options Opções adicionais
   * @returns {Promise<boolean>} Verdadeiro se o usuário tem todas as permissões
   */
  async hasAllPermissions(userId, permissionCodes, resourcePath = null, options = {}) {
    // Verificação rápida para admin
    if (options.allowAdmin !== false) {
      const user = await this.userRepository.findById(userId);
      if (user && user.role === 'admin') {
        return true;
      }
    }

    // Verificar cada permissão
    for (const code of permissionCodes) {
      const hasPermission = await this.hasPermission(
        userId, code, resourcePath, { ...options, allowAdmin: false }
      );
      
      if (!hasPermission) {
        return false;
      }
    }

    return true;
  }

  /**
   * Verifica se o usuário é proprietário de um recurso
   * 
   * @param {string} userId ID do usuário
   * @param {string} resourceType Tipo do recurso
   * @param {string} resourceId ID do recurso
   * @returns {Promise<boolean>} Verdadeiro se o usuário é proprietário
   */
  async isResourceOwner(userId, resourceType, resourceId) {
    // Implementação estará integrada com os repositórios específicos do domínio
    switch (resourceType) {
      case 'product':
        // return await productRepository.isOwner(userId, resourceId);
        return false; // Implementação futura
      case 'order':
        // return await orderRepository.isOwner(userId, resourceId);
        return false; // Implementação futura
      default:
        return false;
    }
  }

  /**
   * Método para invalidar tokens de um usuário
   * 
   * @param {string} userId ID do usuário
   * @param {Object} options Opções adicionais
   * @returns {Promise<Object>} Resultado da operação
   */
  async invalidateUserTokens(userId, options = {}) {
    // Futura implementação para revogar todos os tokens de um usuário
    // Útil para casos de mudança de senha, desativação de conta, etc.
    return { success: true };
  }

  /**
   * Registra um evento de autenticação no serviço de auditoria
   * 
   * @param {string} action Ação a ser registrada
   * @param {Object} user Usuário associado ao evento
   * @param {string} ipAddress Endereço IP do solicitante
   * @param {Object} details Detalhes adicionais do evento
   */
  async logAuthEvent(action, user, ipAddress, details = {}) {
    if (this.auditService) {
      await this.auditService.log({
        action,
        userId: user.id,
        userEmail: user.email,
        ipAddress,
        details
      });
    }
    
    // Registrar no log do sistema também
    logger.info(`Auth: ${action} - ${user.email} (${ipAddress})`);
  }

  /**
   * Método privado para registrar tentativas de login falhas
   * 
   * @private
   * @param {string|null} userId ID do usuário (se disponível)
   * @param {string} email Email do usuário
   * @param {string} ipAddress Endereço IP do solicitante
   * @param {string} reason Motivo da falha
   * @param {Object} details Detalhes adicionais
   */
  async _logFailedAttempt(userId, email, ipAddress, reason, details = {}) {
    if (this.auditService) {
      await this.auditService.log({
        action: 'LOGIN_FAILED',
        userId,
        userEmail: email,
        ipAddress,
        details: { reason, ...details }
      });
    }
    
    logger.warn(`Tentativa de login falha: ${email} (${ipAddress}) - ${reason}`);
  }
}

// Exportar uma instância singleton com injeção de dependências
const userRepository = require('../database/mysql/repositories/user.repository');
const rbacRepository = require('../database/mysql/repositories/rbac.repository');

// Auditoria (opcional)
let auditService;
try {
  auditService = require('../logging/audit.service');
} catch (error) {
  logger.warn('Serviço de auditoria não disponível');
}

module.exports = new AuthService(userRepository, rbacRepository, auditService);