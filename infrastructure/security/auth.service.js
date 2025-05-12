// src/infrastructure/security/auth.service.js
const tokenService = require('./token.service');
const { UnauthorizedError, ForbiddenError, TooManyRequestsError } = require('../../shared/errors/api-error');
const logger = require('../logging/logger');

class AuthService {
  constructor(userRepository, auditService) {
    this.userRepository = userRepository;
    this.auditService = auditService;
  }

  /**
   * Verifica se um token é válido e não está na blacklist
   * @param {string} token Token JWT a ser verificado
   * @returns {Object} Payload decodificado
   * @throws {UnauthorizedError} Se o token for inválido ou estiver na blacklist
   */
  async verifyToken(token) {
    if (!token) {
      throw new UnauthorizedError('Token não fornecido');
    }

    // Verificar se o token está na blacklist
    const isBlacklisted = await tokenService.isTokenBlacklisted(token);
    if (isBlacklisted) {
      throw new UnauthorizedError('Token revogado ou expirado');
    }

    // Verificar e decodificar o token
    try {
      return tokenService.verifyAccessToken(token);
    } catch (error) {
      throw new UnauthorizedError('Token inválido ou expirado');
    }
  }

  /**
   * Verifica se um usuário existe e está em estado válido
   * @param {string} userId ID do usuário
   * @param {object} options Opções de verificação
   * @returns {Object} Usuário validado
   * @throws {UnauthorizedError|ForbiddenError} Se o usuário não for encontrado ou estiver inativo
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
   * Verifica credenciais de usuário
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
   * Método privado para registrar tentativas de login falhas
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

module.exports = new AuthService(
  require('../database/mongodb/repositories/user.repository'),
  require('../logging/audit.service')
);