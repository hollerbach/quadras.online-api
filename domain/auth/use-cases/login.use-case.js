// src/domain/auth/use-cases/login.use-case.js
const logger = require('../../../infrastructure/logging/logger');
const { UnauthorizedError, TooManyRequestsError } = require('../../../shared/errors/api-error');

/**
 * Caso de uso para autenticação de usuário (login)
 */
class LoginUseCase {
  /**
   * @param {Object} userRepository Repositório de usuários
   * @param {Object} tokenService Serviço de tokens
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(userRepository, tokenService, auditService = null) {
    this.userRepository = userRepository;
    this.tokenService = tokenService;
    this.auditService = auditService;
  }

  /**
   * Executa o caso de uso
   * @param {string} email Email do usuário
   * @param {string} password Senha do usuário
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Tokens e informações do usuário ou token temporário para 2FA
   */
  async execute(email, password, ipAddress) {
    // Buscar usuário por email
    const user = await this.userRepository.findByEmail(email);

    // Verificar se o usuário existe e se está verificado
    if (!user || !user.verified) {
      if (this.auditService && user) {
        await this.auditService.log({
          action: 'LOGIN_FAILED',
          userId: user.id,
          userEmail: email,
          ipAddress,
          details: { reason: 'Conta não verificada' }
        });
      }

      // Não revelar se o usuário existe, apenas retornar erro genérico
      throw new UnauthorizedError('Credenciais inválidas');
    }

    // Verificar se a conta está bloqueada
    if (user.isLocked()) {
      await this.auditService?.log({
        action: 'LOGIN_FAILED',
        userId: user.id,
        userEmail: email,
        ipAddress,
        details: { reason: 'Conta bloqueada' }
      });

      throw new TooManyRequestsError('Conta temporariamente bloqueada por excesso de tentativas. Tente novamente mais tarde.', {
        lockUntil: user.lockUntil
      });
    }

    // Verificar senha
    const isPasswordValid = await this.userRepository.validatePassword(user.id, password);

    if (!isPasswordValid) {
      // Incrementar contador de falhas de login
      const updatedUser = await this.userRepository.incrementLoginAttempts(user.id);

      await this.auditService?.log({
        action: 'LOGIN_FAILED',
        userId: user.id,
        userEmail: email,
        ipAddress,
        details: {
          reason: 'Senha inválida',
          attemptsRemaining: Math.max(0, 5 - updatedUser.loginAttempts),
          isLocked: updatedUser.isLocked()
        }
      });

      throw new UnauthorizedError('Credenciais inválidas');
    }

    // Resetar contagem de tentativas após login bem-sucedido
    await this.userRepository.resetLoginAttempts(user.id);

    // Verificar se 2FA está ativado
    if (user.twoFactorEnabled) {
      const tempToken = this.tokenService.generateTempToken({ id: user.id, email: user.email });

      await this.auditService?.log({
        action: 'LOGIN_2FA_REQUIRED',
        userId: user.id,
        userEmail: email,
        ipAddress,
        details: { success: true }
      });

      return {
        requires2FA: true,
        message: '2FA necessário',
        tempToken
      };
    }

    // Gerar tokens para usuário autenticado
    const accessToken = this.tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await this.tokenService.generateRefreshToken(user, ipAddress);

    // Registrar na auditoria
    await this.auditService?.log({
      action: 'LOGIN',
      userId: user.id,
      userEmail: user.email,
      ipAddress,
      details: { user2FA: user.twoFactorEnabled }
    });

    logger.info(`Login bem-sucedido: ${user.email} (${ipAddress})`);

    return {
      accessToken,
      refreshToken: refreshToken.token,
      user: user.toSafeObject()
    };
  }
}

module.exports = LoginUseCase;