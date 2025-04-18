// src/domain/auth/use-cases/verify-2fa.use-case.js
const { UnauthorizedError, BadRequestError } = require('../../../shared/errors/api-error');
const logger = require('../../../infrastructure/logging/logger');

/**
 * Caso de uso para verificar token 2FA durante login
 */
class Verify2FAUseCase {
  /**
   * @param {Object} userRepository Repositório de usuários
   * @param {Object} tokenService Serviço de tokens
   * @param {Object} twoFactorService Serviço de autenticação 2FA
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(userRepository, tokenService, twoFactorService, auditService = null) {
    this.userRepository = userRepository;
    this.tokenService = tokenService;
    this.twoFactorService = twoFactorService;
    this.auditService = auditService;
  }

  /**
   * Executa o caso de uso
   * @param {string} token Token 2FA (código TOTP)
   * @param {string} tempToken Token temporário recebido no login parcial
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Tokens de acesso e usuário
   */
  async execute(token, tempToken, ipAddress) {
    // Verificar e decodificar o token temporário
    let decoded;
    try {
      decoded = this.tokenService.verifyAccessToken(tempToken);
    } catch (error) {
      throw new BadRequestError('Token temporário inválido ou expirado');
    }

    if (!decoded || !decoded.is2FA) {
      throw new BadRequestError('Token temporário inválido para fluxo 2FA');
    }

    const user = await this.userRepository.findById(decoded.id);

    if (!user) {
      throw new BadRequestError('Usuário não encontrado');
    }

    if (!user.twoFactorEnabled) {
      throw new BadRequestError('2FA não está habilitado para este usuário');
    }

    // Verificar o token TOTP
    const verified = this.twoFactorService.verifyToken(user.twoFactorSecret, token);

    if (!verified) {
      // Registrar falha na auditoria
      if (this.auditService) {
        await this.auditService.log({
          action: 'LOGIN_2FA_FAILED',
          userId: user.id,
          userEmail: user.email,
          ipAddress
        });
      }
      
      throw new UnauthorizedError('Código 2FA inválido');
    }

    // Gerar tokens para usuário autenticado com 2FA
    const accessToken = this.tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await this.tokenService.generateRefreshToken(user, ipAddress);

    // Registrar na auditoria
    if (this.auditService) {
      await this.auditService.log({
        action: 'LOGIN_2FA_SUCCESS',
        userId: user.id,
        userEmail: user.email,
        ipAddress
      });
    }

    logger.info(`Login 2FA bem-sucedido: ${user.email} (${ipAddress})`);

    return {
      accessToken,
      refreshToken: refreshToken.token,
      user: user.toSafeObject()
    };
  }
}

module.exports = Verify2FAUseCase;