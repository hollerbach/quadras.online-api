// src/domain/auth/use-cases/verify-2fa.use-case.js
const BaseAuthUseCase = require('./base-auth-use-case');
const { UnauthorizedError, BadRequestError } = require('../../../shared/errors/api-error');

/**
 * Caso de uso para verificar token 2FA durante login
 * Usa a classe base para reduzir duplicação
 */
class Verify2FAUseCase extends BaseAuthUseCase {
  /**
   * @param {Object} userRepository Repositório de usuários
   * @param {Object} tokenService Serviço de tokens
   * @param {Object} twoFactorService Serviço de autenticação 2FA
   * @param {Object} authService Serviço de autenticação
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(userRepository, tokenService, twoFactorService, authService, auditService = null) {
    super(
      { userRepository },
      { tokenService, twoFactorService, authService, auditService }
    );
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
      decoded = this.services.tokenService.verifyAccessToken(tempToken);
    } catch (error) {
      throw new BadRequestError('Token temporário inválido ou expirado');
    }

    if (!decoded || !decoded.is2FA) {
      throw new BadRequestError('Token temporário inválido para fluxo 2FA');
    }

    // Verificar usuário usando o método da classe base
    const user = await this._verifyUserExists(decoded.id);

    if (!user.twoFactorEnabled) {
      throw new BadRequestError('2FA não está habilitado para este usuário');
    }

    // Verificar o token TOTP
    const verified = this.services.twoFactorService.verifyToken(user.twoFactorSecret, token);

    if (!verified) {
      // Registrar falha na auditoria
      await this._logAuditEvent('LOGIN_2FA_FAILED', user, ipAddress);
      
      throw new UnauthorizedError('Código 2FA inválido');
    }

    // Gerar tokens para usuário autenticado com 2FA
    const accessToken = this.services.tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await this.services.tokenService.generateRefreshToken(user, ipAddress);

    // Registrar na auditoria
    await this._logAuditEvent('LOGIN_2FA_SUCCESS', user, ipAddress);

    return {
      accessToken,
      refreshToken: refreshToken.token,
      user: user.toSafeObject()
    };
  }
}

module.exports = Verify2FAUseCase;