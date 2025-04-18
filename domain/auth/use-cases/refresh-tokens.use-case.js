// src/domain/auth/use-cases/refresh-tokens.use-case.js
const logger = require('../../../infrastructure/logging/logger');
const { UnauthorizedError } = require('../../../shared/errors/api-error');

/**
 * Caso de uso para atualizar tokens usando refresh token
 */
class RefreshTokensUseCase {
  /**
   * @param {Object} tokenService Serviço de tokens
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(tokenService, auditService = null) {
    this.tokenService = tokenService;
    this.auditService = auditService;
  }

  /**
   * Executa o caso de uso
   * @param {string} refreshToken Refresh token a ser utilizado
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Novos tokens
   */
  async execute(refreshToken, ipAddress) {
    if (!refreshToken) {
      throw new UnauthorizedError('Refresh token é obrigatório');
    }

    // Gerar novos tokens
    const { accessToken, refreshToken: newRefreshToken } = await this.tokenService.refreshTokens(
      refreshToken,
      ipAddress
    );

    // Obter payload do token para registro de auditoria
    const decoded = this.tokenService.decodeToken(accessToken);
    
    // Registrar na auditoria, se disponível
    if (this.auditService && decoded && decoded.id) {
      await this.auditService.log({
        action: 'TOKEN_REFRESH',
        userId: decoded.id,
        userEmail: decoded.email,
        ipAddress
      });
    }

    return {
      accessToken,
      refreshToken: newRefreshToken
    };
  }
}

module.exports = RefreshTokensUseCase;