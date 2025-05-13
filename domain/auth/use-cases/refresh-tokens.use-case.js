// src/domain/auth/use-cases/refresh-tokens.use-case.js
const BaseAuthUseCase = require('./base-auth-use-case');
const { UnauthorizedError } = require('../../../shared/errors/api-error');

/**
 * Caso de uso para atualizar tokens usando refresh token
 * Usa a classe base para reduzir duplicação
 */
class RefreshTokensUseCase extends BaseAuthUseCase {
  /**
   * @param {Object} tokenService Serviço de tokens
   * @param {Object} authService Serviço de autenticação
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(tokenService, authService, auditService = null) {
    super(
      {},
      { tokenService, authService, auditService }
    );
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
    const { accessToken, refreshToken: newRefreshToken } = await this.services.tokenService.refreshTokens(
      refreshToken,
      ipAddress
    );

    // Obter payload do token para registro de auditoria
    const decoded = this.services.tokenService.decodeToken(accessToken);
    
    // Registrar evento de atualização de tokens
    if (decoded && decoded.id) {
      await this._logSecurityEvent('TOKEN_REFRESH', 
        { id: decoded.id, email: decoded.email }, 
        ipAddress
      );
    }

    return {
      accessToken,
      refreshToken: newRefreshToken
    };
  }
}

module.exports = RefreshTokensUseCase;