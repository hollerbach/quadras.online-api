// src/domain/auth/use-cases/logout.use-case.js
const BaseAuthUseCase = require('./base-auth-use-case');

/**
 * Caso de uso para realizar logout (revogação de tokens)
 * Usa a classe base para reduzir duplicação
 */
class LogoutUseCase extends BaseAuthUseCase {
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
   * @param {string|null} accessToken Token de acesso (JWT)
   * @param {string|null} refreshToken Refresh token
   * @param {Object} user Informações do usuário (id, email)
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Resultado da operação
   */
  async execute(accessToken, refreshToken, user, ipAddress) {
    // Resultados das operações de revogação
    const results = {
      accessTokenBlacklisted: false,
      refreshTokenRevoked: false
    };

    // Invalidar access token se fornecido
    if (accessToken) {
      // Obter payload do token sem verificar assinatura
      const decoded = this.services.tokenService.decodeToken(accessToken);

      // Adicionar à blacklist pelo tempo restante de validade
      if (decoded && decoded.exp) {
        const timeToExpire = decoded.exp - Math.floor(Date.now() / 1000);
        await this.services.tokenService.blacklistToken(
          accessToken,
          'access',
          timeToExpire > 0 ? timeToExpire : 3600
        );
        results.accessTokenBlacklisted = true;
      }
    }

    // Revogar refresh token se fornecido
    if (refreshToken) {
      // Revogar refresh token
      await this.services.tokenService.revokeRefreshToken(refreshToken, ipAddress);
      results.refreshTokenRevoked = true;
    }

    // Registrar evento de logout
    if (user) {
      await this._logSecurityEvent('LOGOUT', user, ipAddress, results);
    }

    return {
      message: 'Logout realizado com sucesso',
      ...results
    };
  }
}

module.exports = LogoutUseCase;