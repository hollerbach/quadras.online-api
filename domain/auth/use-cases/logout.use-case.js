// src/domain/auth/use-cases/logout.use-case.js
const logger = require('../../../infrastructure/logging/logger');

/**
 * Caso de uso para realizar logout (revogação de tokens)
 */
class LogoutUseCase {
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
      const decoded = this.tokenService.decodeToken(accessToken);

      // Adicionar à blacklist pelo tempo restante de validade
      if (decoded && decoded.exp) {
        const timeToExpire = decoded.exp - Math.floor(Date.now() / 1000);
        await this.tokenService.blacklistToken(
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
      await this.tokenService.revokeRefreshToken(refreshToken, ipAddress);
      results.refreshTokenRevoked = true;
    }

    // Registrar na auditoria
    if (this.auditService && user) {
      await this.auditService.log({
        action: 'LOGOUT',
        userId: user.id,
        userEmail: user.email,
        ipAddress,
        details: results
      });
    }

    logger.info(`Logout realizado: ${user ? user.email : 'Usuário anônimo'} (${ipAddress})`);

    return {
      message: 'Logout realizado com sucesso',
      ...results
    };
  }
}

module.exports = LogoutUseCase;