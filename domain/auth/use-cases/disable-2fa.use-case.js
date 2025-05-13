// src/domain/auth/use-cases/disable-2fa.use-case.js
const BaseAuthUseCase = require('./base-auth-use-case');
const { NotFoundError, UnauthorizedError } = require('../../../shared/errors/api-error');

/**
 * Caso de uso para desativar a autenticação de dois fatores
 * Usa a classe base para reduzir duplicação
 */
class Disable2FAUseCase extends BaseAuthUseCase {
  /**
   * @param {Object} userRepository Repositório de usuários
   * @param {Object} twoFactorService Serviço de autenticação 2FA
   * @param {Object} authService Serviço de autenticação
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(userRepository, twoFactorService, authService, auditService = null) {
    super(
      { userRepository },
      { twoFactorService, authService, auditService }
    );
  }

  /**
   * Executa o caso de uso
   * @param {string} userId ID do usuário
   * @param {string} token Token 2FA fornecido para confirmação
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Resultado da operação
   */
  async execute(userId, token, ipAddress) {
    // Buscar usuário usando o método da classe base
    const user = await this._verifyUserExists(userId);
    
    if (!user.twoFactorEnabled) {
      return {
        success: false,
        message: '2FA já está desativado para este usuário'
      };
    }

    // Verificar token antes de desativar
    const verified = this.services.twoFactorService.verifyToken(user.twoFactorSecret, token);

    if (!verified) {
      // Registrar tentativa inválida
      await this._logSecurityEvent('2FA_DISABLE_FAILED', user, ipAddress, { 
        reason: 'Token inválido',
        success: false
      });
      
      throw new UnauthorizedError('Código 2FA inválido');
    }

    // Desativar 2FA
    user.disable2FA();
    await this.repositories.userRepository.save(user);

    // Registrar evento de desativação 2FA
    await this._logSecurityEvent('2FA_DISABLED', user, ipAddress, { success: true });
    
    return {
      success: true,
      message: '2FA desativado com sucesso'
    };
  }
}

module.exports = Disable2FAUseCase;