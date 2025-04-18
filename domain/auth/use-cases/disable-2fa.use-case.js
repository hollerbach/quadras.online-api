// src/domain/auth/use-cases/disable-2fa.use-case.js
const logger = require('../../../infrastructure/logging/logger');
const { NotFoundError, UnauthorizedError } = require('../../../shared/errors/api-error');

/**
 * Caso de uso para desativar a autenticação de dois fatores
 */
class Disable2FAUseCase {
  /**
   * @param {Object} userRepository Repositório de usuários
   * @param {Object} twoFactorService Serviço de autenticação 2FA
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(userRepository, twoFactorService, auditService = null) {
    this.userRepository = userRepository;
    this.twoFactorService = twoFactorService;
    this.auditService = auditService;
  }

  /**
   * Executa o caso de uso
   * @param {string} userId ID do usuário
   * @param {string} token Token 2FA fornecido para confirmação
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Resultado da operação
   */
  async execute(userId, token, ipAddress) {
    // Buscar usuário
    const user = await this.userRepository.findById(userId);
    
    if (!user) {
      throw new NotFoundError('Usuário não encontrado');
    }

    if (!user.twoFactorEnabled) {
      return {
        success: false,
        message: '2FA já está desativado para este usuário'
      };
    }

    // Verificar token antes de desativar
    const verified = this.twoFactorService.verifyToken(user.twoFactorSecret, token);

    if (!verified) {
      // Registrar tentativa inválida
      if (this.auditService) {
        await this.auditService.log({
          action: '2FA_DISABLE_FAILED',
          userId: user.id,
          userEmail: user.email,
          ipAddress,
          details: { reason: 'Token inválido' }
        });
      }
      
      throw new UnauthorizedError('Código 2FA inválido');
    }

    // Desativar 2FA
    user.disable2FA();
    await this.userRepository.save(user);

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: '2FA_DISABLED',
        userId: user.id,
        userEmail: user.email,
        ipAddress,
        details: { success: true }
      });
    }

    logger.info(`2FA desativado com sucesso para usuário: ${user.email}`);
    
    return {
      success: true,
      message: '2FA desativado com sucesso'
    };
  }
}

module.exports = Disable2FAUseCase;