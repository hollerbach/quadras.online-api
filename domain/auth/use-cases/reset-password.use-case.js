// src/domain/auth/use-cases/reset-password.use-case.js
const logger = require('../../../infrastructure/logging/logger');
const { BadRequestError } = require('../../../shared/errors/api-error');

/**
 * Caso de uso para redefinir a senha do usuário usando token
 */
class ResetPasswordUseCase {
  /**
   * @param {Object} userRepository Repositório de usuários
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(userRepository, auditService = null) {
    this.userRepository = userRepository;
    this.auditService = auditService;
  }

  /**
   * Executa o caso de uso
   * @param {string} token Token de redefinição de senha
   * @param {string} newPassword Nova senha
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Resultado da operação
   */
  async execute(token, newPassword, ipAddress) {
    // Buscar usuário com token válido
    const user = await this.userRepository.findByResetToken(token);

    if (!user) {
      throw new BadRequestError('Token inválido ou expirado');
    }

    // Atualizar senha
    user.password = newPassword; // o hash será feito no repositório
    user.resetToken = null;
    user.resetTokenExpires = null;

    await this.userRepository.save(user);

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: 'PASSWORD_RESET_COMPLETE',
        userId: user.id,
        userEmail: user.email,
        ipAddress,
        details: { 
          resetSuccessful: true
        }
      });
    }

    logger.info(`Senha redefinida com sucesso para usuário: ${user.email}`);
    
    return {
      success: true,
      message: 'Senha redefinida com sucesso'
    };
  }
}

module.exports = ResetPasswordUseCase;