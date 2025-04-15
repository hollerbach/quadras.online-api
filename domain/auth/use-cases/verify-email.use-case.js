// src/domain/auth/use-cases/verify-email.use-case.js
const logger = require('../../../infrastructure/logging/logger');
const { NotFoundError, BadRequestError } = require('../../../shared/errors/api-error');

/**
 * Caso de uso para verificar o e-mail do usuário
 */
class VerifyEmailUseCase {
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
   * @param {string} token Token de verificação
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Resultado da verificação
   */
  async execute(token, ipAddress) {
    // Buscar usuário pelo token de verificação
    const user = await this.userRepository.findByVerifyToken(token);
    
    if (!user) {
      throw new BadRequestError('Token de verificação inválido ou expirado');
    }

    // Verificar e-mail do usuário
    user.verifyEmail();
    
    // Salvar alterações
    await this.userRepository.save(user);

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: 'EMAIL_VERIFIED',
        userId: user.id,
        userEmail: user.email,
        ipAddress
      });
    }

    logger.info(`Email verificado com sucesso: ${user.email}`);
    
    return { 
      message: 'Email verificado com sucesso',
      email: user.email 
    };
  }
}

module.exports = VerifyEmailUseCase;