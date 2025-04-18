// src/domain/auth/use-cases/request-password-reset.use-case.js
const crypto = require('crypto');
const logger = require('../../../infrastructure/logging/logger');
const config = require('../../../infrastructure/config');

/**
 * Caso de uso para solicitar redefinição de senha
 */
class RequestPasswordResetUseCase {
  /**
   * @param {Object} userRepository Repositório de usuários
   * @param {Object} mailService Serviço de e-mail
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(userRepository, mailService, auditService = null) {
    this.userRepository = userRepository;
    this.mailService = mailService;
    this.auditService = auditService;
  }

  /**
   * Executa o caso de uso
   * @param {string} email Email do usuário
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Resultado da operação
   */
  async execute(email, ipAddress) {
    // Buscar usuário pelo email
    const user = await this.userRepository.findByEmail(email);

    // Se o usuário não existe, retornar mensagem genérica
    // para não revelar se o email está cadastrado (segurança)
    if (!user) {
      logger.info(`Solicitação de redefinição de senha para email não cadastrado: ${email}`);
      return {
        success: true,
        message: 'Instruções de redefinição enviadas para o e-mail, se estiver cadastrado'
      };
    }

    // Gerar token de redefinição
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + config.auth.password.resetTokenExpiry);

    // Salvar token no usuário
    user.resetToken = resetToken;
    user.resetTokenExpires = resetTokenExpires;
    await this.userRepository.save(user);

    // Enviar e-mail com token
    await this.mailService.sendResetPasswordEmail(email, resetToken);

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: 'PASSWORD_RESET_REQUEST',
        userId: user.id,
        userEmail: email,
        ipAddress,
        details: { 
          tokenExpiry: resetTokenExpires 
        }
      });
    }

    logger.info(`Solicitação de redefinição de senha enviada para: ${email}`);
    
    return {
      success: true,
      message: 'Instruções de redefinição enviadas para o e-mail, se estiver cadastrado'
    };
  }
}

module.exports = RequestPasswordResetUseCase;