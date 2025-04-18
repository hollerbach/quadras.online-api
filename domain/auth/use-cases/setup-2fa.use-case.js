// src/domain/auth/use-cases/setup-2fa.use-case.js
const logger = require('../../../infrastructure/logging/logger');
const { NotFoundError } = require('../../../shared/errors/api-error');
const config = require('../../../infrastructure/config');

/**
 * Caso de uso para configurar a autenticação de dois fatores para um usuário
 */
class Setup2FAUseCase {
  /**
   * @param {Object} userRepository Repositório de usuários
   * @param {Object} twoFactorService Serviço de autenticação 2FA
   * @param {Object} mailService Serviço de e-mail
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(userRepository, twoFactorService, mailService, auditService = null) {
    this.userRepository = userRepository;
    this.twoFactorService = twoFactorService;
    this.mailService = mailService;
    this.auditService = auditService;
  }

  /**
   * Executa o caso de uso
   * @param {string} userId ID do usuário
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Informações de configuração 2FA
   */
  async execute(userId, ipAddress) {
    // Buscar usuário
    const user = await this.userRepository.findById(userId);
    
    if (!user) {
      throw new NotFoundError('Usuário não encontrado');
    }

    // Gerar segredo para 2FA
    const secret = this.twoFactorService.generateSecret(user.email);

    // Atualizar usuário com segredo 2FA
    user.enable2FA(secret.base32);
    await this.userRepository.save(user);

    // Gerar QR Code para configuração
    const qrCode = await this.twoFactorService.generateQRCode(secret.otpauth_url);

    // Gerar códigos de recuperação
    const recoveryCodes = this.twoFactorService.generateRecoveryCodes();

    // Salvar códigos de recuperação
    user.setRecoveryCodes(recoveryCodes);
    await this.userRepository.save(user);

    // Enviar códigos por email como backup
    await this.mailService.sendRecoveryCodes(user.email, recoveryCodes);

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: '2FA_SETUP',
        userId: user.id,
        userEmail: user.email,
        ipAddress,
        details: { 
          recoveryCodes: recoveryCodes.length,
          secretProvided: config.app.env === 'development'
        }
      });
    }

    logger.info(`2FA configurado com sucesso para usuário: ${user.email}`);
    
    // Retornar informações de configuração
    return {
      qrCode,
      recoveryCodes,
      // Apenas em desenvolvimento para facilitar testes
      secret: config.app.env === 'development' ? secret.base32 : undefined
    };
  }
}

module.exports = Setup2FAUseCase;