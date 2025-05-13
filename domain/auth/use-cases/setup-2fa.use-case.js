// src/domain/auth/use-cases/setup-2fa.use-case.js
const BaseAuthUseCase = require('./base-auth-use-case');
const { NotFoundError } = require('../../../shared/errors/api-error');
const config = require('../../../infrastructure/config');

/**
 * Caso de uso para configurar a autenticação de dois fatores para um usuário
 * Usa a classe base para reduzir duplicação
 */
class Setup2FAUseCase extends BaseAuthUseCase {
  /**
   * @param {Object} userRepository Repositório de usuários
   * @param {Object} twoFactorService Serviço de autenticação 2FA
   * @param {Object} mailService Serviço de e-mail
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(userRepository, twoFactorService, mailService, authService, auditService = null) {
    super(
      { userRepository },
      { twoFactorService, mailService, authService, auditService }
    );
  }

  /**
   * Executa o caso de uso
   * @param {string} userId ID do usuário
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Informações de configuração 2FA
   */
  async execute(userId, ipAddress) {
    // Buscar usuário usando o método da classe base
    const user = await this._verifyUserExists(userId);

    // Gerar segredo para 2FA
    const secret = this.services.twoFactorService.generateSecret(user.email);

    // Atualizar usuário com segredo 2FA
    user.enable2FA(secret.base32);
    await this.repositories.userRepository.save(user);

    // Gerar QR Code para configuração
    const qrCode = await this.services.twoFactorService.generateQRCode(secret.otpauth_url);

    // Gerar códigos de recuperação
    const recoveryCodes = this.services.twoFactorService.generateRecoveryCodes();

    // Salvar códigos de recuperação
    user.setRecoveryCodes(recoveryCodes);
    await this.repositories.userRepository.save(user);

    // Enviar códigos por email como backup
    await this.services.mailService.sendRecoveryCodes(user.email, recoveryCodes);

    // Registrar evento de configuração 2FA
    await this._logSecurityEvent('2FA_SETUP', user, ipAddress, { 
      recoveryCodes: recoveryCodes.length,
      secretProvided: config.app.env === 'development'
    });
    
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