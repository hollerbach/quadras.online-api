// src/domain/auth/use-cases/register-user.use-case.js
const crypto = require('crypto');
const logger = require('../../../infrastructure/logging/logger');
const { ConflictError } = require('../../../shared/errors/api-error');
const config = require('../../../infrastructure/config');

/**
 * Caso de uso para registrar um novo usuário
 */
class RegisterUserUseCase {
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
   * @param {Object} userData Dados do usuário a ser registrado
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Usuário registrado e token de verificação
   */
  async execute(userData, ipAddress) {
    const { email, password, role = 'user', enable2FA = false } = userData;

    // Verificar se o e-mail já está em uso
    const existingUser = await this.userRepository.findByEmail(email);
    if (existingUser) {
      throw new ConflictError('Email já está em uso');
    }

    // Gerar token de verificação
    const verifyToken = crypto.randomBytes(32).toString('hex');
    const verifyTokenExpires = new Date(Date.now() + config.auth.verification.tokenExpiry);

    // Criar o usuário
    const user = await this.userRepository.create({
      email,
      password,
      role,
      verified: false,
      verifyToken,
      verifyTokenExpires,
      twoFactorEnabled: enable2FA
    });

    // Enviar e-mail de verificação
    await this.mailService.sendVerificationEmail(email, verifyToken);

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: 'REGISTER',
        userEmail: email,
        ipAddress,
        details: { role, enable2FA }
      });
    }

    logger.info(`Novo usuário registrado: ${email}`);
    
    // Retornar usuário (sem senha e outros dados sensíveis)
    return {
      user: user.toSafeObject(),
      verifyToken: process.env.NODE_ENV === 'development' ? verifyToken : undefined // Apenas para desenvolvimento
    };
  }
}

module.exports = RegisterUserUseCase;