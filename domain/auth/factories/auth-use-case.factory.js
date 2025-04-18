// src/domain/auth/factories/auth-use-case.factory.js
const RegisterUserUseCase = require('../use-cases/register-user.use-case');
const VerifyEmailUseCase = require('../use-cases/verify-email.use-case');
const Verify2FAUseCase = require('../use-cases/verify-2fa.use-case');
const LogoutUseCase = require('../use-cases/logout.use-case');
const RefreshTokensUseCase = require('../use-cases/refresh-tokens.use-case');

// Importar outros casos de uso que podem ser necessários
const RequestPasswordResetUseCase = require('../use-cases/request-password-reset.use-case');
const ResetPasswordUseCase = require('../use-cases/reset-password.use-case');
const Setup2FAUseCase = require('../use-cases/setup-2fa.use-case');
const Disable2FAUseCase = require('../use-cases/disable-2fa.use-case');
const LoginUseCase = require('../use-cases/login.use-case');

// Repositórios
const userRepository = require('../../../infrastructure/database/mongodb/repositories/user.repository');
const authRepository = require('../../../infrastructure/database/mongodb/repositories/auth.repository');

// Serviços
const mailService = require('../../../infrastructure/external/mail.service');
const tokenService = require('../../../infrastructure/security/token.service');
const twoFactorService = require('../../../infrastructure/security/two-factor.service');

// Auditoria (opcional)
let auditService;
try {
  auditService = require('../../../infrastructure/logging/audit.service');
} catch (error) {
  console.warn('Serviço de auditoria não disponível');
}

/**
 * Factory para criação de casos de uso de autenticação
 * Facilita a injeção de dependências e mocking para testes
 */
class AuthUseCaseFactory {
  /**
   * Cria um caso de uso para registro de usuário
   * @param {Object} customDeps Dependências personalizadas (para testes)
   * @returns {RegisterUserUseCase} Instância do caso de uso
   */
  static createRegisterUserUseCase(customDeps = {}) {
    return new RegisterUserUseCase(
      customDeps.userRepository || userRepository,
      customDeps.mailService || mailService,
      customDeps.auditService || auditService
    );
  }

  /**
   * Cria um caso de uso para verificação de e-mail
   * @param {Object} customDeps Dependências personalizadas (para testes)
   * @returns {VerifyEmailUseCase} Instância do caso de uso
   */
  static createVerifyEmailUseCase(customDeps = {}) {
    return new VerifyEmailUseCase(
      customDeps.userRepository || userRepository,
      customDeps.auditService || auditService
    );
  }

  /**
   * Cria um caso de uso para login
   * @param {Object} customDeps Dependências personalizadas (para testes)
   * @returns {LoginUseCase} Instância do caso de uso
   */
  static createLoginUseCase(customDeps = {}) {
    return new LoginUseCase(
      customDeps.userRepository || userRepository,
      customDeps.tokenService || tokenService,
      customDeps.auditService || auditService
    );
  }

  /**
   * Cria um caso de uso para verificação de 2FA
   * @param {Object} customDeps Dependências personalizadas (para testes)
   * @returns {Verify2FAUseCase} Instância do caso de uso
   */
  static createVerify2FAUseCase(customDeps = {}) {
    return new Verify2FAUseCase(
      customDeps.userRepository || userRepository,
      customDeps.tokenService || tokenService,
      customDeps.twoFactorService || twoFactorService,
      customDeps.auditService || auditService
    );
  }

  /**
   * Cria um caso de uso para configuração de 2FA
   * @param {Object} customDeps Dependências personalizadas (para testes)
   * @returns {Setup2FAUseCase} Instância do caso de uso
   */
  static createSetup2FAUseCase(customDeps = {}) {
    return new Setup2FAUseCase(
      customDeps.userRepository || userRepository,
      customDeps.twoFactorService || twoFactorService,
      customDeps.mailService || mailService,
      customDeps.auditService || auditService
    );
  }

  /**
   * Cria um caso de uso para desativação de 2FA
   * @param {Object} customDeps Dependências personalizadas (para testes)
   * @returns {Disable2FAUseCase} Instância do caso de uso
   */
  static createDisable2FAUseCase(customDeps = {}) {
    return new Disable2FAUseCase(
      customDeps.userRepository || userRepository,
      customDeps.twoFactorService || twoFactorService,
      customDeps.auditService || auditService
    );
  }

  /**
   * Cria um caso de uso para logout
   * @param {Object} customDeps Dependências personalizadas (para testes)
   * @returns {LogoutUseCase} Instância do caso de uso
   */
  static createLogoutUseCase(customDeps = {}) {
    return new LogoutUseCase(
      customDeps.tokenService || tokenService,
      customDeps.auditService || auditService
    );
  }

  /**
   * Cria um caso de uso para refresh tokens
   * @param {Object} customDeps Dependências personalizadas (para testes)
   * @returns {RefreshTokensUseCase} Instância do caso de uso
   */
  static createRefreshTokensUseCase(customDeps = {}) {
    return new RefreshTokensUseCase(
      customDeps.tokenService || tokenService,
      customDeps.auditService || auditService
    );
  }

  /**
   * Cria um caso de uso para solicitação de redefinição de senha
   * @param {Object} customDeps Dependências personalizadas (para testes)
   * @returns {RequestPasswordResetUseCase} Instância do caso de uso
   */
  static createRequestPasswordResetUseCase(customDeps = {}) {
    return new RequestPasswordResetUseCase(
      customDeps.userRepository || userRepository,
      customDeps.mailService || mailService,
      customDeps.auditService || auditService
    );
  }

  /**
   * Cria um caso de uso para redefinição de senha
   * @param {Object} customDeps Dependências personalizadas (para testes)
   * @returns {ResetPasswordUseCase} Instância do caso de uso
   */
  static createResetPasswordUseCase(customDeps = {}) {
    return new ResetPasswordUseCase(
      customDeps.userRepository || userRepository,
      customDeps.auditService || auditService
    );
  }
}

module.exports = AuthUseCaseFactory;