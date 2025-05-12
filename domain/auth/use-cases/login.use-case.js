// src/domain/auth/use-cases/login.use-case.js
const logger = require('../../../infrastructure/logging/logger');
const { UnauthorizedError, TooManyRequestsError } = require('../../../shared/errors/api-error');

/**
 * Caso de uso para autenticação de usuário (login)
 * Responsável pela lógica de negócio do processo de login
 */
class LoginUseCase {
  /**
   * @param {Object} userRepository Repositório de usuários
   * @param {Object} tokenService Serviço de tokens
   * @param {Object} authService Serviço centralizado de autenticação
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(userRepository, tokenService, authService, auditService = null) {
    this.userRepository = userRepository;
    this.tokenService = tokenService;
    this.authService = authService;
    this.auditService = auditService;
  }

  /**
   * Executa o caso de uso de login
   * @param {string} email Email do usuário
   * @param {string} password Senha do usuário
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Tokens e informações do usuário ou token temporário para 2FA
   */
  async execute(email, password, ipAddress) {
    try {
      // Validar entrada
      this._validateInput(email, password);

      // Verificar credenciais através do serviço de autenticação
      // Isso delega as verificações de usuário para o serviço centralizado
      const user = await this.authService.verifyCredentials(email, password, ipAddress);

      // Se chegamos aqui, as credenciais são válidas
      // Resetar contagem de tentativas após login bem-sucedido
      await this.userRepository.resetLoginAttempts(user.id);

      // Verificar se 2FA está ativado
      if (user.twoFactorEnabled) {
        return this._handle2FARequired(user, ipAddress);
      }

      // Caso o usuário não tenha 2FA, gerar tokens normais
      return this._generateAuthTokens(user, ipAddress);
    } catch (error) {
      // Re-lançar erros conhecidos
      if (error instanceof UnauthorizedError || error instanceof TooManyRequestsError) {
        throw error;
      }

      // Registrar erro inesperado
      logger.error(`Erro inesperado no login: ${error.message}`, { 
        email, 
        ipAddress, 
        stack: error.stack 
      });
      
      // Retornar erro genérico para não expor detalhes internos
      throw new UnauthorizedError('Falha na autenticação');
    }
  }

  /**
   * Valida os dados de entrada
   * @private
   * @param {string} email Email do usuário
   * @param {string} password Senha do usuário
   * @throws {UnauthorizedError} Se os dados de entrada forem inválidos
   */
  _validateInput(email, password) {
    if (!email || !password) {
      throw new UnauthorizedError('Email e senha são obrigatórios');
    }

    if (typeof email !== 'string' || typeof password !== 'string') {
      throw new UnauthorizedError('Formato de credenciais inválido');
    }

    // Poderíamos adicionar validações mais rigorosas aqui, 
    // mas normalmente isso já é feito pelos validadores da API
  }

  /**
   * Lida com o caso em que 2FA é necessário
   * @private
   * @param {Object} user Usuário autenticado
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Resposta com token temporário
   */
  async _handle2FARequired(user, ipAddress) {
    // Gerar token temporário para a etapa de 2FA
    const tempToken = this.tokenService.generateTempToken({ 
      id: user.id, 
      email: user.email,
      is2FA: true // Flag para indicar que é um token para fluxo 2FA
    });

    // Registrar evento de 2FA necessário
    await this._logAuditEvent('LOGIN_2FA_REQUIRED', user, ipAddress, {
      success: true
    });

    logger.info(`Login parcial (2FA necessário): ${user.email} (${ipAddress})`);

    return {
      requires2FA: true,
      message: '2FA necessário',
      tempToken
    };
  }

  /**
   * Gera tokens de autenticação (access + refresh) para um usuário validado
   * @private
   * @param {Object} user Usuário autenticado
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Tokens de autenticação
   */
  async _generateAuthTokens(user, ipAddress) {
    // Gerar token de acesso (JWT)
    const accessToken = this.tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    // Gerar refresh token (persistido no banco)
    const refreshToken = await this.tokenService.generateRefreshToken(user, ipAddress);

    // Registrar evento de login bem-sucedido
    await this._logAuditEvent('LOGIN', user, ipAddress, {
      user2FA: user.twoFactorEnabled
    });

    logger.info(`Login bem-sucedido: ${user.email} (${ipAddress})`);

    return {
      accessToken,
      refreshToken: refreshToken.token,
      user: user.toSafeObject()
    };
  }

  /**
   * Registra um evento de auditoria
   * @private
   * @param {string} action Ação a ser registrada
   * @param {Object} user Usuário relacionado
   * @param {string} ipAddress Endereço IP
   * @param {Object} details Detalhes adicionais
   */
  async _logAuditEvent(action, user, ipAddress, details = {}) {
    if (this.auditService) {
      await this.auditService.log({
        action,
        userId: user.id,
        userEmail: user.email,
        ipAddress,
        details
      });
    }
  }
}

module.exports = LoginUseCase;