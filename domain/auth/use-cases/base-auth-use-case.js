// src/domain/auth/use-cases/base-auth-use-case.js
const { NotFoundError } = require('../../../shared/errors/api-error');
const logger = require('../../../infrastructure/logging/logger');

/**
 * Classe base para todos os casos de uso de autenticação
 * Fornece métodos e comportamentos comuns, reduzindo duplicações
 */
class BaseAuthUseCase {
  /**
   * @param {Object} repositories Repositórios necessários
   * @param {Object} services Serviços necessários
   */
  constructor(repositories = {}, services = {}) {
    this.repositories = repositories;
    this.services = services;
    
    // Serviço de auditoria é opcional
    this.auditService = services.auditService;
  }
  
  /**
   * Verifica se o usuário existe
   * @protected
   * @param {string} userId ID do usuário
   * @param {Object} options Opções adicionais
   * @returns {Promise<Object>} Usuário encontrado
   * @throws {NotFoundError} Se o usuário não for encontrado
   */
  async _verifyUserExists(userId, options = {}) {
    const userRepository = this.repositories.userRepository;
    
    if (!userRepository) {
      throw new Error('User repository not available');
    }
    
    const user = await userRepository.findById(userId);
    
    if (!user) {
      if (options.silent) {
        return null;
      }
      throw new NotFoundError('Usuário não encontrado');
    }
    
    return user;
  }
  
  /**
   * Registra um evento de auditoria
   * @protected
   * @param {string} action Ação a ser registrada
   * @param {Object} user Usuário relacionado
   * @param {string} ipAddress Endereço IP
   * @param {Object} details Detalhes adicionais
   * @returns {Promise<void>}
   */
  async _logAuditEvent(action, user, ipAddress, details = {}) {
    if (this.auditService) {
      try {
        await this.auditService.log({
          action,
          userId: user.id,
          userEmail: user.email,
          ipAddress,
          details
        });
      } catch (error) {
        // Falhas na auditoria não devem interromper o fluxo principal
        logger.warn(`Falha ao registrar evento de auditoria: ${error.message}`);
      }
    }
    
    logger.info(`Auth: ${action} - ${user.email} (${ipAddress})`);
  }
  
  /**
   * Registra uma tentativa de login falha
   * @protected
   * @param {string|null} userId ID do usuário (se disponível)
   * @param {string} email Email do usuário
   * @param {string} ipAddress Endereço IP do solicitante
   * @param {string} reason Motivo da falha
   * @param {Object} details Detalhes adicionais
   * @returns {Promise<void>}
   */
  async _logFailedLoginAttempt(userId, email, ipAddress, reason, details = {}) {
    await this._logAuditEvent('LOGIN_FAILED', 
      { id: userId, email }, 
      ipAddress, 
      { reason, ...details }
    );
    
    logger.warn(`Tentativa de login falha: ${email} (${ipAddress}) - ${reason}`);
  }
  
  /**
   * Registra ação de segurança
   * @protected
   * @param {string} action Ação de segurança
   * @param {Object} user Usuário relacionado
   * @param {string} ipAddress Endereço IP
   * @param {Object} result Resultado da operação
   * @returns {Promise<void>}
   */
  async _logSecurityEvent(action, user, ipAddress, result = {}) {
    await this._logAuditEvent(action, user, ipAddress, {
      success: result.success !== false,
      ...result
    });
    
    const successMsg = result.success !== false ? 'sucedido' : 'falhou';
    logger.info(`Ação de segurança ${action} ${successMsg}: ${user.email} (${ipAddress})`);
  }
  
  /**
   * Método para centralizar a lógica do caso de uso
   * @abstract
   * @param  {...any} args Argumentos necessários para o caso de uso específico
   * @returns {Promise<any>} Resultado da execução
   */
  async execute(...args) {
    // Este método deve ser sobrescrito pelas classes filhas
    throw new Error('Method not implemented: execute');
  }
}

module.exports = BaseAuthUseCase;