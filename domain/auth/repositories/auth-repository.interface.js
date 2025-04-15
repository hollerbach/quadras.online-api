// src/domain/auth/repositories/auth-repository.interface.js

/**
 * Interface para o repositório de autenticação
 * Define os métodos que qualquer implementação de repositório de autenticação deve fornecer
 */
class AuthRepositoryInterface {
    /**
     * Salva um token de atualização (refresh token)
     * @param {Object} tokenData Dados do token
     * @returns {Promise<Object>} Token salvo
     */
    async saveRefreshToken(tokenData) {
      throw new Error('Method not implemented: saveRefreshToken');
    }
  
    /**
     * Busca um token de atualização pelo valor
     * @param {string} token Valor do token
     * @returns {Promise<Object|null>} Token encontrado ou null
     */
    async findRefreshToken(token) {
      throw new Error('Method not implemented: findRefreshToken');
    }
  
    /**
     * Revoga um token de atualização
     * @param {string} token Valor do token
     * @param {string} ipAddress Endereço IP que revogou o token
     * @returns {Promise<Object>} Token revogado
     */
    async revokeRefreshToken(token, ipAddress) {
      throw new Error('Method not implemented: revokeRefreshToken');
    }
  
    /**
     * Adiciona um token à blacklist
     * @param {string} token Valor do token
     * @param {string} type Tipo do token ('access' ou 'refresh')
     * @param {number} expiresIn Tempo em segundos até a expiração
     * @returns {Promise<Object>} Token na blacklist
     */
    async blacklistToken(token, type, expiresIn) {
      throw new Error('Method not implemented: blacklistToken');
    }
  
    /**
     * Verifica se um token está na blacklist
     * @param {string} token Valor do token
     * @returns {Promise<boolean>} Verdadeiro se estiver na blacklist
     */
    async isTokenBlacklisted(token) {
      throw new Error('Method not implemented: isTokenBlacklisted');
    }
  
    /**
     * Salva um token de verificação de email
     * @param {string} userId ID do usuário
     * @param {string} token Token de verificação
     * @param {Date} expires Data de expiração
     * @returns {Promise<Object>} Resultado da operação
     */
    async saveVerifyEmailToken(userId, token, expires) {
      throw new Error('Method not implemented: saveVerifyEmailToken');
    }
  
    /**
     * Salva um token de redefinição de senha
     * @param {string} userId ID do usuário
     * @param {string} token Token de redefinição
     * @param {Date} expires Data de expiração
     * @returns {Promise<Object>} Resultado da operação
     */
    async savePasswordResetToken(userId, token, expires) {
      throw new Error('Method not implemented: savePasswordResetToken');
    }
  
    /**
     * Registra uma tentativa de login
     * @param {string} userId ID do usuário
     * @param {boolean} success Se a tentativa foi bem-sucedida
     * @param {string} ipAddress Endereço IP da tentativa
     * @returns {Promise<Object>} Registro da tentativa
     */
    async logLoginAttempt(userId, success, ipAddress) {
      throw new Error('Method not implemented: logLoginAttempt');
    }
  }
  
  module.exports = AuthRepositoryInterface;