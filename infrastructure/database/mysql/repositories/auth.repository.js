// src/infrastructure/database/mysql/repositories/auth.repository.js
const { getConnection } = require('../connection');
const defineModels = require('../models');
const AuthRepositoryInterface = require('../../../../domain/auth/repositories/auth-repository.interface');
const { NotFoundError, BadRequestError } = require('../../../../shared/errors/api-error');
const logger = require('../../../logging/logger');
const { v4: uuidv4 } = require('uuid');
const { Op } = require('sequelize');

/**
 * Implementação MySQL do repositório de autenticação
 * @implements {AuthRepositoryInterface}
 */
class MySQLAuthRepository extends AuthRepositoryInterface {
  constructor() {
    super();
    // Inicializar os modelos
    this.models = defineModels();
  }

  /**
   * Salva um token de atualização (refresh token)
   * @param {Object} tokenData Dados do token
   * @returns {Promise<Object>} Token salvo
   */
  async saveRefreshToken(tokenData) {
    const token = await this.models.RefreshToken.create({
      id: uuidv4(),
      token: tokenData.token,
      userId: tokenData.userId,
      userEmail: tokenData.userEmail,
      expires: tokenData.expires,
      createdByIp: tokenData.createdByIp
    });
    
    return token.toJSON();
  }

  /**
   * Busca um token de atualização pelo valor
   * @param {string} token Valor do token
   * @returns {Promise<Object|null>} Token encontrado ou null
   */
  async findRefreshToken(token) {
    const refreshToken = await this.models.RefreshToken.findOne({
      where: { token }
    });
    
    return refreshToken ? refreshToken.toJSON() : null;
  }

  /**
   * Revoga um token de atualização
   * @param {string} token Valor do token
   * @param {string} ipAddress Endereço IP que revogou o token
   * @returns {Promise<Object>} Token revogado
   */
  async revokeRefreshToken(token, ipAddress) {
    const refreshToken = await this.models.RefreshToken.findOne({
      where: { token }
    });
    
    if (!refreshToken) {
      throw new NotFoundError('Token não encontrado');
    }
    
    if (refreshToken.revoked) {
      throw new BadRequestError('Token já foi revogado');
    }
    
    // Atualizar token como revogado
    await refreshToken.update({
      revoked: true,
      revokedAt: new Date(),
      revokedByIp: ipAddress
    });
    
    return refreshToken.toJSON();
  }

  /**
   * Adiciona um token à blacklist
   * @param {string} token Valor do token
   * @param {string} type Tipo do token ('access' ou 'refresh')
   * @param {number} expiresIn Tempo em segundos até a expiração
   * @returns {Promise<Object>} Token na blacklist
   */
  async blacklistToken(token, type, expiresIn) {
    const expires = new Date(Date.now() + expiresIn * 1000);
    
    const blacklistedToken = await this.models.TokenBlacklist.create({
      id: uuidv4(),
      token,
      type,
      expires
    });
    
    logger.info(`Token adicionado à blacklist: ${type}`);
    return blacklistedToken.toJSON();
  }

  /**
   * Verifica se um token está na blacklist
   * @param {string} token Valor do token
   * @returns {Promise<boolean>} Verdadeiro se estiver na blacklist
   */
  async isTokenBlacklisted(token) {
    const tokenDoc = await this.models.TokenBlacklist.findOne({
      where: { token }
    });
    
    return !!tokenDoc;
  }

  /**
   * Salva um token de verificação de email
   * @param {string} userId ID do usuário
   * @param {string} token Token de verificação
   * @param {Date} expires Data de expiração
   * @returns {Promise<Object>} Resultado da operação
   */
  async saveVerifyEmailToken(userId, token, expires) {
    const user = await this.models.User.findByPk(userId);
    
    if (!user) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    await user.update({
      verifyToken: token,
      verifyTokenExpires: expires
    });
    
    return { success: true };
  }

  /**
   * Salva um token de redefinição de senha
   * @param {string} userId ID do usuário
   * @param {string} token Token de redefinição
   * @param {Date} expires Data de expiração
   * @returns {Promise<Object>} Resultado da operação
   */
  async savePasswordResetToken(userId, token, expires) {
    const user = await this.models.User.findByPk(userId);
    
    if (!user) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    await user.update({
      resetToken: token,
      resetTokenExpires: expires
    });
    
    return { success: true };
  }

  /**
   * Registra uma tentativa de login
   * @param {string} userId ID do usuário
   * @param {boolean} success Se a tentativa foi bem-sucedida
   * @param {string} ipAddress Endereço IP da tentativa
   * @returns {Promise<Object>} Registro da tentativa
   */
  async logLoginAttempt(userId, success, ipAddress) {
    // Criar entrada no log de tentativas
    const loginAttempt = await this.models.LoginAttempt.create({
      id: uuidv4(),
      userId,
      email: null, // Será preenchido abaixo
      success,
      ipAddress,
      details: {},
      createdAt: new Date()
    });
    
    // Se a tentativa de login for bem-sucedida
    if (success) {
      const user = await this.models.User.findByPk(userId);
      
      if (user) {
        // Atualizar o email na tentativa de login
        await loginAttempt.update({
          email: user.email
        });
        
        // Resetar contagens de tentativas
        await user.resetLoginAttempts();
        
        logger.info(`Login bem-sucedido: ${user.email} (${ipAddress})`);
      }
      
      return { success: true };
    } 
    
    // Se a tentativa de login falhar
    const user = await this.models.User.findByPk(userId);
    
    if (user) {
      // Atualizar o email na tentativa de login
      await loginAttempt.update({
        email: user.email
      });
      
      // Incrementar tentativas de login
      await user.incrementLoginAttempts();
      
      // Buscar usuário atualizado para verificar bloqueio
      const updatedUser = await this.models.User.findByPk(userId);
      
      logger.warn(`Tentativa de login falha: ${user.email} (${ipAddress})`);
      
      return {
        success: false,
        isLocked: updatedUser.isLocked(),
        attemptsRemaining: Math.max(0, 5 - updatedUser.failedLoginAttempts),
        lockExpiry: updatedUser.lockUntil
      };
    }
    
    // Se o usuário não for encontrado, retornar sucesso falso mas sem dados adicionais
    return { success: false };
  }
}

module.exports = new MySQLAuthRepository();