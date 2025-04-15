// src/infrastructure/database/mongodb/repositories/auth.repository.js
const { TokenBlacklist, RefreshToken } = require('../models/token.models');
const UserModel = require('../models/user.model');
const AuthRepositoryInterface = require('../../../../domain/auth/repositories/auth-repository.interface');
const { NotFoundError, BadRequestError } = require('../../../../shared/errors/api-error');
const logger = require('../../../logging/logger');

/**
 * Implementação MongoDB do repositório de autenticação
 * @implements {AuthRepositoryInterface}
 */
class MongoAuthRepository extends AuthRepositoryInterface {
  /**
   * Salva um token de atualização (refresh token)
   * @param {Object} tokenData Dados do token
   * @returns {Promise<Object>} Token salvo
   */
  async saveRefreshToken(tokenData) {
    const refreshToken = await RefreshToken.create(tokenData);
    return refreshToken.toObject();
  }

  /**
   * Busca um token de atualização pelo valor
   * @param {string} token Valor do token
   * @returns {Promise<Object|null>} Token encontrado ou null
   */
  async findRefreshToken(token) {
    const refreshToken = await RefreshToken.findOne({ token });
    return refreshToken ? refreshToken.toObject() : null;
  }

  /**
   * Revoga um token de atualização
   * @param {string} token Valor do token
   * @param {string} ipAddress Endereço IP que revogou o token
   * @returns {Promise<Object>} Token revogado
   */
  async revokeRefreshToken(token, ipAddress) {
    const refreshToken = await RefreshToken.findOne({ token });
    
    if (!refreshToken) {
      throw new NotFoundError('Token não encontrado');
    }
    
    if (refreshToken.revoked) {
      throw new BadRequestError('Token já foi revogado');
    }
    
    // Atualizar token como revogado
    refreshToken.revoked = true;
    refreshToken.revokedAt = new Date();
    refreshToken.revokedByIp = ipAddress;
    
    await refreshToken.save();
    return refreshToken.toObject();
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
    
    const blacklistedToken = await TokenBlacklist.create({
      token,
      type,
      expires
    });
    
    logger.info(`Token adicionado à blacklist: ${type}`);
    return blacklistedToken.toObject();
  }

  /**
   * Verifica se um token está na blacklist
   * @param {string} token Valor do token
   * @returns {Promise<boolean>} Verdadeiro se estiver na blacklist
   */
  async isTokenBlacklisted(token) {
    const tokenDoc = await TokenBlacklist.findOne({ token });
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
    const user = await UserModel.findById(userId);
    
    if (!user) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    user.verifyToken = token;
    user.verifyTokenExpires = expires;
    
    await user.save();
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
    const user = await UserModel.findById(userId);
    
    if (!user) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    user.resetToken = token;
    user.resetTokenExpires = expires;
    
    await user.save();
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
    // Se a tentativa de login for bem-sucedida
    if (success) {
      const user = await UserModel.findById(userId);
      
      if (user) {
        await user.resetLoginAttempts();
        logger.info(`Login bem-sucedido: ${user.email} (${ipAddress})`);
      }
      
      return { success: true };
    } 
    
    // Se a tentativa de login falhar
    const user = await UserModel.findById(userId);
    
    if (user) {
      const result = await user.incrementLoginAttempts();
      const updatedUser = await UserModel.findById(userId);
      
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

module.exports = new MongoAuthRepository();