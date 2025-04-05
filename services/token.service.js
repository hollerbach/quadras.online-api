// services/token.service.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const mongoose = require('mongoose');
const config = require('../config/env.config');
const logger = require('./logger');
const { ApiError } = require('../middlewares/errorHandler.middleware');

// Modelo para tokens inválidos (blacklist)
const TokenBlacklist = mongoose.model(
  'TokenBlacklist',
  new mongoose.Schema({
    token: { type: String, required: true, index: true },
    type: { type: String, enum: ['access', 'refresh'], required: true },
    expires: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now, expires: '30d' }
  })
);

// Modelo para refresh tokens
const RefreshToken = mongoose.model(
  'RefreshToken',
  new mongoose.Schema({
    token: { type: String, required: true, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userEmail: { type: String, required: true },
    expires: { type: Date, required: true },
    revoked: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    createdByIp: String,
    revokedAt: Date,
    revokedByIp: String,
    replacedByToken: String
  })
);

class TokenService {
  /**
   * Gera um token JWT de acesso
   * @param {Object} payload - Dados a serem codificados no token
   * @returns {string} Token JWT assinado
   */
  generateAccessToken(payload) {
    return jwt.sign(payload, config.auth.jwt.secret, {
      expiresIn: config.auth.jwt.expiresIn
    });
  }

  /**
   * Gera um token JWT temporário (para 2FA)
   * @param {Object} payload - Dados a serem codificados no token
   * @returns {string} Token JWT temporário
   */
  generateTempToken(payload) {
    return jwt.sign({ ...payload, is2FA: true }, config.auth.jwt.secret, {
      expiresIn: '5m' // Token temporário válido por 5 minutos
    });
  }

  /**
   * Gera um token de atualização (refresh token)
   * @param {Object} user - Usuário para quem o token será gerado
   * @param {string} ipAddress - Endereço IP do solicitante
   * @returns {Promise<Object>} Refresh token gerado
   */
  async generateRefreshToken(user, ipAddress) {
    // Criar um token aleatório seguro
    const token = crypto.randomBytes(40).toString('hex');
    const expires = new Date(Date.now() + parseInt(config.auth.jwt.refreshExpiresIn) * 1000);

    // Salvar no banco de dados
    const refreshToken = await RefreshToken.create({
      token,
      userId: user._id,
      userEmail: user.email,
      expires,
      createdByIp: ipAddress
    });

    return refreshToken.toObject();
  }

  /**
   * Verifica e decodifica um token JWT
   * @param {string} token - Token JWT a ser verificado
   * @returns {Object} Payload decodificado
   */
  verifyAccessToken(token) {
    try {
      return jwt.verify(token, config.auth.jwt.secret);
    } catch (error) {
      throw new ApiError(401, 'Token inválido ou expirado');
    }
  }

  /**
   * Verifica se um token está na blacklist
   * @param {string} token - Token a ser verificado
   * @returns {Promise<boolean>} Verdadeiro se o token estiver na blacklist
   */
  async isTokenBlacklisted(token) {
    const tokenDoc = await TokenBlacklist.findOne({ token });
    return !!tokenDoc;
  }

  /**
   * Adiciona um token à blacklist
   * @param {string} token - Token a ser invalidado
   * @param {string} type - Tipo do token ('access' ou 'refresh')
   * @param {number} expiresIn - Tempo em segundos até a expiração do token
   * @returns {Promise<Object>} Token invalidado
   */
  async blacklistToken(token, type, expiresIn) {
    const expires = new Date(Date.now() + expiresIn * 1000);

    const blacklistedToken = await TokenBlacklist.create({
      token,
      type,
      expires
    });

    logger.info(`Token adicionado à blacklist: ${type}`);
    return blacklistedToken;
  }

  /**
   * Revoga um refresh token
   * @param {string} token - Token a ser revogado
   * @param {string} ipAddress - Endereço IP do solicitante
   * @returns {Promise<Object>} Token revogado
   */
  async revokeRefreshToken(token, ipAddress) {
    const refreshToken = await RefreshToken.findOne({ token });

    if (!refreshToken || refreshToken.revoked) {
      throw new ApiError(400, 'Token inválido ou já revogado');
    }

    // Marcar como revogado
    refreshToken.revoked = true;
    refreshToken.revokedAt = Date.now();
    refreshToken.revokedByIp = ipAddress;

    await refreshToken.save();
    logger.info(`Refresh token revogado: ${token.substring(0, 10)}...`);

    return refreshToken;
  }

  /**
   * Utiliza um refresh token para gerar novos tokens de acesso e atualização
   * @param {string} token - Refresh token a ser utilizado
   * @param {string} ipAddress - Endereço IP do solicitante
   * @returns {Promise<Object>} Novos tokens gerados
   */
  async refreshTokens(token, ipAddress) {
    const refreshToken = await RefreshToken.findOne({
      token,
      revoked: false,
      expires: { $gt: new Date() }
    });

    if (!refreshToken) {
      throw new ApiError(401, 'Token inválido, expirado ou revogado');
    }

    // Gerar novo refresh token
    const newRefreshToken = await this.generateRefreshToken(
      { _id: refreshToken.userId, email: refreshToken.userEmail },
      ipAddress
    );

    // Revogar o token anterior
    refreshToken.revoked = true;
    refreshToken.revokedAt = Date.now();
    refreshToken.revokedByIp = ipAddress;
    refreshToken.replacedByToken = newRefreshToken.token;
    await refreshToken.save();

    // Gerar novo token de acesso
    const accessToken = this.generateAccessToken({
      id: refreshToken.userId,
      email: refreshToken.userEmail
    });

    return {
      accessToken,
      refreshToken: newRefreshToken.token
    };
  }

  /**
   * Decodifica um token sem verificar a assinatura
   * @param {string} token - Token a ser decodificado
   * @returns {Object} Payload decodificado
   */
  decodeToken(token) {
    try {
      return jwt.decode(token);
    } catch (error) {
      throw new ApiError(400, 'Formato de token inválido');
    }
  }
}

module.exports = new TokenService();
