// src/infrastructure/security/token.service.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config');
const logger = require('../logging/logger');
const authRepository = require('../database/mongodb/repositories/auth.repository');
const { UnauthorizedError, BadRequestError } = require('../../shared/errors/api-error');

/**
 * Serviço para gerenciamento de tokens JWT e refresh tokens
 */
class TokenService {
  /**
   * Gera um token JWT de acesso
   * @param {Object} payload Dados a serem codificados no token
   * @returns {string} Token JWT assinado
   */
  generateAccessToken(payload) {
    return jwt.sign(payload, config.auth.jwt.secret, {
      expiresIn: config.auth.jwt.expiresIn
    });
  }

  /**
   * Gera um token JWT temporário (para 2FA)
   * @param {Object} payload Dados a serem codificados no token
   * @returns {string} Token JWT temporário
   */
  generateTempToken(payload) {
    return jwt.sign({ ...payload, is2FA: true }, config.auth.jwt.secret, {
      expiresIn: '5m' // Token temporário válido por 5 minutos
    });
  }

  /**
   * Gera um token de atualização (refresh token)
   * @param {Object} user Usuário para quem o token será gerado
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Refresh token gerado
   */
  async generateRefreshToken(user, ipAddress) {
    // Criar um token aleatório seguro
    const token = crypto.randomBytes(40).toString('hex');
    const expires = new Date(Date.now() + parseInt(config.auth.jwt.refreshExpiresIn) * 1000);

    // Salvar no banco de dados
    const refreshToken = await authRepository.saveRefreshToken({
      token,
      userId: user.id,
      userEmail: user.email,
      expires,
      createdByIp: ipAddress
    });

    return refreshToken;
  }

  /**
   * Verifica e decodifica um token JWT
   * @param {string} token Token JWT a ser verificado
   * @returns {Object} Payload decodificado
   */
  verifyAccessToken(token) {
    try {
      return jwt.verify(token, config.auth.jwt.secret);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedError('Token expirado');
      }
      throw new UnauthorizedError('Token inválido');
    }
  }

  /**
   * Verifica se um token está na blacklist
   * @param {string} token Token a ser verificado
   * @returns {Promise<boolean>} Verdadeiro se o token estiver na blacklist
   */
  async isTokenBlacklisted(token) {
    // Add debug logging to see if the token is being checked
    console.log('Checking if token is blacklisted:', token?.substring(0, 10) + '...');
    return await authRepository.isTokenBlacklisted(token);
  }
  
  /**
   * Adiciona um token à blacklist
   * @param {string} token Token a ser invalidado
   * @param {string} type Tipo do token ('access' ou 'refresh')
   * @param {number} expiresIn Tempo em segundos até a expiração do token
   * @returns {Promise<Object>} Token invalidado
   */
  async blacklistToken(token, type, expiresIn) {
    return await authRepository.blacklistToken(token, type, expiresIn);
  }

  /**
   * Revoga um refresh token
   * @param {string} token Token a ser revogado
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Token revogado
   */
  async revokeRefreshToken(token, ipAddress) {
    return await authRepository.revokeRefreshToken(token, ipAddress);
  }

  /**
   * Utiliza um refresh token para gerar novos tokens de acesso e atualização
   * @param {string} token Refresh token a ser utilizado
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Novos tokens gerados
   */
  async refreshTokens(token, ipAddress) {
    const refreshToken = await authRepository.findRefreshToken(token);

    if (!refreshToken) {
      throw new UnauthorizedError('Token de atualização não encontrado');
    }

    if (refreshToken.revoked) {
      throw new UnauthorizedError('Token de atualização foi revogado');
    }

    if (new Date(refreshToken.expires) < new Date()) {
      throw new UnauthorizedError('Token de atualização expirado');
    }

    // Gerar novo refresh token
    const newRefreshToken = await this.generateRefreshToken(
      { id: refreshToken.userId, email: refreshToken.userEmail },
      ipAddress
    );

    // Revogar o token anterior
    await this.revokeRefreshToken(token, ipAddress);

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
   * @param {string} token Token a ser decodificado
   * @returns {Object} Payload decodificado
   */
  decodeToken(token) {
    try {
      return jwt.decode(token);
    } catch (error) {
      throw new BadRequestError('Formato de token inválido');
    }
  }
}

module.exports = new TokenService();