// src/infrastructure/security/token.service.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config');
const logger = require('../logging/logger');
const { UnauthorizedError, BadRequestError } = require('../../shared/errors/api-error');

/**
 * Serviço para gerenciamento de tokens JWT e refresh tokens
 * Centraliza toda a lógica de tokens para evitar duplicações
 */
class TokenService {
  constructor(authRepository) {
    this.authRepository = authRepository;
  }

  /**
   * Gera um token JWT de acesso
   * @param {Object} payload Dados a serem codificados no token
   * @param {Object} options Opções adicionais para geração do token
   * @returns {string} Token JWT assinado
   */
  generateAccessToken(payload, options = {}) {
    const { expiresIn = config.auth.jwt.expiresIn } = options;
    
    return jwt.sign(payload, config.auth.jwt.secret, {
      expiresIn
    });
  }

  /**
   * Gera um token JWT temporário (para 2FA)
   * @param {Object} payload Dados a serem codificados no token
   * @param {Object} options Opções adicionais para geração do token
   * @returns {string} Token JWT temporário
   */
  generateTempToken(payload, options = {}) {
    const { expiresIn = '5m' } = options;
    
    return jwt.sign({ ...payload, is2FA: true }, config.auth.jwt.secret, {
      expiresIn
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
    const expires = new Date(Date.now() + this._parseExpiryTime(config.auth.jwt.refreshExpiresIn));

    // Salvar no banco de dados
    const refreshToken = await this.authRepository.saveRefreshToken({
      token,
      userId: user.id,
      userEmail: user.email,
      expires,
      createdByIp: ipAddress
    });

    return refreshToken;
  }

  /**
   * Verifica e decodifica um token JWT com validações completas
   * Método centralizado que combina várias verificações
   * 
   * @param {string} token Token JWT a ser verificado
   * @param {Object} options Opções adicionais para verificação
   * @returns {Promise<Object>} Payload decodificado
   * @throws {UnauthorizedError} Se o token for inválido, expirado ou estiver na blacklist
   */
  async verifyAndDecodeToken(token, options = {}) {
    const { 
      requireRegularToken = false, 
      require2FAToken = false,
      checkBlacklist = true
    } = options;

    // Verificar se o token foi fornecido
    if (!token) {
      throw new UnauthorizedError('Token não fornecido');
    }

    try {
      // Verificar se o token está na blacklist (se solicitado)
      if (checkBlacklist) {
        const isBlacklisted = await this.isTokenBlacklisted(token);
        if (isBlacklisted) {
          throw new UnauthorizedError('Token revogado ou expirado');
        }
      }

      // Verificar e decodificar o token
      const decoded = jwt.verify(token, config.auth.jwt.secret);

      // Verificar se há informações mínimas necessárias no token
      if (!decoded || !decoded.id) {
        throw new UnauthorizedError('Token inválido ou malformado');
      }

      // Se for um token especial para 2FA, verificar flag
      if (requireRegularToken && decoded.is2FA) {
        throw new UnauthorizedError('Token de autenticação 2FA usado em contexto inválido');
      }

      // Se for um token temporário, verificar flag
      if (require2FAToken && !decoded.is2FA) {
        throw new UnauthorizedError('Token de acesso usado em contexto 2FA');
      }

      return decoded;
    } catch (error) {
      // Capturar erros específicos de autenticação
      if (error instanceof UnauthorizedError) {
        throw error;
      } else if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedError('Token expirado');
      } else if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedError('Token inválido');
      } else {
        logger.error(`Erro na verificação do token: ${error.message}`);
        throw new UnauthorizedError('Falha na autenticação');
      }
    }
  }

  /**
   * Verifica se um token está na blacklist
   * @param {string} token Token a ser verificado
   * @returns {Promise<boolean>} Verdadeiro se o token estiver na blacklist
   */
  async isTokenBlacklisted(token) {
    return await this.authRepository.isTokenBlacklisted(token);
  }
  
  /**
   * Adiciona um token à blacklist
   * @param {string} token Token a ser invalidado
   * @param {string} type Tipo do token ('access' ou 'refresh')
   * @param {number} expiresIn Tempo em segundos até a expiração do token
   * @returns {Promise<Object>} Token invalidado
   */
  async blacklistToken(token, type, expiresIn) {
    return await this.authRepository.blacklistToken(token, type, expiresIn);
  }

  /**
   * Revoga um refresh token
   * @param {string} token Token a ser revogado
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Token revogado
   */
  async revokeRefreshToken(token, ipAddress) {
    return await this.authRepository.revokeRefreshToken(token, ipAddress);
  }

  /**
   * Valida um refresh token
   * @param {string} token Refresh token a ser validado
   * @returns {Promise<Object|null>} Informações do token se válido, null caso contrário
   */
  async validateRefreshToken(token) {
    const refreshToken = await this.authRepository.findRefreshToken(token);
    
    if (!refreshToken) {
      return null;
    }
    
    if (refreshToken.revoked) {
      return null;
    }
    
    if (new Date(refreshToken.expires) < new Date()) {
      return null;
    }
    
    return refreshToken;
  }

  /**
   * Utiliza um refresh token para gerar novos tokens de acesso e atualização
   * @param {string} token Refresh token a ser utilizado
   * @param {string} ipAddress Endereço IP do solicitante
   * @returns {Promise<Object>} Novos tokens gerados
   */
  async refreshTokens(token, ipAddress) {
    const refreshToken = await this.validateRefreshToken(token);

    if (!refreshToken) {
      throw new UnauthorizedError('Refresh token inválido ou expirado');
    }

    // Gerar novo refresh token
    const user = { id: refreshToken.userId, email: refreshToken.userEmail };
    const newRefreshToken = await this.generateRefreshToken(user, ipAddress);

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

  /**
   * Obtém o tempo restante de um token JWT em segundos
   * @param {string} token Token JWT
   * @returns {number} Tempo em segundos até a expiração do token, 0 se expirado
   */
  getRemainingTokenTime(token) {
    try {
      const decoded = this.decodeToken(token);
      if (decoded && decoded.exp) {
        const now = Math.floor(Date.now() / 1000);
        return Math.max(0, decoded.exp - now);
      }
      return 0;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Extrai o ID e email do usuário de um token JWT
   * @param {string} token Token JWT
   * @returns {Object|null} Objeto com id e email do usuário, ou null se inválido
   */
  extractUserFromToken(token) {
    try {
      const decoded = this.decodeToken(token);
      if (decoded && decoded.id && decoded.email) {
        return {
          id: decoded.id,
          email: decoded.email,
          role: decoded.role || 'user'
        };
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Converte string de tempo para milissegundos
   * @private
   * @param {string|number} time Tempo em formato de string (ex: '7d', '1h', '30m') ou número em segundos
   * @returns {number} Tempo em milissegundos
   */
  _parseExpiryTime(time) {
    if (typeof time === 'number') {
      return time * 1000;
    }

    const match = time.match(/^(\d+)([smhdw])$/);
    if (!match) {
      return 24 * 60 * 60 * 1000; // Default para 1 dia se formato não reconhecido
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    const multipliers = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000,
      w: 7 * 24 * 60 * 60 * 1000
    };

    return value * multipliers[unit];
  }
}

// Inicializar com as dependências
const authRepository = require('../database/mongodb/repositories/auth.repository');
module.exports = new TokenService(authRepository);