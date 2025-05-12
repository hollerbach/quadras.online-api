// src/interfaces/api/middlewares/auth.middleware.js
const passport = require('passport');
const authService = require('../../../infrastructure/security/auth.service');
const tokenService = require('../../../infrastructure/security/token.service');
const { UnauthorizedError, ForbiddenError } = require('../../../shared/errors/api-error');
const { asyncHandler } = require('./error.middleware');
const logger = require('../../../infrastructure/logging/logger');
const permissionCache = require('../../../cache/permission-cache');

/**
 * Middleware para gestão de autenticação e autorização
 * Centraliza a lógica de verificação de tokens e estado do usuário
 */
class AuthMiddleware {
  /**
   * Middleware para autenticação usando JWT
   * Verifica o token, sua validade e blacklist
   * @param {Request} req Objeto de requisição Express
   * @param {Response} res Objeto de resposta Express
   * @param {Function} next Próxima função middleware
   */
  authenticate = asyncHandler(async (req, res, next) => {
    try {
      // Extrair token do header Authorization
      const token = this._extractTokenFromRequest(req);
      
      if (!token) {
        throw new UnauthorizedError('Token de acesso não fornecido');
      }
      
      // Verificar se o token está na blacklist
      const isBlacklisted = await tokenService.isTokenBlacklisted(token);
      if (isBlacklisted) {
        throw new UnauthorizedError('Token revogado ou expirado');
      }
      
      // Verificar e decodificar o token
      const decoded = tokenService.verifyAccessToken(token);
      
      // Verificar se há informações mínimas necessárias no token
      if (!decoded || !decoded.id || !decoded.email) {
        throw new UnauthorizedError('Token inválido ou malformado');
      }
      
      // Armazenar informações básicas do usuário no objeto req
      req.user = {
        id: decoded.id,
        email: decoded.email,
        role: decoded.role || 'user'
      };
      
      next();
    } catch (error) {
      // Capturar erros específicos de autenticação e enviar respostas apropriadas
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedError('Token expirado');
      } else if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedError('Token inválido');
      } else if (error instanceof UnauthorizedError) {
        throw error;
      } else {
        logger.error(`Erro de autenticação: ${error.message}`);
        throw new UnauthorizedError('Falha na autenticação');
      }
    }
  });

  /**
   * Middleware para verificar o estado do usuário
   * Verifica se o usuário está ativo, verificado e não bloqueado
   * @param {Request} req Objeto de requisição Express
   * @param {Response} res Objeto de resposta Express
   * @param {Function} next Próxima função middleware
   */
  verifyUserStatus = asyncHandler(async (req, res, next) => {
    if (!req.user || !req.user.id) {
      throw new UnauthorizedError('Usuário não autenticado');
    }
    
    // Verificar se a rota requer email verificado
    const requireVerified = !this._isVerificationExemptRoute(req.path);
    
    try {
      // Usar o serviço de autenticação para verificar o estado do usuário
      await authService.verifyUser(req.user.id, {
        requireVerified,
        requireActive: true,
        checkLocked: false // Já verificado no login
      });
      
      next();
    } catch (error) {
      // Se for erro de permissão, vamos registrar detalhes
      if (error instanceof ForbiddenError) {
        logger.warn(`Acesso negado por estado do usuário: ${req.user.email}`, {
          userId: req.user.id,
          path: req.path,
          method: req.method,
          reason: error.message
        });
      }
      
      throw error;
    }
  });

  /**
   * Middleware para autenticação opcional
   * Não rejeita se não houver token, apenas popula req.user se tiver um token válido
   * @param {Request} req Objeto de requisição Express
   * @param {Response} res Objeto de resposta Express
   * @param {Function} next Próxima função middleware
   */
  optionalAuthenticate = asyncHandler(async (req, res, next) => {
    try {
      const token = this._extractTokenFromRequest(req);
      
      if (token) {
        // Verificar blacklist
        const isBlacklisted = await tokenService.isTokenBlacklisted(token);
        if (!isBlacklisted) {
          // Verificar e decodificar o token
          const decoded = tokenService.verifyAccessToken(token);
          
          if (decoded && decoded.id) {
            req.user = {
              id: decoded.id,
              email: decoded.email,
              role: decoded.role || 'user'
            };
          }
        }
      }
      
      // Seguir para o próximo middleware mesmo sem autenticação
      next();
    } catch (error) {
      // Ignorar erros de autenticação, apenas não popula req.user
      logger.debug(`Autenticação opcional falhou: ${error.message}`);
      next();
    }
  });

  /**
   * Middleware para verificar tokens de refresh
   * Usado em rotas de refresh token
   * @param {Request} req Objeto de requisição Express
   * @param {Response} res Objeto de resposta Express
   * @param {Function} next Próxima função middleware
   */
  verifyRefreshToken = asyncHandler(async (req, res, next) => {
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    
    if (!refreshToken) {
      throw new UnauthorizedError('Refresh token não fornecido');
    }
    
    try {
      // Validar o refresh token através do serviço
      const tokenInfo = await tokenService.validateRefreshToken(refreshToken);
      
      if (!tokenInfo) {
        throw new UnauthorizedError('Refresh token inválido ou expirado');
      }
      
      // Armazenar informações para uso no controlador
      req.refreshToken = {
        token: refreshToken,
        userId: tokenInfo.userId,
        userEmail: tokenInfo.userEmail
      };
      
      next();
    } catch (error) {
      logger.warn(`Falha na validação de refresh token: ${error.message}`);
      throw new UnauthorizedError('Refresh token inválido ou expirado');
    }
  });

  /**
   * Middleware que combina autenticação e verificação de estado do usuário
   * Útil para rotas que precisam de ambos
   * @param {Request} req Objeto de requisição Express
   * @param {Response} res Objeto de resposta Express
   * @param {Function} next Próxima função middleware
   */
  authenticated = [
    this.authenticate,
    this.verifyUserStatus
  ];

  /**
   * Middleware que instala funções de autorização no objeto req
   * Permite verificações de autorização dentro dos controladores
   * @param {Request} req Objeto de requisição Express
   * @param {Response} res Objeto de resposta Express
   * @param {Function} next Próxima função middleware
   */
  injectAuthHelpers = asyncHandler(async (req, res, next) => {
    if (!req.user) {
      next();
      return;
    }
    
    // Adicionar funções de autorização ao objeto req
    req.auth = {
      // Verificar permissão RBAC
      hasPermission: async (permissionCode, resourcePath = null) => {
        // Gerar chave de cache
        const cacheKey = `user:${req.user.id}:perm:${permissionCode}:${resourcePath || 'global'}`;
        let result = permissionCache.get(cacheKey);
        
        if (result === undefined) {
          result = await authService.hasPermission(req.user.id, permissionCode, resourcePath);
          permissionCache.set(cacheKey, result, 300); // Cache por 5 minutos
        }
        
        return result;
      },
      
      // Verificar se o usuário tem um papel específico
      hasRole: async (roleName) => {
        return await authService.hasRole(req.user.id, roleName);
      },
      
      // Verificar se o usuário é dono de um recurso
      isOwnerOf: async (resourceType, resourceId) => {
        return await authService.isResourceOwner(req.user.id, resourceType, resourceId);
      }
    };
    
    next();
  });

  /**
   * Extrair token de autorização da requisição
   * @private
   * @param {Request} req Objeto de requisição Express
   * @returns {string|null} Token extraído ou null
   */
  _extractTokenFromRequest(req) {
    // Verificar header de autorização
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    
    // Verificar query param (apenas para APIs específicas como downloads, etc.)
    if (req.query && req.query.token) {
      return req.query.token;
    }
    
    return null;
  }

  /**
   * Verifica se uma rota está isenta de verificação de email
   * @private
   * @param {string} path Caminho da rota
   * @returns {boolean} Verdadeiro se a rota está isenta
   */
  _isVerificationExemptRoute(path) {
    const exemptRoutes = [
      '/auth/logout',
      '/auth/verify-email',
      '/auth/password-reset',
      '/users/password'
    ];
    
    return exemptRoutes.some(route => path.startsWith(route));
  }
}

// Criar instância singleton
const middleware = new AuthMiddleware();

// Exportar métodos individualmente para compatibilidade com código existente
module.exports = {
  authenticate: middleware.authenticate,
  verifyUserStatus: middleware.verifyUserStatus,
  optionalAuthenticate: middleware.optionalAuthenticate,
  verifyRefreshToken: middleware.verifyRefreshToken,
  authenticated: middleware.authenticated,
  injectAuthHelpers: middleware.injectAuthHelpers,
  
  // Composição de middlewares para diferentes níveis de segurança
  auth: middleware.authenticated,
  
  // Para rotas que precisam de autenticação, mas não verificam o estado do usuário
  authOnly: middleware.authenticate,
  
  // Para rotas que precisam de autenticação e ajuda de autorização
  authWithHelpers: [middleware.authenticate, middleware.verifyUserStatus, middleware.injectAuthHelpers]
};