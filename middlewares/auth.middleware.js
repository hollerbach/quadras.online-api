// middlewares/auth.middleware.js
const passport = require('passport');
const { ApiError } = require('./errorHandler.middleware');
const tokenService = require('../services/token.service');

/**
 * Middleware para autenticação usando JWT
 */
exports.authenticate = (req, res, next) => {
  passport.authenticate('jwt', { session: false }, async (err, user, info) => {
    try {
      if (err) {
        return next(err);
      }

      if (!user) {
        const token = req.headers.authorization?.split(' ')[1];
        
        // Se temos um token, verificar se está na blacklist antes de dizer que é inválido
        if (token) {
          const isBlacklisted = await tokenService.isTokenBlacklisted(token);
          if (isBlacklisted) {
            throw new ApiError(401, 'Token revogado ou expirado');
          }
        }
        
        throw new ApiError(401, info?.message || 'Acesso não autorizado');
      }

      // Verificar se usuário está ativo
      if (!user.active) {
        throw new ApiError(403, 'Conta desativada');
      }

      // Verificar se usuário está verificado (exceto para mudança de senha e logout)
      const isVerificationRequired = ![
        '/api/auth/logout',
        '/api/users/password'
      ].includes(req.path);

      if (isVerificationRequired && !user.verified) {
        throw new ApiError(403, 'Conta não verificada');
      }

      req.user = {
        id: user._id,
        email: user.email,
        role: user.role
      };
      next();
    } catch (error) {
      next(error);
    }
  })(req, res, next);
};

/**
 * Middleware opcional que não rejeita se não houver token
 * Útil para rotas que podem ter autenticação opcional
 */
exports.optionalAuthenticate = (req, res, next) => {
  passport.authenticate('jwt', { session: false }, (err, user) => {
    if (user && !err) {
      req.user = {
        id: user._id,
        email: user.email,
        role: user.role
      };
    }
    next();
  })(req, res, next);
};