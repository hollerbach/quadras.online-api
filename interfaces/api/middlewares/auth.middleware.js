// src/interfaces/api/middlewares/auth.middleware.js
const passport = require('passport');
const tokenService = require('../../../infrastructure/security/token.service');
const { UnauthorizedError, ForbiddenError } = require('../../../shared/errors/api-error');

/**
 * Middleware para autenticação usando JWT
 */
const authenticate = (req, res, next) => {
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
            throw new UnauthorizedError('Token revogado ou expirado');
          }
        }
        
        throw new UnauthorizedError(info?.message || 'Acesso não autorizado');
      }

      // Verificar se usuário está ativo
      if (!user.active) {
        throw new ForbiddenError('Conta desativada');
      }

      // Verificar se usuário está verificado (exceto para mudança de senha e logout)
      const isVerificationRequired = ![
        '/auth/logout',
        '/users/password'
      ].includes(req.path);

      if (isVerificationRequired && !user.verified) {
        throw new ForbiddenError('Conta não verificada');
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
const optionalAuthenticate = (req, res, next) => {
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

module.exports = {
  authenticate,
  optionalAuthenticate
};