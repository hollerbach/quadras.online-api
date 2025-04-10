// 2. Create a new controller: controllers/oauth.controller.js
const passport = require('passport');
const oauthService = require('../services/googleOauth.service');
const tokenService = require('../services/token.service');
const config = require('../config/env.config');
const logger = require('../services/logger');
const { ApiError } = require('../middlewares/errorHandler.middleware');
const auditService = require('../services/audit.service');

class OAuthController {
  /**
   * Inicia autenticação Google
   */
  googleAuth(req, res, next) {
    passport.authenticate('google', {
      scope: ['profile', 'email'],
      session: false
    })(req, res, next);
  }

  /**
   * Callback para autenticação Google
   */
  async googleCallback(req, res, next) {
    try {
      passport.authenticate('google', { session: false }, async (err, user, info) => {
        if (err) {
          logger.error(`Erro na autenticação Google: ${err.message}`);
          return next(new ApiError(500, 'Erro na autenticação com Google'));
        }

        if (!user) {
          return next(new ApiError(401, 'Falha na autenticação com Google'));
        }

        // Processar o login
        const ipAddress = req.ip;
        const result = await oauthService.processGoogleLogin(user, ipAddress);

        // Definir cookie HTTP-only para refresh token
        res.cookie('refreshToken', result.refreshToken, {
          httpOnly: true,
          secure: config.app.env === 'production',
          sameSite: 'strict',
          maxAge: 7 * 24 * 60 * 60 * 1000 // 7 dias
        });

        // Registrar na auditoria
        await auditService.log({
          action: 'OAUTH_LOGIN_SUCCESS',
          userId: user._id,
          userEmail: user.email,
          ipAddress,
          details: { provider: 'google' }
        });

        // Redirecionar para a página do frontend com token
        res.redirect(`${config.oauth.redirectUrl}?token=${result.accessToken}`);
      })(req, res, next);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Desvincula conta Google do usuário atual
   */
  async unlinkGoogle(req, res, next) {
    try {
      const userId = req.user.id;
      const result = await oauthService.unlinkGoogleAccount(userId);

      // Registrar na auditoria
      await auditService.log({
        action: 'GOOGLE_ACCOUNT_UNLINKED',
        userId,
        userEmail: req.user.email,
        ipAddress: req.ip
      });

      res.status(200).json(result);
    } catch (error) {
      next(new ApiError(400, error.message));
    }
  }
}

module.exports = new OAuthController();
