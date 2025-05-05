// src/interfaces/api/routes/auth.routes.js
const express = require('express');
const router = express.Router();
const passport = require('passport');
const authController = require('../controllers/auth.controller');
const { asyncHandler } = require('../middlewares/error.middleware');
const { authenticate } = require('../middlewares/auth.middleware');
const { validate } = require('../validators/auth.validator');
const rateLimit = require('express-rate-limit');
const config = require('../../../infrastructure/config');
const securityConfig = require('../../../infrastructure/security/security.config');

// Aplicar limites de taxa para todas as rotas de autenticação
router.use(securityConfig.authRateLimit);

// Rotas de registro e verificação
router.post('/register', validate('register'), asyncHandler(authController.register));
router.get('/verify-email', asyncHandler(authController.verifyEmail));

// Rotas de login e gerenciamento de sessão
// Aplicar limit especificamente para login
router.post('/login', securityConfig.authRateLimit, validate('login'), asyncHandler(authController.login));
router.post('/refresh-token', validate('refreshToken'), asyncHandler(authController.refreshToken));
router.post('/logout', authenticate, asyncHandler(authController.logout));

// Rotas de autenticação em dois fatores (2FA)
router.post('/2fa/verify', validate('verify2FA'), asyncHandler(authController.verify2FA));
router.post('/2fa/setup', authenticate, securityConfig.sensitiveRateLimit, asyncHandler(authController.setup2FA));
router.post('/2fa/disable', authenticate, validate('verify2FA'), asyncHandler(authController.disable2FA));
router.post('/2fa/recovery', validate('recoveryCode'), asyncHandler(authController.verify2FARecovery));

// Rotas de redefinição de senha - aplicar limite estrito
router.post(
  '/password-reset/request',
  securityConfig.sensitiveRateLimit,
  validate('requestPasswordReset'),
  asyncHandler(authController.requestPasswordReset)
);

router.post(
  '/password-reset/confirm',
  securityConfig.sensitiveRateLimit,
  validate('resetPassword'),
  asyncHandler(authController.resetPassword)
);

// Rotas de autenticação OAuth
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false
  })
);

router.get(
  '/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/login',
    session: false
  }),
  asyncHandler(authController.googleCallback)
);

module.exports = router;