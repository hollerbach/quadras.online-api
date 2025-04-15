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

// Rate limiters para rotas específicas
const loginRateLimit = rateLimit({
  windowMs: config.security.rateLimit.windowMs,
  max: config.security.rateLimit.loginMax,
  message: 'Muitas tentativas de login. Tente novamente mais tarde.',
  standardHeaders: true,
  legacyHeaders: false
});

const passwordResetRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 3, // 3 tentativas por hora por IP
  message: 'Muitas solicitações de redefinição de senha. Tente novamente mais tarde.'
});

const twoFactorSetupRateLimit = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 24 horas
  max: 5, // 5 tentativas por dia por IP
  message: 'Muitas solicitações para configurar 2FA. Tente novamente mais tarde.'
});

// Rotas de registro e verificação
router.post('/register', validate('register'), asyncHandler(authController.register));
router.get('/verify-email', asyncHandler(authController.verifyEmail));

// Rotas de login e gerenciamento de sessão
router.post('/login', loginRateLimit, validate('login'), asyncHandler(authController.login));
router.post('/refresh-token', asyncHandler(authController.refreshToken));
router.post('/logout', authenticate, asyncHandler(authController.logout));

// Rotas de autenticação em dois fatores (2FA)
router.post('/2fa/verify', validate('verify2FA'), asyncHandler(authController.verify2FA));
router.post('/2fa/setup', authenticate, twoFactorSetupRateLimit, asyncHandler(authController.setup2FA));
router.post('/2fa/disable', authenticate, validate('verify2FA'), asyncHandler(authController.disable2FA));
router.post('/2fa/recovery', validate('recoveryCode'), asyncHandler(authController.verify2FARecovery));

// Rotas de redefinição de senha
router.post(
  '/password-reset/request',
  passwordResetRateLimit,
  validate('requestPasswordReset'),
  asyncHandler(authController.requestPasswordReset)
);
router.post(
  '/password-reset/confirm',
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