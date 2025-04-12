// routes/auth.routes.js
const express = require('express');
const router = express.Router();
const passport = require('passport');
const authController = require('../controllers/auth.controller');

// Middlewares
const { authenticate } = require('../middlewares/auth.middleware');
const { authorize } = require('../middlewares/rbac.middleware');
const { validateRequest, validationSchemas } = require('../middlewares/validation.middleware');
const {
  loginRateLimit,
  verifyAppKey,
  sensitiveRouteProtection
} = require('../middlewares/security.middleware');

/**
 * @route POST /auth/register
 * @desc Registrar novo usuário
 * @access Público
 */
router.post('/register', validationSchemas.register, validateRequest, authController.register);

/**
 * @route GET /auth/verify-email
 * @desc Verificar e-mail via token
 * @access Público
 */
router.get('/verify-email', authController.verifyEmail);

/**
 * @route POST /auth/login
 * @desc Login de usuário
 * @access Público
 */
router.post(
  '/login',
  loginRateLimit,
  verifyAppKey,
  validationSchemas.login,
  validateRequest,
  authController.login
);

/**
 * @route POST /auth/refresh-token
 * @desc Atualizar tokens usando refresh token
 * @access Público
 */
router.post('/refresh-token', authController.refreshToken);

/**
 * @route POST /auth/logout
 * @desc Logout e invalidação de tokens
 * @access Privado
 */
router.post('/logout', authenticate, authController.logout);

/**
 * @route POST /auth/2fa/verify
 * @desc Verificar token 2FA durante login
 * @access Público
 */
router.post('/2fa/verify', validationSchemas.verify2FA, validateRequest, authController.verify2FA);

/**
 * @route POST /auth/2fa/setup
 * @desc Configurar autenticação de dois fatores
 * @access Privado
 */
router.post(
  '/2fa/setup',
  authenticate,
  sensitiveRouteProtection.twoFactorSetup,
  authController.setup2FA
);

/**
 * @route POST /auth/2fa/disable
 * @desc Desativar autenticação de dois fatores
 * @access Privado
 */
router.post(
  '/2fa/disable',
  authenticate,
  validationSchemas.verify2FA,
  validateRequest,
  authController.disable2FA
);

/**
 * @route POST /auth/password-reset/request
 * @desc Solicitar redefinição de senha
 * @access Público
 */
router.post(
  '/password-reset/request',
  sensitiveRouteProtection.passwordReset,
  validationSchemas.requestPasswordReset,
  validateRequest,
  authController.requestPasswordReset
);

/**
 * @route POST /auth/password-reset/confirm
 * @desc Confirmar redefinição de senha com token
 * @access Público
 */
router.post(
  '/password-reset/confirm',
  validationSchemas.resetPassword,
  validateRequest,
  authController.resetPassword
);

/**
 * @route POST /auth/2fa/recovery
 * @desc Login usando código de recuperação 2FA
 * @access Público
 */
router.post(
  '/2fa/recovery',
  validationSchemas.recoveryCode,
  validateRequest,
  authController.verify2FARecovery
);

/**
 * @route GET /auth/google
 * @desc Iniciar autenticação com Google
 * @access Público
 */
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false
  })
);

/**
 * @route GET /auth/google/callback
 * @desc Callback da autenticação Google
 * @access Público
 */
router.get(
  '/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/login',
    session: false
  }),
  authController.googleCallback
);

module.exports = router;