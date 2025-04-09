// routes/auth.routes.js (atualizado com rotas OAuth)
const express = require('express');
const router = express.Router();
const passport = require('passport'); // Adicionar importação do passport
const authController = require('../controllers/auth.controller');
const oauthController = require('../controllers/oauth.controller'); // Novo controlador

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
 * @route POST /api/auth/register
 * @desc Registrar novo usuário
 * @access Público
 */
router.post('/register', validationSchemas.register, validateRequest, authController.register);

/**
 * @route GET /api/auth/verify-email
 * @desc Verificar e-mail via token
 * @access Público
 */
router.get('/verify-email', authController.verifyEmail);

/**
 * @route POST /api/auth/login
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
 * @route POST /api/auth/refresh-token
 * @desc Atualizar tokens usando refresh token
 * @access Público
 */
router.post('/refresh-token', authController.refreshToken);

/**
 * @route POST /api/auth/logout
 * @desc Logout e invalidação de tokens
 * @access Privado
 */
router.post('/logout', authenticate, authController.logout);

/**
 * @route POST /api/auth/2fa/verify
 * @desc Verificar token 2FA durante login
 * @access Público
 */
router.post('/2fa/verify', validationSchemas.verify2FA, validateRequest, authController.verify2FA);

/**
 * @route POST /api/auth/2fa/setup
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
 * @route POST /api/auth/2fa/disable
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
 * @route POST /api/auth/password-reset/request
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
 * @route POST /api/auth/password-reset/confirm
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
 * @route POST /api/auth/2fa/recovery
 * @desc Login usando código de recuperação 2FA
 * @access Público
 */
router.post(
  '/2fa/recovery',
  validationSchemas.recoveryCode,
  validateRequest,
  authController.verify2FARecovery
);

// NOVAS ROTAS DE AUTENTICAÇÃO OAUTH

/**
 * @route GET /api/auth/google
 * @desc Iniciar autenticação com Google
 * @access Público
 */
router.get('/google', oauthController.googleAuth);

/**
 * @route GET /api/auth/google/callback
 * @desc Callback de autenticação Google
 * @access Público
 */
router.get('/google/callback', oauthController.googleCallback);

/**
 * @route POST /api/auth/google/unlink
 * @desc Desvincular conta do Google
 * @access Privado
 */
router.post('/google/unlink', authenticate, oauthController.unlinkGoogle);

module.exports = router;