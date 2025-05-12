// src/interfaces/api/routes/auth.routes.js
const express = require('express');
const router = express.Router();
const passport = require('passport');
const authController = require('../controllers/auth.controller');
const { asyncHandler } = require('../middlewares/error.middleware');
const { authenticate, auth, verifyUserStatus, optionalAuthenticate } = require('../middlewares/auth.middleware');
const { validate } = require('../validators/auth.validator');
const rateLimit = require('express-rate-limit');
const config = require('../../../infrastructure/config');
const securityConfig = require('../../../infrastructure/security/security.config');

/**
 * Agrupamento de middlewares por funcionalidade para manter o código DRY
 */
const middlewares = {
  // Middlewares para endpoints de autenticação básica
  login: [
    securityConfig.authRateLimit, 
    validate('login')
  ],
  
  // Middlewares para endpoints que requerem autenticação
  authenticated: [
    authenticate, 
    verifyUserStatus
  ],
  
  // Middlewares para endpoints que requerem autenticação e são sensíveis
  sensitive: [
    authenticate, 
    verifyUserStatus, 
    securityConfig.sensitiveRateLimit
  ],
  
  // Middlewares para registro
  register: [
    validate('register')
  ],
  
  // Middlewares para verificação 2FA
  verify2FA: [
    validate('verify2FA')
  ],
  
  // Middlewares para operações de senha
  passwordReset: [
    securityConfig.sensitiveRateLimit,
    validate('requestPasswordReset')
  ],
  
  passwordResetConfirm: [
    securityConfig.sensitiveRateLimit,
    validate('resetPassword')
  ],
  
  // Middlewares para recovery code
  recoveryCode: [
    validate('recoveryCode')
  ]
};

// Aplicar limites de taxa para todas as rotas de autenticação
router.use(securityConfig.authRateLimit);

/**
 * @route POST /auth/register
 * @desc Registrar novo usuário
 * @access Public
 */
router.post('/register', 
  middlewares.register, 
  asyncHandler(authController.register)
);

/**
 * @route GET /auth/verify-email
 * @desc Verificar e-mail via token
 * @access Public
 */
router.get('/verify-email', 
  asyncHandler(authController.verifyEmail)
);

/**
 * @route POST /auth/login
 * @desc Autenticar usuário
 * @access Public
 */
router.post('/login', 
  middlewares.login, 
  asyncHandler(authController.login)
);

/**
 * @route POST /auth/refresh-token
 * @desc Atualizar tokens usando refresh token
 * @access Public
 */
router.post('/refresh-token', 
  validate('refreshToken'), 
  asyncHandler(authController.refreshToken)
);

/**
 * @route POST /auth/logout
 * @desc Logout do usuário
 * @access Private
 */
router.post('/logout', 
  middlewares.authenticated, 
  asyncHandler(authController.logout)
);

/**
 * @route POST /auth/2fa/verify
 * @desc Verificar token 2FA durante login
 * @access Public
 */
router.post('/2fa/verify', 
  middlewares.verify2FA, 
  asyncHandler(authController.verify2FA)
);

/**
 * @route POST /auth/2fa/setup
 * @desc Configurar autenticação de dois fatores
 * @access Private
 */
router.post('/2fa/setup', 
  middlewares.sensitive, 
  asyncHandler(authController.setup2FA)
);

/**
 * @route POST /auth/2fa/disable
 * @desc Desativar autenticação de dois fatores
 * @access Private
 */
router.post('/2fa/disable', 
  [...middlewares.authenticated, validate('verify2FA')], 
  asyncHandler(authController.disable2FA)
);

/**
 * @route POST /auth/2fa/recovery
 * @desc Autenticar usando código de recuperação 2FA
 * @access Public
 */
router.post('/2fa/recovery', 
  middlewares.recoveryCode, 
  asyncHandler(authController.verify2FARecovery)
);

/**
 * @route POST /auth/password-reset/request
 * @desc Solicitar redefinição de senha
 * @access Public
 */
router.post(
  '/password-reset/request',
  middlewares.passwordReset,
  asyncHandler(authController.requestPasswordReset)
);

/**
 * @route POST /auth/password-reset/confirm
 * @desc Confirmar redefinição de senha
 * @access Public
 */
router.post(
  '/password-reset/confirm',
  middlewares.passwordResetConfirm,
  asyncHandler(authController.resetPassword)
);

/**
 * @route GET /auth/google
 * @desc Iniciar autenticação com Google
 * @access Public
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
 * @access Public
 */
router.get(
  '/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/login',
    session: false
  }),
  asyncHandler(authController.googleCallback)
);

/**
 * @route POST /auth/validate
 * @desc Validar token atual (endpoint leve)
 * @access Private
 */
router.post(
  '/validate',
  middlewares.authenticated,
  asyncHandler(authController.validateToken)
);

module.exports = router;