// routes/auth.routes.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');

// Middlewares
const { authenticate } = require('../middlewares/auth.middleware');
const { authorize } = require('../middlewares/rbac.middleware');
const {
  validateRequest,
  validationSchemas
} = require('../middlewares/validation.middleware');
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
router.post(
  '/register',
  validationSchemas.register,
  validateRequest,
  authController.register
);

/**
 * @route GET /api/auth/verify-email
 * @desc Verificar e-mail via token
 * @access Público
 */
router.get(
  '/verify-email',
  authController.verifyEmail
);

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
router.post(
  '/refresh-token',
  authController.refreshToken
);

/**
 * @route POST /api/auth/logout
 * @desc Logout e invalidação de tokens
 * @access Privado
 */
router.post(
  '/logout',
  authenticate,
  authController.logout
);

/**
 * @route POST /api/auth/2fa/verify
 * @desc Verificar token 2FA durante login
 * @access Público
 */
router.post(
  '/2fa/verify',
  validationSchemas.verify2FA,
  validateRequest,
  authController.verify2FA
);

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

// Em auth.routes.js
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

// E implementar o controller correspondente
async verify2FARecovery(req, res, next) {
  try {
    const { code, tempToken } = req.body;
    const ipAddress = req.ip;

    // Verificar e decodificar o token temporário
    const decoded = tokenService.verifyAccessToken(tempToken);

    if (!decoded || !decoded.is2FA) {
      throw new ApiError(400, 'Token temporário inválido');
    }

    const user = await userService.findById(decoded.id);

    if (!user || !user.twoFactorEnabled) {
      throw new ApiError(400, '2FA não está habilitado para este usuário');
    }

    // Verificar o código de recuperação
    const recoveryCodeResult = await user.validateRecoveryCode(code);

    if (!recoveryCodeResult) {
      logger.warn(`Código de recuperação 2FA inválido: ${user.email}`);
      throw new ApiError(401, 'Código de recuperação inválido');
    }

    // Código válido, gerar novos tokens
    const accessToken = tokenService.generateAccessToken({
      id: user._id,
      email: user.email,
      role: user.role
    });

    const refreshToken = await tokenService.generateRefreshToken(user, ipAddress);

    // Definir cookie HTTP-only para refresh token
    res.cookie('refreshToken', refreshToken.token, {
      httpOnly: true,
      secure: config.app.env === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 dias
    });

    logger.info(`Login via código de recuperação 2FA: ${user.email}`);

    // Registrar na auditoria
    await auditService.log({
      action: 'LOGIN_RECOVERY_CODE',
      userId: user._id,
      userEmail: user.email,
      ipAddress
    });

    res.status(200).json({
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        role: user.role
      },
      recoveryCodesRemaining: user.recoveryCodes.filter(c => !c.used).length
    });
  } catch (error) {
    next(error);
  }
}

module.exports = router;
