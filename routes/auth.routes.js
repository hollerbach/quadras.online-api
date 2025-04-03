const express = require('express');
const router = express.Router();
const authCtrl = require('../controllers/auth.controller');

// Middlewares
const { authenticate } = require('../middlewares/auth.middleware');
const { authorize } = require('../middlewares/rbac.middleware');
const appKeyMiddleware = require('../middlewares/appKey.middleware');
const recaptchaMiddleware = require('../middlewares/recaptcha.middleware');
const rateLimiter = require('../middlewares/rateLimiter.middleware');

// Registro de novo usuário
router.post('/register', authCtrl.register);

// Verificação de e-mail via token
router.get('/verify-email', authCtrl.verifyEmail);

// Login com segurança: App Key, rate limit e reCAPTCHA
router.post('/login', rateLimiter, appKeyMiddleware, recaptchaMiddleware, authCtrl.login);

// Logout (JWT deve ser descartado no front)
router.post('/logout', authenticate, authCtrl.logout);

// Solicitar redefinição de senha
router.post('/password-reset/request', authCtrl.requestPasswordReset);

// Confirmar nova senha com token
router.post('/password-reset/confirm', authCtrl.resetPassword);

// Rota protegida para admin
router.get(
  '/admin-only',
  authenticate,
  authorize(['admin']),
  (req, res) => {
    res.json({ message: 'Acesso autorizado para admin' });
  }
);

module.exports = router;
