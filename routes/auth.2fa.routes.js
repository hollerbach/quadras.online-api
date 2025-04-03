const express = require('express');
const router = express.Router();
const { setup2FA, verify2FA } = require('../controllers/auth.controller.2fa');
const authMiddleware = require('../middlewares/auth.middleware');

// Rota protegida para configurar 2FA (usuário autenticado)
router.post('/2fa/setup', authMiddleware, setup2FA);

// Rota protegida para verificar o token TOTP
router.post('/2fa/verify', authMiddleware, verify2FA);

module.exports = router;
