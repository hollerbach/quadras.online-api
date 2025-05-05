// src/interfaces/api/routes/user.routes.js
const express = require('express');
const router = express.Router();
const userController = require('../controllers/user.controller');
const { asyncHandler } = require('../middlewares/error.middleware');
const { authenticate } = require('../middlewares/auth.middleware');
const { authorize } = require('../middlewares/rbac.middleware');
const { validate } = require('../validators/user.validator');
const securityConfig = require('../../../infrastructure/security/security.config');

// Aplicar autenticação para todas as rotas de usuário
router.use(authenticate);

// Endpoint leve para validação de token
router.post('/me', asyncHandler(userController.validateToken));

// Rotas de perfil (para usuário autenticado)
router.get('/profile', asyncHandler(userController.getProfile));

router.put(
  '/profile',
  validate('updateProfile'), 
  asyncHandler(userController.updateProfile)
);

// Aplicar limite de taxa para mudança de senha (operação sensível)
router.put(
  '/password',
  securityConfig.sensitiveRateLimit,
  validate('changePassword'),
  asyncHandler(userController.changePassword)
);

// Adicionar autorização RBAC
router.get(
  '/',
  authorize(['admin']),
  validate('getAllUsers'),
  asyncHandler(userController.getAllUsers)
);

router.get(
  '/:id',
  authorize(['admin']),
  validate('getUserById'),
  asyncHandler(userController.getUserById)
);

router.put(
  '/:id',
  authorize(['admin']),
  validate('adminUpdateUser'),
  asyncHandler(userController.updateUser)
);

// Aplicar limite de taxa para desativação (operação sensível)
router.delete(
  '/:id',
  authorize(['admin']),
  securityConfig.sensitiveRateLimit,
  validate('deactivateUser'),
  asyncHandler(userController.deactivateUser)
);

module.exports = router;