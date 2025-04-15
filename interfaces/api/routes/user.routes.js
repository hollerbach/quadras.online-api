// src/interfaces/api/routes/user.routes.js
const express = require('express');
const router = express.Router();
const userController = require('../controllers/user.controller');
const { asyncHandler } = require('../middlewares/error.middleware');
const { authenticate } = require('../middlewares/auth.middleware');
const { authorize } = require('../middlewares/rbac.middleware');
const { validate } = require('../validators/user.validator');

// Rotas de perfil (para usuário autenticado)
router.get('/profile', authenticate, asyncHandler(userController.getProfile));
router.put(
  '/profile',
  authenticate, 
  validate('updateProfile'), 
  asyncHandler(userController.updateProfile)
);
router.put(
  '/password',
  authenticate,
  validate('changePassword'),
  asyncHandler(userController.changePassword)
);

// Rotas administrativas (requerem role de admin)
router.get(
  '/',
  authenticate,
  authorize(['admin']),
  asyncHandler(userController.getAllUsers)
);

router.get(
  '/:id',
  authenticate,
  authorize(['admin']),
  asyncHandler(userController.getUserById)
);

router.put(
  '/:id',
  authenticate,
  authorize(['admin']),
  validate('adminUpdateUser'),
  asyncHandler(userController.updateUser)
);

router.delete(
  '/:id',
  authenticate,
  authorize(['admin']),
  asyncHandler(userController.deactivateUser)
);

module.exports = router;