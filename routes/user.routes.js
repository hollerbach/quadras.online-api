// routes/user.routes.js
const express = require('express');
const router = express.Router();
const userController = require('../controllers/user.controller');
const { authenticate } = require('../middlewares/auth.middleware');
const { authorize } = require('../middlewares/rbac.middleware');
const { validateRequest, validationSchemas } = require('../middlewares/validation.middleware');

/**
 * @route GET /api/users/profile
 * @desc Obter perfil do usuário atual
 * @access Privado
 */
router.get(
  '/profile',
  authenticate,
  userController.getProfile
);

/**
 * @route PUT /api/users/profile
 * @desc Atualizar perfil do usuário
 * @access Privado
 */
router.put(
  '/profile',
  authenticate,
  validationSchemas.updateProfile,
  validateRequest,
  userController.updateProfile
);

/**
 * @route PUT /api/users/password
 * @desc Alterar senha do usuário
 * @access Privado
 */
router.put(
  '/password',
  authenticate,
  validationSchemas.changePassword,
  validateRequest,
  userController.changePassword
);

/**
 * @route GET /api/users
 * @desc Listar todos os usuários (somente admin)
 * @access Privado/Admin
 */
router.get(
  '/',
  authenticate,
  authorize(['admin']),
  userController.getAllUsers
);

/**
 * @route GET /api/users/:id
 * @desc Obter usuário por ID (somente admin)
 * @access Privado/Admin
 */
router.get(
  '/:id',
  authenticate,
  authorize(['admin']),
  userController.getUserById
);

/**
 * @route PUT /api/users/:id
 * @desc Atualizar usuário por ID (somente admin)
 * @access Privado/Admin
 */
router.put(
  '/:id',
  authenticate,
  authorize(['admin']),
  validationSchemas.adminUpdateUser,
  validateRequest,
  userController.updateUser
);

/**
 * @route DELETE /api/users/:id
 * @desc Desativar usuário por ID (somente admin)
 * @access Privado/Admin
 */
router.delete(
  '/:id',
  authenticate,
  authorize(['admin']),
  userController.deactivateUser
);

module.exports = router;
