// src/interfaces/api/routes/rbac.routes.js
const express = require('express');
const router = express.Router();
const rbacController = require('../controllers/rbac.controller');
const { asyncHandler } = require('../middlewares/error.middleware');
const { authenticate } = require('../middlewares/auth.middleware');
const { requirePermission } = require('../middlewares/rbac.middleware');
const { validate } = require('../validators/rbac.validator');

// Todas as rotas precisam de autenticação
router.use(authenticate);

// Rotas para gerenciamento de papéis (roles)
router.post(
  '/roles',
  requirePermission('ROLE_CREATE'),
  validate('createRole'),
  asyncHandler(rbacController.createRole)
);

router.get(
  '/roles',
  requirePermission('ROLE_VIEW'),
  validate('getAllRoles'),
  asyncHandler(rbacController.getAllRoles)
);

router.get(
  '/roles/:id',
  requirePermission('ROLE_VIEW'),
  validate('getRoleById'),
  asyncHandler(rbacController.getRoleById)
);

router.put(
  '/roles/:id',
  requirePermission('ROLE_EDIT'),
  validate('updateRole'),
  asyncHandler(rbacController.updateRole)
);

router.delete(
  '/roles/:id',
  requirePermission('ROLE_DELETE'),
  validate('deleteRole'),
  asyncHandler(rbacController.deleteRole)
);

// Rotas para gerenciamento de permissões
router.post(
  '/permissions',
  requirePermission('PERMISSION_CREATE'),
  validate('createPermission'),
  asyncHandler(rbacController.createPermission)
);

router.get(
  '/permissions',
  requirePermission('PERMISSION_VIEW'),
  validate('getAllPermissions'),
  asyncHandler(rbacController.getAllPermissions)
);

router.get(
  '/permissions/:id',
  requirePermission('PERMISSION_VIEW'),
  validate('getPermissionById'),
  asyncHandler(rbacController.getPermissionById)
);

router.put(
  '/permissions/:id',
  requirePermission('PERMISSION_EDIT'),
  validate('updatePermission'),
  asyncHandler(rbacController.updatePermission)
);

router.delete(
  '/permissions/:id',
  requirePermission('PERMISSION_DELETE'),
  validate('deletePermission'),
  asyncHandler(rbacController.deletePermission)
);

// Rotas para gerenciamento da relação entre papéis e permissões
router.post(
  '/roles/:roleId/permissions/:permissionId',
  requirePermission('ROLE_PERMISSION_ASSIGN'),
  validate('addPermissionToRole'),
  asyncHandler(rbacController.addPermissionToRole)
);

router.delete(
  '/roles/:roleId/permissions/:permissionId',
  requirePermission('ROLE_PERMISSION_REMOVE'),
  validate('removePermissionFromRole'),
  asyncHandler(rbacController.removePermissionFromRole)
);

// Rotas para gerenciamento da relação entre usuários e papéis
router.post(
  '/users/:userId/roles/:roleId',
  requirePermission('USER_ROLE_ASSIGN'),
  validate('assignRoleToUser'),
  asyncHandler(rbacController.assignRoleToUser)
);

router.delete(
  '/users/:userId/roles/:roleId',
  requirePermission('USER_ROLE_REMOVE'),
  validate('removeRoleFromUser'),
  asyncHandler(rbacController.removeRoleFromUser)
);

router.get(
  '/users/:userId/roles',
  requirePermission('USER_ROLE_VIEW'),
  validate('getUserRoles'),
  asyncHandler(rbacController.getUserRoles)
);

module.exports = router;