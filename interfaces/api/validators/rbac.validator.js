// src/interfaces/api/validators/rbac.validator.js
const { body, param, query } = require('express-validator');
const { validators, createValidator } = require('../middlewares/validation.middleware');
const { BadRequestError } = require('../../../shared/errors/api-error');

/**
 * Schemas de validação para o sistema RBAC
 */
const rbacValidationSchemas = {
  // Validações para papéis (roles)
  createRole: [
    body('name')
      .notEmpty().withMessage('Nome do papel é obrigatório')
      .isString().withMessage('Nome do papel deve ser texto')
      .isLength({ min: 3, max: 50 }).withMessage('Nome do papel deve ter entre 3 e 50 caracteres')
      .matches(/^[a-zA-Z0-9_-]+$/).withMessage('Nome do papel deve conter apenas letras, números, hífens e underscores')
      .trim(),
    
    body('description')
      .notEmpty().withMessage('Descrição do papel é obrigatória')
      .isString().withMessage('Descrição do papel deve ser texto')
      .isLength({ min: 5, max: 200 }).withMessage('Descrição do papel deve ter entre 5 e 200 caracteres')
      .trim(),
    
    body('isSystem')
      .optional()
      .isBoolean().withMessage('isSystem deve ser um booleano')
  ],

  updateRole: [
    param('id')
      .isMongoId().withMessage('ID do papel inválido'),
    
    body('name')
      .optional()
      .isString().withMessage('Nome do papel deve ser texto')
      .isLength({ min: 3, max: 50 }).withMessage('Nome do papel deve ter entre 3 e 50 caracteres')
      .matches(/^[a-zA-Z0-9_-]+$/).withMessage('Nome do papel deve conter apenas letras, números, hífens e underscores')
      .trim(),
    
    body('description')
      .optional()
      .isString().withMessage('Descrição do papel deve ser texto')
      .isLength({ min: 5, max: 200 }).withMessage('Descrição do papel deve ter entre 5 e 200 caracteres')
      .trim()
  ],

  getAllRoles: [
    query('page')
      .optional()
      .isInt({ min: 1 }).withMessage('Página deve ser um número positivo')
      .toInt(),
    
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 }).withMessage('Limite deve ser entre 1 e 100')
      .toInt(),
    
    query('sort')
      .optional()
      .isString().withMessage('Campo de ordenação deve ser texto')
      .isIn(['name', 'createdAt', 'updatedAt']).withMessage('Campo de ordenação inválido'),
    
    query('order')
      .optional()
      .isString().withMessage('Ordem deve ser texto')
      .isIn(['asc', 'desc']).withMessage('Ordem deve ser "asc" ou "desc"'),
    
    query('search')
      .optional()
      .isString().withMessage('Termo de busca deve ser texto')
      .trim(),
    
    query('isSystem')
      .optional()
      .isBoolean().withMessage('isSystem deve ser um booleano')
      .toBoolean()
  ],

  getRoleById: [
    param('id')
      .isMongoId().withMessage('ID do papel inválido')
  ],

  deleteRole: [
    param('id')
      .isMongoId().withMessage('ID do papel inválido')
  ],

  // Validações para permissões
  createPermission: [
    body('name')
      .notEmpty().withMessage('Nome da permissão é obrigatório')
      .isString().withMessage('Nome da permissão deve ser texto')
      .isLength({ min: 3, max: 50 }).withMessage('Nome da permissão deve ter entre 3 e 50 caracteres')
      .trim(),
    
    body('code')
      .notEmpty().withMessage('Código da permissão é obrigatório')
      .isString().withMessage('Código da permissão deve ser texto')
      .isLength({ min: 3, max: 50 }).withMessage('Código da permissão deve ter entre 3 e 50 caracteres')
      .matches(/^[A-Z0-9_]+$/).withMessage('Código da permissão deve conter apenas letras maiúsculas, números e underscores')
      .trim(),
    
    body('description')
      .notEmpty().withMessage('Descrição da permissão é obrigatória')
      .isString().withMessage('Descrição da permissão deve ser texto')
      .isLength({ min: 5, max: 200 }).withMessage('Descrição da permissão deve ter entre 5 e 200 caracteres')
      .trim(),
    
    body('category')
      .notEmpty().withMessage('Categoria da permissão é obrigatória')
      .isString().withMessage('Categoria da permissão deve ser texto')
      .isIn(['user', 'product', 'order', 'delivery', 'report', 'system']).withMessage('Categoria da permissão inválida')
  ],

  updatePermission: [
    param('id')
      .isMongoId().withMessage('ID da permissão inválido'),
    
    body('name')
      .optional()
      .isString().withMessage('Nome da permissão deve ser texto')
      .isLength({ min: 3, max: 50 }).withMessage('Nome da permissão deve ter entre 3 e 50 caracteres')
      .trim(),
    
    body('description')
      .optional()
      .isString().withMessage('Descrição da permissão deve ser texto')
      .isLength({ min: 5, max: 200 }).withMessage('Descrição da permissão deve ter entre 5 e 200 caracteres')
      .trim(),
    
    body('category')
      .optional()
      .isString().withMessage('Categoria da permissão deve ser texto')
      .isIn(['user', 'product', 'order', 'delivery', 'report', 'system']).withMessage('Categoria da permissão inválida')
  ],

  getAllPermissions: [
    query('page')
      .optional()
      .isInt({ min: 1 }).withMessage('Página deve ser um número positivo')
      .toInt(),
    
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 }).withMessage('Limite deve ser entre 1 e 100')
      .toInt(),
    
    query('sort')
      .optional()
      .isString().withMessage('Campo de ordenação deve ser texto')
      .isIn(['name', 'code', 'category', 'createdAt']).withMessage('Campo de ordenação inválido'),
    
    query('order')
      .optional()
      .isString().withMessage('Ordem deve ser texto')
      .isIn(['asc', 'desc']).withMessage('Ordem deve ser "asc" ou "desc"'),
    
    query('search')
      .optional()
      .isString().withMessage('Termo de busca deve ser texto')
      .trim(),
    
    query('category')
      .optional()
      .isString().withMessage('Categoria deve ser texto')
      .isIn(['user', 'product', 'order', 'delivery', 'report', 'system']).withMessage('Categoria inválida')
  ],

  getPermissionById: [
    param('id')
      .isMongoId().withMessage('ID da permissão inválido')
  ],

  deletePermission: [
    param('id')
      .isMongoId().withMessage('ID da permissão inválido')
  ],

  // Validações para relação entre papéis e permissões
  addPermissionToRole: [
    param('roleId')
      .isMongoId().withMessage('ID do papel inválido'),
    
    param('permissionId')
      .isMongoId().withMessage('ID da permissão inválido'),
    
    body('resources')
      .optional()
      .isArray().withMessage('Resources deve ser um array'),
    
    body('resources.*.resource')
      .optional()
      .isMongoId().withMessage('ID do recurso inválido'),
    
    body('resources.*.conditions')
      .optional()
      .isObject().withMessage('Conditions deve ser um objeto')
  ],

  removePermissionFromRole: [
    param('roleId')
      .isMongoId().withMessage('ID do papel inválido'),
    
    param('permissionId')
      .isMongoId().withMessage('ID da permissão inválido')
  ],

  // Validações para relação entre usuários e papéis
  assignRoleToUser: [
    param('userId')
      .isMongoId().withMessage('ID do usuário inválido'),
    
    param('roleId')
      .isMongoId().withMessage('ID do papel inválido'),
    
    body('scope')
      .optional()
      .isString().withMessage('Escopo deve ser texto')
      .isIn(['global', 'store', 'department']).withMessage('Escopo inválido'),
    
    body('scopeId')
      .optional()
      .custom((value, { req }) => {
        // Só é obrigatório se o escopo não for global
        if (req.body.scope && req.body.scope !== 'global' && !value) {
          throw new Error('ID do escopo é obrigatório para escopos não-globais');
        }
        
        if (value) {
          // Verificar se é um MongoDB ObjectId válido
          if (!/^[0-9a-fA-F]{24}$/.test(value)) {
            throw new Error('ID do escopo inválido');
          }
        }
        
        return true;
      })
  ],

  removeRoleFromUser: [
    param('userId')
      .isMongoId().withMessage('ID do usuário inválido'),
    
    param('roleId')
      .isMongoId().withMessage('ID do papel inválido'),
    
    body('scope')
      .optional()
      .isString().withMessage('Escopo deve ser texto')
      .isIn(['global', 'store', 'department']).withMessage('Escopo inválido'),
    
    body('scopeId')
      .optional()
      .isMongoId().withMessage('ID do escopo inválido')
  ],

  getUserRoles: [
    param('userId')
      .isMongoId().withMessage('ID do usuário inválido')
  ]
};

/**
 * Middleware para validar requisições com base no schema especificado
 * @param {string} schema Nome do schema de validação a ser utilizado
 * @returns {Array<Function>} Middleware de validação
 */
const validate = (schema) => {
  if (!rbacValidationSchemas[schema]) {
    throw new Error(`Schema de validação '${schema}' não definido`);
  }
  
  return createValidator(rbacValidationSchemas[schema]);
};

module.exports = {
  validate
};