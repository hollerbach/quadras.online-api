// src/interfaces/api/validators/user.validator.js
const { body, validationResult } = require('express-validator');
const { BadRequestError } = require('../../../shared/errors/api-error');

// Definição de esquemas de validação
const validationSchemas = {
  updateProfile: [
    body('name')
      .optional()
      .trim()
      .escape(),
    body('surname')
      .optional()
      .trim()
      .escape(),
    body('phoneNumber')
      .optional()
      .isMobilePhone()
      .withMessage('Número de telefone inválido'),
    body('address.street')
      .optional()
      .trim(),
    body('address.city')
      .optional()
      .trim(),
    body('address.state')
      .optional()
      .trim(),
    body('address.postalCode')
      .optional()
      .trim(),
    body('address.country')
      .optional()
      .trim()
  ],

  changePassword: [
    body('currentPassword')
      .notEmpty()
      .withMessage('Senha atual é obrigatória'),
    body('newPassword')
      .isLength({ min: 8 })
      .withMessage('Nova senha deve ter pelo menos 8 caracteres')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage(
        'Senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial'
      )
  ],

  adminUpdateUser: [
    body('role')
      .optional()
      .isIn(['user', 'admin'])
      .withMessage('Função inválida'),
    body('verified')
      .optional()
      .isBoolean()
      .withMessage('O campo verified deve ser um booleano'),
    body('active')
      .optional()
      .isBoolean()
      .withMessage('O campo active deve ser um booleano'),
    body('twoFactorEnabled')
      .optional()
      .isBoolean()
      .withMessage('O campo twoFactorEnabled deve ser um booleano'),
    body('name')
      .optional()
      .trim()
      .escape(),
    body('surname')
      .optional()
      .trim()
      .escape()
  ]
};

/**
 * Middleware para validar requisições com base no esquema especificado
 * @param {string} schema Nome do esquema de validação a ser utilizado
 * @returns {Array<Function>} Middleware de validação
 */
const validate = (schema) => {
  if (!validationSchemas[schema]) {
    throw new Error(`Esquema de validação '${schema}' não definido`);
  }
  
  return [
    ...validationSchemas[schema],
    (req, res, next) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        const formattedErrors = errors.array().map(err => ({
          field: err.path,
          message: err.msg
        }));
        
        throw new BadRequestError('Erro de validação', formattedErrors);
      }
      next();
    }
  ];
};

module.exports = {
  validate
};