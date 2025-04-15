// src/interfaces/api/validators/auth.validator.js
const { body, validationResult } = require('express-validator');
const { BadRequestError } = require('../../../shared/errors/api-error');

// Definição de esquemas de validação
const validationSchemas = {
  register: [
    body('email')
      .isEmail()
      .withMessage('E-mail inválido')
      .normalizeEmail(),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Senha deve ter pelo menos 8 caracteres')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage(
        'Senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial'
      ),
    body('role')
      .optional()
      .isIn(['user', 'admin'])
      .withMessage('Função inválida'),
    body('enable2FA')
      .optional()
      .isBoolean()
      .withMessage('O valor de enable2FA deve ser um booleano')
  ],

  login: [
    body('email')
      .isEmail()
      .withMessage('E-mail inválido')
      .normalizeEmail(),
    body('password')
      .notEmpty()
      .withMessage('Senha é obrigatória')
  ],

  requestPasswordReset: [
    body('email')
      .isEmail()
      .withMessage('E-mail inválido')
      .normalizeEmail()
  ],

  resetPassword: [
    body('token')
      .notEmpty()
      .withMessage('Token é obrigatório'),
    body('newPassword')
      .isLength({ min: 8 })
      .withMessage('Nova senha deve ter pelo menos 8 caracteres')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage(
        'Senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial'
      )
  ],

  verify2FA: [
    body('token')
      .isNumeric()
      .withMessage('Token deve conter apenas números')
      .isLength({ min: 6, max: 6 })
      .withMessage('Token deve ter 6 dígitos'),
    body('tempToken')
      .notEmpty()
      .withMessage('Token temporário é obrigatório')
  ],

  recoveryCode: [
    body('code')
      .notEmpty()
      .withMessage('Código de recuperação é obrigatório')
      .isString()
      .withMessage('Código de recuperação deve ser uma string'),
    body('tempToken')
      .notEmpty()
      .withMessage('Token temporário é obrigatório')
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