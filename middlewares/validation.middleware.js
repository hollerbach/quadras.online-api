// middlewares/validation.middleware.js
const { validationResult, body } = require('express-validator');
const { ApiError } = require('./errorHandler.middleware');

// Função para verificar resultados da validação
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const error = new ApiError(400, 'Erro de validação', true);
    error.errors = errors.array().map(err => ({
      field: err.path,
      message: err.msg
    }));
    return next(error);
  }
  next();
};

// Esquemas de validação para diferentes rotas
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
      .withMessage('Senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial'),
    body('role')
      .optional()
      .isIn(['user', 'admin'])
      .withMessage('Função inválida')
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
      .withMessage('Senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial')
  ],

  updateProfile: [
    body('name').optional().trim().escape(),
    body('phoneNumber').optional().isMobilePhone().withMessage('Número de telefone inválido'),
    body('address.street').optional().trim(),
    body('address.city').optional().trim(),
    body('address.state').optional().trim(),
    body('address.postalCode').optional().trim(),
    body('address.country').optional().trim()
  ],

  changePassword: [
    body('currentPassword').notEmpty().withMessage('Senha atual é obrigatória'),
    body('newPassword')
      .isLength({ min: 8 })
      .withMessage('Nova senha deve ter pelo menos 8 caracteres')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial')
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
      .withMessage('O campo twoFactorEnabled deve ser um booleano')
  ],

  verify2FA: [
    body('token')
      .isNumeric()
      .withMessage('Token deve conter apenas números')
      .isLength({ min: 6, max: 6 })
      .withMessage('Token deve ter 6 dígitos')
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

module.exports = {
  validateRequest,
  validationSchemas
};