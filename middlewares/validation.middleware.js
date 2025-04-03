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
  
  verify2FA: [
    body('token')
      .isNumeric()
      .withMessage('Token deve conter apenas números')
      .isLength({ min: 6, max: 6 })
      .withMessage('Token deve ter 6 dígitos')
  ]
};

module.exports = {
  validateRequest,
  validationSchemas
};