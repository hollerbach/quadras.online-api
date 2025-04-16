// src/interfaces/api/validators/auth.validator.js
const { body } = require('express-validator');
const { validators, createValidator } = require('../middlewares/validation.middleware');
const { BadRequestError } = require('../../../shared/errors/api-error');
const userRepository = require('../../../infrastructure/database/mongodb/repositories/user.repository');

/**
 * Validações avançadas específicas do domínio
 */
const customValidators = {
  /**
   * Verifica se um email já existe na base de dados
   */
  emailExists: async (email) => {
    const user = await userRepository.findByEmail(email);
    if (user) {
      throw new Error('Este e-mail já está em uso');
    }
    return true;
  },
  
  /**
   * Valida a força da senha de forma mais abrangente
   */
  strongPassword: (password) => {
    // Verificações de segurança da senha
    const hasMinLength = password.length >= 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    const hasNoCommonPatterns = !/^(12345|qwerty|password|admin|welcome|abc123)/.test(password.toLowerCase());
    
    // Calcular pontuação de força (simples)
    const checks = [hasMinLength, hasUpperCase, hasLowerCase, hasNumbers, hasSpecialChars, hasNoCommonPatterns];
    const strengthScore = checks.filter(Boolean).length;
    
    // Mensagens de erro específicas
    const errors = [];
    if (!hasMinLength) errors.push('Senha deve ter pelo menos 8 caracteres');
    if (!hasUpperCase) errors.push('Senha deve incluir pelo menos uma letra maiúscula');
    if (!hasLowerCase) errors.push('Senha deve incluir pelo menos uma letra minúscula');
    if (!hasNumbers) errors.push('Senha deve incluir pelo menos um número');
    if (!hasSpecialChars) errors.push('Senha deve incluir pelo menos um caractere especial');
    if (!hasNoCommonPatterns) errors.push('Senha não deve incluir padrões comuns como "123456", "password", etc.');
    
    // Exigir pelo menos 4 de 6 critérios atendidos
    if (strengthScore < 4) {
      throw new Error(`Senha muito fraca. ${errors.join('. ')}`);
    }
    
    return true;
  }
};

/**
 * Schemas de validação para autenticação
 */
const authValidationSchemas = {
  register: [
    validators.email()
      .custom(customValidators.emailExists),
    
    validators.password()
      .custom(customValidators.strongPassword),
    
    validators.name(),
    
    body('surname')
      .optional()
      .isLength({ max: 100 }).withMessage('Sobrenome muito longo')
      .matches(/^[a-zA-Z0-9\s.\-']+$/).withMessage('Sobrenome contém caracteres inválidos')
      .trim()
      .escape(),
    
    body('role')
      .optional()
      .isIn(['user', 'admin']).withMessage('Função inválida'),
    
    body('enable2FA')
      .optional()
      .isBoolean().withMessage('O valor de enable2FA deve ser um booleano'),
      
    body('phoneNumber')
      .optional()
      .isMobilePhone().withMessage('Número de telefone inválido')
      .trim(),
      
    // Limitando dados de endereço
    body('address')
      .optional()
      .isObject().withMessage('Endereço deve ser um objeto'),
      
    body('address.street')
      .optional()
      .isString().withMessage('Rua deve ser texto')
      .isLength({ max: 200 }).withMessage('Rua muito longa')
      .trim(),
      
    body('address.city')
      .optional()
      .isString().withMessage('Cidade deve ser texto')
      .isLength({ max: 100 }).withMessage('Cidade muito longa')
      .trim(),
      
    body('address.state')
      .optional()
      .isString().withMessage('Estado deve ser texto')
      .isLength({ max: 100 }).withMessage('Estado muito longo')
      .trim(),
      
    body('address.postalCode')
      .optional()
      .isString().withMessage('CEP deve ser texto')
      .isLength({ max: 20 }).withMessage('CEP muito longo')
      .trim(),
      
    body('address.country')
      .optional()
      .isString().withMessage('País deve ser texto')
      .isLength({ max: 100 }).withMessage('País muito longo')
      .trim()
  ],

  login: [
    validators.email(),
    
    body('password')
      .notEmpty().withMessage('Senha é obrigatória')
      .isString().withMessage('Senha deve ser texto')
      .isLength({ max: 128 }).withMessage('Senha muito longa'),
      
    body('recaptchaToken')
      .optional()
      .isString().withMessage('Token reCAPTCHA inválido')
      .isLength({ max: 2000 }).withMessage('Token reCAPTCHA muito longo')
  ],

  requestPasswordReset: [
    validators.email()
  ],

  resetPassword: [
    body('token')
      .notEmpty().withMessage('Token é obrigatório')
      .isString().withMessage('Token deve ser texto')
      .isLength({ max: 128 }).withMessage('Token muito longo'),
    
    validators.password()
      .custom(customValidators.strongPassword)
  ],

  verify2FA: [
    validators.twoFactorToken(),
    
    body('tempToken')
      .notEmpty().withMessage('Token temporário é obrigatório')
      .isString().withMessage('Token temporário deve ser texto')
      .isLength({ max: 2000 }).withMessage('Token temporário muito longo')
  ],

  recoveryCode: [
    validators.recoveryCode(),
    
    body('tempToken')
      .notEmpty().withMessage('Token temporário é obrigatório')
      .isString().withMessage('Token temporário deve ser texto')
      .isLength({ max: 2000 }).withMessage('Token temporário muito longo')
  ],
  
  refreshToken: [
    body('refreshToken')
      .optional()
      .isString().withMessage('Refresh token deve ser texto')
      .isLength({ max: 1024 }).withMessage('Refresh token muito longo')
  ],
  
  googleAuth: [
    body('idToken')
      .optional()
      .isString().withMessage('ID token deve ser texto')
      .isLength({ max: 2048 }).withMessage('ID token muito longo')
  ]
};

/**
 * Middleware para validar requisições com base no schema especificado
 * @param {string} schema Nome do schema de validação a ser utilizado
 * @returns {Array<Function>} Middleware de validação
 */
const validate = (schema) => {
  if (!authValidationSchemas[schema]) {
    throw new Error(`Schema de validação '${schema}' não definido`);
  }
  
  return createValidator(authValidationSchemas[schema]);
};

module.exports = {
  validate
};