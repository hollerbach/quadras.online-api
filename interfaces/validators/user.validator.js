// src/interfaces/api/validators/user.validator.js
const { body } = require('express-validator');
const { validators, createValidator } = require('../middlewares/validation.middleware');
const { BadRequestError } = require('../../shared/errors/api-error');
const userRepository = require('../../infrastructure/database/mysql/repositories/user.repository');

/**
 * Validações avançadas específicas do domínio
 */
const customValidators = {
  /**
   * Verifica se o ID de usuário existe
   */
  userExists: async (userId) => {
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new Error('Usuário não encontrado');
    }
    return true;
  },
  
  /**
   * Verificações específicas para dados de perfil
   */
  validProfileData: (value, { req }) => {
    // Verificar se há tentativa de atualizar campos protegidos
    const protectedFields = ['password', 'email', 'role', 'verified', 'twoFactorSecret'];
    
    for (const field of protectedFields) {
      if (field in req.body) {
        throw new Error(`Não é permitido atualizar o campo "${field}" através desta rota`);
      }
    }
    
    return true;
  }
};

/**
 * Schemas de validação para usuários
 */
const userValidationSchemas = {
  updateProfile: [
    // Verificar se não há campos protegidos
    body().custom(customValidators.validProfileData),
    
    validators.name(),
    
    body('surname')
      .optional()
      .isLength({ max: 100 }).withMessage('Sobrenome muito longo')
      .matches(/^[a-zA-Z0-9\s.\-']+$/).withMessage('Sobrenome contém caracteres inválidos')
      .trim()
      .escape(),
    
    body('phoneNumber')
      .optional()
      .isMobilePhone().withMessage('Número de telefone inválido')
      .trim(),
    
    // Validação para cada campo do endereço
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
      .trim(),
      
    // Validação para preferências do usuário (exemplo)
    body('preferences')
      .optional()
      .isObject().withMessage('Preferências devem ser um objeto'),
      
    body('preferences.language')
      .optional()
      .isString().withMessage('Idioma deve ser texto')
      .isLength({ max: 10 }).withMessage('Idioma inválido')
      .trim(),
      
    body('preferences.timezone')
      .optional()
      .isString().withMessage('Fuso horário deve ser texto')
      .isLength({ max: 50 }).withMessage('Fuso horário inválido')
      .trim(),
      
    body('preferences.currency')
      .optional()
      .isString().withMessage('Moeda deve ser texto')
      .isLength({ max: 3 }).withMessage('Moeda inválida')
      .trim(),
      
    // Validação para notificações
    body('notifications')
      .optional()
      .isObject().withMessage('Configurações de notificação devem ser um objeto'),
      
    body('notifications.email')
      .optional()
      .isBoolean().withMessage('Notificação por email deve ser booleano'),
      
    body('notifications.push')
      .optional()
      .isBoolean().withMessage('Notificação push deve ser booleano'),
      
    body('notifications.sms')
      .optional()
      .isBoolean().withMessage('Notificação SMS deve ser booleano')
  ],

  changePassword: [
    body('currentPassword')
      .notEmpty().withMessage('Senha atual é obrigatória')
      .isString().withMessage('Senha atual deve ser texto')
      .isLength({ max: 128 }).withMessage('Senha atual muito longa'),
    
    validators.password()
      .custom((value, { req }) => {
        // Verificar se a nova senha é diferente da atual
        if (value === req.body.currentPassword) {
          throw new Error('Nova senha deve ser diferente da senha atual');
        }
        return true;
      }),
      
    // Confirmar nova senha (opcional)
    body('confirmPassword')
      .optional()
      .isString().withMessage('Confirmação de senha deve ser texto')
      .custom((value, { req }) => {
        if (value !== req.body.newPassword) {
          throw new Error('Senhas não coincidem');
        }
        return true;
      })
  ],

  adminUpdateUser: [
    // Verificar se usuário existe (via middleware posterior)
    
    body('role')
      .optional()
      .isIn(['user', 'admin']).withMessage('Função inválida'),
    
    body('verified')
      .optional()
      .isBoolean().withMessage('O campo verified deve ser um booleano'),
    
    body('active')
      .optional()
      .isBoolean().withMessage('O campo active deve ser um booleano'),
    
    body('twoFactorEnabled')
      .optional()
      .isBoolean().withMessage('O campo twoFactorEnabled deve ser um booleano'),
    
    validators.name(),
    
    body('surname')
      .optional()
      .isLength({ max: 100 }).withMessage('Sobrenome muito longo')
      .matches(/^[a-zA-Z0-9\s.\-']+$/).withMessage('Sobrenome contém caracteres inválidos')
      .trim()
      .escape(),
      
    // Limitação de número de campos permitidos
    body()
      .custom((value, { req }) => {
        const allowedFields = ['role', 'verified', 'active', 'twoFactorEnabled', 'name', 'surname'];
        const providedFields = Object.keys(req.body);
        
        // Verificar se todos os campos fornecidos são permitidos
        const invalidFields = providedFields.filter(field => !allowedFields.includes(field));
        
        if (invalidFields.length > 0) {
          throw new Error(`Campos não permitidos: ${invalidFields.join(', ')}`);
        }
        
        return true;
      })
  ],
  
  getAllUsers: [
    validators.page(),
    validators.limit(),
    validators.search(),
    
    body('filters')
      .optional()
      .isObject().withMessage('Filtros devem ser um objeto'),
      
    body('filters.role')
      .optional()
      .isIn(['user', 'admin']).withMessage('Função inválida'),
      
    body('filters.active')
      .optional()
      .isBoolean().withMessage('Status ativo deve ser booleano'),
      
    body('filters.verified')
      .optional()
      .isBoolean().withMessage('Status verificado deve ser booleano')
  ],
  
  getUserById: [
    validators.id() // Validação de ID
  ],
  
  deactivateUser: [
    validators.id(), // Validação de ID
    
    // Impedir que usuário desative a própria conta
    body()
      .custom((value, { req }) => {
        if (req.params.id === req.user?.id) {
          throw new Error('Não é possível desativar sua própria conta');
        }
        return true;
      })
  ]
};

/**
 * Middleware para validar requisições com base no schema especificado
 * @param {string} schema Nome do schema de validação a ser utilizado
 * @returns {Array<Function>} Middleware de validação
 */
const validate = (schema) => {
  if (!userValidationSchemas[schema]) {
    throw new Error(`Schema de validação '${schema}' não definido`);
  }
  
  return createValidator(userValidationSchemas[schema]);
};

module.exports = {
  validate
};