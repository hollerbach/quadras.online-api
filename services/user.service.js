// services/user.service.js
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/user.model');
const logger = require('./logger');
const { ApiError } = require('../middlewares/errorHandler.middleware');
const config = require('../config/env.config');

class UserService {
  /**
   * Cria um novo usuário no sistema
   * @param {Object} userData - Dados do usuário
   * @returns {Promise<Object>} Usuário criado sem dados sensíveis
   */
  async createUser(userData) {
    const { email, password, role = 'user', enable2FA = false } = userData;

    // Verificar se usuário já existe
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new ApiError(400, 'Email já está em uso');
    }

    // Gerar hash da senha
    const hashedPassword = await bcrypt.hash(password, config.auth.password.saltRounds);

    // Gerar token de verificação
    const verifyToken = crypto.randomBytes(32).toString('hex');
    const verifyTokenExpires = Date.now() + config.auth.verification.tokenExpiry;

    // Criar o usuário
    const user = new User({
      email,
      password: hashedPassword,
      role,
      verified: false,
      verifyToken,
      verifyTokenExpires,
      twoFactorEnabled: enable2FA
    });

    await user.save();
    logger.info(`Novo usuário registrado: ${email}`);

    // Retornar usuário sem dados sensíveis
    const userResponse = user.toObject();
    delete userResponse.password;
    delete userResponse.verifyToken;
    delete userResponse.twoFactorSecret;

    return {
      user: userResponse,
      verifyToken
    };
  }

  /**
   * Busca um usuário por ID
   * @param {string} id - ID do usuário
   * @returns {Promise<Object>} Usuário encontrado
   */
  async findById(id) {
    const user = await User.findById(id);
    if (!user) {
      throw new ApiError(404, 'Usuário não encontrado');
    }
    return user;
  }

  /**
   * Atualiza os dados de um usuário
   * @param {string} userId - ID do usuário
   * @param {Object} updates - Dados a serem atualizados
   * @returns {Promise<Object>} Usuário atualizado
   */
  async updateUser(userId, updates) {
    const user = await this.findById(userId);

    // Aplicar atualizações
    Object.keys(updates).forEach(key => {
      if (
        key !== 'password' &&
        key !== 'role' &&
        key !== 'verified' &&
        key !== 'twoFactorEnabled' &&
        key !== 'twoFactorSecret'
      ) {
        user[key] = updates[key];
      }
    });

    await user.save();
    return user;
  }

  /**
   * Altera a senha de um usuário
   * @param {string} userId - ID do usuário
   * @param {string} currentPassword - Senha atual
   * @param {string} newPassword - Nova senha
   * @returns {Promise<Object>} Resultado da operação
   */
  async changePassword(userId, currentPassword, newPassword) {
    const user = await this.findById(userId);

    // Verificar senha atual
    const isValid = await bcrypt.compare(currentPassword, user.password);
    if (!isValid) {
      throw new ApiError(400, 'Senha atual incorreta');
    }

    // Atualizar senha
    user.password = await bcrypt.hash(newPassword, config.auth.password.saltRounds);
    await user.save();

    return { message: 'Senha alterada com sucesso' };
  }

  /**
   * Busca todos os usuários com paginação e filtros
   * @param {Object} options - Opções de busca e paginação
   * @returns {Promise<Object>} Usuários encontrados e metadados de paginação
   */
  async findAllUsers(options) {
    const { page, limit, sort, order, search } = options;

    // Montar query
    let query = {};
    if (search) {
      query.email = { $regex: search, $options: 'i' };
    }

    // Calcular total
    const total = await User.countDocuments(query);

    // Ordenação
    const sortOptions = {};
    sortOptions[sort] = order === 'desc' ? -1 : 1;

    // Executar query com paginação
    const users = await User.find(query)
      .sort(sortOptions)
      .skip((page - 1) * limit)
      .limit(limit);

    return {
      users,
      total,
      page,
      limit,
      pages: Math.ceil(total / limit)
    };
  }

  /**
   * Atualiza um usuário por um administrador
   * @param {string} userId - ID do usuário
   * @param {Object} updates - Dados a serem atualizados
   * @returns {Promise<Object>} Usuário atualizado
   */
  async adminUpdateUser(userId, updates) {
    const user = await this.findById(userId);

    // Aplicar atualizações permitidas para admin
    Object.keys(updates).forEach(key => {
      if (key !== 'password' && key !== 'twoFactorSecret') {
        user[key] = updates[key];
      }
    });

    await user.save();
    return user;
  }

  /**
   * Desativa um usuário (sem excluir do banco)
   * @param {string} userId - ID do usuário
   * @returns {Promise<Object>} Resultado da operação
   */
  async deactivateUser(userId) {
    const user = await this.findById(userId);

    user.active = false;
    await user.save();

    return { message: 'Usuário desativado com sucesso' };
  }

  /**
   * Sanitiza dados do usuário para retorno na API
   * @param {Object} user - Usuário a ser sanitizado
   * @param {boolean} isAdmin - Se o sanitizador está sendo usado por um admin
   * @returns {Object} Usuário sem dados sensíveis
   */
  sanitizeUser(user, isAdmin = false) {
    const sanitized = user.toObject ? user.toObject() : { ...user };

    // Remover campos sensíveis
    delete sanitized.password;
    delete sanitized.twoFactorSecret;
    delete sanitized.verifyToken;
    delete sanitized.verifyTokenExpires;
    delete sanitized.resetToken;
    delete sanitized.resetTokenExpires;

    // Se não for admin, remover campos adicionais
    if (!isAdmin) {
      delete sanitized.failedLoginAttempts;
      delete sanitized.lockUntil;
    }

    return sanitized;
  }

  /**
   * Verifica o email do usuário usando um token
   * @param {string} token - Token de verificação
   * @returns {Promise<Object>} Resultado da verificação
   */
  async verifyEmail(token) {
    const user = await User.findOne({
      verifyToken: token,
      verifyTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      throw new ApiError(400, 'Token de verificação inválido ou expirado');
    }

    user.verified = true;
    user.verifyToken = undefined;
    user.verifyTokenExpires = undefined;
    await user.save();

    logger.info(`Email verificado com sucesso: ${user.email}`);
    return { message: 'Email verificado com sucesso' };
  }

  /**
   * Cria um token para redefinição de senha
   * @param {string} email - Email do usuário
   * @returns {Promise<Object>} Token de redefinição
   */
  async createPasswordResetToken(email) {
    const user = await User.findOne({ email });
    if (!user) {
      throw new ApiError(404, 'Usuário não encontrado');
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpires = Date.now() + config.auth.password.resetTokenExpiry;
    await user.save();

    logger.info(`Token de redefinição de senha gerado para: ${email}`);
    return { email, resetToken };
  }

  /**
   * Redefine a senha do usuário usando um token
   * @param {string} token - Token de redefinição
   * @param {string} newPassword - Nova senha
   * @returns {Promise<Object>} Resultado da operação
   */
  async resetPassword(token, newPassword) {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      throw new ApiError(400, 'Token de redefinição inválido ou expirado');
    }

    user.password = await bcrypt.hash(newPassword, config.auth.password.saltRounds);
    user.resetToken = undefined;
    user.resetTokenExpires = undefined;
    await user.save();

    logger.info(`Senha redefinida com sucesso para: ${user.email}`);
    return { message: 'Senha redefinida com sucesso' };
  }

  /**
   * Ativa 2FA para um usuário
   * @param {string} userId - ID do usuário
   * @param {string} secret - Segredo 2FA gerado
   * @returns {Promise<Object>} Usuário atualizado
   */
  async enable2FA(userId, secret) {
    const user = await User.findById(userId);
    if (!user) {
      throw new ApiError(404, 'Usuário não encontrado');
    }

    user.twoFactorSecret = secret;
    user.twoFactorEnabled = true;
    await user.save();

    logger.info(`2FA ativado para usuário: ${user.email}`);
    return user;
  }

  /**
   * Desativa 2FA para um usuário
   * @param {string} userId - ID do usuário
   * @returns {Promise<Object>} Usuário atualizado
   */
  async disable2FA(userId) {
    const user = await User.findById(userId);
    if (!user) {
      throw new ApiError(404, 'Usuário não encontrado');
    }

    user.twoFactorSecret = undefined;
    user.twoFactorEnabled = false;
    await user.save();

    logger.info(`2FA desativado para usuário: ${user.email}`);
    return user;
  }

  /**
   * Busca um usuário por email e verifica credenciais
   * @param {string} email - Email do usuário
   * @param {string} password - Senha fornecida
   * @returns {Promise<Object>} Usuário verificado
   */
  async validateCredentials(email, password) {
    const user = await User.findOne({ email });
    if (!user) {
      throw new ApiError(401, 'Credenciais inválidas');
    }

    if (!user.verified) {
      throw new ApiError(403, 'Conta não verificada. Verifique seu email.');
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      throw new ApiError(401, 'Credenciais inválidas');
    }

    return user;
  }

  // Adicionar ao userService.js
  /**
   * Incrementa contador de falhas de login e bloqueia conta se necessário
   * @param {string} email - Email do usuário
   * @returns {Promise<Object>} Informação sobre bloqueio
   */
  async incrementLoginAttempts(email) {
    const user = await User.findOne({ email });
    if (!user) {
      // Mesmo para usuários que não existem, simular delays para evitar
      // inferência de existência por timing attacks
      await new Promise(resolve => setTimeout(resolve, Math.random() * 500));
      return null;
    }

    await user.incrementLoginAttempts();

    return {
      isLocked: user.isLocked(),
      attemptsRemaining: Math.max(0, 5 - user.failedLoginAttempts),
      lockExpiry: user.lockUntil
    };
  }

  /**
   * Reseta contador de falhas de login após login bem-sucedido
   * @param {string} userId - ID do usuário
   */
  async resetLoginAttempts(userId) {
    const user = await this.findById(userId);
    await user.resetLoginAttempts();
  }
}

module.exports = new UserService();
