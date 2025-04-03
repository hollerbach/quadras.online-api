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
}

module.exports = new UserService();
