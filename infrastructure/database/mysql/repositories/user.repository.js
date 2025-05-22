// src/infrastructure/database/mysql/repositories/user.repository.js
const { getConnection } = require('../connection');
const defineModels = require('../models');
const UserRepositoryInterface = require('../../../../domain/users/repositories/user-repository.interface');
const User = require('../../../../domain/users/entities/user.entity');
const { NotFoundError } = require('../../../../shared/errors/api-error');
const { v4: uuidv4 } = require('uuid');
const { Op } = require('sequelize');

/**
 * Implementação MySQL do repositório de usuários
 * @implements {UserRepositoryInterface}
 */
class MySQLUserRepository extends UserRepositoryInterface {
  constructor() {
    super();
    // Inicializar os modelos
    this.models = defineModels();
  }

  /**
   * Converte um modelo Sequelize para uma entidade de domínio
   * @param {Object} model Modelo do Sequelize
   * @returns {User} Entidade de domínio
   */
  _toEntity(model) {
    if (!model) return null;
    
    const userModel = model.toJSON ? model.toJSON() : model;
    
    // Mapear os códigos de recuperação se disponíveis
    let recoveryCodes = [];
    if (userModel.recoveryCodes && userModel.recoveryCodes.length > 0) {
      recoveryCodes = userModel.recoveryCodes.map(rc => ({
        code: rc.code,
        used: rc.used
      }));
    }
    
    // Mapear contas OAuth se disponíveis
    let oauth = {};
    if (userModel.oauthAccounts && userModel.oauthAccounts.length > 0) {
      userModel.oauthAccounts.forEach(account => {
        oauth[account.provider] = {
          id: account.providerId,
          email: account.providerEmail,
          name: account.providerName,
          picture: account.providerPicture
        };
      });
    
    // Atualizar códigos de recuperação, se fornecidos
    if (user.recoveryCodes && user.recoveryCodes.length > 0) {
      // Remover códigos antigos
      await this.models.UserRecoveryCode.destroy({
        where: { userId: user.id }
      });
      
      // Adicionar novos códigos
      const recoveryCodesData = user.recoveryCodes.map(rc => ({
        userId: user.id,
        code: rc.code,
        used: rc.used || false
      }));
      
      await this.models.UserRecoveryCode.bulkCreate(recoveryCodesData);
    }
    
    // Atualizar contas OAuth, se fornecidas
    if (user.oauth) {
      // Primeiro, remover todas as contas existentes
      await this.models.UserOAuth.destroy({
        where: { userId: user.id }
      });
      
      // Depois, criar as novas contas
      for (const [provider, profile] of Object.entries(user.oauth)) {
        await this.models.UserOAuth.create({
          userId: user.id,
          provider,
          providerId: profile.id,
          providerEmail: profile.email,
          providerName: profile.name,
          providerPicture: profile.picture
        });
      }
    }
    
    // Buscar o usuário atualizado com todos os relacionamentos
    const updatedUser = await this.models.User.findByPk(user.id, {
      include: [
        { model: this.models.UserRecoveryCode, as: 'recoveryCodes' },
        { model: this.models.UserOAuth, as: 'oauthAccounts' }
      ]
    });
    
    return this._toEntity(updatedUser);
  }

  /**
   * Desativa um usuário
   * @param {string} id ID do usuário
   * @returns {Promise<User>} Usuário desativado
   */
  async deactivate(id) {
    const userModel = await this.models.User.findByPk(id);
    
    if (!userModel) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    await userModel.update({
      active: false
    });
    
    return this._toEntity(userModel);
  }

  /**
   * Lista usuários com paginação e filtros opcionais
   * @param {Object} options Opções de busca e paginação
   * @returns {Promise<Object>} Resultado paginado com usuários e metadados
   */
  async findAll(options = {}) {
    const { 
      page = 1, 
      limit = 20, 
      sort = 'email', 
      order = 'asc', 
      search = null,
      role = null,
      active = null
    } = options;
    
    // Construir filtro de busca
    const where = {};
    
    if (search) {
      where[Op.or] = [
        { email: { [Op.like]: `%${search}%` } },
        { name: { [Op.like]: `%${search}%` } }
      ];
    }
    
    if (role) {
      where.role = role;
    }
    
    if (active !== null) {
      where.active = active;
    }
    
    // Configurar ordenação
    const sortOption = [[sort, order.toUpperCase()]];
    
    // Buscar usuários com paginação
    const { count, rows } = await this.models.User.findAndCountAll({
      where,
      order: sortOption,
      offset: (page - 1) * limit,
      limit: parseInt(limit),
      include: [
        { model: this.models.UserRecoveryCode, as: 'recoveryCodes' },
        { model: this.models.UserOAuth, as: 'oauthAccounts' }
      ]
    });
    
    // Converter para entidades de domínio
    const userEntities = rows.map(user => this._toEntity(user));
    
    // Retornar resultado paginado
    return {
      users: userEntities,
      pagination: {
        total: count,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(count / limit)
      }
    };
  }

  /**
   * Valida a senha de um usuário
   * @param {string} id ID do usuário
   * @param {string} password Senha a ser validada
   * @returns {Promise<boolean>} Verdadeiro se a senha for válida
   */
  async validatePassword(id, password) {
    const userModel = await this.models.User.findByPk(id);
    
    if (!userModel) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    return await userModel.comparePassword(password);
  }
  
  /**
   * Incrementa o contador de falhas de login e bloqueia conta se necessário
   * @param {string} id ID do usuário
   * @returns {Promise<User>} Usuário atualizado
   */
  async incrementLoginAttempts(id) {
    const userModel = await this.models.User.findByPk(id);
    
    if (!userModel) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    await userModel.incrementLoginAttempts();
    
    return this._toEntity(userModel);
  }
  
  /**
   * Reseta o contador de falhas de login após login bem-sucedido
   * @param {string} id ID do usuário
   * @returns {Promise<User>} Usuário atualizado
   */
  async resetLoginAttempts(id) {
    const userModel = await this.models.User.findByPk(id);
    
    if (!userModel) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    await userModel.resetLoginAttempts();
    
    return this._toEntity(userModel);
  }
}

module.exports = new MySQLUserRepository();
    }
    
    return new User({
      id: userModel.id,
      email: userModel.email,
      password: userModel.password,
      role: userModel.role,
      verified: userModel.verified,
      active: userModel.active,
      twoFactorEnabled: userModel.twoFactorEnabled,
      twoFactorSecret: userModel.twoFactorSecret,
      recoveryCodes: recoveryCodes,
      oauth: oauth,
      name: userModel.name,
      surname: userModel.surname,
      createdAt: userModel.createdAt,
      updatedAt: userModel.updatedAt,
      lastLogin: userModel.lastLogin,
      loginAttempts: userModel.failedLoginAttempts,
      lockUntil: userModel.lockUntil
    });
  }

  /**
   * Cria um novo usuário
   * @param {Object} userData Dados do usuário
   * @returns {Promise<User>} Usuário criado
   */
  async create(userData) {
    // Gerar ID se não fornecido
    if (!userData.id) {
      userData.id = uuidv4();
    }
    
    // Criar o usuário no banco de dados
    const userModel = await this.models.User.create(userData);
    
    // Se tiver códigos de recuperação, criar também
    if (userData.recoveryCodes && userData.recoveryCodes.length > 0) {
      const recoveryCodesData = userData.recoveryCodes.map(rc => ({
        userId: userModel.id,
        code: rc.code,
        used: rc.used || false
      }));
      
      await this.models.UserRecoveryCode.bulkCreate(recoveryCodesData);
    }
    
    // Se tiver dados OAuth, criar também
    if (userData.oauth) {
      for (const [provider, profile] of Object.entries(userData.oauth)) {
        await this.models.UserOAuth.create({
          userId: userModel.id,
          provider,
          providerId: profile.id,
          providerEmail: profile.email,
          providerName: profile.name,
          providerPicture: profile.picture
        });
      }
    }
    
    // Buscar o usuário completo com os relacionamentos
    const fullUser = await this.models.User.findByPk(userModel.id, {
      include: [
        { model: this.models.UserRecoveryCode, as: 'recoveryCodes' },
        { model: this.models.UserOAuth, as: 'oauthAccounts' }
      ]
    });
    
    return this._toEntity(fullUser);
  }

  /**
   * Busca um usuário por ID
   * @param {string} id ID do usuário
   * @returns {Promise<User|null>} Usuário encontrado ou null
   */
  async findById(id) {
    const userModel = await this.models.User.findByPk(id, {
      include: [
        { model: this.models.UserRecoveryCode, as: 'recoveryCodes' },
        { model: this.models.UserOAuth, as: 'oauthAccounts' },
        { 
          model: this.models.UserRole, 
          as: 'roles',
          include: [{ model: this.models.Role }]
        }
      ]
    });
    
    return this._toEntity(userModel);
  }

  /**
   * Busca um usuário por email
   * @param {string} email Email do usuário
   * @returns {Promise<User|null>} Usuário encontrado ou null
   */
  async findByEmail(email) {
    const userModel = await this.models.User.findOne({
      where: { email: email.toLowerCase() },
      include: [
        { model: this.models.UserRecoveryCode, as: 'recoveryCodes' },
        { model: this.models.UserOAuth, as: 'oauthAccounts' },
        { 
          model: this.models.UserRole, 
          as: 'roles',
          include: [{ model: this.models.Role }]
        }
      ]
    });
    
    return this._toEntity(userModel);
  }

  /**
   * Busca um usuário por token de verificação de email
   * @param {string} token Token de verificação
   * @returns {Promise<User|null>} Usuário encontrado ou null
   */
  async findByVerifyToken(token) {
    const userModel = await this.models.User.findOne({
      where: {
        verifyToken: token,
        verifyTokenExpires: { [Op.gt]: new Date() }
      },
      include: [
        { model: this.models.UserRecoveryCode, as: 'recoveryCodes' },
        { model: this.models.UserOAuth, as: 'oauthAccounts' }
      ]
    });
    
    return this._toEntity(userModel);
  }

  /**
   * Busca um usuário por token de redefinição de senha
   * @param {string} token Token de redefinição
   * @returns {Promise<User|null>} Usuário encontrado ou null
   */
  async findByResetToken(token) {
    const userModel = await this.models.User.findOne({
      where: {
        resetToken: token,
        resetTokenExpires: { [Op.gt]: new Date() }
      },
      include: [
        { model: this.models.UserRecoveryCode, as: 'recoveryCodes' },
        { model: this.models.UserOAuth, as: 'oauthAccounts' }
      ]
    });
    
    return this._toEntity(userModel);
  }

  /**
   * Busca um usuário por ID do provedor OAuth
   * @param {string} provider Nome do provedor (google, facebook, etc)
   * @param {string} id ID no provedor
   * @returns {Promise<User|null>} Usuário encontrado ou null
   */
  async findByOAuthId(provider, id) {
    const oauthAccount = await this.models.UserOAuth.findOne({
      where: {
        provider,
        providerId: id
      },
      include: [{
        model: this.models.User,
        include: [
          { model: this.models.UserRecoveryCode, as: 'recoveryCodes' },
          { model: this.models.UserOAuth, as: 'oauthAccounts' }
        ]
      }]
    });
    
    if (!oauthAccount) {
      return null;
    }
    
    return this._toEntity(oauthAccount.User);
  }

  /**
   * Atualiza um usuário
   * @param {string} id ID do usuário
   * @param {Object} userData Dados a serem atualizados
   * @returns {Promise<User>} Usuário atualizado
   */
  async update(id, userData) {
    const userModel = await this.models.User.findByPk(id);
    
    if (!userModel) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    await userModel.update(userData);
    
    const updatedUser = await this.models.User.findByPk(id, {
      include: [
        { model: this.models.UserRecoveryCode, as: 'recoveryCodes' },
        { model: this.models.UserOAuth, as: 'oauthAccounts' }
      ]
    });
    
    return this._toEntity(updatedUser);
  }

  /**
   * Salva as alterações em um usuário existente
   * @param {User} user Instância de usuário com alterações
   * @returns {Promise<User>} Usuário salvo
   */
  async save(user) {
    const userModel = await this.models.User.findByPk(user.id);
    
    if (!userModel) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    // Atualizar campos do modelo com valores da entidade
    await userModel.update({
      email: user.email,
      role: user.role,
      verified: user.verified,
      active: user.active,
      twoFactorEnabled: user.twoFactorEnabled,
      twoFactorSecret: user.twoFactorSecret,
      verifyToken: user.verifyToken,
      verifyTokenExpires: user.verifyTokenExpires,
      resetToken: user.resetToken,
      resetTokenExpires: user.resetTokenExpires,
      name: user.name,
      surname: user.surname,
      lastLogin: user.lastLogin,
      failedLoginAttempts: user.loginAttempts,
      lockUntil: user.lockUntil,
      // Se a senha foi alterada, o hook do modelo fará o hash
      ...(user.password && { password: user.password })
    });