// src/infrastructure/database/mongodb/repositories/user.repository.js
const UserModel = require('../models/user.model');
const UserRepositoryInterface = require('../../../../domain/users/repositories/user-repository.interface');
const User = require('../../../../domain/users/entities/user.entity');
const { NotFoundError } = require('../../../../shared/errors/api-error');
const bcrypt = require('bcryptjs');
const config = require('../../../config');

/**
 * Implementação MongoDB do repositório de usuários
 * @implements {UserRepositoryInterface}
 */
class MongoUserRepository extends UserRepositoryInterface {
  /**
   * Converte um documento Mongoose para uma entidade de domínio
   * @param {Object} doc Documento do Mongoose
   * @returns {User} Entidade de domínio
   */
  _toEntity(doc) {
    if (!doc) return null;
    
    const userDoc = doc.toObject ? doc.toObject() : doc;
    
    return new User({
      id: userDoc._id.toString(),
      email: userDoc.email,
      password: userDoc.password,
      role: userDoc.role,
      verified: userDoc.verified,
      active: userDoc.active,
      twoFactorEnabled: userDoc.twoFactorEnabled,
      twoFactorSecret: userDoc.twoFactorSecret,
      recoveryCodes: userDoc.recoveryCodes || [],
      oauth: userDoc.oauth || {},
      name: userDoc.name,
      surname: userDoc.surname,
      createdAt: userDoc.createdAt,
      updatedAt: userDoc.updatedAt,
      lastLogin: userDoc.lastLogin,
      loginAttempts: userDoc.failedLoginAttempts,
      lockUntil: userDoc.lockUntil
    });
  }

  /**
   * Cria um novo usuário
   * @param {Object} userData Dados do usuário
   * @returns {Promise<User>} Usuário criado
   */
  async create(userData) {
    // Gerar hash da senha se fornecida
    let hashedPassword = userData.password;
    if (userData.password && !userData.password.startsWith('$2')) {
      hashedPassword = await bcrypt.hash(userData.password, config.auth.password.saltRounds);
    }

    const userDoc = await UserModel.create({
      ...userData,
      password: hashedPassword
    });

    return this._toEntity(userDoc);
  }

  /**
   * Busca um usuário por ID
   * @param {string} id ID do usuário
   * @returns {Promise<User|null>} Usuário encontrado ou null
   */
  async findById(id) {
    const userDoc = await UserModel.findById(id);
    return this._toEntity(userDoc);
  }

  /**
   * Busca um usuário por email
   * @param {string} email Email do usuário
   * @returns {Promise<User|null>} Usuário encontrado ou null
   */
  async findByEmail(email) {
    const userDoc = await UserModel.findOne({ email: email.toLowerCase() });
    return this._toEntity(userDoc);
  }

  /**
   * Busca um usuário por token de verificação de email
   * @param {string} token Token de verificação
   * @returns {Promise<User|null>} Usuário encontrado ou null
   */
  async findByVerifyToken(token) {
    const userDoc = await UserModel.findOne({
      verifyToken: token,
      verifyTokenExpires: { $gt: Date.now() }
    });
    return this._toEntity(userDoc);
  }

  /**
   * Busca um usuário por token de redefinição de senha
   * @param {string} token Token de redefinição
   * @returns {Promise<User|null>} Usuário encontrado ou null
   */
  async findByResetToken(token) {
    const userDoc = await UserModel.findOne({
      resetToken: token,
      resetTokenExpires: { $gt: Date.now() }
    });
    return this._toEntity(userDoc);
  }

  /**
   * Busca um usuário por ID do provedor OAuth
   * @param {string} provider Nome do provedor (google, facebook, etc)
   * @param {string} id ID no provedor
   * @returns {Promise<User|null>} Usuário encontrado ou null
   */
  async findByOAuthId(provider, id) {
    const query = {};
    query[`oauth.${provider}.id`] = id;
    
    const userDoc = await UserModel.findOne(query);
    return this._toEntity(userDoc);
  }

  /**
   * Atualiza um usuário
   * @param {string} id ID do usuário
   * @param {Object} userData Dados a serem atualizados
   * @returns {Promise<User>} Usuário atualizado
   */
  async update(id, userData) {
    // Se estiver atualizando a senha, hash primeiro
    if (userData.password && !userData.password.startsWith('$2')) {
      userData.password = await bcrypt.hash(userData.password, config.auth.password.saltRounds);
    }
    
    const userDoc = await UserModel.findByIdAndUpdate(
      id,
      { $set: userData },
      { new: true } // Retorna o documento atualizado
    );
    
    if (!userDoc) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    return this._toEntity(userDoc);
  }

  /**
   * Salva as alterações em um usuário existente
   * @param {User} user Instância de usuário com alterações
   * @returns {Promise<User>} Usuário salvo
   */
  async save(user) {
    const userDoc = await UserModel.findById(user.id);
    
    if (!userDoc) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    // Atualizar campos do documento com valores da entidade
    userDoc.email = user.email;
    userDoc.role = user.role;
    userDoc.verified = user.verified;
    userDoc.active = user.active;
    userDoc.twoFactorEnabled = user.twoFactorEnabled;
    userDoc.twoFactorSecret = user.twoFactorSecret;
    userDoc.recoveryCodes = user.recoveryCodes;
    userDoc.oauth = user.oauth;
    userDoc.name = user.name;
    userDoc.surname = user.surname;
    userDoc.lastLogin = user.lastLogin;
    userDoc.failedLoginAttempts = user.loginAttempts;
    userDoc.lockUntil = user.lockUntil;
    userDoc.updatedAt = new Date();
    
    // Se a senha foi alterada e não está hashed, fazer hash
    if (user.password && !user.password.startsWith('$2')) {
      userDoc.password = await bcrypt.hash(user.password, config.auth.password.saltRounds);
    }
    
    await userDoc.save();
    return this._toEntity(userDoc);
  }

  /**
   * Desativa um usuário
   * @param {string} id ID do usuário
   * @returns {Promise<User>} Usuário desativado
   */
  async deactivate(id) {
    const userDoc = await UserModel.findByIdAndUpdate(
      id,
      { $set: { active: false, updatedAt: new Date() } },
      { new: true }
    );
    
    if (!userDoc) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    return this._toEntity(userDoc);
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
    const query = {};
    
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { name: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (role) {
      query.role = role;
    }
    
    if (active !== null) {
      query.active = active;
    }
    
    // Configurar ordenação
    const sortOption = {};
    sortOption[sort] = order === 'asc' ? 1 : -1;
    
    // Contar total de registros
    const total = await UserModel.countDocuments(query);
    
    // Buscar usuários com paginação
    const users = await UserModel.find(query)
      .sort(sortOption)
      .skip((page - 1) * limit)
      .limit(limit);
    
    // Converter para entidades de domínio
    const userEntities = users.map(user => this._toEntity(user));
    
    // Retornar resultado paginado
    return {
      users: userEntities,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    };
  }

// src/infrastructure/database/mongodb/repositories/user.repository.js - métodos adicionais

/**
 * Valida a senha de um usuário
 * @param {string} id ID do usuário
 * @param {string} password Senha a ser validada
 * @returns {Promise<boolean>} Verdadeiro se a senha for válida
 */
async validatePassword(id, password) {
    const userDoc = await UserModel.findById(id);
    
    if (!userDoc) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    return bcrypt.compare(password, userDoc.password);
  }
  
  /**
   * Incrementa o contador de falhas de login e bloqueia conta se necessário
   * @param {string} id ID do usuário
   * @returns {Promise<User>} Usuário atualizado
   */
  async incrementLoginAttempts(id) {
    const userDoc = await UserModel.findById(id);
    
    if (!userDoc) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    await userDoc.incrementLoginAttempts();
    
    return this._toEntity(await UserModel.findById(id));
  }
  
  /**
   * Reseta o contador de falhas de login após login bem-sucedido
   * @param {string} id ID do usuário
   * @returns {Promise<User>} Usuário atualizado
   */
  async resetLoginAttempts(id) {
    const userDoc = await UserModel.findById(id);
    
    if (!userDoc) {
      throw new NotFoundError('Usuário não encontrado');
    }
    
    await userDoc.resetLoginAttempts();
    
    return this._toEntity(await UserModel.findById(id));
  }
}

module.exports = new MongoUserRepository();