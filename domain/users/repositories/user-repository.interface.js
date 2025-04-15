// src/domain/users/repositories/user-repository.interface.js

/**
 * Interface para o repositório de usuários
 * Define os métodos que qualquer implementação de repositório de usuários deve fornecer
 */
class UserRepositoryInterface {
    /**
     * Cria um novo usuário
     * @param {Object} userData Dados do usuário
     * @returns {Promise<User>} Usuário criado
     */
    async create(userData) {
      throw new Error('Method not implemented: create');
    }
  
    /**
     * Busca um usuário por ID
     * @param {string} id ID do usuário
     * @returns {Promise<User|null>} Usuário encontrado ou null
     */
    async findById(id) {
      throw new Error('Method not implemented: findById');
    }
  
    /**
     * Busca um usuário por email
     * @param {string} email Email do usuário
     * @returns {Promise<User|null>} Usuário encontrado ou null
     */
    async findByEmail(email) {
      throw new Error('Method not implemented: findByEmail');
    }
  
    /**
     * Busca um usuário por token de verificação de email
     * @param {string} token Token de verificação
     * @returns {Promise<User|null>} Usuário encontrado ou null
     */
    async findByVerifyToken(token) {
      throw new Error('Method not implemented: findByVerifyToken');
    }
  
    /**
     * Busca um usuário por token de redefinição de senha
     * @param {string} token Token de redefinição
     * @returns {Promise<User|null>} Usuário encontrado ou null
     */
    async findByResetToken(token) {
      throw new Error('Method not implemented: findByResetToken');
    }
  
    /**
     * Busca um usuário por ID do provedor OAuth
     * @param {string} provider Nome do provedor (google, facebook, etc)
     * @param {string} id ID no provedor
     * @returns {Promise<User|null>} Usuário encontrado ou null
     */
    async findByOAuthId(provider, id) {
      throw new Error('Method not implemented: findByOAuthId');
    }
  
    /**
     * Atualiza um usuário
     * @param {string} id ID do usuário
     * @param {Object} userData Dados a serem atualizados
     * @returns {Promise<User>} Usuário atualizado
     */
    async update(id, userData) {
      throw new Error('Method not implemented: update');
    }
  
    /**
     * Salva as alterações em um usuário existente
     * @param {User} user Instância de usuário com alterações
     * @returns {Promise<User>} Usuário salvo
     */
    async save(user) {
      throw new Error('Method not implemented: save');
    }
  
    /**
     * Desativa um usuário
     * @param {string} id ID do usuário
     * @returns {Promise<User>} Usuário desativado
     */
    async deactivate(id) {
      throw new Error('Method not implemented: deactivate');
    }
  
    /**
     * Lista usuários com paginação e filtros opcionais
     * @param {Object} options Opções de busca e paginação
     * @returns {Promise<Object>} Resultado paginado com usuários e metadados
     */
    async findAll(options) {
      throw new Error('Method not implemented: findAll');
    }
  }
  
  module.exports = UserRepositoryInterface;