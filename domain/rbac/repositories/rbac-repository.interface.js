// src/domain/rbac/repositories/rbac-repository.interface.js

/**
 * Interface para o repositório RBAC
 * Define os métodos que qualquer implementação de repositório RBAC deve fornecer
 */
class RbacRepositoryInterface {
    /**
     * Cria um novo papel
     * @param {Object} roleData Dados do papel
     * @returns {Promise<Object>} Papel criado
     */
    async createRole(roleData) {
      throw new Error('Method not implemented: createRole');
    }
  
    /**
     * Busca um papel por ID
     * @param {string} id ID do papel
     * @returns {Promise<Object|null>} Papel encontrado ou null
     */
    async findRoleById(id) {
      throw new Error('Method not implemented: findRoleById');
    }
  
    /**
     * Busca um papel por nome
     * @param {string} name Nome do papel
     * @returns {Promise<Object|null>} Papel encontrado ou null
     */
    async findRoleByName(name) {
      throw new Error('Method not implemented: findRoleByName');
    }
  
    /**
     * Lista todos os papéis com paginação e filtros opcionais
     * @param {Object} options Opções de busca e paginação
     * @returns {Promise<Object>} Resultado paginado com papéis e metadados
     */
    async findAllRoles(options) {
      throw new Error('Method not implemented: findAllRoles');
    }
  
    /**
     * Atualiza um papel
     * @param {string} id ID do papel
     * @param {Object} roleData Dados a serem atualizados
     * @returns {Promise<Object>} Papel atualizado
     */
    async updateRole(id, roleData) {
      throw new Error('Method not implemented: updateRole');
    }
  
    /**
     * Remove um papel
     * @param {string} id ID do papel
     * @returns {Promise<boolean>} Verdadeiro se removido com sucesso
     */
    async deleteRole(id) {
      throw new Error('Method not implemented: deleteRole');
    }
  
    /**
     * Cria uma nova permissão
     * @param {Object} permissionData Dados da permissão
     * @returns {Promise<Object>} Permissão criada
     */
    async createPermission(permissionData) {
      throw new Error('Method not implemented: createPermission');
    }
  
    /**
     * Busca uma permissão por ID
     * @param {string} id ID da permissão
     * @returns {Promise<Object|null>} Permissão encontrada ou null
     */
    async findPermissionById(id) {
      throw new Error('Method not implemented: findPermissionById');
    }
  
    /**
     * Busca uma permissão por código
     * @param {string} code Código da permissão
     * @returns {Promise<Object|null>} Permissão encontrada ou null
     */
    async findPermissionByCode(code) {
      throw new Error('Method not implemented: findPermissionByCode');
    }
  
    /**
     * Lista todas as permissões com paginação e filtros opcionais
     * @param {Object} options Opções de busca e paginação
     * @returns {Promise<Object>} Resultado paginado com permissões e metadados
     */
    async findAllPermissions(options) {
      throw new Error('Method not implemented: findAllPermissions');
    }
  
    /**
     * Atualiza uma permissão
     * @param {string} id ID da permissão
     * @param {Object} permissionData Dados a serem atualizados
     * @returns {Promise<Object>} Permissão atualizada
     */
    async updatePermission(id, permissionData) {
      throw new Error('Method not implemented: updatePermission');
    }
  
    /**
     * Remove uma permissão
     * @param {string} id ID da permissão
     * @returns {Promise<boolean>} Verdadeiro se removida com sucesso
     */
    async deletePermission(id) {
      throw new Error('Method not implemented: deletePermission');
    }
  
    /**
     * Cria um novo recurso
     * @param {Object} resourceData Dados do recurso
     * @returns {Promise<Object>} Recurso criado
     */
    async createResource(resourceData) {
      throw new Error('Method not implemented: createResource');
    }
  
    /**
     * Busca um recurso por ID
     * @param {string} id ID do recurso
     * @returns {Promise<Object|null>} Recurso encontrado ou null
     */
    async findResourceById(id) {
      throw new Error('Method not implemented: findResourceById');
    }
  
    /**
     * Busca um recurso por caminho
     * @param {string} path Caminho do recurso
     * @returns {Promise<Object|null>} Recurso encontrado ou null
     */
    async findResourceByPath(path) {
      throw new Error('Method not implemented: findResourceByPath');
    }
  
    /**
     * Lista todos os recursos com paginação e filtros opcionais
     * @param {Object} options Opções de busca e paginação
     * @returns {Promise<Object>} Resultado paginado com recursos e metadados
     */
    async findAllResources(options) {
      throw new Error('Method not implemented: findAllResources');
    }
  
    /**
     * Atualiza um recurso
     * @param {string} id ID do recurso
     * @param {Object} resourceData Dados a serem atualizados
     * @returns {Promise<Object>} Recurso atualizado
     */
    async updateResource(id, resourceData) {
      throw new Error('Method not implemented: updateResource');
    }
  
    /**
     * Remove um recurso
     * @param {string} id ID do recurso
     * @returns {Promise<boolean>} Verdadeiro se removido com sucesso
     */
    async deleteResource(id) {
      throw new Error('Method not implemented: deleteResource');
    }
  
    /**
     * Adiciona uma permissão a um papel
     * @param {string} roleId ID do papel
     * @param {string} permissionId ID da permissão
     * @param {Array} resources Lista de recursos associados à permissão
     * @returns {Promise<Object>} Papel atualizado
     */
    async addPermissionToRole(roleId, permissionId, resources = []) {
      throw new Error('Method not implemented: addPermissionToRole');
    }
  
    /**
     * Remove uma permissão de um papel
     * @param {string} roleId ID do papel
     * @param {string} permissionId ID da permissão
     * @returns {Promise<Object>} Papel atualizado
     */
    async removePermissionFromRole(roleId, permissionId) {
      throw new Error('Method not implemented: removePermissionFromRole');
    }
  
    /**
     * Verifica se um papel tem uma permissão específica
     * @param {string} roleId ID do papel
     * @param {string} permissionCode Código da permissão
     * @param {string|null} resourcePath Caminho do recurso (opcional)
     * @returns {Promise<boolean>} Verdadeiro se o papel tem a permissão
     */
    async roleHasPermission(roleId, permissionCode, resourcePath = null) {
      throw new Error('Method not implemented: roleHasPermission');
    }
  }
  
  module.exports = RbacRepositoryInterface;