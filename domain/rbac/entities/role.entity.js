// src/domain/rbac/entities/role.entity.js

/**
 * Classe de entidade Role
 * Representa um papel com suas permissões
 */
class Role {
    constructor({
      id,
      name,
      description,
      isSystem = false,
      permissions = [],
      createdAt = new Date(),
      updatedAt = new Date()
    }) {
      this.id = id;
      this.name = name;
      this.description = description;
      this.isSystem = isSystem;
      this.permissions = permissions;
      this.createdAt = createdAt;
      this.updatedAt = updatedAt;
    }
  
    /**
     * Adiciona uma permissão ao papel
     * @param {Object} permission Permissão a ser adicionada
     * @param {Array} resources Recursos associados à permissão
     * @returns {Role} Instância atualizada do papel
     */
    addPermission(permission, resources = []) {
      // Verificar se a permissão já existe
      const existingIndex = this.permissions.findIndex(
        p => p.permission.id === permission.id
      );
  
      if (existingIndex >= 0) {
        // Atualizar recursos da permissão existente
        this.permissions[existingIndex].resources = resources;
      } else {
        // Adicionar nova permissão
        this.permissions.push({
          permission,
          resources
        });
      }
  
      this.updatedAt = new Date();
      return this;
    }
  
    /**
     * Remove uma permissão do papel
     * @param {string} permissionId ID da permissão a ser removida
     * @returns {Role} Instância atualizada do papel
     */
    removePermission(permissionId) {
      this.permissions = this.permissions.filter(
        p => p.permission.id !== permissionId
      );
  
      this.updatedAt = new Date();
      return this;
    }
  
    /**
     * Verifica se o papel tem uma permissão específica
     * @param {string} permissionCode Código da permissão
     * @param {string|null} resourcePath Caminho do recurso (opcional)
     * @returns {boolean} Verdadeiro se o papel tem a permissão
     */
    hasPermission(permissionCode, resourcePath = null) {
      for (const permEntry of this.permissions) {
        if (permEntry.permission.code === permissionCode) {
          // Se não precisamos verificar um recurso específico, a permissão está concedida
          if (!resourcePath) {
            return true;
          }
          
          // Se temos um recurso específico, verificar se está autorizado
          for (const resourceEntry of permEntry.resources) {
            if (resourceEntry.resource && resourceEntry.resource.path === resourcePath) {
              return true;
            }
          }
        }
      }
      
      return false;
    }
  
    /**
     * Atualiza as informações do papel
     * @param {Object} data Dados a serem atualizados
     * @returns {Role} Instância atualizada do papel
     */
    update(data) {
      const allowedFields = [
        'name',
        'description'
      ];
  
      for (const [key, value] of Object.entries(data)) {
        if (allowedFields.includes(key)) {
          this[key] = value;
        }
      }
  
      this.updatedAt = new Date();
      return this;
    }
  
    /**
     * Retorna uma versão sanitizada do papel (sem campos sensíveis)
     * @returns {Object} Objeto do papel sem campos sensíveis
     */
    toSafeObject() {
      return {
        id: this.id,
        name: this.name,
        description: this.description,
        isSystem: this.isSystem,
        permissions: this.permissions.map(p => ({
          permission: {
            id: p.permission.id,
            name: p.permission.name,
            code: p.permission.code,
            category: p.permission.category
          },
          resources: p.resources.map(r => ({
            resource: r.resource ? {
              id: r.resource.id,
              name: r.resource.name,
              type: r.resource.type,
              path: r.resource.path
            } : null,
            conditions: r.conditions
          }))
        })),
        createdAt: this.createdAt,
        updatedAt: this.updatedAt
      };
    }
  }
  
  module.exports = Role;
  
  // src/domain/rbac/entities/permission.entity.js
  
  /**
   * Classe de entidade Permission
   * Representa uma permissão que pode ser atribuída a papéis
   */
  class Permission {
    constructor({
      id,
      name,
      code,
      description,
      category,
      createdAt = new Date(),
      updatedAt = new Date()
    }) {
      this.id = id;
      this.name = name;
      this.code = code;
      this.description = description;
      this.category = category;
      this.createdAt = createdAt;
      this.updatedAt = updatedAt;
    }
  
    /**
     * Atualiza as informações da permissão
     * @param {Object} data Dados a serem atualizados
     * @returns {Permission} Instância atualizada da permissão
     */
    update(data) {
      const allowedFields = [
        'name',
        'description',
        'category'
      ];
  
      for (const [key, value] of Object.entries(data)) {
        if (allowedFields.includes(key)) {
          this[key] = value;
        }
      }
  
      this.updatedAt = new Date();
      return this;
    }
  
    /**
     * Retorna uma versão sanitizada da permissão (sem campos sensíveis)
     * @returns {Object} Objeto da permissão sem campos sensíveis
     */
    toSafeObject() {
      return {
        id: this.id,
        name: this.name,
        code: this.code,
        description: this.description,
        category: this.category,
        createdAt: this.createdAt,
        updatedAt: this.updatedAt
      };
    }
  }
  
  module.exports = Permission;
  
  // src/domain/rbac/entities/resource.entity.js
  
  /**
   * Classe de entidade Resource
   * Representa um recurso que pode ser protegido por permissões
   */
  class Resource {
    constructor({
      id,
      name,
      description,
      type,
      path,
      createdAt = new Date(),
      updatedAt = new Date()
    }) {
      this.id = id;
      this.name = name;
      this.description = description;
      this.type = type;
      this.path = path;
      this.createdAt = createdAt;
      this.updatedAt = updatedAt;
    }
  
    /**
     * Atualiza as informações do recurso
     * @param {Object} data Dados a serem atualizados
     * @returns {Resource} Instância atualizada do recurso
     */
    update(data) {
      const allowedFields = [
        'name',
        'description',
        'type',
        'path'
      ];
  
      for (const [key, value] of Object.entries(data)) {
        if (allowedFields.includes(key)) {
          this[key] = value;
        }
      }
  
      this.updatedAt = new Date();
      return this;
    }
  
    /**
     * Retorna uma versão sanitizada do recurso (sem campos sensíveis)
     * @returns {Object} Objeto do recurso sem campos sensíveis
     */
    toSafeObject() {
      return {
        id: this.id,
        name: this.name,
        description: this.description,
        type: this.type,
        path: this.path,
        createdAt: this.createdAt,
        updatedAt: this.updatedAt
      };
    }
  }
  
  module.exports = Resource;