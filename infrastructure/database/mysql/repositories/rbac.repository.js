// src/infrastructure/database/mysql/repositories/rbac.repository.js
const { getConnection } = require('../connection');
const defineModels = require('../models');
const RbacRepositoryInterface = require('../../../../domain/rbac/repositories/rbac-repository.interface');
const { NotFoundError } = require('../../../../shared/errors/api-error');
const logger = require('../../../logging/logger');
const permissionCache = require('../../../cache/permission-cache');
const { v4: uuidv4 } = require('uuid');
const { Op, Sequelize } = require('sequelize');

/**
 * Implementação MySQL do repositório RBAC
 * @implements {RbacRepositoryInterface}
 */
class MySQLRbacRepository extends RbacRepositoryInterface {
  constructor() {
    super();
    // Inicializar os modelos
    this.models = defineModels();
  }

  /**
   * Cria um novo papel
   * @param {Object} roleData Dados do papel
   * @returns {Promise<Object>} Papel criado
   */
  async createRole(roleData) {
    try {
      const role = await this.models.Role.create({
        id: uuidv4(),
        name: roleData.name,
        description: roleData.description,
        isSystem: roleData.isSystem || false
      });
      
      return role.toJSON();
    } catch (error) {
      logger.error(`Erro ao criar papel: ${error.message}`);
      throw error;
    }
  }

  /**
   * Busca um papel por ID
   * @param {string} id ID do papel
   * @returns {Promise<Object|null>} Papel encontrado ou null
   */
  async findRoleById(id) {
    try {
      const role = await this.models.Role.findByPk(id, {
        include: [{
          model: this.models.RolePermission,
          as: 'rolePermissions',
          include: [
            {
              model: this.models.Permission,
              as: 'permission'
            },
            {
              model: this.models.RolePermissionResource,
              as: 'resources',
              include: [{
                model: this.models.Resource,
                as: 'resource'
              }]
            }
          ]
        }]
      });
      
      if (!role) {
        return null;
      }
      
      // Transformar para o formato esperado pela aplicação
      const roleData = role.toJSON();
      
      // Mapear permissões para o formato esperado
      const permissions = roleData.rolePermissions.map(rp => ({
        permission: rp.permission,
        resources: rp.resources.map(rpr => ({
          resource: rpr.resource,
          conditions: rpr.conditions
        }))
      }));
      
      return {
        ...roleData,
        permissions
      };
    } catch (error) {
      logger.error(`Erro ao buscar papel por ID: ${error.message}`);
      return null;
    }
  }

  /**
   * Busca um papel por nome
   * @param {string} name Nome do papel
   * @returns {Promise<Object|null>} Papel encontrado ou null
   */
  async findRoleByName(name) {
    try {
      const role = await this.models.Role.findOne({
        where: { name },
        include: [{
          model: this.models.RolePermission,
          as: 'rolePermissions',
          include: [
            {
              model: this.models.Permission,
              as: 'permission'
            },
            {
              model: this.models.RolePermissionResource,
              as: 'resources',
              include: [{
                model: this.models.Resource,
                as: 'resource'
              }]
            }
          ]
        }]
      });
      
      if (!role) {
        return null;
      }
      
      // Transformar para o formato esperado pela aplicação
      const roleData = role.toJSON();
      
      // Mapear permissões para o formato esperado
      const permissions = roleData.rolePermissions.map(rp => ({
        permission: rp.permission,
        resources: rp.resources.map(rpr => ({
          resource: rpr.resource,
          conditions: rpr.conditions
        }))
      }));
      
      return {
        ...roleData,
        permissions
      };
    } catch (error) {
      logger.error(`Erro ao buscar papel por nome: ${error.message}`);
      return null;
    }
  }

  /**
   * Lista todos os papéis com paginação e filtros opcionais
   * @param {Object} options Opções de busca e paginação
   * @returns {Promise<Object>} Resultado paginado com papéis e metadados
   */
  async findAllRoles(options = {}) {
    try {
      const { 
        page = 1, 
        limit = 20, 
        sort = 'name', 
        order = 'asc', 
        search = null,
        isSystem = null
      } = options;
      
      // Construir filtro de busca
      const where = {};
      
      if (search) {
        where[Op.or] = [
          { name: { [Op.like]: `%${search}%` } },
          { description: { [Op.like]: `%${search}%` } }
        ];
      }
      
      if (isSystem !== null) {
        where.isSystem = isSystem;
      }
      
      // Configurar ordenação
      const sortOption = [[sort, order.toUpperCase()]];
      
      // Contar total de registros
      const total = await this.models.Role.count({ where });
      
      // Buscar papéis com paginação
      const roles = await this.models.Role.findAll({
        where,
        order: sortOption,
        offset: (page - 1) * limit,
        limit: parseInt(limit),
        include: [{
          model: this.models.RolePermission,
          as: 'rolePermissions',
          include: [{
            model: this.models.Permission,
            as: 'permission'
          }]
        }]
      });
      
      // Transformar para o formato esperado
      const roleObjects = roles.map(role => {
        const roleData = role.toJSON();
        
        // Mapear permissões para o formato esperado
        const permissions = roleData.rolePermissions.map(rp => ({
          permission: rp.permission
        }));
        
        return {
          ...roleData,
          permissions
        };
      });
      
      // Retornar resultado paginado
      return {
        roles: roleObjects,
        pagination: this._buildPaginationData(total, page, limit)
      };
    } catch (error) {
      logger.error(`Erro ao listar papéis: ${error.message}`);
      throw error;
    }
  }

  /**
   * Atualiza um papel
   * @param {string} id ID do papel
   * @param {Object} roleData Dados a serem atualizados
   * @returns {Promise<Object>} Papel atualizado
   */
  async updateRole(id, roleData) {
    try {
      const role = await this.models.Role.findByPk(id);
      
      if (!role) {
        throw new NotFoundError('Papel não encontrado');
      }
      
      await role.update(roleData);
      
      // Invalidar cache de permissões relacionadas a este papel
      await this._invalidateRoleCache(id);
      
      // Buscar papel atualizado com relações
      const updatedRole = await this.findRoleById(id);
      
      return updatedRole;
    } catch (error) {
      logger.error(`Erro ao atualizar papel: ${error.message}`);
      throw error;
    }
  }

  /**
   * Remove um papel
   * @param {string} id ID do papel
   * @returns {Promise<boolean>} Verdadeiro se removido com sucesso
   */
  async deleteRole(id) {
    try {
      const role = await this.models.Role.findByPk(id);
      
      if (!role) {
        throw new NotFoundError('Papel não encontrado');
      }
      
      // Verificar se é um papel do sistema
      if (role.isSystem) {
        throw new Error('Não é possível remover um papel do sistema');
      }
      
      // Remover todas as atribuições de usuários
      await this.models.UserRole.destroy({
        where: { roleId: id }
      });
      
      // Remover todas as permissões do papel
      const rolePermissions = await this.models.RolePermission.findAll({
        where: { roleId: id }
      });
      
      // Remover recursos associados a permissões do papel
      for (const rp of rolePermissions) {
        await this.models.RolePermissionResource.destroy({
          where: { rolePermissionId: rp.id }
        });
      }
      
      // Remover permissões do papel
      await this.models.RolePermission.destroy({
        where: { roleId: id }
      });
      
      // Finalmente, remover o papel
      await role.destroy();
      
      // Invalidar cache de permissões relacionadas a este papel
      await this._invalidateRoleCache(id);
      
      return true;
    } catch (error) {
      logger.error(`Erro ao remover papel: ${error.message}`);
      throw error;
    }
  }

  /**
   * Cria uma nova permissão
   * @param {Object} permissionData Dados da permissão
   * @returns {Promise<Object>} Permissão criada
   */
  async createPermission(permissionData) {
    try {
      const permission = await this.models.Permission.create({
        id: uuidv4(),
        name: permissionData.name,
        code: permissionData.code.toUpperCase(),
        description: permissionData.description,
        category: permissionData.category
      });
      
      return permission.toJSON();
    } catch (error) {
      logger.error(`Erro ao criar permissão: ${error.message}`);
      throw error;
    }
  }

  /**
   * Busca uma permissão por ID
   * @param {string} id ID da permissão
   * @returns {Promise<Object|null>} Permissão encontrada ou null
   */
  async findPermissionById(id) {
    try {
      const permission = await this.models.Permission.findByPk(id);
      return permission ? permission.toJSON() : null;
    } catch (error) {
      logger.error(`Erro ao buscar permissão por ID: ${error.message}`);
      return null;
    }
  }

  /**
   * Busca uma permissão por código
   * @param {string} code Código da permissão
   * @returns {Promise<Object|null>} Permissão encontrada ou null
   */
  async findPermissionByCode(code) {
    try {
      const permission = await this.models.Permission.findOne({
        where: { code: code.toUpperCase() }
      });
      return permission ? permission.toJSON() : null;
    } catch (error) {
      logger.error(`Erro ao buscar permissão por código: ${error.message}`);
      return null;
    }
  }

  /**
   * Lista todas as permissões com paginação e filtros opcionais
   * @param {Object} options Opções de busca e paginação
   * @returns {Promise<Object>} Resultado paginado com permissões e metadados
   */
  async findAllPermissions(options = {}) {
    try {
      const { 
        page = 1, 
        limit = 20, 
        sort = 'name', 
        order = 'asc', 
        search = null,
        category = null
      } = options;
      
      // Construir filtro de busca
      const where = {};
      
      if (search) {
        where[Op.or] = [
          { name: { [Op.like]: `%${search}%` } },
          { code: { [Op.like]: `%${search}%` } },
          { description: { [Op.like]: `%${search}%` } }
        ];
      }
      
      if (category) {
        where.category = category;
      }
      
      // Configurar ordenação
      const sortOption = [[sort, order.toUpperCase()]];
      
      // Contar total de registros
      const total = await this.models.Permission.count({ where });
      
      // Buscar permissões com paginação
      const permissions = await this.models.Permission.findAll({
        where,
        order: sortOption,
        offset: (page - 1) * limit,
        limit: parseInt(limit)
      });
      
      // Converter para objetos
      const permissionObjects = permissions.map(permission => permission.toJSON());
      
      // Retornar resultado paginado
      return {
        permissions: permissionObjects,
        pagination: this._buildPaginationData(total, page, limit)
      };
    } catch (error) {
      logger.error(`Erro ao listar permissões: ${error.message}`);
      throw error;
    }
  }

  /**
   * Atualiza uma permissão
   * @param {string} id ID da permissão
   * @param {Object} permissionData Dados a serem atualizados
   * @returns {Promise<Object>} Permissão atualizada
   */
  async updatePermission(id, permissionData) {
    try {
      const permission = await this.models.Permission.findByPk(id);
      
      if (!permission) {
        throw new NotFoundError('Permissão não encontrada');
      }
      
      await permission.update(permissionData);
      
      // Invalidar cache de permissões
      permissionCache.invalidateAll();
      
      return permission.toJSON();
    } catch (error) {
      logger.error(`Erro ao atualizar permissão: ${error.message}`);
      throw error;
    }
  }

  /**
   * Remove uma permissão
   * @param {string} id ID da permissão
   * @returns {Promise<boolean>} Verdadeiro se removida com sucesso
   */
  async deletePermission(id) {
    try {
      const permission = await this.models.Permission.findByPk(id);
      
      if (!permission) {
        throw new NotFoundError('Permissão não encontrada');
      }
      
      // Verificar se a permissão está sendo usada por algum papel
      const rolePermissions = await this.models.RolePermission.findAll({
        where: { permissionId: id }
      });
      
      if (rolePermissions.length > 0) {
        throw new Error('Esta permissão está sendo utilizada por um ou mais papéis');
      }
      
      await permission.destroy();
      
      // Invalidar cache de permissões
      permissionCache.invalidateAll();
      
      return true;
    } catch (error) {
      logger.error(`Erro ao remover permissão: ${error.message}`);
      throw error;
    }
  }