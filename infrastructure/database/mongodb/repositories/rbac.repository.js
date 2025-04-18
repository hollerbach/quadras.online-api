// src/infrastructure/database/mongodb/repositories/rbac.repository.js
const { Role, Permission, Resource } = require('../models/rbac.models');
const RbacRepositoryInterface = require('../../../../domain/rbac/repositories/rbac-repository.interface');
const { NotFoundError } = require('../../../../shared/errors/api-error');
const logger = require('../../../logging/logger');



/**
 * Implementação MongoDB do repositório RBAC
 * @implements {RbacRepositoryInterface}
 */
class MongoRbacRepository extends RbacRepositoryInterface {
  /**
   * Cria um novo papel
   * @param {Object} roleData Dados do papel
   * @returns {Promise<Object>} Papel criado
   */
  async createRole(roleData) {
    try {
      const role = await Role.create(roleData);
      return role.toObject();
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
      const role = await Role.findById(id)
        .populate({
          path: 'permissions.permission',
          model: 'Permission'
        })
        .populate({
          path: 'permissions.resources.resource',
          model: 'Resource'
        });
      return role ? role.toObject() : null;
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
      const role = await Role.findOne({ name })
        .populate({
          path: 'permissions.permission',
          model: 'Permission'
        })
        .populate({
          path: 'permissions.resources.resource',
          model: 'Resource'
        });
      return role ? role.toObject() : null;
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
      const query = {};
      
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } }
        ];
      }
      
      if (isSystem !== null) {
        query.isSystem = isSystem;
      }
      
      // Configurar ordenação
      const sortOption = {};
      sortOption[sort] = order === 'asc' ? 1 : -1;
      
      // Contar total de registros
      const total = await Role.countDocuments(query);
      
      // Buscar papéis com paginação
      const roles = await Role.find(query)
        .sort(sortOption)
        .skip((page - 1) * limit)
        .limit(limit)
        .populate({
          path: 'permissions.permission',
          model: 'Permission'
        });
      
      // Converter para objetos
      const roleObjects = roles.map(role => role.toObject());
      
      // Retornar resultado paginado
      return {
        roles: roleObjects,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(total / limit)
        }
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
      const role = await Role.findByIdAndUpdate(
        id,
        { $set: roleData },
        { new: true } // Retorna o documento atualizado
      );
      
      if (!role) {
        throw new NotFoundError('Papel não encontrado');
      }
      
      return role.toObject();
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
      const role = await Role.findById(id);
      
      if (!role) {
        throw new NotFoundError('Papel não encontrado');
      }
      
      // Verificar se é um papel do sistema
      if (role.isSystem) {
        throw new Error('Não é possível remover um papel do sistema');
      }
      
      await Role.deleteOne({ _id: id });
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
      const permission = await Permission.create(permissionData);
      return permission.toObject();
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
      const permission = await Permission.findById(id);
      return permission ? permission.toObject() : null;
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
      const permission = await Permission.findOne({ code });
      return permission ? permission.toObject() : null;
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
      const query = {};
      
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: 'i' } },
          { code: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } }
        ];
      }
      
      if (category) {
        query.category = category;
      }
      
      // Configurar ordenação
      const sortOption = {};
      sortOption[sort] = order === 'asc' ? 1 : -1;
      
      // Contar total de registros
      const total = await Permission.countDocuments(query);
      
      // Buscar permissões com paginação
      const permissions = await Permission.find(query)
        .sort(sortOption)
        .skip((page - 1) * limit)
        .limit(limit);
      
      // Converter para objetos
      const permissionObjects = permissions.map(permission => permission.toObject());
      
      // Retornar resultado paginado
      return {
        permissions: permissionObjects,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(total / limit)
        }
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
      const permission = await Permission.findByIdAndUpdate(
        id,
        { $set: permissionData },
        { new: true } // Retorna o documento atualizado
      );
      
      if (!permission) {
        throw new NotFoundError('Permissão não encontrada');
      }
      
      return permission.toObject();
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
      const permission = await Permission.findById(id);
      
      if (!permission) {
        throw new NotFoundError('Permissão não encontrada');
      }
      
      // Verificar se a permissão está sendo usada por algum papel
      const rolesUsingPermission = await Role.find({
        'permissions.permission': id
      });
      
      if (rolesUsingPermission.length > 0) {
        throw new Error('Esta permissão está sendo utilizada por um ou mais papéis');
      }
      
      await Permission.deleteOne({ _id: id });
      return true;
    } catch (error) {
      logger.error(`Erro ao remover permissão: ${error.message}`);
      throw error;
    }
  }

  /**
   * Cria um novo recurso
   * @param {Object} resourceData Dados do recurso
   * @returns {Promise<Object>} Recurso criado
   */
  async createResource(resourceData) {
    try {
      const resource = await Resource.create(resourceData);
      return resource.toObject();
    } catch (error) {
      logger.error(`Erro ao criar recurso: ${error.message}`);
      throw error;
    }
  }

  /**
   * Busca um recurso por ID
   * @param {string} id ID do recurso
   * @returns {Promise<Object|null>} Recurso encontrado ou null
   */
  async findResourceById(id) {
    try {
      const resource = await Resource.findById(id);
      return resource ? resource.toObject() : null;
    } catch (error) {
      logger.error(`Erro ao buscar recurso por ID: ${error.message}`);
      return null;
    }
  }

  /**
   * Busca um recurso por caminho
   * @param {string} path Caminho do recurso
   * @returns {Promise<Object|null>} Recurso encontrado ou null
   */
  async findResourceByPath(path) {
    try {
      const resource = await Resource.findOne({ path });
      return resource ? resource.toObject() : null;
    } catch (error) {
      logger.error(`Erro ao buscar recurso por caminho: ${error.message}`);
      return null;
    }
  }

  /**
   * Lista todos os recursos com paginação e filtros opcionais
   * @param {Object} options Opções de busca e paginação
   * @returns {Promise<Object>} Resultado paginado com recursos e metadados
   */
  async findAllResources(options = {}) {
    try {
      const { 
        page = 1, 
        limit = 20, 
        sort = 'name', 
        order = 'asc', 
        search = null,
        type = null
      } = options;
      
      // Construir filtro de busca
      const query = {};
      
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: 'i' } },
          { path: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } }
        ];
      }
      
      if (type) {
        query.type = type;
      }
      
      // Configurar ordenação
      const sortOption = {};
      sortOption[sort] = order === 'asc' ? 1 : -1;
      
      // Contar total de registros
      const total = await Resource.countDocuments(query);
      
      // Buscar recursos com paginação
      const resources = await Resource.find(query)
        .sort(sortOption)
        .skip((page - 1) * limit)
        .limit(limit);
      
      // Converter para objetos
      const resourceObjects = resources.map(resource => resource.toObject());
      
      // Retornar resultado paginado
      return {
        resources: resourceObjects,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error(`Erro ao listar recursos: ${error.message}`);
      throw error;
    }
  }

  /**
   * Atualiza um recurso
   * @param {string} id ID do recurso
   * @param {Object} resourceData Dados a serem atualizados
   * @returns {Promise<Object>} Recurso atualizado
   */
  async updateResource(id, resourceData) {
    try {
      const resource = await Resource.findByIdAndUpdate(
        id,
        { $set: resourceData },
        { new: true } // Retorna o documento atualizado
      );
      
      if (!resource) {
        throw new NotFoundError('Recurso não encontrado');
      }
      
      return resource.toObject();
    } catch (error) {
      logger.error(`Erro ao atualizar recurso: ${error.message}`);
      throw error;
    }
  }

  /**
   * Remove um recurso
   * @param {string} id ID do recurso
   * @returns {Promise<boolean>} Verdadeiro se removido com sucesso
   */
  async deleteResource(id) {
    try {
      const resource = await Resource.findById(id);
      
      if (!resource) {
        throw new NotFoundError('Recurso não encontrado');
      }
      
      // Verificar se o recurso está sendo usado por algum papel
      const rolesUsingResource = await Role.find({
        'permissions.resources.resource': id
      });
      
      if (rolesUsingResource.length > 0) {
        throw new Error('Este recurso está sendo utilizado por um ou mais papéis');
      }
      
      await Resource.deleteOne({ _id: id });
      return true;
    } catch (error) {
      logger.error(`Erro ao remover recurso: ${error.message}`);
      throw error;
    }
  }

  /**
   * Adiciona uma permissão a um papel
   * @param {string} roleId ID do papel
   * @param {string} permissionId ID da permissão
   * @param {Array} resources Lista de recursos associados à permissão
   * @returns {Promise<Object>} Papel atualizado
   */
  async addPermissionToRole(roleId, permissionId, resources = []) {
    try {
      const role = await Role.findById(roleId);
      
      if (!role) {
        throw new NotFoundError('Papel não encontrado');
      }
      
      const permission = await Permission.findById(permissionId);
      
      if (!permission) {
        throw new NotFoundError('Permissão não encontrada');
      }
      
      // Verificar se a permissão já existe no papel
      const existingPermissionIndex = role.permissions.findIndex(
        p => p.permission.toString() === permissionId
      );
      
      // Preparar os recursos
      const resourceEntries = [];
      
      for (const resourceData of resources) {
        let resourceId = resourceData.resource;
        let resourceObj = null;
        
        // Verificar se o recurso existe
        resourceObj = await Resource.findById(resourceId);
        
        if (!resourceObj) {
          throw new NotFoundError(`Recurso ${resourceId} não encontrado`);
        }
        
        resourceEntries.push({
          resource: resourceId,
          conditions: resourceData.conditions || {}
        });
      }
      
      // Se a permissão já existe, atualizar os recursos
      if (existingPermissionIndex >= 0) {
        role.permissions[existingPermissionIndex].resources = resourceEntries;
      } else {
        // Caso contrário, adicionar nova permissão
        role.permissions.push({
          permission: permissionId,
          resources: resourceEntries
        });
      }
      
      await role.save();
      return role.toObject();
    } catch (error) {
      logger.error(`Erro ao adicionar permissão ao papel: ${error.message}`);
      throw error;
    }
  }

  /**
   * Remove uma permissão de um papel
   * @param {string} roleId ID do papel
   * @param {string} permissionId ID da permissão
   * @returns {Promise<Object>} Papel atualizado
   */
  async removePermissionFromRole(roleId, permissionId) {
    try {
      const role = await Role.findById(roleId);
      
      if (!role) {
        throw new NotFoundError('Papel não encontrado');
      }
      
      // Filtrar as permissões para remover a especificada
      role.permissions = role.permissions.filter(
        p => p.permission.toString() !== permissionId
      );
      
      await role.save();
      return role.toObject();
    } catch (error) {
      logger.error(`Erro ao remover permissão do papel: ${error.message}`);
      throw error;
    }
  }

  /**
   * Verifica se um papel tem uma permissão específica
   * @param {string} roleId ID do papel
   * @param {string} permissionCode Código da permissão
   * @param {string|null} resourcePath Caminho do recurso (opcional)
   * @returns {Promise<boolean>} Verdadeiro se o papel tem a permissão
   */
  async roleHasPermission(roleId, permissionCode, resourcePath = null) {
    try {
      // Buscar o papel com suas permissões
      const role = await Role.findById(roleId)
        .populate({
          path: 'permissions.permission',
          model: 'Permission'
        })
        .populate({
          path: 'permissions.resources.resource',
          model: 'Resource'
        });
      
      if (!role) {
        return false;
      }
      
      // Buscar a permissão pelo código
      for (const permissionEntry of role.permissions) {
        if (permissionEntry.permission.code === permissionCode) {
          // Se não precisamos verificar um recurso específico, a permissão está concedida
          if (!resourcePath) {
            return true;
          }
          
          // Se temos um recurso específico, verificar se está autorizado
          for (const resourceEntry of permissionEntry.resources) {
            if (resourceEntry.resource && resourceEntry.resource.path === resourcePath) {
              return true;
            }
          }
        }
      }
      
      return false;
    } catch (error) {
      logger.error(`Erro ao verificar permissão do papel: ${error.message}`);
      return false;
    }
  }
}

module.exports = new MongoRbacRepository();