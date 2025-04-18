// src/domain/rbac/use-cases/create-role.use-case.js
const { ConflictError } = require('../../../shared/errors/api-error');
const logger = require('../../../infrastructure/logging/logger');

/**
 * Caso de uso para criar um novo papel (role)
 */
class CreateRoleUseCase {
  /**
   * @param {Object} rbacRepository Repositório RBAC
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(rbacRepository, auditService = null) {
    this.rbacRepository = rbacRepository;
    this.auditService = auditService;
  }

  /**
   * Executa o caso de uso
   * @param {Object} roleData Dados do papel a ser criado
   * @param {Object} user Usuário que está criando o papel
   * @returns {Promise<Object>} Papel criado
   */
  async execute(roleData, user) {
    const { name, description, isSystem = false } = roleData;

    // Verificar se o papel já existe
    const existingRole = await this.rbacRepository.findRoleByName(name);
    if (existingRole) {
      throw new ConflictError(`Papel com nome '${name}' já existe`);
    }

    // Criar o papel
    const role = await this.rbacRepository.createRole({
      name,
      description,
      isSystem
    });

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: 'ROLE_CREATED',
        userId: user.id,
        userEmail: user.email,
        details: { roleName: name, isSystem }
      });
    }

    logger.info(`Novo papel criado: ${name} por ${user.email}`);
    
    return role;
  }
}

// src/domain/rbac/use-cases/assign-role-to-user.use-case.js
const { NotFoundError } = require('../../../shared/errors/api-error');

/**
 * Caso de uso para atribuir um papel a um usuário
 */
class AssignRoleToUserUseCase {
  /**
   * @param {Object} userRepository Repositório de usuários
   * @param {Object} rbacRepository Repositório RBAC
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(userRepository, rbacRepository, auditService = null) {
    this.userRepository = userRepository;
    this.rbacRepository = rbacRepository;
    this.auditService = auditService;
  }

  /**
   * Executa o caso de uso
   * @param {string} userId ID do usuário
   * @param {string} roleId ID do papel
   * @param {Object} options Opções adicionais (escopo, etc.)
   * @param {Object} adminUser Usuário administrador que está atribuindo o papel
   * @returns {Promise<Object>} Usuário atualizado
   */
  async execute(userId, roleId, options = {}, adminUser) {
    // Carregar o usuário
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new NotFoundError('Usuário não encontrado');
    }

    // Verificar se o papel existe
    const role = await this.rbacRepository.findRoleById(roleId);
    if (!role) {
      throw new NotFoundError('Papel não encontrado');
    }

    // Atribuir o papel ao usuário
    const assigned = await user.assignRole(roleId, {
      ...options,
      assignedBy: adminUser.id
    });

    // Salvar o usuário
    await this.userRepository.save(user);

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: 'ROLE_ASSIGNED',
        userId: adminUser.id,
        userEmail: adminUser.email,
        details: { 
          targetUserId: userId, 
          targetUserEmail: user.email,
          roleName: role.name,
          roleId: role.id,
          scope: options.scope || 'global',
          scopeId: options.scopeId
        }
      });
    }

    logger.info(`Papel ${role.name} atribuído ao usuário ${user.email} por ${adminUser.email}`);
    
    return user;
  }
}

// src/domain/rbac/use-cases/create-permission.use-case.js
const { ConflictError } = require('../../../shared/errors/api-error');
const logger = require('../../../infrastructure/logging/logger');

/**
 * Caso de uso para criar uma nova permissão
 */
class CreatePermissionUseCase {
  /**
   * @param {Object} rbacRepository Repositório RBAC
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(rbacRepository, auditService = null) {
    this.rbacRepository = rbacRepository;
    this.auditService = auditService;
  }

  /**
   * Executa o caso de uso
   * @param {Object} permissionData Dados da permissão a ser criada
   * @param {Object} user Usuário que está criando a permissão
   * @returns {Promise<Object>} Permissão criada
   */
  async execute(permissionData, user) {
    const { name, code, description, category } = permissionData;

    // Verificar se a permissão já existe
    const existingPermission = await this.rbacRepository.findPermissionByCode(code);
    if (existingPermission) {
      throw new ConflictError(`Permissão com código '${code}' já existe`);
    }

    // Criar a permissão
    const permission = await this.rbacRepository.createPermission({
      name,
      code: code.toUpperCase(), // Garantir que o código está em maiúsculas
      description,
      category
    });

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: 'PERMISSION_CREATED',
        userId: user.id,
        userEmail: user.email,
        details: { permissionName: name, permissionCode: code, category }
      });
    }

    logger.info(`Nova permissão criada: ${name} (${code}) por ${user.email}`);
    
    return permission;
  }
}

// src/domain/rbac/use-cases/add-permission-to-role.use-case.js
const { NotFoundError } = require('../../../shared/errors/api-error');
const logger = require('../../../infrastructure/logging/logger');

/**
 * Caso de uso para adicionar uma permissão a um papel
 */
class AddPermissionToRoleUseCase {
  /**
   * @param {Object} rbacRepository Repositório RBAC
   * @param {Object} auditService Serviço de auditoria (opcional)
   */
  constructor(rbacRepository, auditService = null) {
    this.rbacRepository = rbacRepository;
    this.auditService = auditService;
  }

  /**
   * Executa o caso de uso
   * @param {string} roleId ID do papel
   * @param {string} permissionId ID da permissão
   * @param {Array} resources Lista de recursos associados à permissão
   * @param {Object} user Usuário que está adicionando a permissão
   * @returns {Promise<Object>} Papel atualizado
   */
  async execute(roleId, permissionId, resources = [], user) {
    // Verificar se o papel existe
    const role = await this.rbacRepository.findRoleById(roleId);
    if (!role) {
      throw new NotFoundError('Papel não encontrado');
    }

    // Verificar se a permissão existe
    const permission = await this.rbacRepository.findPermissionById(permissionId);
    if (!permission) {
      throw new NotFoundError('Permissão não encontrada');
    }

    // Adicionar a permissão ao papel
    const updatedRole = await this.rbacRepository.addPermissionToRole(roleId, permissionId, resources);

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: 'PERMISSION_ADDED_TO_ROLE',
        userId: user.id,
        userEmail: user.email,
        details: { 
          roleName: role.name, 
          roleId: role.id,
          permissionName: permission.name,
          permissionCode: permission.code,
          permissionId: permission.id,
          resourceCount: resources.length
        }
      });
    }

    logger.info(`Permissão ${permission.code} adicionada ao papel ${role.name} por ${user.email}`);
    
    return updatedRole;
  }
}

module.exports = {
  CreateRoleUseCase,
  AssignRoleToUserUseCase,
  CreatePermissionUseCase,
  AddPermissionToRoleUseCase
};