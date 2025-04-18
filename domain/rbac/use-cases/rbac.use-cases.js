// src/domain/rbac/use-cases/rbac.use-cases.js
const { ConflictError, NotFoundError } = require('../../../shared/errors/api-error');
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

/**
 * Caso de uso para remover um papel de um usuário
 */
class RemoveRoleFromUserUseCase {
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
   * @param {Object} adminUser Usuário administrador que está removendo o papel
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

    // Remover o papel do usuário
    const removed = await user.removeRole(roleId, options);
    
    if (!removed) {
      throw new NotFoundError('Papel não encontrado no usuário ou escopo informado');
    }

    // Salvar o usuário
    await this.userRepository.save(user);

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: 'ROLE_REMOVED',
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

    logger.info(`Papel ${role.name} removido do usuário ${user.email} por ${adminUser.email}`);
    
    return user;
  }
}

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

/**
 * Caso de uso para atualizar uma permissão existente
 */
class UpdatePermissionUseCase {
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
   * @param {string} permissionId ID da permissão
   * @param {Object} permissionData Dados para atualização
   * @param {Object} user Usuário que está atualizando a permissão
   * @returns {Promise<Object>} Permissão atualizada
   */
  async execute(permissionId, permissionData, user) {
    // Verificar se a permissão existe
    const permission = await this.rbacRepository.findPermissionById(permissionId);
    if (!permission) {
      throw new NotFoundError('Permissão não encontrada');
    }

    // Não permitir alteração do código da permissão
    if (permissionData.code) {
      delete permissionData.code;
    }

    // Atualizar a permissão
    const updatedPermission = await this.rbacRepository.updatePermission(permissionId, permissionData);

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: 'PERMISSION_UPDATED',
        userId: user.id,
        userEmail: user.email,
        details: { 
          permissionId,
          permissionName: updatedPermission.name,
          permissionCode: updatedPermission.code
        }
      });
    }

    logger.info(`Permissão atualizada: ${updatedPermission.name} (${updatedPermission.code}) por ${user.email}`);
    
    return updatedPermission;
  }
}

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

/**
 * Caso de uso para remover uma permissão de um papel
 */
class RemovePermissionFromRoleUseCase {
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
   * @param {Object} user Usuário que está removendo a permissão
   * @returns {Promise<Object>} Papel atualizado
   */
  async execute(roleId, permissionId, user) {
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

    // Verificar se a permissão está atribuída ao papel
    const hasPermission = role.permissions.some(p => 
      p.permission._id.toString() === permissionId || 
      p.permission.id.toString() === permissionId
    );

    if (!hasPermission) {
      throw new NotFoundError('Permissão não está atribuída a este papel');
    }

    // Remover a permissão do papel
    const updatedRole = await this.rbacRepository.removePermissionFromRole(roleId, permissionId);

    // Registrar na auditoria, se disponível
    if (this.auditService) {
      await this.auditService.log({
        action: 'PERMISSION_REMOVED_FROM_ROLE',
        userId: user.id,
        userEmail: user.email,
        details: { 
          roleName: role.name, 
          roleId: role.id,
          permissionName: permission.name,
          permissionCode: permission.code,
          permissionId: permission.id
        }
      });
    }

    logger.info(`Permissão ${permission.code} removida do papel ${role.name} por ${user.email}`);
    
    return updatedRole;
  }
}

/**
 * Caso de uso para obter todos os papéis 
 */
class GetAllRolesUseCase {
  /**
   * @param {Object} rbacRepository Repositório RBAC
   */
  constructor(rbacRepository) {
    this.rbacRepository = rbacRepository;
  }

  /**
   * Executa o caso de uso
   * @param {Object} options Opções de paginação e filtros
   * @returns {Promise<Object>} Lista paginada de papéis
   */
  async execute(options = {}) {
    return await this.rbacRepository.findAllRoles(options);
  }
}

/**
 * Caso de uso para obter todas as permissões
 */
class GetAllPermissionsUseCase {
  /**
   * @param {Object} rbacRepository Repositório RBAC
   */
  constructor(rbacRepository) {
    this.rbacRepository = rbacRepository;
  }

  /**
   * Executa o caso de uso
   * @param {Object} options Opções de paginação e filtros
   * @returns {Promise<Object>} Lista paginada de permissões
   */
  async execute(options = {}) {
    return await this.rbacRepository.findAllPermissions(options);
  }
}

// Exportar todos os casos de uso
module.exports = {
  CreateRoleUseCase,
  AssignRoleToUserUseCase,
  RemoveRoleFromUserUseCase,
  CreatePermissionUseCase,
  UpdatePermissionUseCase,
  AddPermissionToRoleUseCase,
  RemovePermissionFromRoleUseCase,
  GetAllRolesUseCase,
  GetAllPermissionsUseCase
};