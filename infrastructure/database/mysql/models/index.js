// src/infrastructure/database/mysql/models/index.js - VERSÃO COMPLETA
const { Sequelize, DataTypes } = require('sequelize');
const { getConnection } = require('../connection');
const config = require('../../../config');
const logger = require('../../../logging/logger');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const sequelize = getConnection();

const defineModels = () => {
  if (!sequelize) {
    throw new Error('Conexão com banco de dados não estabelecida');
  }

  // Modelo User
  const User = sequelize.define('User', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    email: {
      type: DataTypes.STRING(255),
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true
      }
    },
    password: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    role: {
      type: DataTypes.ENUM('user', 'admin'),
      defaultValue: 'user'
    },
    verified: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    },
    active: {
      type: DataTypes.BOOLEAN,
      defaultValue: true
    },
    verifyToken: {
      type: DataTypes.STRING(255),
      field: 'verify_token',
      allowNull: true
    },
    verifyTokenExpires: {
      type: DataTypes.DATE,
      field: 'verify_token_expires',
      allowNull: true
    },
    resetToken: {
      type: DataTypes.STRING(255),
      field: 'reset_token',
      allowNull: true
    },
    resetTokenExpires: {
      type: DataTypes.DATE,
      field: 'reset_token_expires',
      allowNull: true
    },
    twoFactorEnabled: {
      type: DataTypes.BOOLEAN,
      field: 'two_factor_enabled',
      defaultValue: false
    },
    twoFactorSecret: {
      type: DataTypes.STRING(255),
      field: 'two_factor_secret',
      allowNull: true
    },
    name: {
      type: DataTypes.STRING(100),
      allowNull: true
    },
    surname: {
      type: DataTypes.STRING(100),
      allowNull: true
    },
    lastLogin: {
      type: DataTypes.DATE,
      field: 'last_login',
      allowNull: true
    },
    failedLoginAttempts: {
      type: DataTypes.INTEGER,
      field: 'failed_login_attempts',
      defaultValue: 0
    },
    lockUntil: {
      type: DataTypes.DATE,
      field: 'lock_until',
      allowNull: true
    }
  }, {
    tableName: 'users',
    timestamps: true,
    underscored: true,
    paranoid: true,
    hooks: {
      beforeCreate: async (user) => {
        if (user.password && !user.password.startsWith('$2')) {
          user.password = await bcrypt.hash(user.password, config.auth.password.saltRounds);
        }
      },
      beforeUpdate: async (user) => {
        if (user.changed('password') && !user.password.startsWith('$2')) {
          user.password = await bcrypt.hash(user.password, config.auth.password.saltRounds);
        }
      }
    }
  });

  // Adicionar métodos de instância para User
  User.prototype.isLocked = function() {
    return !!(this.lockUntil && this.lockUntil > new Date());
  };

  User.prototype.incrementLoginAttempts = async function() {
    if (this.lockUntil && this.lockUntil < new Date()) {
      this.failedLoginAttempts = 1;
      this.lockUntil = null;
    } else {
      this.failedLoginAttempts += 1;
      
      if (this.failedLoginAttempts >= 5 && !this.isLocked()) {
        this.lockUntil = new Date(Date.now() + 60 * 60 * 1000); // 1 hora
      }
    }
    
    await this.save();
  };

  User.prototype.resetLoginAttempts = async function() {
    this.failedLoginAttempts = 0;
    this.lockUntil = null;
    this.lastLogin = new Date();
    await this.save();
  };

  User.prototype.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
  };

  // Modelo UserRecoveryCode
  const UserRecoveryCode = sequelize.define('UserRecoveryCode', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    userId: {
      type: DataTypes.UUID,
      field: 'user_id',
      allowNull: false,
      references: {
        model: 'users',
        key: 'id'
      }
    },
    code: {
      type: DataTypes.STRING(20),
      allowNull: false
    },
    used: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    }
  }, {
    tableName: 'user_recovery_codes',
    timestamps: true,
    underscored: true,
    paranoid: false,
    updatedAt: false
  });

  // Modelo UserOAuth
  const UserOAuth = sequelize.define('UserOAuth', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    userId: {
      type: DataTypes.UUID,
      field: 'user_id',
      allowNull: false,
      references: {
        model: 'users',
        key: 'id'
      }
    },
    provider: {
      type: DataTypes.STRING(50),
      allowNull: false
    },
    providerId: {
      type: DataTypes.STRING(255),
      field: 'provider_id',
      allowNull: false
    },
    providerEmail: {
      type: DataTypes.STRING(255),
      field: 'provider_email',
      allowNull: true
    },
    providerName: {
      type: DataTypes.STRING(255),
      field: 'provider_name',
      allowNull: true
    },
    providerPicture: {
      type: DataTypes.TEXT,
      field: 'provider_picture',
      allowNull: true
    }
  }, {
    tableName: 'user_oauth',
    timestamps: true,
    underscored: true,
    paranoid: false,
    indexes: [
      {
        unique: true,
        fields: ['user_id', 'provider']
      }
    ]
  });

  // Modelo Permission
  const Permission = sequelize.define('Permission', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    name: {
      type: DataTypes.STRING(100),
      allowNull: false
    },
    code: {
      type: DataTypes.STRING(100),
      allowNull: false,
      unique: true
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: false
    },
    category: {
      type: DataTypes.ENUM('user', 'product', 'order', 'delivery', 'report', 'system'),
      allowNull: false
    }
  }, {
    tableName: 'permissions',
    timestamps: true,
    underscored: true,
    paranoid: false
  });

  // Modelo Resource
  const Resource = sequelize.define('Resource', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    name: {
      type: DataTypes.STRING(100),
      allowNull: false
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: false
    },
    type: {
      type: DataTypes.ENUM('route', 'entity', 'feature', 'report', 'menu'),
      allowNull: false
    },
    path: {
      type: DataTypes.STRING(255),
      allowNull: true
    }
  }, {
    tableName: 'resources',
    timestamps: true,
    underscored: true,
    paranoid: false
  });

  // Modelo Role
  const Role = sequelize.define('Role', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    name: {
      type: DataTypes.STRING(100),
      allowNull: false,
      unique: true
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: false
    },
    isSystem: {
      type: DataTypes.BOOLEAN,
      field: 'is_system',
      defaultValue: false
    }
  }, {
    tableName: 'roles',
    timestamps: true,
    underscored: true,
    paranoid: false
  });

  // Modelo RolePermission
  const RolePermission = sequelize.define('RolePermission', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    roleId: {
      type: DataTypes.UUID,
      field: 'role_id',
      allowNull: false,
      references: {
        model: 'roles',
        key: 'id'
      }
    },
    permissionId: {
      type: DataTypes.UUID,
      field: 'permission_id',
      allowNull: false,
      references: {
        model: 'permissions',
        key: 'id'
      }
    }
  }, {
    tableName: 'role_permissions',
    timestamps: true,
    underscored: true,
    paranoid: false,
    updatedAt: false,
    indexes: [
      {
        unique: true,
        fields: ['role_id', 'permission_id']
      }
    ]
  });

  // Modelo RolePermissionResource
  const RolePermissionResource = sequelize.define('RolePermissionResource', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    rolePermissionId: {
      type: DataTypes.UUID,
      field: 'role_permission_id',
      allowNull: false,
      references: {
        model: 'role_permissions',
        key: 'id'
      }
    },
    resourceId: {
      type: DataTypes.UUID,
      field: 'resource_id',
      allowNull: false,
      references: {
        model: 'resources',
        key: 'id'
      }
    },
    conditions: {
      type: DataTypes.JSON,
      allowNull: true
    }
  }, {
    tableName: 'role_permission_resources',
    timestamps: true,
    underscored: true,
    paranoid: false,
    updatedAt: false,
    indexes: [
      {
        unique: true,
        fields: ['role_permission_id', 'resource_id']
      }
    ]
  });

  // Modelo UserRole
  const UserRole = sequelize.define('UserRole', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    userId: {
      type: DataTypes.UUID,
      field: 'user_id',
      allowNull: false,
      references: {
        model: 'users',
        key: 'id'
      }
    },
    roleId: {
      type: DataTypes.UUID,
      field: 'role_id',
      allowNull: false,
      references: {
        model: 'roles',
        key: 'id'
      }
    },
    assignedAt: {
      type: DataTypes.DATE,
      field: 'assigned_at',
      defaultValue: DataTypes.NOW
    },
    assignedBy: {
      type: DataTypes.UUID,
      field: 'assigned_by',
      allowNull: true,
      references: {
        model: 'users',
        key: 'id'
      }
    },
    scope: {
      type: DataTypes.ENUM('global', 'store', 'department'),
      defaultValue: 'global'
    },
    scopeId: {
      type: DataTypes.UUID,
      field: 'scope_id',
      allowNull: true
    }
  }, {
    tableName: 'user_roles',
    timestamps: false,
    underscored: true,
    paranoid: false,
    indexes: [
      {
        unique: true,
        fields: ['user_id', 'role_id', 'scope', 'scope_id']
      }
    ]
  });

  // Modelo RefreshToken
  const RefreshToken = sequelize.define('RefreshToken', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    token: {
      type: DataTypes.STRING(255),
      allowNull: false,
      unique: true
    },
    userId: {
      type: DataTypes.UUID,
      field: 'user_id',
      allowNull: false,
      references: {
        model: 'users',
        key: 'id'
      }
    },
    userEmail: {
      type: DataTypes.STRING(255),
      field: 'user_email',
      allowNull: false
    },
    expires: {
      type: DataTypes.DATE,
      allowNull: false
    },
    revoked: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    },
    createdAt: {
      type: DataTypes.DATE,
      field: 'created_at',
      defaultValue: DataTypes.NOW
    },
    createdByIp: {
      type: DataTypes.STRING(50),
      field: 'created_by_ip',
      allowNull: true
    },
    revokedAt: {
      type: DataTypes.DATE,
      field: 'revoked_at',
      allowNull: true
    },
    revokedByIp: {
      type: DataTypes.STRING(50),
      field: 'revoked_by_ip',
      allowNull: true
    },
    replacedByToken: {
      type: DataTypes.STRING(255),
      field: 'replaced_by_token',
      allowNull: true
    }
  }, {
    tableName: 'refresh_tokens',
    timestamps: false,
    underscored: true,
    paranoid: false,
    indexes: [
      {
        fields: ['token']
      },
      {
        fields: ['user_id']
      },
      {
        fields: ['expires']
      }
    ]
  });

  // Modelo TokenBlacklist
  const TokenBlacklist = sequelize.define('TokenBlacklist', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    token: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    type: {
      type: DataTypes.ENUM('access', 'refresh'),
      allowNull: false
    },
    expires: {
      type: DataTypes.DATE,
      allowNull: false
    },
    createdAt: {
      type: DataTypes.DATE,
      field: 'created_at',
      defaultValue: DataTypes.NOW
    }
  }, {
    tableName: 'token_blacklist',
    timestamps: false,
    underscored: true,
    paranoid: false,
    indexes: [
      {
        fields: ['token']
      },
      {
        fields: ['expires']
      }
    ]
  });

  // Modelo AuditLog (opcional)
  const AuditLog = sequelize.define('AuditLog', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    action: {
      type: DataTypes.STRING(100),
      allowNull: false
    },
    userId: {
      type: DataTypes.UUID,
      field: 'user_id',
      allowNull: true,
      references: {
        model: 'users',
        key: 'id'
      }
    },
    userEmail: {
      type: DataTypes.STRING(255),
      field: 'user_email',
      allowNull: true
    },
    ipAddress: {
      type: DataTypes.STRING(50),
      field: 'ip_address',
      allowNull: true
    },
    details: {
      type: DataTypes.JSON,
      allowNull: true
    },
    timestamp: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW
    }
  }, {
    tableName: 'audit_logs',
    timestamps: false,
    underscored: true,
    paranoid: false,
    indexes: [
      {
        fields: ['action']
      },
      {
        fields: ['user_id']
      },
      {
        fields: ['timestamp']
      }
    ]
  });

  // Modelo LoginAttempt
  const LoginAttempt = sequelize.define('LoginAttempt', {
    id: {
      type: DataTypes.UUID,
      defaultValue: () => uuidv4(),
      primaryKey: true,
      allowNull: false
    },
    userId: {
      type: DataTypes.UUID,
      field: 'user_id',
      allowNull: true,
      references: {
        model: 'users',
        key: 'id'
      }
    },
    email: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    success: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    },
    ipAddress: {
      type: DataTypes.STRING(50),
      field: 'ip_address',
      allowNull: true
    },
    details: {
      type: DataTypes.JSON,
      allowNull: true
    },
    createdAt: {
      type: DataTypes.DATE,
      field: 'created_at',
      defaultValue: DataTypes.NOW
    }
  }, {
    tableName: 'login_attempts',
    timestamps: false,
    underscored: true,
    paranoid: false,
    indexes: [
      {
        fields: ['user_id']
      },
      {
        fields: ['email']
      },
      {
        fields: ['ip_address']
      },
      {
        fields: ['created_at']
      }
    ]
  });

  // ===========================
  // DEFINIR RELACIONAMENTOS
  // ===========================

  // User relacionamentos
  User.hasMany(UserRecoveryCode, { 
    foreignKey: 'userId', 
    as: 'recoveryCodes',
    onDelete: 'CASCADE'
  });
  UserRecoveryCode.belongsTo(User, { 
    foreignKey: 'userId',
    as: 'user'
  });

  User.hasMany(UserOAuth, { 
    foreignKey: 'userId', 
    as: 'oauthAccounts',
    onDelete: 'CASCADE'
  });
  UserOAuth.belongsTo(User, { 
    foreignKey: 'userId',
    as: 'user'
  });

  User.hasMany(UserRole, { 
    foreignKey: 'userId', 
    as: 'roles',
    onDelete: 'CASCADE'
  });
  UserRole.belongsTo(User, { 
    foreignKey: 'userId',
    as: 'user'
  });

  User.hasMany(RefreshToken, { 
    foreignKey: 'userId', 
    as: 'refreshTokens',
    onDelete: 'CASCADE'
  });
  RefreshToken.belongsTo(User, { 
    foreignKey: 'userId',
    as: 'user'
  });

  User.hasMany(AuditLog, { 
    foreignKey: 'userId', 
    as: 'auditLogs',
    onDelete: 'SET NULL'
  });
  AuditLog.belongsTo(User, { 
    foreignKey: 'userId',
    as: 'user'
  });

  User.hasMany(LoginAttempt, { 
    foreignKey: 'userId', 
    as: 'loginAttempts',
    onDelete: 'SET NULL'
  });
  LoginAttempt.belongsTo(User, { 
    foreignKey: 'userId',
    as: 'user'
  });

  // Role relacionamentos
  Role.hasMany(RolePermission, { 
    foreignKey: 'roleId', 
    as: 'rolePermissions',
    onDelete: 'CASCADE'
  });
  RolePermission.belongsTo(Role, { 
    foreignKey: 'roleId',
    as: 'role'
  });

  Role.hasMany(UserRole, { 
    foreignKey: 'roleId', 
    as: 'userRoles',
    onDelete: 'CASCADE'
  });
  UserRole.belongsTo(Role, { 
    foreignKey: 'roleId',
    as: 'role'
  });

  // Permission relacionamentos
  Permission.hasMany(RolePermission, { 
    foreignKey: 'permissionId', 
    as: 'rolePermissions',
    onDelete: 'CASCADE'
  });
  RolePermission.belongsTo(Permission, { 
    foreignKey: 'permissionId',
    as: 'permission'
  });

  // Resource relacionamentos
  Resource.hasMany(RolePermissionResource, { 
    foreignKey: 'resourceId', 
    as: 'rolePermissionResources',
    onDelete: 'CASCADE'
  });
  RolePermissionResource.belongsTo(Resource, { 
    foreignKey: 'resourceId',
    as: 'resource'
  });

  // RolePermission relacionamentos
  RolePermission.hasMany(RolePermissionResource, { 
    foreignKey: 'rolePermissionId', 
    as: 'resources',
    onDelete: 'CASCADE'
  });
  RolePermissionResource.belongsTo(RolePermission, { 
    foreignKey: 'rolePermissionId',
    as: 'rolePermission'
  });

  // UserRole relacionamentos para assignedBy
  User.hasMany(UserRole, { 
    foreignKey: 'assignedBy', 
    as: 'assignedRoles',
    onDelete: 'SET NULL'
  });
  UserRole.belongsTo(User, { 
    foreignKey: 'assignedBy',
    as: 'assignedByUser'
  });

  return {
    User,
    UserRecoveryCode,
    UserOAuth,
    Permission,
    Resource,
    Role,
    RolePermission,
    RolePermissionResource,
    UserRole,
    RefreshToken,
    TokenBlacklist,
    AuditLog,
    LoginAttempt
  };
};

module.exports = defineModels;