// src/infrastructure/database/mysql/models/index.js
const { Sequelize, DataTypes } = require('sequelize');
const { getConnection } = require('../connection');
const config = require('../../../config');
const logger = require('../../../logging/logger');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// Obter a instância do Sequelize
const sequelize = getConnection();

// Definir os modelos
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
    paranoid: true, // soft delete
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

  // Modelo RolePermission (Relacionamento entre Role e Permission)
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

  // Modelo RolePermissionResource (Relacionamento entre RolePermission e Resource)
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