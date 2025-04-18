// src/infrastructure/database/mongodb/models/user.model.js

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const userSchema = new mongoose.Schema(
  {
    uuid: {
      type: String,
      default: () => uuidv4(),
      required: true,
      immutable: true
    },
    email: {
      type: String,
      unique: true,
      required: true,
      trim: true,
      lowercase: true
    },
    password: {
      type: String,
      required: true
    },
    // Sistema RBAC - Múltiplos papéis em vez de papel único
    roles: [{
      role: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Role',
        required: true
      },
      assignedAt: {
        type: Date,
        default: Date.now
      },
      assignedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      scope: {
        type: String,
        enum: ['global', 'store', 'department'],
        default: 'global'
      },
      scopeId: {
        type: mongoose.Schema.Types.ObjectId,
        default: null
      }
    }],
    // Manter o campo role para compatibilidade retroativa
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user'
    },
    verified: {
      type: Boolean,
      default: false
    },
    active: {
      type: Boolean,
      default: true
    },
    verifyToken: String,
    verifyTokenExpires: Date,
    resetToken: String,
    resetTokenExpires: Date,
    twoFactorEnabled: {
      type: Boolean,
      default: false
    },
    twoFactorSecret: {
      type: String
    },
    oauth: {
      google: {
        id: String,
        email: String,
        name: String,
        picture: String
      }
    },
    recoveryCodes: [
      {
        code: String,
        used: {
          type: Boolean,
          default: false
        }
      }
    ],
    name: {
      type: String,
      trim: true
    },
    surname: {
      type: String,
      trim: true
    },
    lastLogin: Date,
    failedLoginAttempts: {
      type: Number,
      default: 0
    },
    lockUntil: Date
  },
  {
    timestamps: true
  }
);

// Método para verificar se a conta está bloqueada
userSchema.methods.isLocked = function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

// Incrementar tentativas de login falhas
userSchema.methods.incrementLoginAttempts = async function () {
  // Se existe um bloqueio, mas já expirou
  if (this.lockUntil && this.lockUntil < Date.now()) {
    // Reiniciar contador e remover bloqueio
    return this.updateOne({
      $set: {
        failedLoginAttempts: 1
      },
      $unset: {
        lockUntil: 1
      }
    });
  }

  // Incrementar contador
  const updates = { $inc: { failedLoginAttempts: 1 } };

  // Bloquear a conta após 5 tentativas falhas
  if (this.failedLoginAttempts + 1 >= 5 && !this.isLocked()) {
    updates.$set = { lockUntil: Date.now() + 60 * 60 * 1000 }; // 1 hora
  }

  return this.updateOne(updates);
};

// Após login bem-sucedido, resetar contador de tentativas
userSchema.methods.resetLoginAttempts = function () {
  return this.updateOne({
    $set: {
      failedLoginAttempts: 0,
      lastLogin: Date.now()
    },
    $unset: { lockUntil: 1 }
  });
};

// Verificação de senha
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Verificar um código de recuperação 2FA
userSchema.methods.validateRecoveryCode = async function (code) {
  const recoveryCodeEntry = this.recoveryCodes.find(entry => entry.code === code && !entry.used);

  if (recoveryCodeEntry) {
    // Marcar código como usado
    recoveryCodeEntry.used = true;
    await this.save();
    return true;
  }

  return false;
};

// Adicionar códigos de recuperação
userSchema.methods.setRecoveryCodes = async function (codes) {
  this.recoveryCodes = codes.map(code => ({
    code,
    used: false
  }));

  return this.save();
};

// Métodos RBAC - Verificar permissões
userSchema.methods.hasPermission = async function(permissionCode, resourcePath = null) {
  const populated = await this.populate({
    path: 'roles.role',
    populate: {
      path: 'permissions.permission',
      model: 'Permission'
    }
  });

  for (const roleAssignment of populated.roles) {
    const role = roleAssignment.role;
    
    for (const permissionEntry of role.permissions) {
      const permission = permissionEntry.permission;
      
      if (permission.code === permissionCode) {
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
  }
  
  return false;
};

// Método para atribuir um papel ao usuário
userSchema.methods.assignRole = async function(roleId, options = {}) {
  const { scope = 'global', scopeId = null, assignedBy = null } = options;
  
  // Verificar se o papel já está atribuído com o mesmo escopo
  const existingRole = this.roles.find(r => 
    r.role.toString() === roleId.toString() && 
    r.scope === scope && 
    (scopeId === null || r.scopeId && r.scopeId.toString() === scopeId.toString())
  );
  
  if (existingRole) {
    return false; // Papel já atribuído
  }
  
  // Adicionar o novo papel
  this.roles.push({
    role: roleId,
    assignedAt: new Date(),
    assignedBy: assignedBy,
    scope: scope,
    scopeId: scopeId
  });
  
  await this.save();
  return true;
};

// Método para remover um papel do usuário
userSchema.methods.removeRole = async function(roleId, options = {}) {
  const { scope = 'global', scopeId = null } = options;
  
  const initialLength = this.roles.length;
  
  this.roles = this.roles.filter(r => 
    r.role.toString() !== roleId.toString() || 
    r.scope !== scope || 
    (scopeId !== null && (!r.scopeId || r.scopeId.toString() !== scopeId.toString()))
  );
  
  if (this.roles.length !== initialLength) {
    await this.save();
    return true;
  }
  
  return false; // Papel não encontrado
};

// Método para obter todos os papéis do usuário
userSchema.methods.getRoles = async function() {
  return await this.populate('roles.role');
};

// Pré-save hook para atualizar timestamp
userSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

// Índices para melhorar performance de consultas
userSchema.index({ uuid: 1 });
userSchema.index({ verifyToken: 1 }, { sparse: true });
userSchema.index({ resetToken: 1 }, { sparse: true });
userSchema.index({ role: 1 });
userSchema.index({ 'oauth.google.id': 1 }, { sparse: true });
userSchema.index({ 'roles.role': 1 });

module.exports = mongoose.model('User', userSchema);