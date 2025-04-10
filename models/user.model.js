// models/user.model.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
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
    name: {
      type: String,
      trim: true
    },
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
    // Adicione o campo OAuth para armazenar informações de autenticação externa
    oauth: {
      google: {
        id: String,
        email: String,
        name: String,
        picture: String
      },
      // Pode adicionar outros provedores no futuro (Facebook, Apple, etc)
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
    failedLoginAttempts: {
      type: Number,
      default: 0
    },
    lockUntil: Date,
    lastLogin: Date,
    createdAt: {
      type: Date,
      default: Date.now
    },
    updatedAt: {
      type: Date,
      default: Date.now
    }
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

// Pré-save hook para atualizar timestamp
userSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

// Índices para melhorar performance de consultas
userSchema.index({ verifyToken: 1 }, { sparse: true });
userSchema.index({ resetToken: 1 }, { sparse: true });
userSchema.index({ role: 1 });
userSchema.index({ 'oauth.google.id': 1 }, { sparse: true });

module.exports = mongoose.model('User', userSchema);