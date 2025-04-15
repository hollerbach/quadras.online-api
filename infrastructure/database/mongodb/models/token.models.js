// src/infrastructure/database/mongodb/models/token.models.js
const mongoose = require('mongoose');

/**
 * Modelo para tokens inválidos (blacklist)
 * Armazena tokens que foram revogados mas ainda não expiraram
 */
const TokenBlacklistSchema = new mongoose.Schema({
  token: { 
    type: String, 
    required: true, 
    index: true 
  },
  type: { 
    type: String, 
    enum: ['access', 'refresh'], 
    required: true 
  },
  expires: { 
    type: Date, 
    required: true 
  },
  createdAt: { 
    type: Date, 
    default: Date.now, 
    expires: '30d' // Documento expira após 30 dias
  }
});

/**
 * Modelo para refresh tokens
 * Armazena tokens de atualização e seu estado
 */
const RefreshTokenSchema = new mongoose.Schema({
  token: { 
    type: String, 
    required: true
  },
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  userEmail: { 
    type: String, 
    required: true 
  },
  expires: { 
    type: Date, 
    required: true 
  },
  revoked: { 
    type: Boolean, 
    default: false 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  createdByIp: String,
  revokedAt: Date,
  revokedByIp: String,
  replacedByToken: String
});

/**
 * Configurar expiração automática de refresh tokens
 * Remove tokens expirados e não utilizados
 */
RefreshTokenSchema.index(
  { expires: 1 }, 
  { 
    expireAfterSeconds: 0,
    partialFilterExpression: { revoked: false }
  }
);

// Índices para melhorar performance
TokenBlacklistSchema.index({ expires: 1 }, { expireAfterSeconds: 0 }); // Auto-remove expirados
RefreshTokenSchema.index({ userId: 1 });
RefreshTokenSchema.index({ token: 1 });

// Criar modelos
const TokenBlacklist = mongoose.model('TokenBlacklist', TokenBlacklistSchema);
const RefreshToken = mongoose.model('RefreshToken', RefreshTokenSchema);

module.exports = {
  TokenBlacklist,
  RefreshToken
};