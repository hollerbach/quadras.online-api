// Novo arquivo: services/audit.service.js
const mongoose = require('mongoose');
const logger = require('./logger');

// Modelo para log de auditoria
const AuditLog = mongoose.model('AuditLog', new mongoose.Schema({
  action: {
    type: String,
    required: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
  },
  userEmail: String,
  ipAddress: String,
  details: mongoose.Schema.Types.Mixed,
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
}));

class AuditService {
  /**
   * Registra uma ação para auditoria
   * @param {Object} logData - Dados do log
   */
  async log(logData) {
    try {
      const { action, userId, userEmail, ipAddress, details } = logData;
      
      await AuditLog.create({
        action,
        userId,
        userEmail,
        ipAddress,
        details
      });
      
      logger.info(`Audit: [${action}] ${userEmail || userId || 'Sistema'}`);
    } catch (error) {
      logger.error(`Erro ao registrar auditoria: ${error.message}`);
    }
  }
  
  /**
   * Busca logs de auditoria com filtros
   * @param {Object} filters - Filtros de busca
   * @param {Object} options - Opções de paginação
   * @returns {Promise<Object>} Logs encontrados e metadados
   */
  async getLogs(filters = {}, options = {}) {
    const { page = 1, limit = 50, sort = '-timestamp' } = options;
    
    const total = await AuditLog.countDocuments(filters);
    const logs = await AuditLog.find(filters)
      .sort(sort)
      .skip((page - 1) * limit)
      .limit(limit);
    
    return {
      logs,
      total,
      page,
      limit,
      pages: Math.ceil(total / limit)
    };
  }
}

module.exports = new AuditService();