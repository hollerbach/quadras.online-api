const defineModels = require('../database/mysql/models');
const logger = require('./logger');
const { v4: uuidv4 } = require('uuid');

/**
 * Serviço para registro de logs de auditoria usando MySQL/Sequelize
 * Substitui o audit.service.js que usava MongoDB
 */
class MySQLAuditService {
  constructor() {
    try {
      this.models = defineModels();
    } catch (error) {
      logger.error('Erro ao inicializar modelos para auditoria:', error);
      this.models = null;
    }
  }

  /**
   * Registra uma ação para auditoria
   * @param {Object} logData - Dados do log
   */
  async log(logData) {
    try {
      if (!this.models || !this.models.AuditLog) {
        logger.warn('Modelo AuditLog não disponível');
        return;
      }

      const { action, userId, userEmail, ipAddress, details } = logData;

      await this.models.AuditLog.create({
        id: uuidv4(),
        action,
        userId,
        userEmail,
        ipAddress,
        details: JSON.stringify(details || {}),
        timestamp: new Date()
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
    try {
      if (!this.models || !this.models.AuditLog) {
        throw new Error('Modelo AuditLog não disponível');
      }

      const { page = 1, limit = 50, sort = [['timestamp', 'DESC']] } = options;

      // Construir where clause para Sequelize
      const whereClause = {};
      
      if (filters.action) {
        whereClause.action = filters.action;
      }
      
      if (filters.userId) {
        whereClause.userId = filters.userId;
      }
      
      if (filters.userEmail) {
        whereClause.userEmail = filters.userEmail;
      }

      if (filters.startDate && filters.endDate) {
        whereClause.timestamp = {
          [this.models.AuditLog.sequelize.Sequelize.Op.between]: [filters.startDate, filters.endDate]
        };
      }

      const { count, rows } = await this.models.AuditLog.findAndCountAll({
        where: whereClause,
        order: sort,
        offset: (page - 1) * limit,
        limit: limit
      });

      // Parse JSON details se necessário
      const logs = rows.map(log => {
        const logData = log.toJSON();
        try {
          if (typeof logData.details === 'string') {
            logData.details = JSON.parse(logData.details);
          }
        } catch (error) {
          // Manter como string se não for JSON válido
        }
        return logData;
      });

      return {
        logs,
        total: count,
        page,
        limit,
        pages: Math.ceil(count / limit)
      };
    } catch (error) {
      logger.error(`Erro ao buscar logs de auditoria: ${error.message}`);
      throw error;
    }
  }

  /**
   * Busca logs de auditoria por usuário
   * @param {string} userId - ID do usuário
   * @param {Object} options - Opções de paginação
   * @returns {Promise<Object>} Logs encontrados e metadados
   */
  async getLogsByUser(userId, options = {}) {
    return this.getLogs({ userId }, options);
  }

  /**
   * Busca logs de auditoria por ação
   * @param {string} action - Ação a ser buscada
   * @param {Object} options - Opções de paginação
   * @returns {Promise<Object>} Logs encontrados e metadados
   */
  async getLogsByAction(action, options = {}) {
    return this.getLogs({ action }, options);
  }

  /**
   * Remove logs antigos (limpeza de dados)
   * @param {number} daysOld - Número de dias para manter
   * @returns {Promise<number>} Número de registros removidos
   */
  async cleanupOldLogs(daysOld = 365) {
    try {
      if (!this.models || !this.models.AuditLog) {
        throw new Error('Modelo AuditLog não disponível');
      }

      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysOld);

      const deletedCount = await this.models.AuditLog.destroy({
        where: {
          timestamp: {
            [this.models.AuditLog.sequelize.Sequelize.Op.lt]: cutoffDate
          }
        }
      });

      logger.info(`Removidos ${deletedCount} logs de auditoria antigos (>${daysOld} dias)`);
      return deletedCount;
    } catch (error) {
      logger.error(`Erro ao limpar logs antigos: ${error.message}`);
      throw error;
    }
  }
}

module.exports = new MySQLAuditService();