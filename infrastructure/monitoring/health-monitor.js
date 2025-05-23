// src/infrastructure/monitoring/health-monitor.js
const { getConnection } = require('../database/mysql/connection');
const os = require('os');
const logger = require('../logging/logger');
const mailService = require('../external/mail.service');

/**
 * Monitor de saúde da aplicação para MySQL
 * Substitui o health-monitor.js que usava MongoDB
 */
class MySQLHealthMonitor {
  /**
   * Verifica o estado geral da aplicação
   * @returns {Object} Estado de saúde da aplicação e seus componentes
   */
  async checkHealth() {
    try {
      const startTime = process.hrtime();
      
      const [
        dbStatus,
        emailStatus,
        systemInfo
      ] = await Promise.all([
        this.checkDatabase(),
        this.checkEmailService(),
        this.getSystemInfo()
      ]);
      
      const endTime = process.hrtime(startTime);
      const responseTime = Math.round((endTime[0] * 1000) + (endTime[1] / 1000000));
      
      // Determinar status geral com base nos componentes críticos
      const overallStatus = dbStatus.status === 'UP' ? 'UP' : 'DOWN';
      
      return {
        status: overallStatus,
        timestamp: new Date().toISOString(),
        responseTime: `${responseTime}ms`,
        services: {
          database: dbStatus,
          email: emailStatus
        },
        system: systemInfo
      };
    } catch (error) {
      logger.error(`Erro ao verificar saúde da aplicação: ${error.message}`);
      return {
        status: 'DOWN',
        timestamp: new Date().toISOString(),
        error: error.message
      };
    }
  }
  
  /**
   * Verifica o estado da conexão com o banco de dados MySQL
   * @returns {Object} Estado da conexão com o MySQL
   */
  async checkDatabase() {
    try {
      const sequelize = getConnection();
      
      if (!sequelize) {
        return {
          status: 'DOWN',
          error: 'Nenhuma conexão disponível'
        };
      }

      // Verificar se a conexão está ativa
      let connectionStatus = 'disconnected';
      let pingResult = null;
      
      try {
        // Testar conexão
        await sequelize.authenticate();
        connectionStatus = 'connected';
        
        // Fazer ping no banco
        const startTime = process.hrtime();
        await sequelize.query('SELECT 1 as ping');
        const endTime = process.hrtime(startTime);
        pingResult = Math.round((endTime[0] * 1000) + (endTime[1] / 1000000));
        
      } catch (error) {
        logger.error(`Erro ao verificar conexão MySQL: ${error.message}`);
        return {
          status: 'DOWN',
          error: error.message
        };
      }
      
      return {
        status: connectionStatus === 'connected' ? 'UP' : 'DOWN',
        details: {
          state: connectionStatus,
          pingTime: pingResult ? `${pingResult}ms` : null,
          dialect: sequelize.getDialect(),
          database: sequelize.getDatabaseName(),
          host: sequelize.config.host,
          port: sequelize.config.port
        }
      };
    } catch (error) {
      logger.error(`Erro ao verificar conexão com MySQL: ${error.message}`);
      return {
        status: 'DOWN',
        error: error.message
      };
    }
  }
  
  /**
   * Verifica o estado do serviço de e-mail
   * @returns {Object} Estado do serviço de e-mail
   */
  async checkEmailService() {
    try {
      // Verificação não invasiva do serviço de e-mail
      if (!mailService || !mailService.transporter) {
        return {
          status: 'UNKNOWN',
          details: {
            reason: 'Serviço de e-mail não configurado'
          }
        };
      }
      
      // Verificar se o transporter está verificado (sem enviar e-mail)
      const emailCheck = await new Promise((resolve) => {
        mailService.transporter.verify((error) => {
          if (error) {
            logger.warn(`Verificação do servidor de e-mail falhou: ${error.message}`);
            resolve({ success: false, error: error.message });
          } else {
            resolve({ success: true });
          }
        });
      });
      
      return {
        status: emailCheck.success ? 'UP' : 'DOWN',
        details: emailCheck.success ? {
          host: mailService.transporter.options.host,
          port: mailService.transporter.options.port,
          secure: mailService.transporter.options.secure
        } : {
          error: emailCheck.error
        }
      };
    } catch (error) {
      logger.error(`Erro ao verificar serviço de e-mail: ${error.message}`);
      return {
        status: 'DOWN',
        error: error.message
      };
    }
  }
  
  /**
   * Coleta informações do sistema e da aplicação
   * @returns {Object} Informações do sistema
   */
  async getSystemInfo() {
    try {
      const freeMem = os.freemem();
      const totalMem = os.totalmem();
      const usedMem = totalMem - freeMem;
      const memUsage = process.memoryUsage();
      
      return {
        uptime: {
          system: Math.floor(os.uptime()),
          process: Math.floor(process.uptime())
        },
        memory: {
          system: {
            total: this.formatBytes(totalMem),
            used: this.formatBytes(usedMem),
            free: this.formatBytes(freeMem),
            usage: Math.round((usedMem / totalMem) * 100)
          },
          process: {
            rss: this.formatBytes(memUsage.rss),
            heapTotal: this.formatBytes(memUsage.heapTotal),
            heapUsed: this.formatBytes(memUsage.heapUsed),
            external: this.formatBytes(memUsage.external)
          }
        },
        cpu: {
          arch: os.arch(),
          cores: os.cpus().length,
          model: os.cpus()[0].model,
          loadAvg: os.loadavg().map(load => load.toFixed(2))
        },
        node: {
          version: process.version,
          environment: process.env.NODE_ENV
        }
      };
    } catch (error) {
      logger.error(`Erro ao coletar informações do sistema: ${error.message}`);
      return {
        error: 'Não foi possível coletar informações do sistema'
      };
    }
  }
  
  /**
   * Formata bytes para uma representação legível
   * @param {number} bytes Número de bytes
   * @returns {string} Representação formatada
   */
  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    
    return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${sizes[i]}`;
  }
}

module.exports = new MySQLHealthMonitor();