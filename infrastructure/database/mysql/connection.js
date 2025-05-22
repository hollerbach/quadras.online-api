// src/infrastructure/database/mysql/connection.js
const { Sequelize } = require('sequelize');
const config = require('../../config');
const logger = require('../../logging/logger');

// Instância do Sequelize
let sequelize;

/**
 * Conecta ao banco de dados MySQL com as configurações definidas
 * @returns {Promise<Sequelize>} Instância do Sequelize conectada
 */
const connectToDatabase = async () => {
  try {
    // Criar instância do Sequelize com as configurações
    sequelize = new Sequelize(
      config.db.mysql.database,
      config.db.mysql.username,
      config.db.mysql.password,
      {
        host: config.db.mysql.host,
        port: config.db.mysql.port,
        dialect: config.db.mysql.dialect,
        dialectOptions: config.db.mysql.dialectOptions,
        pool: config.db.mysql.pool,
        define: config.db.mysql.define,
        logging: config.db.mysql.logging
      }
    );

    // Testar a conexão
    await sequelize.authenticate();
    logger.info('Conexão com MySQL estabelecida com sucesso');
    
    // Configurar manipuladores de eventos para gerenciar a conexão
    sequelize.addHook('beforeConnect', (config) => {
      logger.debug('Tentando conectar ao MySQL...');
    });
    
    sequelize.addHook('afterConnect', (connection) => {
      logger.info('MySQL conectado');
    });
    
    sequelize.addHook('beforeDisconnect', (connection) => {
      logger.debug('Encerrando conexão com MySQL...');
    });
    
    sequelize.addHook('afterDisconnect', () => {
      logger.info('MySQL desconectado');
    });
    
    return sequelize;
  } catch (error) {
    logger.error(`Erro ao conectar ao MySQL: ${error.message}`);
    throw error;
  }
};

/**
 * Fecha a conexão com o banco de dados
 * @returns {Promise<void>}
 */
const closeConnection = async () => {
  if (sequelize) {
    logger.info('Encerrando conexão com MySQL...');
    await sequelize.close();
    logger.info('Conexão MySQL encerrada');
  }
};

/**
 * Retorna a instância atual do Sequelize
 * @returns {Sequelize|null} Instância do Sequelize ou null
 */
const getConnection = () => sequelize;

// Exportar funções
module.exports = {
  connectToDatabase,
  closeConnection,
  getConnection
};