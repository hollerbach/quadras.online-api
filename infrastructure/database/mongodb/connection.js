// src/infrastructure/database/mongodb/connection.js
const mongoose = require('mongoose');
const config = require('../../config');
const logger = require('../../logging/logger');

// Armazena a conexão para uso posterior
let connection;

/**
 * Conecta ao banco de dados MongoDB com opções robustas
 * @returns {Promise<mongoose.Connection>} Conexão do MongoDB
 */
const connectToDatabase = async () => {
  try {
    // Configurações de conexão robustas para ambiente de produção
    const options = {
      serverSelectionTimeoutMS: 5000, // Tempo limite de seleção de servidor
      socketTimeoutMS: 45000, // Tempo limite para operações de socket
      family: 4, // Use IPv4, ignore IPv6
      maxPoolSize: 10, // Máximo de conexões no pool
      minPoolSize: 2, // Mínimo de conexões mantidas no pool
      connectTimeoutMS: 10000, // Tempo limite para conexão inicial
      heartbeatFrequencyMS: 10000, // Frequência de verificação de servidores
      retryWrites: true, // Tentar reescrever em caso de falha
      writeConcern: {
        w: 'majority', // Confirmar escrita na maioria dos servidores
        j: true // Aguardar gravação no journal
      }
    };

    // Manipuladores de eventos para monitoramento da conexão
    mongoose.connection.on('connected', () => {
      logger.info('Mongoose conectado ao MongoDB');
    });

    mongoose.connection.on('error', (err) => {
      logger.error(`Erro de conexão Mongoose: ${err.message}`);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('Mongoose desconectado do MongoDB');
    });

    mongoose.connection.on('reconnected', () => {
      logger.info('Mongoose reconectado ao MongoDB');
    });

    // Lidar com sinais de término para encerrar a conexão adequadamente
    process.on('SIGINT', () => closeConnection().then(() => process.exit(0)));
    process.on('SIGTERM', () => closeConnection().then(() => process.exit(0)));

    // Fazer a conexão
    await mongoose.connect(config.db.uri, options);
    
    // Armazenar referência
    connection = mongoose.connection;
    
    return connection;
  } catch (error) {
    logger.error(`Erro ao conectar ao MongoDB: ${error.message}`);
    throw error;
  }
};

/**
 * Fecha a conexão com o banco de dados
 * @returns {Promise<void>}
 */
const closeConnection = async () => {
  if (connection) {
    logger.info('Encerrando conexão com MongoDB...');
    await mongoose.disconnect();
    logger.info('Conexão MongoDB encerrada');
  }
};

/**
 * Retorna a conexão atual com o MongoDB
 * @returns {mongoose.Connection|null} Conexão existente ou null
 */
const getConnection = () => connection;

module.exports = {
  connectToDatabase,
  closeConnection,
  getConnection
};